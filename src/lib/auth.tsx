import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api, ApiError, setCsrfToken } from "./api";
import {
  clearVaultKey,
  loadVaultKey,
  refreshVaultKeyStamp,
  saveVaultKey,
} from "./keyStore";
import {
  DEFAULT_ARGON2_PARAMS,
  bytesToBase64Url,
  base64UrlToBytes,
  deriveAuthKey,
  deriveMasterKey,
  deriveRootKey,
  generateKeySalt,
  generateVaultKey,
  importVaultKey,
  unwrapVaultKey,
  vaultStamp,
  wrapVaultKey,
} from "./e2ee";

interface AuthContextType {
  isAuthenticated: boolean;
  isLoading: boolean;
  /** null means the server has not answered yet. */
  configured: boolean | null;
  /** True when claiming this instance requires the SETUP_TOKEN secret. */
  setupTokenRequired: boolean;
  vaultKey: CryptoKey | null;
  error: string | null;
  setup: (
    passphrase: string,
    rememberDevice: boolean,
    setupToken?: string,
  ) => Promise<void>;
  login: (passphrase: string, rememberDevice: boolean) => Promise<void>;
  logout: () => Promise<void>;
  /** Drop the vault key locally (memory + cache) without ending the session. */
  lock: () => Promise<void>;
  changePassphrase: (oldPassphrase: string, newPassphrase: string) => Promise<void>;
  checkAuth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);
const LOGOUT_STORAGE_KEY = "ghostbin-logout";
const MIN_PASSPHRASE_LENGTH = 8;

function wipe(...arrays: Array<Uint8Array | null | undefined>): void {
  for (const array of arrays) array?.fill(0);
}

function messageFor(error: unknown): string {
  if (error instanceof ApiError) {
    return error.retryAfter
      ? `${error.message}. Try again in ${error.retryAfter}s.`
      : error.message;
  }
  return error instanceof Error ? error.message : "Something went wrong";
}

function assertPassphrase(passphrase: string): void {
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`Use a passphrase of at least ${MIN_PASSPHRASE_LENGTH} characters.`);
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [isLoading, setIsLoading] = useState(true);
  const [configured, setConfigured] = useState<boolean | null>(null);
  const [setupTokenRequired, setSetupTokenRequired] = useState(false);
  const [vaultKey, setVaultKey] = useState<CryptoKey | null>(null);
  const [error, setError] = useState<string | null>(null);

  const forgetVaultKey = useCallback(async () => {
    setVaultKey(null);
    try {
      await clearVaultKey();
    } catch {
      // IndexedDB may be unavailable; the in-memory key is already gone.
    }
  }, []);

  const checkAuth = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const params = await api.auth.params();
      if (params.configured !== true && params.configured !== false) {
        throw new Error("The server returned invalid configuration data.");
      }
      setConfigured(params.configured);
      if (params.configured === false) {
        setSetupTokenRequired(params.setupTokenRequired === true);
        await forgetVaultKey();
        return;
      }
      setSetupTokenRequired(false);
      if (!params.kdfSalt || !params.kdfParams) {
        throw new Error("The server returned invalid login parameters.");
      }

      let vault;
      try {
        vault = await api.auth.vault();
      } catch (vaultError) {
        if (vaultError instanceof ApiError && vaultError.status === 401) {
          // The session is gone: lock the app but keep the cached key. A
          // 401 must not log the user out or delete the cached key; they
          // only need to log in again with the same passphrase.
          setCsrfToken(null);
          setVaultKey(null);
          return;
        }
        throw vaultError;
      }

      let storedKey: CryptoKey | null = null;
      try {
        // loadVaultKey discards the cached record when its canary or its
        // stamp (hash of the current wrapped vault key) does not match.
        storedKey = await loadVaultKey(await vaultStamp(vault.wrappedVaultKey));
      } catch {
        // The passphrase can still unlock the vault for this page load.
      }
      setVaultKey(storedKey);
    } catch (authError) {
      setError(messageFor(authError));
    } finally {
      setIsLoading(false);
    }
  }, [forgetVaultKey]);

  useEffect(() => {
    void checkAuth();
  }, [checkAuth]);

  useEffect(() => {
    const handleInvalidAuth = () => {
      void checkAuth();
    };
    const handleStorage = (event: StorageEvent) => {
      if (event.key !== LOGOUT_STORAGE_KEY) return;
      setCsrfToken(null);
      void forgetVaultKey();
    };

    window.addEventListener("ghostbin-auth-invalid", handleInvalidAuth);
    window.addEventListener("storage", handleStorage);
    return () => {
      window.removeEventListener("ghostbin-auth-invalid", handleInvalidAuth);
      window.removeEventListener("storage", handleStorage);
    };
  }, [checkAuth, forgetVaultKey]);

  const persistKey = useCallback(
    async (keyHandle: CryptoKey, stamp: string, rememberDevice: boolean) => {
      if (!rememberDevice) {
        // The user declined persistence: drop any previous grant so a
        // device that was remembered earlier does not stay remembered.
        try {
          await clearVaultKey();
        } catch {
          // Persistence is best-effort; the in-memory key still works.
        }
        return;
      }
      try {
        await saveVaultKey(keyHandle, stamp);
      } catch {
        // Continue with an in-memory key if persistence is unavailable.
      }
    },
    [],
  );

  const setup = useCallback(
    async (passphrase: string, rememberDevice: boolean, setupToken?: string) => {
    setIsLoading(true);
    setError(null);

    let salt: Uint8Array | null = null;
    let root: Uint8Array | null = null;
    let authKey: Uint8Array | null = null;
    let vaultBytes: Uint8Array | null = null;

    try {
      const params = await api.auth.params();
      if (params.configured === true) {
        setConfigured(true);
        throw new Error("This server is already configured; log in instead.");
      }
      if (params.configured !== false) {
        throw new Error("The server returned invalid setup parameters.");
      }
      assertPassphrase(passphrase);

      salt = generateKeySalt();
      root = await deriveRootKey(
        passphrase,
        salt,
        DEFAULT_ARGON2_PARAMS,
      );
      authKey = await deriveAuthKey(root);
      const masterKey = await deriveMasterKey(root);
      vaultBytes = generateVaultKey();
      const wrappedVaultKey = await wrapVaultKey(masterKey, vaultBytes);

      await api.auth.setup(
        {
          authKey: bytesToBase64Url(authKey),
          kdfSalt: bytesToBase64Url(salt),
          kdfParams: { ...DEFAULT_ARGON2_PARAMS },
          wrappedVaultKey,
        },
        setupToken,
      );

      const keyHandle = await importVaultKey(vaultBytes);
      await persistKey(keyHandle, await vaultStamp(wrappedVaultKey), rememberDevice);
      setVaultKey(keyHandle);
      setConfigured(true);
    } catch (setupError) {
      setError(messageFor(setupError));
      throw setupError;
    } finally {
      wipe(salt, root, authKey, vaultBytes);
      setIsLoading(false);
    }
  }, [persistKey]);

  const login = useCallback(async (passphrase: string, rememberDevice: boolean) => {
    setIsLoading(true);
    setError(null);

    let salt: Uint8Array | null = null;
    let root: Uint8Array | null = null;
    let authKey: Uint8Array | null = null;
    let vaultBytes: Uint8Array | null = null;

    try {
      const params = await api.auth.params();
      setConfigured(params.configured === true);
      if (params.configured !== true) {
        throw new Error("This server is not set up yet.");
      }
      if (!params.kdfSalt || !params.kdfParams) {
        throw new Error("The server did not return valid login parameters.");
      }

      salt = base64UrlToBytes(params.kdfSalt);
      root = await deriveRootKey(passphrase, salt, params.kdfParams);
      authKey = await deriveAuthKey(root);
      const masterKey = await deriveMasterKey(root);

      await api.auth.login({ authKey: bytesToBase64Url(authKey) });
      const vault = await api.auth.vault();
      vaultBytes = await unwrapVaultKey(masterKey, vault.wrappedVaultKey);

      const keyHandle = await importVaultKey(vaultBytes);
      await persistKey(
        keyHandle,
        await vaultStamp(vault.wrappedVaultKey),
        rememberDevice,
      );
      setVaultKey(keyHandle);
      setConfigured(true);
    } catch (loginError) {
      setError(messageFor(loginError));
      throw loginError;
    } finally {
      wipe(salt, root, authKey, vaultBytes);
      setIsLoading(false);
    }
  }, [persistKey]);

  const changePassphrase = useCallback(
    async (oldPassphrase: string, newPassphrase: string) => {
      setError(null);

      let oldSalt: Uint8Array | null = null;
      let oldRoot: Uint8Array | null = null;
      let oldAuthKey: Uint8Array | null = null;
      let newSalt: Uint8Array | null = null;
      let newRoot: Uint8Array | null = null;
      let newAuthKey: Uint8Array | null = null;
      let vaultBytes: Uint8Array | null = null;

      try {
        assertPassphrase(newPassphrase);

        const params = await api.auth.params();
        if (params.configured !== true || !params.kdfSalt || !params.kdfParams) {
          throw new Error("The server did not return valid login parameters.");
        }

        // Verify the old passphrase and unwrap the vault key with it.
        oldSalt = base64UrlToBytes(params.kdfSalt);
        oldRoot = await deriveRootKey(oldPassphrase, oldSalt, params.kdfParams);
        oldAuthKey = await deriveAuthKey(oldRoot);
        const oldMasterKey = await deriveMasterKey(oldRoot);

        const vault = await api.auth.vault();
        vaultBytes = await unwrapVaultKey(oldMasterKey, vault.wrappedVaultKey);

        // Derive fresh material for the new passphrase and rewrap the
        // unchanged vault key with the new master key.
        newSalt = generateKeySalt();
        newRoot = await deriveRootKey(newPassphrase, newSalt, DEFAULT_ARGON2_PARAMS);
        newAuthKey = await deriveAuthKey(newRoot);
        const newMasterKey = await deriveMasterKey(newRoot);
        const newWrappedVaultKey = await wrapVaultKey(newMasterKey, vaultBytes);

        await api.auth.changePassphrase({
          oldAuthKey: bytesToBase64Url(oldAuthKey),
          newAuthKey: bytesToBase64Url(newAuthKey),
          newKdfSalt: bytesToBase64Url(newSalt),
          newKdfParams: { ...DEFAULT_ARGON2_PARAMS },
          newWrappedVaultKey,
        });

        // The vault key itself is unchanged, so the live handle stays valid.
        // If this device had a cached key, refresh its stamp: the new
        // envelope invalidates the old stamp. Other devices see a stamp
        // mismatch on their next load and must derive the key again.
        const stamp = await vaultStamp(newWrappedVaultKey);
        const handle = await importVaultKey(vaultBytes);
        setVaultKey((current) => current ?? handle);
        try {
          await refreshVaultKeyStamp(handle, stamp);
        } catch {
          // A broken cache does not fail the passphrase change.
        }
      } catch (changeError) {
        setError(messageFor(changeError));
        throw changeError;
      } finally {
        wipe(oldSalt, oldRoot, oldAuthKey, newSalt, newRoot, newAuthKey, vaultBytes);
      }
    },
    [],
  );

  const lock = useCallback(async () => {
    await forgetVaultKey();
  }, [forgetVaultKey]);

  const logout = useCallback(async () => {
    setError(null);
    setCsrfToken(null);
    // Remove the local key first. If the network request stalls and the tab
    // closes, a later reload must not auto-unlock from the cached key.
    await forgetVaultKey();
    try {
      window.localStorage.setItem(LOGOUT_STORAGE_KEY, String(Date.now()));
    } catch {
      // Storage may be unavailable; local logout still succeeded.
    }
    try {
      await api.auth.logout();
    } catch (logoutError) {
      // Even if the session is already gone, the local key is removed.
      if (!(logoutError instanceof ApiError && logoutError.status === 401)) {
        setError(messageFor(logoutError));
      }
    }
  }, [forgetVaultKey]);

  const value = useMemo<AuthContextType>(
    () => ({
      isAuthenticated: vaultKey !== null,
      isLoading,
      configured,
      setupTokenRequired,
      vaultKey,
      error,
      setup,
      login,
      logout,
      lock,
      changePassphrase,
      checkAuth,
    }),
    [
      vaultKey,
      isLoading,
      configured,
      setupTokenRequired,
      error,
      setup,
      login,
      logout,
      lock,
      changePassphrase,
      checkAuth,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used inside AuthProvider");
  }
  return context;
}

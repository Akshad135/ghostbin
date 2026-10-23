// API client for the Phase 3 encrypted backend.
//
// All owner requests use the HttpOnly session cookie. Mutating requests also
// send the CSRF token issued at login/setup and stored in the readable
// __Host-gb_csrf cookie. Guest share requests use a short-lived share token.

const API_BASE = "/api";

// Attachment transfers scale their abort timer with the payload size so a
// max-size file on a slow link is not cut off mid-transfer.
const SLOW_LINK_BYTES_PER_SEC = 100 * 1024;
const timeoutForBytes = (bytes: number, floorMs: number) =>
  Math.max(floorMs, (bytes / SLOW_LINK_BYTES_PER_SEC) * 1000);

export type BurnMode = "time" | "unlock_count";

export interface KdfParams {
  memorySize: number;
  iterations: number;
  parallelism: number;
  hashLength: number;
}

export interface AuthParams {
  configured: boolean;
  /** True when the server requires SETUP_TOKEN to claim a fresh instance. */
  setupTokenRequired?: boolean;
  /** Server-side size limits; the browser adopts these at runtime. */
  maxTextSize?: number;
  maxFileSize?: number;
  kdfSalt?: string;
  kdfParams?: KdfParams;
}

export interface VaultResponse {
  kdfSalt: string;
  kdfParams: KdfParams;
  wrappedVaultKey: string;
}

export interface AuthSessionResponse {
  success: boolean;
  csrfToken: string;
}

export interface FileMeta {
  id: string;
  encMeta: string;
  /** Encrypted body length in bytes, as stored by the server. */
  size: number;
  createdAt: number;
}

export interface PasteSummary {
  id: string;
  keySalt: string;
  titleCt: string;
  languageCt: string | null;
  pinned: boolean;
  burnMode: BurnMode | null;
  burnAfter: number | null;
  burnAt: number | null;
  createdAt: number;
  updatedAt: number;
  fileCount: number;
}

export interface PasteDetail extends PasteSummary {
  contentCt: string;
  files: FileMeta[];
}

export interface PasteListResponse {
  pastes: PasteSummary[];
  total: number;
  page: number;
  limit: number;
  hasMore: boolean;
}

export interface CreatePasteInput {
  id: string;
  keySalt: string;
  titleCt: string;
  contentCt: string;
  languageCt?: string | null;
  pinned?: boolean;
  burnMode?: BurnMode | "none" | null;
  burnAfter?: number | null;
  burnAfterSeconds?: number | null;
}

export interface UpdatePasteInput {
  titleCt?: string;
  contentCt?: string;
  languageCt?: string | null;
  pinned?: boolean;
  burnMode?: BurnMode | "none";
  burnAfter?: number | null;
  burnAfterSeconds?: number | null;
}

export interface ShareInfo {
  createdAt: number;
  expiresAt: number | null;
  unlocksUsed?: number;
  maxUnlocks: number | null;
}

export type ShareStatusResponse =
  | { exists: false }
  | { exists: true; share: ShareInfo };

export interface CreateShareInput {
  shareSalt: string;
  shareAuthKey: string;
  /** KDF params the share keys were derived with; pinned per share. */
  kdfParams: KdfParams;
  wrappedPasteKey: string;
  expiresAt?: number | null;
  maxUnlocks?: number | null;
  replace?: boolean;
}

export interface ShareParams {
  shareSalt: string;
  kdfParams: KdfParams;
  expiresAt: number | null;
  unlocksUsed: number;
  maxUnlocks: number | null;
}

export interface ChallengeResponse {
  nonce: string;
  expiresAt: number;
}

export interface UnlockResponse {
  shareToken: string;
  shareTokenExpiresAt: number;
  unlocksUsed: number;
  maxUnlocks: number | null;
  files: FileMeta[];
}

export interface GuestPaste {
  id: string;
  titleCt: string;
  contentCt: string;
  languageCt: string | null;
  pinned: boolean;
  burnMode: BurnMode | null;
  burnAfter: number | null;
  burnAt: number | null;
  createdAt: number;
  updatedAt: number;
}

export interface GuestShare {
  shareSalt: string;
  wrappedPasteKey: string;
}

export interface ViewResponse {
  success: boolean;
  unlocksUsed: number;
  burned: boolean;
  paste: GuestPaste;
  share: GuestShare;
  files: FileMeta[];
}

export interface PasteEvent {
  type: string;
  // Empty for "resync" events: the server sends those (without a pasteId)
  // when a connection lagged and may have dropped events, so listeners
  // should refetch state instead of keying on a specific paste.
  pasteId: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly retryAfter?: number;

  constructor(
    message: string,
    status: number,
    code: string,
    retryAfter?: number,
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.retryAfter = retryAfter;
  }
}

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

function readCsrfCookie(): string | null {
  if (typeof document === "undefined") return null;
  const name = "__Host-gb_csrf=";
  for (const part of document.cookie.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(name)) {
      return decodeURIComponent(trimmed.slice(name.length));
    }
  }
  return null;
}

function currentCsrfToken(): string | null {
  // The cookie is shared by every tab. Prefer it so a login in another tab
  // does not leave this tab holding a stale in-memory token.
  return readCsrfCookie() ?? csrfToken;
}

function retryAfterSeconds(response: Response): number | undefined {
  const header = response.headers.get("retry-after");
  if (!header) return undefined;
  const value = Number(header);
  return Number.isFinite(value) && value > 0 ? value : undefined;
}

async function errorFromResponse(response: Response): Promise<ApiError> {
  let message = `Request failed (${response.status})`;
  let code = `HTTP_${response.status}`;

  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    try {
      const body = (await response.json()) as {
        error?: unknown;
        message?: unknown;
        code?: unknown;
      };
      if (typeof body.error === "string" && body.error) message = body.error;
      else if (typeof body.message === "string" && body.message) {
        message = body.message;
      }
      if (typeof body.code === "string" && body.code) code = body.code;
    } catch {
      // Keep the status-based fallback.
    }
  }

  return new ApiError(
    message,
    response.status,
    code,
    retryAfterSeconds(response),
  );
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  headers.set("Accept", "application/json");

  const token = currentCsrfToken();
  if (token) headers.set("X-CSRF-Token", token);

  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 30_000);

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers,
      credentials: "include",
      cache: "no-store",
      signal: options.signal ?? controller.signal,
    });
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new ApiError("The request timed out", 0, "TIMEOUT");
    }
    throw new ApiError("Cannot reach the server", 0, "NETWORK");
  } finally {
    window.clearTimeout(timeout);
  }

  if (!response.ok) {
    const error = await errorFromResponse(response);
    if (error.status === 403 && error.code === "CSRF_REJECTED") {
      window.dispatchEvent(new Event("ghostbin-auth-invalid"));
    }
    throw error;
  }
  if (response.status === 204) return undefined as T;

  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    throw new ApiError(
      "The server returned an unexpected response",
      response.status,
      "INVALID_RESPONSE",
    );
  }
  return (await response.json()) as T;
}

function jsonRequest<T>(
  path: string,
  method: "POST" | "PUT" | "DELETE",
  body?: unknown,
): Promise<T> {
  const headers: Record<string, string> = {};
  let encoded: string | undefined;
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    encoded = JSON.stringify(body);
  }
  return request<T>(path, { method, body: encoded, headers });
}

async function downloadFile(
  fileId: string,
  shareToken?: string,
): Promise<Uint8Array> {
  const headers = new Headers();
  if (shareToken) headers.set("X-Share-Token", shareToken);

  const controller = new AbortController();
  let timeout = window.setTimeout(() => controller.abort(), timeoutForBytes(0, 60_000));

  try {
    const response = await fetch(`${API_BASE}/files/${encodeURIComponent(fileId)}`, {
      headers,
      credentials: "include",
      cache: "no-store",
      signal: controller.signal,
    });
    // Headers are in — re-arm the timer for the body based on its size so
    // large attachments on slow links are not cut off mid-download.
    window.clearTimeout(timeout);
    timeout = window.setTimeout(
      () => controller.abort(),
      timeoutForBytes(Number(response.headers.get("Content-Length") ?? 0), 60_000),
    );
    if (!response.ok) throw await errorFromResponse(response);
    return new Uint8Array(await response.arrayBuffer());
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new ApiError("The file download timed out", 0, "TIMEOUT");
    }
    throw new ApiError("Cannot reach the server", 0, "NETWORK");
  } finally {
    window.clearTimeout(timeout);
  }
}

interface UploadFileInput {
  pasteId: string;
  fileId: string;
  encrypted: Uint8Array;
  encMeta: string;
}

function arrayBufferOf(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}

async function uploadFile(input: UploadFileInput): Promise<void> {
  const headers = new Headers();
  headers.set("Content-Type", "application/octet-stream");
  headers.set("X-File-Meta", input.encMeta);

  const token = currentCsrfToken();
  if (token) headers.set("X-CSRF-Token", token);

  const query = new URLSearchParams({
    pasteId: input.pasteId,
    fileId: input.fileId,
    size: String(input.encrypted.byteLength),
  });

  const controller = new AbortController();
  const timeout = window.setTimeout(
    () => controller.abort(),
    timeoutForBytes(input.encrypted.byteLength, 120_000),
  );

  let response: Response;
  try {
    response = await fetch(`${API_BASE}/files?${query.toString()}`, {
      method: "POST",
      headers,
      body: arrayBufferOf(input.encrypted),
      credentials: "include",
      cache: "no-store",
      signal: controller.signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new ApiError("The file upload timed out", 0, "TIMEOUT");
    }
    throw new ApiError("Cannot reach the server", 0, "NETWORK");
  } finally {
    window.clearTimeout(timeout);
  }

  if (!response.ok) throw await errorFromResponse(response);
}

function subscribeEvents(listener: (event: PasteEvent) => void): () => void {
  if (typeof window === "undefined") return () => {};

  let socket: WebSocket | null = null;
  let closed = false;
  let retryTimer: number | null = null;
  let attempt = 0;

  const connect = () => {
    if (closed) return;
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    socket = new WebSocket(`${protocol}//${window.location.host}/api/events`);

    socket.addEventListener("open", () => {
      attempt = 0;
    });

    socket.addEventListener("message", (message) => {
      if (typeof message.data !== "string") return;
      try {
        const event = JSON.parse(message.data) as Partial<PasteEvent>;
        if (event.type === "resync") {
          listener({ type: "resync", pasteId: "" });
        } else if (
          typeof event.type === "string" &&
          typeof event.pasteId === "string"
        ) {
          listener({ type: event.type, pasteId: event.pasteId });
        }
      } catch {
        // The event channel is notification-only; ignore malformed messages.
      }
    });

    socket.addEventListener("close", () => {
      socket = null;
      if (closed) return;
      const delay = Math.min(30_000, 1_000 * 2 ** Math.min(attempt, 5));
      attempt += 1;
      retryTimer = window.setTimeout(connect, delay);
    });

    socket.addEventListener("error", () => {
      socket?.close();
    });
  };

  connect();

  return () => {
    closed = true;
    if (retryTimer != null) window.clearTimeout(retryTimer);
    socket?.close();
    socket = null;
  };
}

function assertAuthSession(
  response: AuthSessionResponse,
): AuthSessionResponse {
  if (typeof response.csrfToken !== "string" || !response.csrfToken) {
    throw new ApiError(
      "The server did not return a valid session",
      502,
      "INVALID_RESPONSE",
    );
  }
  return response;
}

export const api = {
  auth: {
    params: () => request<AuthParams>("/auth/params"),
    setup: async (
      body: {
        authKey: string;
        kdfSalt: string;
        kdfParams: KdfParams;
        wrappedVaultKey: string;
      },
      setupToken?: string,
    ) => {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      };
      if (setupToken) headers["X-Setup-Token"] = setupToken;
      const response = assertAuthSession(
        await request<AuthSessionResponse>("/auth/setup", {
          method: "POST",
          body: JSON.stringify(body),
          headers,
        }),
      );
      setCsrfToken(response.csrfToken);
      return response;
    },
    login: async (body: { authKey: string }) => {
      const response = assertAuthSession(
        await jsonRequest<AuthSessionResponse>("/auth/login", "POST", body),
      );
      setCsrfToken(response.csrfToken);
      return response;
    },
    vault: () => request<VaultResponse>("/vault"),
    changePassphrase: (body: {
      oldAuthKey: string;
      newAuthKey: string;
      newKdfSalt: string;
      newKdfParams: KdfParams;
      newWrappedVaultKey: string;
    }) =>
      jsonRequest<{ success: boolean }>(
        "/auth/change-passphrase",
        "POST",
        body,
      ),
    logout: async () => {
      const response = await jsonRequest<{ success: boolean }>(
        "/auth/logout",
        "POST",
      );
      setCsrfToken(null);
      return response;
    },
  },

  pastes: {
    list: (page = 1, limit = 20) =>
      request<PasteListResponse>(
        `/pastes?page=${encodeURIComponent(page)}&limit=${encodeURIComponent(limit)}`,
      ),
    get: async (id: string) => {
      const response = await request<{ paste: PasteDetail }>(
        `/pastes/${encodeURIComponent(id)}`,
      );
      return response.paste;
    },
    create: async (body: CreatePasteInput) => {
      const response = await jsonRequest<{ paste: PasteSummary }>(
        "/pastes",
        "POST",
        body,
      );
      return response.paste;
    },
    update: async (id: string, body: UpdatePasteInput) => {
      const response = await jsonRequest<{ paste: PasteSummary }>(
        `/pastes/${encodeURIComponent(id)}`,
        "PUT",
        body,
      );
      return response.paste;
    },
    delete: (id: string) =>
      jsonRequest<{ success: boolean }>(
        `/pastes/${encodeURIComponent(id)}`,
        "DELETE",
      ),
  },

  share: {
    status: (pasteId: string) =>
      request<ShareStatusResponse>(
        `/pastes/${encodeURIComponent(pasteId)}/share`,
      ),
    create: (pasteId: string, body: CreateShareInput) =>
      jsonRequest<{ success: boolean; share: ShareInfo }>(
        `/pastes/${encodeURIComponent(pasteId)}/share`,
        "POST",
        body,
      ),
    delete: (pasteId: string) =>
      jsonRequest<{ success: boolean }>(
        `/pastes/${encodeURIComponent(pasteId)}/share`,
        "DELETE",
      ),
  },

  guest: {
    params: (pasteId: string) =>
      request<ShareParams>(
        `/shares/${encodeURIComponent(pasteId)}/params`,
      ),
    challenge: (pasteId: string) =>
      jsonRequest<ChallengeResponse>(
        `/shares/${encodeURIComponent(pasteId)}/challenge`,
        "POST",
      ),
    unlock: (pasteId: string, body: { nonce: string; proof: string }) =>
      jsonRequest<UnlockResponse>(
        `/shares/${encodeURIComponent(pasteId)}/unlock`,
        "POST",
        body,
      ),
    view: (pasteId: string, shareToken: string) =>
      jsonRequest<ViewResponse>(
        `/shares/${encodeURIComponent(pasteId)}/view`,
        "POST",
        { shareToken },
      ),
  },

  files: {
    upload: uploadFile,
    download: downloadFile,
  },

  events: {
    subscribe: subscribeEvents,
  },
};

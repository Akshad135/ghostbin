import { useCallback, useEffect, useMemo, useRef, useState, Fragment, type CSSProperties } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import { codeToTokens, isSupportedLanguage } from '@pierre/highlights';
import { useAuth } from '@/lib/auth';
import { highlightThemeFor } from '@/lib/highlight';
import {
    api,
    ApiError,
    type FileMeta,
    type GuestPaste,
    type PasteDetail,
    type ShareInfo,
    type ShareParams,
} from '@/lib/api';
import {
    decryptAttachmentBytes,
    decryptAttachmentMeta,
    decryptGuestPaste,
    decryptPasteWithKey,
    pasteKeyForSummary,
    type AttachmentMeta,
    type PasteFields,
} from '@/lib/paste';
import {
    base64UrlToBytes,
    bytesToBase64Url,
    decodeFragmentSecret,
    deriveShareKeys,
    deriveShareProof,
    importPasteKey,
    normalizeShareCode,
    toArrayBuffer,
    ShareCodeError,
    unwrapPasteKeyFromShare,
} from '@/lib/e2ee';
import { useTheme } from '@/components/ThemeProvider';
import {
    LANG_MAP,
    burnStatusLabel,
    formatTimestamp,
    getLanguageLabel,
    timeAgo,
} from '@/lib/constants';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import {
    Dialog,
    DialogClose,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { ArrowLeftIcon } from '@/components/ui/animated-arrow-left';
import { CopyIcon } from '@/components/ui/animated-copy';
import { DeleteIcon } from '@/components/ui/animated-delete';
import { DownloadIcon } from '@/components/ui/animated-download';
import { FileTextIcon } from '@/components/ui/animated-file-text';
import { HourglassIcon } from '@/components/ui/animated-hourglass';
import { KeyIcon } from '@/components/ui/animated-key';
import { LoaderPinwheelIcon } from '@/components/ui/animated-loader-pinwheel';
import { LockIcon } from '@/components/ui/animated-lock';
import { PinIcon } from '@/components/ui/animated-pin';
import { ShareIcon } from '@/components/ui/animated-share';
import { SquarePenIcon } from '@/components/ui/animated-square-pen';
import { SharePasteDialog } from '@/components/SharePasteDialog';
import { ErrorState } from '@/components/ErrorState';
import { formatFileSize, truncateFileName } from '@/lib/utils';
import { toast } from 'sonner';

type PageState = 'loading' | 'owner' | 'guest-locked' | 'guest-ready' | 'private' | 'error';

interface OwnerFile {
    meta: FileMeta;
    plain: AttachmentMeta;
}

interface GuestFile {
    meta: FileMeta;
    plain: AttachmentMeta;
    bytes: Uint8Array;
}

interface OwnerData {
    paste: PasteDetail;
    fields: PasteFields;
    files: OwnerFile[];
    key: CryptoKey;
}

interface GuestData {
    paste: GuestPaste;
    fields: PasteFields;
    files: GuestFile[];
    burned: boolean;
    unlocksUsed: number;
    maxUnlocks: number | null;
}

function downloadBlob(bytes: Uint8Array, name: string, mime: string): void {
    const blob = new Blob([toArrayBuffer(bytes)], { type: mime || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = name;
    anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

const MAX_HIGHLIGHT_CHARS = 100_000;

interface HighlightToken {
    content: string;
    color?: string;
    fontStyle?: number;
}

// Shiki fontStyle is a bitmask: 1 italic, 2 bold, 4 underline, 8 strike.
function tokenStyle(token: HighlightToken): CSSProperties {
    const style: React.CSSProperties = {};
    if (token.color) style.color = token.color;
    const font = token.fontStyle ?? 0;
    if (font & 1) style.fontStyle = 'italic';
    if (font & 2) style.fontWeight = 'bold';
    if (font & 4) style.textDecoration = 'underline';
    if (font & 8) {
        style.textDecoration = `${style.textDecoration ?? ''} line-through`.trim();
    }
    return style;
}

function CodeBlock({ code, language }: { code: string; language: string }) {
    const { mode, palette } = useTheme();
    const tooLarge = code.length > MAX_HIGHLIGHT_CHARS;

    // Tokenizing is synchronous (wasm). Unknown languages and tokenizer
    // errors fall back to the plain <pre> render below.
    const tokens = useMemo<HighlightToken[][] | null>(() => {
        if (tooLarge) return null;
        const lang = LANG_MAP[language] || language;
        if (!isSupportedLanguage(lang)) return null;
        try {
            return codeToTokens(code || ' ', {
                lang,
                theme: highlightThemeFor(palette, mode),
            }).tokens;
        } catch {
            return null;
        }
    }, [code, language, mode, palette, tooLarge]);

    if (tooLarge || !tokens) {
        return (
            <pre className="overflow-auto max-h-[70vh] rounded-md border border-border/60 bg-muted/20 p-4 text-sm">
                <code>{code}</code>
            </pre>
        );
    }

    return (
        <pre className="max-h-[70vh] overflow-auto rounded-md border border-border/60 bg-muted/20 p-4 text-sm">
            <code>
                {tokens.map((line, lineIndex) => (
                    <Fragment key={lineIndex}>
                        {line.map((token, tokenIndex) => (
                            <span key={tokenIndex} style={tokenStyle(token)}>
                                {token.content}
                            </span>
                        ))}
                        {lineIndex < tokens.length - 1 ? '\n' : null}
                    </Fragment>
                ))}
            </code>
        </pre>
    );
}

function AttachmentRow({
    name,
    mime,
    size,
    bytes,
    downloading,
    onDownload,
}: {
    name: string;
    mime: string;
    size: number;
    bytes?: Uint8Array;
    downloading?: boolean;
    onDownload: () => void;
}) {
    const previewUrl = useMemo(() => {
        // SVG previews are disallowed (plan §8.7); raster images only.
        if (!bytes || !mime.startsWith('image/') || mime === 'image/svg+xml') return null;
        return URL.createObjectURL(new Blob([toArrayBuffer(bytes)], { type: mime }));
    }, [bytes, mime]);

    useEffect(() => {
        return () => {
            if (previewUrl) URL.revokeObjectURL(previewUrl);
        };
    }, [previewUrl]);

    return (
        <div className="rounded-md border border-border/60 bg-muted/10 p-3">
            <div className="flex items-center gap-2">
                <FileTextIcon size={16} className="text-primary/70 shrink-0" />
                <span className="text-sm truncate flex-1" title={name}>
                    {truncateFileName(name, 56)}
                </span>
                <span className="text-[11px] text-muted-foreground shrink-0">
                    {formatFileSize(size)}
                </span>
                <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7"
                    onClick={onDownload}
                    disabled={downloading}
                    aria-label={`Download ${name}`}
                >
                    {downloading
                        ? <LoaderPinwheelIcon size={14} className="animate-spin" />
                        : <DownloadIcon size={14} />}
                </Button>
            </div>
            {previewUrl && (
                <div className="mt-2">
                    <img
                        src={previewUrl}
                        alt={name}
                        className="max-h-72 max-w-full rounded-md border border-border/40 object-contain"
                    />
                </div>
            )}
        </div>
    );
}

export function ViewPaste() {
    const { id } = useParams<{ id: string }>();
    const location = useLocation();
    const navigate = useNavigate();
    const { isAuthenticated, vaultKey, isLoading: authLoading, checkAuth } = useAuth();

    const [page, setPage] = useState<PageState>('loading');
    const [error, setError] = useState('');
    const [ownerData, setOwnerData] = useState<OwnerData | null>(null);
    const [shareInfo, setShareInfo] = useState<ShareInfo | null>(null);
    const [guestData, setGuestData] = useState<GuestData | null>(null);
    const [shareParams, setShareParams] = useState<ShareParams | null>(null);
    const [fragmentSecret, setFragmentSecret] = useState<Uint8Array | null>(null);
    const [code, setCode] = useState('');
    const [unlocking, setUnlocking] = useState(false);
    const [unlockError, setUnlockError] = useState('');
    const [missingFileCount, setMissingFileCount] = useState(0);
    const [allowMissingFiles, setAllowMissingFiles] = useState(false);
    const [ownerReload, setOwnerReload] = useState(0);
    const [shareDialogOpen, setShareDialogOpen] = useState(false);
    const [deleteOpen, setDeleteOpen] = useState(false);
    const [deleting, setDeleting] = useState(false);
    const [downloadingId, setDownloadingId] = useState<string | null>(null);
    const unlockAttemptRef = useRef(0);

    const rawHash = location.hash.startsWith('#') ? location.hash.slice(1) : location.hash;
    const isOwner = Boolean(isAuthenticated && vaultKey);
    const effectivePage = authLoading ? 'loading' : page;

    useEffect(() => {
        return () => {
            // Invalidate any in-flight guest unlock. The critical check is
            // immediately before POST /view, which consumes a view.
            unlockAttemptRef.current += 1;
        };
    }, [id, isOwner, rawHash]);

    useEffect(() => {
        if (authLoading) return;
        if (!id) {
            setError('Missing paste ID.');
            setPage('error');
            return;
        }
        if (!isOwner || !vaultKey) return;

        let cancelled = false;
        setPage('loading');
        setError('');
        setGuestData(null);
        setShareParams(null);

        const load = async () => {
            try {
                const detail = await api.pastes.get(id);
                const key = await pasteKeyForSummary(vaultKey, detail);
                const fields = await decryptPasteWithKey(key, detail);
                const files: OwnerFile[] = [];
                let failedFiles = 0;
                for (const file of detail.files) {
                    try {
                        files.push({
                            meta: file,
                            plain: await decryptAttachmentMeta(key, id, file),
                        });
                    } catch {
                        failedFiles += 1;
                    }
                }
                const status = await api.share.status(id).catch(() => ({ exists: false as const }));
                if (cancelled) return;
                setOwnerData({ paste: detail, fields, files, key });
                setShareInfo(status.exists ? status.share : null);
                setPage('owner');
                if (failedFiles > 0) {
                    toast.error(
                        `${failedFiles} attachment${failedFiles === 1 ? '' : 's'} could not be decrypted`,
                    );
                }
            } catch (loadError) {
                if (cancelled) return;
                if (loadError instanceof ApiError && (loadError.status === 404 || loadError.status === 410)) {
                    setError('This paste has been deleted or burned.');
                } else if (loadError instanceof ApiError && loadError.status === 401) {
                    setError('Your session expired. Unlock your vault again.');
                    // Re-run the auth check so the whole app locks consistently
                    // instead of leaving unlocked-looking chrome on this page.
                    void checkAuth();
                } else {
                    setError(loadError instanceof Error ? loadError.message : 'Failed to load paste');
                }
                setPage('error');
            }
        };

        void load();
        return () => { cancelled = true; };
    }, [id, authLoading, isOwner, vaultKey, ownerReload, checkAuth]);

    useEffect(() => {
        if (authLoading) return;
        if (!id) return;
        if (isOwner) return;

        setOwnerData(null);
        setShareInfo(null);
        setGuestData(null);
        setShareParams(null);
        setFragmentSecret(null);
        setUnlockError('');
        setMissingFileCount(0);
        setAllowMissingFiles(false);
        setCode('');
        // A vault login mid-unlock invalidates the in-flight attempt without
        // running its finally block; without this the form stays disabled.
        setUnlocking(false);

        if (!rawHash) {
            setPage('private');
            return;
        }

        let fragment: Uint8Array;
        try {
            fragment = decodeFragmentSecret(rawHash);
        } catch {
            setError('The share link is missing a valid secret fragment. Ask the sender for the full link.');
            setPage('error');
            return;
        }
        setFragmentSecret(fragment);
        setPage('loading');

        let cancelled = false;
        api.guest.params(id)
            .then((params) => {
                if (cancelled) return;
                setShareParams(params);
                setPage('guest-locked');
            })
            .catch((paramsError) => {
                if (cancelled) return;
                if (paramsError instanceof ApiError && (paramsError.status === 404 || paramsError.status === 410)) {
                    setError('This share is no longer available.');
                } else {
                    setError(paramsError instanceof Error ? paramsError.message : 'Failed to load share');
                }
                setPage('error');
            });

        return () => { cancelled = true; };
    }, [id, authLoading, isOwner, rawHash]);

    const refreshShareInfo = useCallback(async () => {
        if (!id) return;
        try {
            const status = await api.share.status(id);
            setShareInfo(status.exists ? status.share : null);
        } catch {
            // The share may have just been revoked or the paste burned.
            setShareInfo(null);
        }
    }, [id]);

    useEffect(() => {
        if (!isOwner || !id) return;
        return api.events.subscribe((event) => {
            if (event.type === 'resync') {
                // This connection lagged and may have missed events —
                // including this paste being deleted or burned.
                if (!shareDialogOpen) {
                    setOwnerReload((value) => value + 1);
                }
                return;
            }
            if (event.pasteId !== id) return;
            if (event.type === 'paste_deleted' || event.type === 'paste_burned') {
                setOwnerData(null);
                setError('This paste has been deleted or burned.');
                setPage('error');
                return;
            }
            if (event.type === 'share_created' || event.type === 'share_updated' || event.type === 'share_revoked') {
                // Refresh only the share badge. A full reload would unmount the
                // share dialog and lose the newly generated link and code.
                void refreshShareInfo();
                return;
            }
            if (!shareDialogOpen) {
                setOwnerReload((value) => value + 1);
            }
        });
    }, [id, isOwner, refreshShareInfo, shareDialogOpen]);

    const shareLabel = useMemo(() => {
        const source = ownerData?.paste ?? guestData?.paste;
        return source ? burnStatusLabel(source, true) : '';
    }, [ownerData, guestData]);

    const currentTitle = ownerData?.fields.title || guestData?.fields.title || 'Untitled paste';
    const currentLanguage = ownerData?.fields.language || guestData?.fields.language || 'plaintext';
    const currentContent = ownerData?.fields.content ?? guestData?.fields.content ?? '';
    const currentFiles = ownerData?.files ?? guestData?.files ?? [];
    const isBurned = guestData?.burned ?? false;

    const copyContent = async () => {
        try {
            await navigator.clipboard.writeText(currentContent);
            toast.success('Content copied');
        } catch {
            toast.error('Failed to copy content');
        }
    };

    const handleOwnerDownload = async (file: OwnerFile) => {
        if (!ownerData || !id) return;
        setDownloadingId(file.meta.id);
        try {
            const encrypted = await api.files.download(file.meta.id);
            const bytes = await decryptAttachmentBytes(
                ownerData.key,
                id,
                file.meta.id,
                encrypted,
                file.plain.size,
            );
            downloadBlob(bytes, file.plain.name, file.plain.mime);
        } catch (downloadError) {
            toast.error(downloadError instanceof Error ? downloadError.message : 'Failed to download file');
        } finally {
            setDownloadingId(null);
        }
    };

    const handleGuestDownload = (file: GuestFile) => {
        downloadBlob(file.bytes, file.plain.name, file.plain.mime);
    };

    const togglePin = async () => {
        if (!ownerData) return;
        try {
            await api.pastes.update(ownerData.paste.id, { pinned: !ownerData.paste.pinned });
            toast.success(ownerData.paste.pinned ? 'Paste unpinned' : 'Paste pinned');
            setOwnerReload((value) => value + 1);
        } catch (pinError) {
            toast.error(pinError instanceof Error ? pinError.message : 'Failed to update pin');
        }
    };

    const deletePaste = async () => {
        if (!ownerData) return;
        setDeleting(true);
        try {
            await api.pastes.delete(ownerData.paste.id);
            toast.success('Paste deleted');
            navigate('/');
        } catch (deleteError) {
            toast.error(deleteError instanceof Error ? deleteError.message : 'Failed to delete paste');
        } finally {
            setDeleting(false);
        }
    };

    const handleUnlock = async (event: React.FormEvent) => {
        event.preventDefault();
        if (!id || !shareParams || !fragmentSecret) return;

        const attempt = unlockAttemptRef.current + 1;
        unlockAttemptRef.current = attempt;
        const isCurrent = () => unlockAttemptRef.current === attempt;

        setUnlocking(true);
        setUnlockError('');
        setMissingFileCount(0);
        let codeKey: Uint8Array | null = null;
        let authKey: Uint8Array | null = null;
        let pasteKeyBytes: Uint8Array | null = null;
        let stage: 'code' | 'share' | 'view' = 'code';

        try {
            const normalized = normalizeShareCode(code);
            const shareSalt = base64UrlToBytes(shareParams.shareSalt);
            const keys = await deriveShareKeys(
                normalized,
                shareSalt,
                fragmentSecret,
                shareParams.kdfParams,
            );
            codeKey = keys.codeKey;
            authKey = keys.authKey;
            if (!isCurrent()) return;

            const challenge = await api.guest.challenge(id);
            const proof = await deriveShareProof(keys.authKey, challenge.nonce, id);
            const unlocked = await api.guest.unlock(id, {
                nonce: challenge.nonce,
                proof: bytesToBase64Url(proof),
            });
            stage = 'share';
            if (!isCurrent()) return;

            // Download every encrypted file before calling /view when possible.
            // A missing or slow attachment must not make the paste text
            // unviewable, so missing files are counted and reported after the
            // view. /view itself remains the counted step.
            const encryptedFiles = new Map<string, Uint8Array>();
            let failedDownloads = 0;
            for (const file of unlocked.files) {
                try {
                    encryptedFiles.set(
                        file.id,
                        await api.files.download(file.id, unlocked.shareToken),
                    );
                } catch {
                    failedDownloads += 1;
                }
                if (!isCurrent()) return;
            }
            setMissingFileCount(failedDownloads);
            if (failedDownloads > 0 && !allowMissingFiles) {
                setUnlockError(
                    `${failedDownloads} encrypted attachment${failedDownloads === 1 ? '' : 's'} could not be downloaded. Check your connection and retry, or choose to continue without ${failedDownloads === 1 ? 'it' : 'them'}.`,
                );
                return;
            }

            // Navigate-away and login transitions invalidate this attempt.
            // Do not consume a view for a result the user can no longer see.
            if (!isCurrent()) return;
            const view = await api.guest.view(id, unlocked.shareToken);
            stage = 'view';
            if (!isCurrent()) return;

            const viewSalt = base64UrlToBytes(view.share.shareSalt);
            if (bytesToBase64Url(viewSalt) !== bytesToBase64Url(shareSalt)) {
                throw new Error('The share parameters changed while unlocking. Try again.');
            }

            pasteKeyBytes = await unwrapPasteKeyFromShare(
                keys.wrapKey,
                view.share.wrappedPasteKey,
                id,
                viewSalt,
            );
            const pasteKey = await importPasteKey(pasteKeyBytes);
            const fields = await decryptGuestPaste(pasteKey, view.paste);

            // The view is already consumed at this point. Decrypt files
            // best-effort so one missing or corrupt attachment does not discard
            // the paste text as well.
            const files: GuestFile[] = [];
            let failedFiles = 0;
            for (const meta of view.files) {
                const encrypted = encryptedFiles.get(meta.id);
                if (!encrypted) {
                    failedFiles += 1;
                    continue;
                }
                try {
                    const plain = await decryptAttachmentMeta(pasteKey, id, meta);
                    const bytes = await decryptAttachmentBytes(
                        pasteKey,
                        id,
                        meta.id,
                        encrypted,
                        plain.size,
                    );
                    files.push({ meta, plain, bytes });
                } catch {
                    failedFiles += 1;
                }
            }
            if (!isCurrent()) return;

            setGuestData({
                paste: view.paste,
                fields,
                files,
                burned: view.burned,
                unlocksUsed: view.unlocksUsed,
                maxUnlocks: unlocked.maxUnlocks,
            });
            setShareParams((previous) => previous
                ? { ...previous, unlocksUsed: view.unlocksUsed }
                : previous);
            setCode('');
            setPage('guest-ready');
            if (failedFiles > 0) {
                toast.error(
                    `${failedFiles} attachment${failedFiles === 1 ? '' : 's'} could not be decrypted or loaded`,
                );
            }
        } catch (unlockFailure) {
            if (!isCurrent()) return;
            if (unlockFailure instanceof ShareCodeError) {
                setUnlockError(
                    unlockFailure.reason === 'alphabet'
                        ? 'The code contains a character outside its alphabet (no 0, 1, I, or O).'
                        : 'Enter the full 14-character access code.',
                );
            } else if (unlockFailure instanceof ApiError) {
                if (unlockFailure.status === 429) {
                    setUnlockError(
                        unlockFailure.retryAfter
                            ? `Too many attempts. Try again in ${unlockFailure.retryAfter}s.`
                            : 'Too many attempts. Try again shortly.',
                    );
                } else if (unlockFailure.status === 401) {
                    if (stage === 'code') {
                        setUnlockError('Incorrect access code.');
                    } else {
                        setPage('error');
                        setError('This share is no longer available or has reached its view limit.');
                    }
                } else if (unlockFailure.status === 410) {
                    setPage('error');
                    setError('This share is no longer available.');
                } else if (unlockFailure.status === 404) {
                    setPage('error');
                    setError('This share is no longer available.');
                } else {
                    setUnlockError(unlockFailure.message);
                }
            } else {
                setUnlockError(unlockFailure instanceof Error ? unlockFailure.message : 'Failed to unlock share');
            }
        } finally {
            codeKey?.fill(0);
            authKey?.fill(0);
            pasteKeyBytes?.fill(0);
            if (isCurrent()) setUnlocking(false);
        }
    };

    if (effectivePage === 'loading') {
        return (
            <div className="flex-1 flex items-center justify-center text-muted-foreground">
                <LoaderPinwheelIcon size={20} className="animate-spin mr-2" />
                Loading encrypted paste…
            </div>
        );
    }

    if (effectivePage === 'error') {
        return <ErrorState type="error" error={error} />;
    }

    if (effectivePage === 'private') {
        return (
            <div className="flex-1 flex flex-col items-center justify-center text-center max-w-xl mx-auto px-6">
                <div className="rounded-full bg-primary/10 p-5 mb-5">
                    <LockIcon size={30} className="text-primary" />
                </div>
                <h1 className="text-xl font-semibold">This paste is private.</h1>
                <p className="text-sm text-muted-foreground mt-2">
                    Unlock your vault to view it, or open the full share link that includes
                    the secret fragment.
                </p>
                <Button className="mt-5" onClick={() => window.dispatchEvent(new Event('open-login'))}>
                    <KeyIcon size={16} className="mr-2" />
                    Unlock Vault
                </Button>
            </div>
        );
    }

    if (effectivePage === 'guest-locked') {
        return (
            <div className="flex-1 flex flex-col items-center justify-center px-6">
                <div className="w-full max-w-md">
                    <div className="text-center mb-6">
                        <div className="rounded-full bg-primary/10 p-5 mb-4 inline-flex">
                            <LockIcon size={30} className="text-primary" />
                        </div>
                        <h1 className="text-xl font-semibold">Encrypted share</h1>
                        <p className="text-sm text-muted-foreground mt-2">
                            Enter the access code from the sender. The code is checked locally;
                            the server only sees a proof.
                        </p>
                    </div>
                    <Card>
                        <CardContent className="p-5">
                            <form onSubmit={handleUnlock} className="flex flex-col gap-3">
                                <label
                                    htmlFor="share-code-input"
                                    className="text-xs font-medium text-muted-foreground text-center"
                                >
                                    Access code
                                </label>
                                <Input
                                    id="share-code-input"
                                    value={code}
                                    onChange={(event) => {
                                        const value = event.target.value
                                            .toUpperCase()
                                            .replace(/[^A-Z0-9\s-]/g, '')
                                            .slice(0, 32);
                                        setCode(value);
                                    }}
                                    placeholder="ABCD EFGH JKLM NP"
                                    className="font-mono text-lg tracking-[0.18em] text-center"
                                    autoFocus
                                    autoComplete="off"
                                    autoCapitalize="characters"
                                    autoCorrect="off"
                                    spellCheck={false}
                                    aria-describedby="share-code-hint share-code-error"
                                />
                                <p
                                    id="share-code-hint"
                                    className="text-[11px] text-muted-foreground text-center"
                                >
                                    14 characters. Spaces and dashes are ignored.
                                </p>
                                {unlockError && (
                                    <p
                                        id="share-code-error"
                                        role="alert"
                                        className="text-xs text-destructive text-center"
                                    >
                                        {unlockError}
                                    </p>
                                )}
                                {missingFileCount > 0 && (
                                    <label className="flex items-start gap-2 text-xs text-muted-foreground">
                                        <input
                                            type="checkbox"
                                            checked={allowMissingFiles}
                                            onChange={(event) => setAllowMissingFiles(event.target.checked)}
                                            className="mt-0.5 accent-primary"
                                        />
                                        <span>
                                            Continue without {missingFileCount} missing attachment
                                            {missingFileCount === 1 ? '' : 's'}. This consumes one view.
                                        </span>
                                    </label>
                                )}
                                <Button type="submit" disabled={unlocking || !code.trim()}>
                                    {unlocking && <LoaderPinwheelIcon size={16} className="mr-2 animate-spin" />}
                                    {unlocking
                                        ? 'Unlocking…'
                                        : allowMissingFiles && missingFileCount > 0
                                            ? 'Unlock Without Attachments'
                                            : 'Unlock Share'}
                                </Button>
                            </form>
                        </CardContent>
                    </Card>
                    {shareParams && (
                        <p className="text-center text-[11px] text-muted-foreground mt-3">
                            {shareParams.unlocksUsed} view{shareParams.unlocksUsed === 1 ? '' : 's'} used
                            {shareParams.maxUnlocks != null ? ` of ${shareParams.maxUnlocks}` : ''}.
                        </p>
                    )}
                </div>
            </div>
        );
    }

    const pasteExists = Boolean(ownerData || guestData);
    if (!pasteExists) return <ErrorState type="error" error={error} />;

    return (
        <div className="mx-auto max-w-5xl w-full px-4 sm:px-6 py-5">
            <div className="flex flex-wrap items-start gap-3">
                <Button variant="ghost" size="icon" onClick={() => navigate('/')}>
                    <ArrowLeftIcon size={18} />
                </Button>
                <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                        <h1 className="text-xl sm:text-2xl font-semibold tracking-tight break-words">
                            {currentTitle || 'Untitled paste'}
                        </h1>
                        {ownerData?.paste.pinned && (
                            <PinIcon size={16} className="text-primary rotate-45 shrink-0" />
                        )}
                        <Badge variant="default" className="text-[10px]">
                            {getLanguageLabel(currentLanguage)}
                        </Badge>
                        {ownerData && shareInfo && (
                            <Badge variant="outline" className="text-[10px] gap-1">
                                <ShareIcon size={10} />
                                Shared
                            </Badge>
                        )}
                        {guestData && (
                            <Badge variant="outline" className="text-[10px] gap-1">
                                <ShareIcon size={10} />
                                Shared
                            </Badge>
                        )}
                    </div>
                    <div className="flex flex-wrap items-center gap-3 text-[11px] text-muted-foreground mt-1.5">
                        {ownerData && <span>Created {timeAgo(ownerData.paste.createdAt)}</span>}
                        {guestData && <span>Created {timeAgo(guestData.paste.createdAt)}</span>}
                        {shareInfo?.unlocksUsed != null && (
                            <span>
                                {shareInfo.unlocksUsed} view{shareInfo.unlocksUsed === 1 ? '' : 's'}
                                {shareInfo.maxUnlocks != null ? ` / ${shareInfo.maxUnlocks}` : ''}
                            </span>
                        )}
                        {guestData && (
                            <span>
                                {guestData.unlocksUsed} view{guestData.unlocksUsed === 1 ? '' : 's'}
                                {guestData.maxUnlocks != null ? ` / ${guestData.maxUnlocks}` : ''}
                            </span>
                        )}
                        {shareLabel && (
                            <span className="flex items-center gap-1 text-amber-500">
                                <HourglassIcon size={12} />
                                {shareLabel}
                            </span>
                        )}
                    </div>
                </div>

                <div className="flex items-center gap-1">
                    <Button variant="ghost" size="icon" onClick={copyContent} title="Copy content">
                        <CopyIcon size={16} />
                    </Button>
                    {ownerData && (
                        <>
                            <Button
                                variant="outline"
                                size="sm"
                                onClick={() => setShareDialogOpen(true)}
                            >
                                <ShareIcon size={15} className="mr-1.5" />
                                {shareInfo ? 'Manage Share' : 'Share'}
                            </Button>
                            <Button variant="ghost" size="icon" onClick={togglePin} title="Pin paste">
                                <PinIcon size={16} />
                            </Button>
                            <Button
                                variant="ghost"
                                size="icon"
                                onClick={() => navigate(`/edit/${ownerData.paste.id}`)}
                                title="Edit paste"
                            >
                                <SquarePenIcon size={16} />
                            </Button>
                            <Button
                                variant="ghost"
                                size="icon"
                                className="text-destructive hover:text-destructive"
                                onClick={() => setDeleteOpen(true)}
                                title="Delete paste"
                            >
                                <DeleteIcon size={16} />
                            </Button>
                        </>
                    )}
                </div>
            </div>

            {isBurned && (
                <div className="mt-4 rounded-md border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-700 dark:text-amber-300">
                    This was the final view. The paste and its files have been deleted from the server.
                </div>
            )}

            {ownerData && shareInfo && (
                <div className="mt-3 text-xs text-muted-foreground">
                    Share created {timeAgo(shareInfo.createdAt)}
                    {shareInfo.expiresAt != null && ` · expires ${formatTimestamp(shareInfo.expiresAt)}`}
                </div>
            )}

            <Card className="mt-4 overflow-hidden">
                <CardContent className="p-0">
                    {currentContent.trim() ? (
                        <CodeBlock code={currentContent} language={currentLanguage} />
                    ) : (
                        <div className="p-8 text-center text-sm text-muted-foreground">
                            No text content. See the encrypted attachments below.
                        </div>
                    )}
                </CardContent>
            </Card>

            {currentFiles.length > 0 && (
                <div className="mt-4 flex flex-col gap-2">
                    <h2 className="text-sm font-medium">
                        Attachments ({currentFiles.length})
                    </h2>
                    {ownerData?.files.map((file) => (
                        <AttachmentRow
                            key={file.meta.id}
                            name={file.plain.name}
                            mime={file.plain.mime}
                            size={file.plain.size}
                            downloading={downloadingId === file.meta.id}
                            onDownload={() => handleOwnerDownload(file)}
                        />
                    ))}
                    {guestData?.files.map((file) => (
                        <AttachmentRow
                            key={file.meta.id}
                            name={file.plain.name}
                            mime={file.plain.mime}
                            size={file.plain.size}
                            bytes={file.bytes}
                            onDownload={() => handleGuestDownload(file)}
                        />
                    ))}
                </div>
            )}

            {ownerData && (
                <SharePasteDialog
                    open={shareDialogOpen}
                    onOpenChange={setShareDialogOpen}
                    paste={ownerData.paste}
                    onChanged={() => { void refreshShareInfo(); }}
                />
            )}

            <Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
                <DialogContent>
                    <DialogHeader>
                        <DialogTitle>Delete Paste</DialogTitle>
                        <DialogDescription>
                            This permanently deletes the paste, its share, and all attachments.
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter className="gap-2 sm:gap-0">
                        <DialogClose asChild>
                            <Button variant="outline" disabled={deleting}>Cancel</Button>
                        </DialogClose>
                        <Button variant="destructive" onClick={deletePaste} disabled={deleting}>
                            {deleting && <LoaderPinwheelIcon size={16} className="mr-1.5 animate-spin" />}
                            Delete
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>
        </div>
    );
}

import { useEffect, useState } from 'react';
import { useAuth } from '@/lib/auth';
import { api, type PasteSummary, type ShareInfo } from '@/lib/api';
import { pasteKeyBytesForSummary } from '@/lib/paste';
import {
    DEFAULT_ARGON2_PARAMS,
    bytesToBase64Url,
    deriveShareKeys,
    encodeFragmentSecret,
    generateFragmentSecret,
    generateShareCode,
    generateShareSalt,
    wrapPasteKeyForShare,
} from '@/lib/e2ee';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { CopyIcon } from '@/components/ui/animated-copy';
import { ShareIcon } from '@/components/ui/animated-share';
import { LockIcon } from '@/components/ui/animated-lock';
import { LoaderPinwheelIcon } from '@/components/ui/animated-loader-pinwheel';
import { RefreshCWIcon } from '@/components/ui/animated-refresh-cw';
import { DeleteIcon } from '@/components/ui/animated-delete';

interface SharePasteDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    paste: PasteSummary;
    onChanged?: () => void;
}

interface CreatedShare {
    code: string;
    link: string;
    maxUnlocks: number | null;
}

function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : 'Failed to create share';
}

export function SharePasteDialog({
    open,
    onOpenChange,
    paste,
    onChanged,
}: SharePasteDialogProps) {
    const { vaultKey } = useAuth();
    const [existing, setExisting] = useState<ShareInfo | null>(null);
    const [loadingStatus, setLoadingStatus] = useState(false);
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState('');
    const [created, setCreated] = useState<CreatedShare | null>(null);
    const [confirmReplace, setConfirmReplace] = useState(false);

    useEffect(() => {
        if (!open) return;
        let cancelled = false;
        setCreated(null);
        setError('');
        setConfirmReplace(false);
        setLoadingStatus(true);
        api.share.status(paste.id)
            .then((response) => {
                if (!cancelled) {
                    setExisting(response.exists ? response.share : null);
                }
            })
            .catch((statusError) => {
                if (!cancelled) setError(errorMessage(statusError));
            })
            .finally(() => {
                if (!cancelled) setLoadingStatus(false);
            });
        return () => { cancelled = true; };
    }, [open, paste.id]);

    const createShare = async (replace: boolean) => {
        if (!vaultKey) {
            setError('Unlock your vault first.');
            return;
        }
        setBusy(true);
        setError('');
        let codeKey: Uint8Array | null = null;
        let authKey: Uint8Array | null = null;
        let pasteKey: Uint8Array | null = null;
        try {
            const shareSalt = generateShareSalt();
            const fragmentSecret = generateFragmentSecret();
            const code = generateShareCode();
            const keys = await deriveShareKeys(
                code,
                shareSalt,
                fragmentSecret,
                DEFAULT_ARGON2_PARAMS,
            );
            codeKey = keys.codeKey;
            authKey = keys.authKey;
            pasteKey = await pasteKeyBytesForSummary(vaultKey, paste);
            const wrappedPasteKey = await wrapPasteKeyForShare(
                keys.wrapKey,
                pasteKey,
                paste.id,
                shareSalt,
            );

            const response = await api.share.create(paste.id, {
                shareSalt: bytesToBase64Url(shareSalt),
                shareAuthKey: bytesToBase64Url(authKey),
                wrappedPasteKey,
                replace,
            });

            setCreated({
                code,
                link: `${window.location.origin}/p/${paste.id}#${encodeFragmentSecret(fragmentSecret)}`,
                maxUnlocks: response.share.maxUnlocks,
            });
            setExisting(response.share);
            onChanged?.();
            toast.success(replace ? 'Share replaced' : 'Share created');
        } catch (createError) {
            setError(errorMessage(createError));
        } finally {
            codeKey?.fill(0);
            authKey?.fill(0);
            pasteKey?.fill(0);
            setBusy(false);
        }
    };

    const revokeShare = async () => {
        setBusy(true);
        setError('');
        try {
            await api.share.delete(paste.id);
            setExisting(null);
            setCreated(null);
            onChanged?.();
            toast.success('Share revoked');
        } catch (revokeError) {
            setError(errorMessage(revokeError));
        } finally {
            setBusy(false);
        }
    };

    const copyText = async (value: string, label: string) => {
        try {
            await navigator.clipboard.writeText(value);
            toast.success(`${label} copied`);
        } catch {
            toast.error('Failed to copy');
        }
    };

    const copyBoth = async () => {
        if (!created) return;
        await copyText(
            `${created.link}\nAccess code: ${created.code}`,
            'Share link and code',
        );
    };

    return (
        <Dialog
            open={open}
            onOpenChange={(nextOpen) => {
                // Closing while a create/replace/revoke request is in flight
                // would hide the only copy of the new link and access code.
                if (!nextOpen && busy) return;
                onOpenChange(nextOpen);
            }}
        >
            <DialogContent className="max-w-xl" onClick={(event) => event.stopPropagation()}>
                <DialogHeader>
                    <DialogTitle className="flex items-center gap-2">
                        <ShareIcon size={18} className="text-primary" />
                        Share encrypted paste
                    </DialogTitle>
                    <DialogDescription>
                        The link contains a secret fragment. The access code is separate.
                        The server never receives either one.
                    </DialogDescription>
                </DialogHeader>

                {loadingStatus ? (
                    <div className="flex items-center justify-center py-8 text-muted-foreground">
                        <LoaderPinwheelIcon size={20} className="animate-spin mr-2" />
                        Checking share status…
                    </div>
                ) : created ? (
                    <div className="flex flex-col gap-4">
                        <div className="rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-700 dark:text-amber-300">
                            Send the link and the access code separately. Anyone with both can read this paste.
                            {created.maxUnlocks != null && (
                                <span className="block mt-1">
                                    This share is limited to {created.maxUnlocks} view
                                    {created.maxUnlocks === 1 ? '' : 's'}.
                                </span>
                            )}
                        </div>

                        <div className="flex flex-col gap-1.5">
                            <label className="text-xs font-medium text-muted-foreground">Share link</label>
                            <div className="flex gap-2">
                                <Input value={created.link} readOnly className="font-mono text-xs" />
                                <Button
                                    variant="outline"
                                    size="icon"
                                    onClick={() => copyText(created.link, 'Share link')}
                                    aria-label="Copy share link"
                                >
                                    <CopyIcon size={16} />
                                </Button>
                            </div>
                        </div>

                        <div className="flex flex-col gap-1.5">
                            <label className="text-xs font-medium text-muted-foreground">Access code</label>
                            <div className="flex gap-2">
                                <Input
                                    value={created.code}
                                    readOnly
                                    className="font-mono text-lg tracking-[0.18em]"
                                />
                                <Button
                                    variant="outline"
                                    size="icon"
                                    onClick={() => copyText(created.code, 'Access code')}
                                    aria-label="Copy access code"
                                >
                                    <CopyIcon size={16} />
                                </Button>
                            </div>
                        </div>

                        <Button onClick={copyBoth} className="w-full">
                            <CopyIcon size={16} className="mr-2" />
                            Copy link and code
                        </Button>
                    </div>
                ) : (
                    <div className="flex flex-col gap-4">
                        {existing ? (
                            <div className="rounded-md border border-border/60 bg-muted/20 p-3">
                                <div className="flex items-center gap-2 text-sm font-medium">
                                    <LockIcon size={16} className="text-primary" />
                                    A share already exists
                                </div>
                                <p className="text-xs text-muted-foreground mt-1">
                                    The old link is not shown here. Replacing it permanently
                                    invalidates the old link and code.
                                </p>
                                {existing.unlocksUsed != null && (
                                    <p className="text-xs text-muted-foreground mt-1">
                                        {existing.unlocksUsed} view{existing.unlocksUsed === 1 ? '' : 's'} used
                                        {existing.maxUnlocks != null ? ` of ${existing.maxUnlocks}` : ''}.
                                    </p>
                                )}
                                {confirmReplace ? (
                                    <div className="flex flex-col gap-2 mt-3">
                                        <p className="text-xs text-amber-600 dark:text-amber-400">
                                            Replace the share? Anyone holding the old link and code
                                            loses access immediately.
                                        </p>
                                        <div className="flex flex-wrap gap-2">
                                            <Button
                                                size="sm"
                                                onClick={() => {
                                                    setConfirmReplace(false);
                                                    void createShare(true);
                                                }}
                                                disabled={busy}
                                            >
                                                {busy
                                                    ? <LoaderPinwheelIcon size={14} className="mr-1.5 animate-spin" />
                                                    : <RefreshCWIcon size={14} className="mr-1.5" />}
                                                Yes, replace it
                                            </Button>
                                            <Button
                                                size="sm"
                                                variant="outline"
                                                onClick={() => setConfirmReplace(false)}
                                                disabled={busy}
                                            >
                                                Cancel
                                            </Button>
                                        </div>
                                    </div>
                                ) : (
                                    <div className="flex flex-wrap gap-2 mt-3">
                                        <Button
                                            size="sm"
                                            variant="outline"
                                            onClick={() => setConfirmReplace(true)}
                                            disabled={busy}
                                        >
                                            <RefreshCWIcon size={14} className="mr-1.5" />
                                            Replace share
                                        </Button>
                                        <Button
                                            size="sm"
                                            variant="outline"
                                            onClick={revokeShare}
                                            disabled={busy}
                                            className="text-destructive hover:text-destructive"
                                        >
                                            <DeleteIcon size={14} className="mr-1.5" />
                                            Revoke
                                        </Button>
                                    </div>
                                )}
                                <p className="text-[11px] text-muted-foreground mt-2">
                                    Revoking stops future fetches. It cannot recall copies
                                    already decrypted.
                                </p>
                            </div>
                        ) : (
                            <div className="rounded-md border border-border/60 bg-muted/20 p-3">
                                <p className="text-sm font-medium">Create a new share?</p>
                                <p className="text-xs text-muted-foreground mt-1">
                                    You will get a link with a secret fragment and a
                                    14-character access code.
                                </p>
                                {paste.burnMode === 'unlock_count' && paste.burnAfter != null && (
                                    <p className="text-xs text-amber-600 dark:text-amber-400 mt-2">
                                        This paste will burn after {paste.burnAfter} unlock
                                        {paste.burnAfter === 1 ? '' : 's'}.
                                    </p>
                                )}
                                <Button
                                    className="mt-3"
                                    onClick={() => createShare(false)}
                                    disabled={busy}
                                >
                                    {busy
                                        ? <LoaderPinwheelIcon size={14} className="mr-1.5 animate-spin" />
                                        : <ShareIcon size={14} className="mr-1.5" />}
                                    Create share
                                </Button>
                            </div>
                        )}

                        {error && (
                            <p className="text-xs text-destructive" role="alert">{error}</p>
                        )}
                    </div>
                )}

                <DialogFooter>
                    <Button
                        variant="outline"
                        onClick={() => onOpenChange(false)}
                        disabled={busy}
                    >
                        Close
                    </Button>
                </DialogFooter>
            </DialogContent>
        </Dialog>
    );
}

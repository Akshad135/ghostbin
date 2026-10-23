import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { useAuth } from '@/lib/auth';
import { api, ApiError, type PasteDetail, type FileMeta } from '@/lib/api';
import {
    decryptAttachmentBytes,
    decryptAttachmentMeta,
    decryptPasteWithKey,
    encryptNewAttachment,
    encryptPasteFields,
    pasteKeyForSummary,
    type AttachmentMeta,
    type EncryptedAttachment,
} from '@/lib/paste';
import { config } from '@/lib/config';
import { toArrayBuffer } from '@/lib/e2ee';
import {
    LANGUAGES,
    validateBurnRule,
    type BurnUnit,
} from '@/lib/constants';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import { ArrowLeftIcon } from '@/components/ui/animated-arrow-left';
import { LoaderPinwheelIcon } from '@/components/ui/animated-loader-pinwheel';
import { PinIcon } from '@/components/ui/animated-pin';
import { UploadIcon } from '@/components/ui/animated-upload';
import { DeleteIcon } from '@/components/ui/animated-delete';
import { FileTextIcon } from '@/components/ui/animated-file-text';
import { LockIcon } from '@/components/ui/animated-lock';
import { DownloadIcon } from '@/components/ui/animated-download';
import { BurnRulesControl } from '@/components/BurnRulesControl';
import { ErrorState } from '@/components/ErrorState';
import {
    Dialog,
    DialogClose,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { cn, formatFileSize, truncateFileName } from '@/lib/utils';
import { toast } from 'sonner';

interface ExistingFile {
    meta: FileMeta;
    plain: AttachmentMeta;
}

interface StagedFile {
    key: string;
    file: File;
}

function burnDisplay(paste: PasteDetail): {
    trigger: string;
    value: string;
    unit: BurnUnit;
    unlocks: string;
} {
    if (paste.burnMode === 'time' && paste.burnAt) {
        const remaining = Math.max(60, paste.burnAt - Math.floor(Date.now() / 1000));
        if (remaining >= 86400) {
            return {
                trigger: 'time',
                value: String(Math.max(1, Math.round(remaining / 86400))),
                unit: 'day',
                unlocks: '3',
            };
        }
        if (remaining >= 3600) {
            return {
                trigger: 'time',
                value: String(Math.max(1, Math.round(remaining / 3600))),
                unit: 'hour',
                unlocks: '3',
            };
        }
        return {
            trigger: 'time',
            value: String(Math.max(1, Math.round(remaining / 60))),
            unit: 'minute',
            unlocks: '3',
        };
    }
    if (paste.burnMode === 'unlock_count' && paste.burnAfter != null) {
        return {
            trigger: 'unlock_count',
            value: '24',
            unit: 'hour',
            unlocks: String(paste.burnAfter),
        };
    }
    return { trigger: 'off', value: '24', unit: 'hour', unlocks: '3' };
}

export function EditPaste() {
    const { id } = useParams<{ id: string }>();
    const navigate = useNavigate();
    const { isAuthenticated, vaultKey, isLoading: authLoading, checkAuth } = useAuth();

    const [paste, setPaste] = useState<PasteDetail | null>(null);
    const [pasteKey, setPasteKey] = useState<CryptoKey | null>(null);
    const [existingFiles, setExistingFiles] = useState<ExistingFile[]>([]);
    const [stagedFiles, setStagedFiles] = useState<StagedFile[]>([]);
    const [hasShare, setHasShare] = useState(false);
    const [loading, setLoading] = useState(true);
    const [notFound, setNotFound] = useState(false);
    const [loadError, setLoadError] = useState('');
    const [title, setTitle] = useState('');
    const [content, setContent] = useState('');
    const [language, setLanguage] = useState('plaintext');
    const [isPinned, setIsPinned] = useState(false);
    const [burnTrigger, setBurnTrigger] = useState('off');
    const [burnValue, setBurnValue] = useState('24');
    const [burnUnit, setBurnUnit] = useState<BurnUnit>('hour');
    const [unlockValue, setUnlockValue] = useState('3');
    const [burnDirty, setBurnDirty] = useState(false);
    const [saving, setSaving] = useState(false);
    const [busyLabel, setBusyLabel] = useState('');
    const [deleteOpen, setDeleteOpen] = useState(false);
    const [deleting, setDeleting] = useState(false);
    const [isDragOver, setIsDragOver] = useState(false);
    const [reloadKey, setReloadKey] = useState(0);

    useEffect(() => {
        if (authLoading) return;
        if (!isAuthenticated) {
            navigate('/');
            return;
        }
        if (!vaultKey || !id) return;

        let cancelled = false;
        const load = async () => {
            setLoading(true);
            setLoadError('');
            try {
                const detail = await api.pastes.get(id);
                const status = await api.share.status(id).catch(() => ({ exists: false as const }));
                const key = await pasteKeyForSummary(vaultKey, detail);
                const fields = await decryptPasteWithKey(key, detail);
                const files: ExistingFile[] = [];
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
                if (cancelled) return;

                const burn = burnDisplay(detail);
                setPaste(detail);
                setPasteKey(key);
                setExistingFiles(files);
                setTitle(fields.title);
                setContent(fields.content);
                setLanguage(fields.language);
                setIsPinned(detail.pinned);
                setBurnTrigger(burn.trigger);
                setBurnValue(burn.value);
                setBurnUnit(burn.unit);
                setUnlockValue(burn.unlocks);
                setBurnDirty(false);
                setHasShare(status.exists);
                setNotFound(false);
                if (failedFiles > 0) {
                    toast.error(
                        `${failedFiles} attachment${failedFiles === 1 ? '' : 's'} could not be decrypted`,
                    );
                }
            } catch (error) {
                if (cancelled) return;
                if (error instanceof ApiError && (error.status === 404 || error.status === 410)) {
                    setNotFound(true);
                } else if (error instanceof ApiError && error.status === 401) {
                    setLoadError('Your session expired. Unlock your vault again.');
                    // Re-run the auth check so the whole app locks consistently.
                    void checkAuth();
                } else {
                    // Transient failures must not masquerade as "not found".
                    setLoadError(error instanceof Error ? error.message : 'Failed to load paste');
                }
            } finally {
                if (!cancelled) setLoading(false);
            }
        };
        void load();
        return () => { cancelled = true; };
    }, [id, isAuthenticated, vaultKey, authLoading, navigate, reloadKey, checkAuth]);

    const existingSize = existingFiles.reduce((sum, file) => sum + file.meta.size, 0);
    const stagedEstimate = stagedFiles.reduce((sum, file) => sum + file.file.size + 28, 0);

    const addFiles = (files: FileList | File[]) => {
        const incoming = Array.from(files);
        if (incoming.length === 0) return;

        let total = existingSize + stagedEstimate;
        const accepted: StagedFile[] = [];
        for (const file of incoming) {
            const encryptedSize = file.size + 28;
            if (encryptedSize > config.maxFileSize) {
                toast.error(
                    `${file.name} is too large. Maximum file size is about ${formatFileSize(config.maxFileSize - 28)}.`,
                );
                continue;
            }
            if (total + encryptedSize > config.maxFileSize) {
                toast.error(
                    `Attachment quota is ${formatFileSize(config.maxFileSize)} per paste.`,
                );
                break;
            }
            total += encryptedSize;
            accepted.push({
                key: `${file.name}-${file.size}-${file.lastModified}-${Math.random()}`,
                file,
            });
        }
        if (accepted.length > 0) {
            setStagedFiles((previous) => [...previous, ...accepted]);
        }
    };

    const handleFileInput = (event: React.ChangeEvent<HTMLInputElement>) => {
        if (event.target.files) addFiles(event.target.files);
        event.target.value = '';
    };

    const handleDrop = (event: React.DragEvent<HTMLDivElement>) => {
        event.preventDefault();
        setIsDragOver(false);
        if (event.dataTransfer.files.length > 0) addFiles(event.dataTransfer.files);
    };

    const removeStaged = (key: string) => {
        setStagedFiles((previous) => previous.filter((file) => file.key !== key));
    };

    const save = async (event: React.FormEvent) => {
        event.preventDefault();
        if (!paste || !pasteKey || !vaultKey || !id) return;
        if (burnDirty && hasShare) {
            toast.error('Revoke the existing share before changing burn rules');
            return;
        }
        if (burnDirty) {
            const burnError = validateBurnRule(burnTrigger, burnValue, burnUnit, unlockValue);
            if (burnError) {
                toast.error(burnError);
                return;
            }
        }
        const contentBytes = new TextEncoder().encode(content).byteLength;
        if (contentBytes > config.maxTextSize) {
            toast.error(`Text is too large. Maximum is ${formatFileSize(config.maxTextSize)}.`);
            return;
        }

        setSaving(true);
        try {
            setBusyLabel('Encrypting…');
            const fields = await encryptPasteFields(pasteKey, id, {
                title,
                content,
                language,
            });

            const update: Parameters<typeof api.pastes.update>[1] = {
                titleCt: fields.titleCt,
                contentCt: fields.contentCt,
                languageCt: fields.languageCt,
                pinned: isPinned,
            };
            if (burnDirty) {
                if (burnTrigger === 'time') {
                    const multiplier = burnUnit === 'minute' ? 60 : burnUnit === 'hour' ? 3600 : 86400;
                    update.burnMode = 'time';
                    update.burnAfterSeconds = Number(burnValue) * multiplier;
                } else if (burnTrigger === 'unlock_count') {
                    update.burnMode = 'unlock_count';
                    update.burnAfter = Number(unlockValue);
                } else {
                    update.burnMode = 'none';
                }
            }

            // Encrypt new attachments before persisting the text edit. If
            // local encryption fails, the paste stays unchanged.
            const prepared: EncryptedAttachment[] = [];
            for (const staged of stagedFiles) {
                const bytes = new Uint8Array(await staged.file.arrayBuffer());
                prepared.push(await encryptNewAttachment(pasteKey, id, {
                    name: staged.file.name,
                    mime: staged.file.type || 'application/octet-stream',
                    bytes,
                }));
            }
            const totalSize = existingSize + prepared.reduce(
                (sum, attachment) => sum + attachment.encrypted.byteLength,
                0,
            );
            if (totalSize > config.maxFileSize) {
                throw new Error('The encrypted attachments exceed the per-paste quota');
            }

            await api.pastes.update(id, update);

            let failed = 0;
            for (let index = 0; index < prepared.length; index += 1) {
                const attachment = prepared[index];
                setBusyLabel(`Uploading file ${index + 1} of ${prepared.length}…`);
                try {
                    await api.files.upload({
                        pasteId: id,
                        fileId: attachment.fileId,
                        encrypted: attachment.encrypted,
                        encMeta: attachment.encMeta,
                    });
                } catch {
                    failed += 1;
                }
            }

            if (failed > 0) {
                toast.error(
                    `Saved, but ${failed} file${failed === 1 ? '' : 's'} failed to upload. Add the missing file${failed === 1 ? '' : 's'} again.`,
                );
                setStagedFiles([]);
                setReloadKey((value) => value + 1);
                return;
            }

            toast.success('Paste updated');
            navigate(`/p/${id}`);
        } catch (error) {
            toast.error(error instanceof Error ? error.message : 'Failed to update paste');
        } finally {
            setSaving(false);
            setBusyLabel('');
        }
    };

    const revokeShare = async () => {
        if (!id) return;
        try {
            await api.share.delete(id);
            setHasShare(false);
            toast.success('Share revoked');
        } catch (error) {
            toast.error(error instanceof Error ? error.message : 'Failed to revoke share');
        }
    };

    const downloadExisting = async (file: ExistingFile) => {
        if (!pasteKey || !id) return;
        try {
            const encrypted = await api.files.download(file.meta.id);
            const plain = await decryptAttachmentBytes(
                pasteKey,
                id,
                file.meta.id,
                encrypted,
                file.plain.size,
            );
            const blob = new Blob([toArrayBuffer(plain)], { type: file.plain.mime });
            const url = URL.createObjectURL(blob);
            const anchor = document.createElement('a');
            anchor.href = url;
            anchor.download = file.plain.name;
            anchor.click();
            window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
        } catch (error) {
            toast.error(error instanceof Error ? error.message : 'Failed to download file');
        }
    };

    const deletePaste = async () => {
        if (!id) return;
        setDeleting(true);
        try {
            await api.pastes.delete(id);
            toast.success('Paste deleted');
            navigate('/');
        } catch (error) {
            toast.error(error instanceof Error ? error.message : 'Failed to delete paste');
        } finally {
            setDeleting(false);
        }
    };

    if (authLoading || loading) {
        return (
            <div className="flex-1 flex items-center justify-center text-muted-foreground">
                <LoaderPinwheelIcon size={20} className="animate-spin mr-2" />
                Decrypting paste…
            </div>
        );
    }
    if (notFound) return <ErrorState type="not-found" />;
    if (loadError) return <ErrorState type="error" error={loadError} />;
    if (!paste || !pasteKey) return <ErrorState type="not-found" />;

    return (
        <div className="mx-auto max-w-6xl w-full px-4 sm:px-6 py-5">
            <form onSubmit={save} className="flex flex-col gap-4">
                <div className="flex items-center gap-2">
                    <Button type="button" variant="ghost" size="icon" onClick={() => navigate(`/p/${paste.id}`)}>
                        <ArrowLeftIcon size={18} />
                    </Button>
                    <div>
                        <h1 className="text-xl font-semibold tracking-tight">Edit Paste</h1>
                        <p className="text-xs text-muted-foreground font-mono">{paste.id}</p>
                    </div>
                </div>

                {hasShare && (
                    <div className="rounded-md border border-amber-500/30 bg-amber-500/10 px-4 py-3 flex flex-wrap items-center gap-3 text-sm">
                        <LockIcon size={16} className="text-amber-600 dark:text-amber-400" />
                        <span className="flex-1 text-amber-700 dark:text-amber-300">
                            Burn rules are locked while a share exists.
                        </span>
                        <Button type="button" size="sm" variant="outline" onClick={revokeShare}>
                            Revoke share
                        </Button>
                    </div>
                )}

                <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
                    <Card>
                        <CardContent className="p-5 flex flex-col gap-4">
                            <div className="flex flex-col gap-1.5">
                                <Label htmlFor="edit-title">Title</Label>
                                <Input
                                    id="edit-title"
                                    value={title}
                                    onChange={(event) => setTitle(event.target.value)}
                                    placeholder="Optional title"
                                    maxLength={512}
                                />
                            </div>
                            <div className="flex flex-col gap-1.5">
                                <div className="flex items-center justify-between">
                                    <Label htmlFor="edit-content">Content</Label>
                                    <span className="text-[11px] text-muted-foreground">
                                        {formatFileSize(new TextEncoder().encode(content).byteLength)} / {formatFileSize(config.maxTextSize)}
                                    </span>
                                </div>
                                <Textarea
                                    id="edit-content"
                                    value={content}
                                    onChange={(event) => setContent(event.target.value)}
                                    className="min-h-[320px] font-mono text-sm"
                                    spellCheck={false}
                                />
                            </div>

                            <div className="flex flex-col gap-2">
                                <div className="flex items-center justify-between">
                                    <Label>Attachments</Label>
                                    <span className="text-[11px] text-muted-foreground">
                                        {formatFileSize(existingSize + stagedEstimate)} / {formatFileSize(config.maxFileSize)}
                                    </span>
                                </div>

                                {existingFiles.length > 0 && (
                                    <div className="flex flex-col gap-1.5">
                                        {existingFiles.map((file) => (
                                            <div
                                                key={file.meta.id}
                                                className="flex items-center gap-2 rounded-md border border-border/50 px-3 py-2"
                                            >
                                                <FileTextIcon size={16} className="text-primary/70 shrink-0" />
                                                <span className="text-sm truncate flex-1">
                                                    {truncateFileName(file.plain.name, 42)}
                                                </span>
                                                <span className="text-[11px] text-muted-foreground shrink-0">
                                                    {formatFileSize(file.plain.size)}
                                                </span>
                                                <Button
                                                    type="button"
                                                    variant="ghost"
                                                    size="icon"
                                                    className="h-7 w-7"
                                                    onClick={() => downloadExisting(file)}
                                                    aria-label="Download attachment"
                                                >
                                                    <DownloadIcon size={14} />
                                                </Button>
                                            </div>
                                        ))}
                                        <p className="text-[11px] text-muted-foreground">
                                            Existing attachments cannot be removed individually. Delete the paste to remove them.
                                        </p>
                                    </div>
                                )}

                                <div
                                    className={cn(
                                        'rounded-md border border-dashed p-4 transition-colors',
                                        isDragOver
                                            ? 'border-primary bg-primary/5'
                                            : 'border-border/60 bg-muted/10',
                                    )}
                                    onDragOver={(event) => {
                                        event.preventDefault();
                                        setIsDragOver(true);
                                    }}
                                    onDragLeave={() => setIsDragOver(false)}
                                    onDrop={handleDrop}
                                >
                                    <div className="flex flex-col items-center gap-2 text-center">
                                        <UploadIcon size={20} className="text-primary/70" />
                                        <p className="text-sm">Add more encrypted files</p>
                                        <label className="cursor-pointer">
                                            <input
                                                type="file"
                                                multiple
                                                className="hidden"
                                                onChange={handleFileInput}
                                            />
                                            <span className="inline-flex h-9 items-center rounded-md border border-input bg-background px-3 text-sm font-medium hover:bg-accent">
                                                Choose Files
                                            </span>
                                        </label>
                                    </div>
                                </div>

                                {stagedFiles.length > 0 && (
                                    <div className="flex flex-col gap-1.5">
                                        {stagedFiles.map((file) => (
                                            <div
                                                key={file.key}
                                                className="flex items-center gap-2 rounded-md border border-border/50 px-3 py-2"
                                            >
                                                <FileTextIcon size={16} className="text-primary/70 shrink-0" />
                                                <span className="text-sm truncate flex-1">
                                                    {truncateFileName(file.file.name, 42)}
                                                </span>
                                                <span className="text-[11px] text-muted-foreground shrink-0">
                                                    {formatFileSize(file.file.size)}
                                                </span>
                                                <Button
                                                    type="button"
                                                    variant="ghost"
                                                    size="icon"
                                                    className="h-7 w-7 text-muted-foreground hover:text-destructive"
                                                    onClick={() => removeStaged(file.key)}
                                                    aria-label="Remove staged attachment"
                                                >
                                                    <DeleteIcon size={14} />
                                                </Button>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </CardContent>
                    </Card>

                    <div className="flex flex-col gap-4">
                        <Card>
                            <CardContent className="p-5 flex flex-col gap-4">
                                <div className="flex flex-col gap-1.5">
                                    <Label htmlFor="edit-language">Language</Label>
                                    <Select value={language} onValueChange={setLanguage}>
                                        <SelectTrigger id="edit-language">
                                            <SelectValue />
                                        </SelectTrigger>
                                        <SelectContent>
                                            {LANGUAGES.map((option) => (
                                                <SelectItem key={option.value} value={option.value}>
                                                    {option.label}
                                                </SelectItem>
                                            ))}
                                        </SelectContent>
                                    </Select>
                                </div>

                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-2">
                                        <PinIcon size={16} className="text-primary" />
                                        <Label htmlFor="edit-pinned">Pin to top</Label>
                                    </div>
                                    <Switch
                                        id="edit-pinned"
                                        checked={isPinned}
                                        onCheckedChange={setIsPinned}
                                    />
                                </div>

                                <div className="h-px bg-border/60" />

                                <BurnRulesControl
                                    trigger={burnTrigger}
                                    onTriggerChange={(value) => {
                                        setBurnTrigger(value);
                                        setBurnDirty(true);
                                    }}
                                    timeValue={burnValue}
                                    onTimeValueChange={(value) => {
                                        setBurnValue(value);
                                        setBurnDirty(true);
                                    }}
                                    unit={burnUnit}
                                    onUnitChange={(value) => {
                                        setBurnUnit(value);
                                        setBurnDirty(true);
                                    }}
                                    unlockValue={unlockValue}
                                    onUnlockValueChange={(value) => {
                                        setUnlockValue(value);
                                        setBurnDirty(true);
                                    }}
                                    disabled={hasShare || saving}
                                    disabledReason={hasShare ? 'Burn rules locked by share' : saving ? 'Saving…' : undefined}
                                />
                            </CardContent>
                        </Card>

                        <Card>
                            <CardContent className="p-5 flex flex-col gap-3">
                                <Button type="submit" disabled={saving} className="w-full">
                                    {saving && <LoaderPinwheelIcon size={16} className="mr-2 animate-spin" />}
                                    {busyLabel || 'Save Changes'}
                                </Button>
                                <Button
                                    type="button"
                                    variant="outline"
                                    className="w-full text-destructive hover:text-destructive"
                                    onClick={() => setDeleteOpen(true)}
                                    disabled={saving}
                                >
                                    <DeleteIcon size={16} className="mr-2" />
                                    Delete Paste
                                </Button>
                            </CardContent>
                        </Card>
                    </div>
                </div>
            </form>

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

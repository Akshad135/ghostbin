import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/lib/auth';
import { api } from '@/lib/api';
import {
    encryptNewAttachment,
    encryptPasteFields,
    encodeKeySalt,
    pasteKeyForSummary,
} from '@/lib/paste';
import { config } from '@/lib/config';
import {
    LANGUAGES,
    validateBurnRule,
    type BurnUnit,
} from '@/lib/constants';
import { generateKeySalt, generatePasteId } from '@/lib/e2ee';
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
import { BurnRulesControl } from '@/components/BurnRulesControl';
import { cn, formatFileSize, truncateFileName } from '@/lib/utils';
import { toast } from 'sonner';

interface StagedFile {
    key: string;
    file: File;
}

export function NewPaste() {
    const { isAuthenticated, vaultKey, isLoading: authLoading } = useAuth();
    const navigate = useNavigate();
    const fileInputRef = useRef<HTMLInputElement>(null);

    const [pasteId] = useState(() => generatePasteId());
    const [keySalt] = useState(() => generateKeySalt());
    const [title, setTitle] = useState('');
    const [content, setContent] = useState('');
    const [language, setLanguage] = useState('plaintext');
    const [isPinned, setIsPinned] = useState(false);
    const [burnTrigger, setBurnTrigger] = useState('off');
    const [burnValue, setBurnValue] = useState('24');
    const [burnUnit, setBurnUnit] = useState<BurnUnit>('hour');
    const [unlockValue, setUnlockValue] = useState('3');
    const [attachments, setAttachments] = useState<StagedFile[]>([]);
    const [isDragOver, setIsDragOver] = useState(false);
    const [busyLabel, setBusyLabel] = useState('');
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        if (!authLoading && !isAuthenticated) navigate('/');
    }, [authLoading, isAuthenticated, navigate]);

    if (authLoading || !isAuthenticated) return null;

    const estimatedEncryptedSize = attachments.reduce(
        (total, attachment) => total + attachment.file.size + 28,
        0,
    );

    const addFiles = (files: FileList | File[]) => {
        const incoming = Array.from(files);
        if (incoming.length === 0) return;

        let total = attachments.reduce(
            (sum, attachment) => sum + attachment.file.size + 28,
            0,
        );
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
                    `Attachment quota is ${formatFileSize(config.maxFileSize)} per paste. Remove a file or use a smaller one.`,
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
            setAttachments((previous) => [...previous, ...accepted]);
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

    const removeAttachment = (key: string) => {
        setAttachments((previous) => previous.filter((attachment) => attachment.key !== key));
    };

    const handleSubmit = async (event: React.FormEvent) => {
        event.preventDefault();
        if (!vaultKey) {
            toast.error('Unlock your vault first');
            return;
        }
        if (!content.trim() && attachments.length === 0) {
            toast.error('Add some text or attach a file');
            return;
        }

        const contentBytes = new TextEncoder().encode(content).byteLength;
        if (contentBytes > config.maxTextSize) {
            toast.error(
                `Text is too large. Maximum is ${formatFileSize(config.maxTextSize)}; attach larger content as a file.`,
            );
            return;
        }

        const burnError = validateBurnRule(burnTrigger, burnValue, burnUnit, unlockValue);
        if (burnError) {
            toast.error(burnError);
            return;
        }

        setLoading(true);
        try {
            setBusyLabel('Encrypting…');
            const salt = encodeKeySalt(keySalt);
            const pasteKey = await pasteKeyForSummary(vaultKey, {
                id: pasteId,
                keySalt: salt,
            });

            const fields = await encryptPasteFields(pasteKey, pasteId, {
                title,
                content,
                language,
            });

            const prepared = [];
            for (const attachment of attachments) {
                const bytes = new Uint8Array(await attachment.file.arrayBuffer());
                prepared.push(await encryptNewAttachment(pasteKey, pasteId, {
                    name: attachment.file.name,
                    mime: attachment.file.type || 'application/octet-stream',
                    bytes,
                }));
            }

            const totalSize = prepared.reduce(
                (sum, attachment) => sum + attachment.encrypted.byteLength,
                0,
            );
            if (totalSize > config.maxFileSize) {
                throw new Error('The encrypted attachments exceed the per-paste quota');
            }

            setBusyLabel('Creating paste…');
            const createInput: Parameters<typeof api.pastes.create>[0] = {
                id: pasteId,
                keySalt: salt,
                titleCt: fields.titleCt,
                contentCt: fields.contentCt,
                languageCt: fields.languageCt,
                pinned: isPinned,
            };
            if (burnTrigger === 'time') {
                const multiplier = burnUnit === 'minute' ? 60 : burnUnit === 'hour' ? 3600 : 86400;
                createInput.burnMode = 'time';
                createInput.burnAfterSeconds = Number(burnValue) * multiplier;
            } else if (burnTrigger === 'unlock_count') {
                createInput.burnMode = 'unlock_count';
                createInput.burnAfter = Number(unlockValue);
            }

            await api.pastes.create(createInput);

            let failedUploads = 0;
            for (let index = 0; index < prepared.length; index += 1) {
                const attachment = prepared[index];
                setBusyLabel(`Uploading file ${index + 1} of ${prepared.length}…`);
                try {
                    await api.files.upload({
                        pasteId,
                        fileId: attachment.fileId,
                        encrypted: attachment.encrypted,
                        encMeta: attachment.encMeta,
                    });
                } catch {
                    failedUploads += 1;
                }
            }

            if (failedUploads > 0) {
                toast.error(
                    `Paste created, but ${failedUploads} file${failedUploads === 1 ? '' : 's'} failed to upload. Add the missing file${failedUploads === 1 ? '' : 's'} again.`,
                );
                navigate(`/edit/${pasteId}`);
            } else {
                toast.success('Paste created');
                navigate(`/p/${pasteId}`);
            }
        } catch (error) {
            toast.error(error instanceof Error ? error.message : 'Failed to create paste');
        } finally {
            setLoading(false);
            setBusyLabel('');
        }
    };

    return (
        <div className="mx-auto max-w-6xl w-full px-4 sm:px-6 py-5">
            <form onSubmit={handleSubmit} className="flex flex-col gap-4">
                <div className="flex items-center gap-2">
                    <Button type="button" variant="ghost" size="icon" onClick={() => navigate('/')}>
                        <ArrowLeftIcon size={18} />
                    </Button>
                    <div>
                        <h1 className="text-xl font-semibold tracking-tight">New Paste</h1>
                        <p className="text-xs text-muted-foreground">
                            Encrypted in this browser before upload.
                        </p>
                    </div>
                </div>

                <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
                    <Card>
                        <CardContent className="p-5 flex flex-col gap-4">
                            <div className="flex flex-col gap-1.5">
                                <Label htmlFor="paste-title">Title</Label>
                                <Input
                                    id="paste-title"
                                    value={title}
                                    onChange={(event) => setTitle(event.target.value)}
                                    placeholder="Optional title"
                                    maxLength={512}
                                />
                            </div>

                            <div className="flex flex-col gap-1.5">
                                <div className="flex items-center justify-between">
                                    <Label htmlFor="paste-content">Content</Label>
                                    <span className="text-[11px] text-muted-foreground">
                                        {formatFileSize(new TextEncoder().encode(content).byteLength)} / {formatFileSize(config.maxTextSize)}
                                    </span>
                                </div>
                                <Textarea
                                    id="paste-content"
                                    value={content}
                                    onChange={(event) => setContent(event.target.value)}
                                    placeholder="Paste your text here…"
                                    className="min-h-[320px] font-mono text-sm"
                                    spellCheck={false}
                                />
                            </div>

                            <div className="flex flex-col gap-2">
                                <div className="flex items-center justify-between">
                                    <Label>Attachments</Label>
                                    <span className="text-[11px] text-muted-foreground">
                                        {formatFileSize(estimatedEncryptedSize)} / {formatFileSize(config.maxFileSize)} encrypted
                                    </span>
                                </div>

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
                                        <p className="text-sm">Drop files here, or choose files</p>
                                        <Button
                                            type="button"
                                            variant="outline"
                                            size="sm"
                                            onClick={() => fileInputRef.current?.click()}
                                        >
                                            Choose Files
                                        </Button>
                                        <input
                                            ref={fileInputRef}
                                            type="file"
                                            multiple
                                            className="hidden"
                                            onChange={handleFileInput}
                                        />
                                        <p className="text-[11px] text-muted-foreground">
                                            File names and types are encrypted too. Quota is per paste.
                                        </p>
                                    </div>
                                </div>

                                {attachments.length > 0 && (
                                    <div className="flex flex-col gap-1.5">
                                        {attachments.map((attachment) => (
                                            <div
                                                key={attachment.key}
                                                className="flex items-center gap-2 rounded-md border border-border/50 px-3 py-2"
                                            >
                                                <FileTextIcon size={16} className="text-primary/70 shrink-0" />
                                                <span className="text-sm truncate flex-1">
                                                    {truncateFileName(attachment.file.name, 42)}
                                                </span>
                                                <span className="text-[11px] text-muted-foreground shrink-0">
                                                    {formatFileSize(attachment.file.size)}
                                                </span>
                                                <Button
                                                    type="button"
                                                    variant="ghost"
                                                    size="icon"
                                                    className="h-7 w-7 text-muted-foreground hover:text-destructive"
                                                    onClick={() => removeAttachment(attachment.key)}
                                                    aria-label="Remove attachment"
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
                                    <Label htmlFor="paste-language">Language</Label>
                                    <Select value={language} onValueChange={setLanguage}>
                                        <SelectTrigger id="paste-language">
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
                                        <Label htmlFor="paste-pinned">Pin to top</Label>
                                    </div>
                                    <Switch
                                        id="paste-pinned"
                                        checked={isPinned}
                                        onCheckedChange={setIsPinned}
                                    />
                                </div>

                                <div className="h-px bg-border/60" />

                                <BurnRulesControl
                                    trigger={burnTrigger}
                                    onTriggerChange={setBurnTrigger}
                                    timeValue={burnValue}
                                    onTimeValueChange={setBurnValue}
                                    unit={burnUnit}
                                    onUnitChange={setBurnUnit}
                                    unlockValue={unlockValue}
                                    onUnlockValueChange={setUnlockValue}
                                    disabled={loading}
                                />
                            </CardContent>
                        </Card>

                        <Card>
                            <CardContent className="p-5 flex flex-col gap-3">
                                <div className="flex items-start gap-2 text-xs text-muted-foreground">
                                    <LockIcon size={14} className="text-primary mt-0.5 shrink-0" />
                                    <p>
                                        The server receives only ciphertext. Your vault key never leaves
                                        this browser.
                                    </p>
                                </div>
                                <Button type="submit" disabled={loading} className="w-full">
                                    {loading && <LoaderPinwheelIcon size={16} className="mr-2 animate-spin" />}
                                    {busyLabel || 'Create Paste'}
                                </Button>
                            </CardContent>
                        </Card>
                    </div>
                </div>
            </form>
        </div>
    );
}

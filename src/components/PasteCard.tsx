import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/lib/auth';
import { api, ApiError, type PasteSummary } from '@/lib/api';
import { decryptPasteTitleAndLanguage } from '@/lib/paste';
import { burnStatusLabel, getLanguageLabel, timeAgo } from '@/lib/constants';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { SharePasteDialog } from '@/components/SharePasteDialog';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
    Dialog,
    DialogClose,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { MenuIcon } from '@/components/ui/animated-menu';
import { LinkIcon } from '@/components/ui/animated-link';
import { SquarePenIcon } from '@/components/ui/animated-square-pen';
import { DeleteIcon } from '@/components/ui/animated-delete';
import { FileTextIcon } from '@/components/ui/animated-file-text';
import { ClockIcon } from '@/components/ui/animated-clock';
import { PinIcon } from '@/components/ui/animated-pin';
import { HourglassIcon } from '@/components/ui/animated-hourglass';
import { ShareIcon } from '@/components/ui/animated-share';
import { LockIcon } from '@/components/ui/animated-lock';
import { LoaderPinwheelIcon } from '@/components/ui/animated-loader-pinwheel';
import { toast } from 'sonner';

interface PasteCardProps {
    paste: PasteSummary;
    onChanged?: () => void;
    onDeleted?: (id: string) => void;
}

export function PasteCard({ paste, onChanged, onDeleted }: PasteCardProps) {
    const navigate = useNavigate();
    const { vaultKey, isAuthenticated } = useAuth();
    const [title, setTitle] = useState('');
    const [language, setLanguage] = useState('plaintext');
    const [decrypting, setDecrypting] = useState(true);
    const [deleteOpen, setDeleteOpen] = useState(false);
    const [deleting, setDeleting] = useState(false);
    const [shareDialogOpen, setShareDialogOpen] = useState(false);

    useEffect(() => {
        let cancelled = false;
        setDecrypting(true);
        if (!vaultKey) {
            setTitle('Private paste');
            setLanguage('plaintext');
            setDecrypting(false);
            return;
        }
        decryptPasteTitleAndLanguage(vaultKey, paste)
            .then((result) => {
                if (!cancelled) {
                    setTitle(result.title || 'Untitled paste');
                    setLanguage(result.language);
                }
            })
            .catch(() => {
                if (!cancelled) {
                    setTitle('Unable to decrypt');
                    setLanguage('plaintext');
                }
            })
            .finally(() => {
                if (!cancelled) setDecrypting(false);
            });
        return () => { cancelled = true; };
    }, [vaultKey, paste]);

    const togglePin = async () => {
        try {
            await api.pastes.update(paste.id, { pinned: !paste.pinned });
            toast.success(paste.pinned ? 'Paste unpinned' : 'Paste pinned');
            onChanged?.();
        } catch (error) {
            toast.error(error instanceof Error ? error.message : 'Failed to update pin');
        }
    };

    const handleDelete = async () => {
        setDeleting(true);
        try {
            await api.pastes.delete(paste.id);
            setDeleteOpen(false);
            toast.success('Paste deleted');
            onDeleted?.(paste.id);
        } catch (error) {
            if (error instanceof ApiError && error.status === 404) {
                onDeleted?.(paste.id);
            } else {
                toast.error(error instanceof Error ? error.message : 'Failed to delete paste');
            }
        } finally {
            setDeleting(false);
        }
    };

    const copyOwnerLink = async () => {
        try {
            await navigator.clipboard.writeText(`${window.location.origin}/p/${paste.id}`);
            toast.success('Owner link copied');
        } catch {
            toast.error('Failed to copy link');
        }
    };

    const burnLabel = burnStatusLabel(paste, true);
    const hasFiles = paste.fileCount > 0;

    return (
        <>
            <Card
                className="group cursor-pointer transition-all duration-200 hover:shadow-lg hover:shadow-primary/5 hover:border-primary/30 border-border/60 h-full flex flex-col"
                onClick={() => navigate(`/p/${paste.id}`)}
            >
                <CardContent className="p-3 gap-2 flex-1 flex flex-col">
                    <div className="flex items-center gap-1.5">
                        {paste.pinned && (
                            <PinIcon size={14} className="text-primary shrink-0 rotate-45" />
                        )}
                        <h3 className="font-medium text-sm truncate text-foreground flex-1 min-w-0">
                            {decrypting ? 'Decrypting…' : title}
                        </h3>

                        {hasFiles && (
                            <Badge variant="outline" className="text-[10px] px-1.5 py-0.5 shrink-0 gap-1 border-primary/20 bg-primary/5 text-primary">
                                <FileTextIcon size={10} />
                                {paste.fileCount}
                            </Badge>
                        )}

                        <Badge variant="default" className="text-[10px] px-1.5 py-0.5 shrink-0">
                            {getLanguageLabel(language)}
                        </Badge>

                        <DropdownMenu>
                            <DropdownMenuTrigger asChild onClick={(event) => event.stopPropagation()}>
                                <Button
                                    variant="ghost"
                                    size="icon"
                                    className="h-6 w-6 shrink-0 opacity-60 group-hover:opacity-100 transition-opacity text-muted-foreground hover:text-foreground"
                                >
                                    <MenuIcon size={14} />
                                </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" onClick={(event) => event.stopPropagation()}>
                                <DropdownMenuItem onClick={copyOwnerLink}>
                                    <LinkIcon size={14} className="mr-2 text-primary" /> Copy owner link
                                </DropdownMenuItem>
                                {isAuthenticated && (
                                    <>
                                        <DropdownMenuItem onClick={() => setShareDialogOpen(true)}>
                                            <ShareIcon size={14} className="mr-2" /> Share
                                        </DropdownMenuItem>
                                        <DropdownMenuItem onClick={() => navigate(`/edit/${paste.id}`)}>
                                            <SquarePenIcon size={14} className="mr-2" /> Edit
                                        </DropdownMenuItem>
                                        <DropdownMenuItem onClick={togglePin}>
                                            <PinIcon size={14} className="mr-2" />
                                            {paste.pinned ? 'Unpin' : 'Pin'}
                                        </DropdownMenuItem>
                                        <DropdownMenuSeparator />
                                        <DropdownMenuItem
                                            onClick={() => setDeleteOpen(true)}
                                            className="text-destructive focus:text-destructive focus:bg-destructive/10"
                                        >
                                            <DeleteIcon size={14} className="mr-2" /> Delete
                                        </DropdownMenuItem>
                                    </>
                                )}
                            </DropdownMenuContent>
                        </DropdownMenu>
                    </div>

                    <div className="flex-1 flex flex-col items-center justify-center rounded-md border border-dashed border-border/40 bg-muted/10 py-6 gap-2 text-muted-foreground">
                        {decrypting ? (
                            <LoaderPinwheelIcon size={18} className="animate-spin text-primary/60" />
                        ) : (
                            <LockIcon size={18} className="text-primary/60" />
                        )}
                        <span className="text-xs font-medium">
                            {hasFiles
                                ? `${paste.fileCount} encrypted file${paste.fileCount === 1 ? '' : 's'}`
                                : 'Encrypted paste'}
                        </span>
                        <span className="text-[10px]">Open to decrypt</span>
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-muted-foreground mt-auto">
                        <div className="flex items-center gap-2 min-w-0">
                            <span className="flex items-center gap-1 shrink-0">
                                <ClockIcon size={12} className="text-primary/60" />
                                {timeAgo(paste.createdAt)}
                            </span>
                            {burnLabel && (
                                <span className="flex items-center gap-1 text-amber-500 truncate">
                                    <HourglassIcon size={12} />
                                    {burnLabel}
                                </span>
                            )}
                        </div>
                        <span className="font-mono truncate ml-2">{paste.id.slice(0, 8)}</span>
                    </div>
                </CardContent>
            </Card>

            <Dialog open={deleteOpen} onOpenChange={setDeleteOpen}>
                <DialogContent onClick={(event) => event.stopPropagation()}>
                    <DialogHeader>
                        <DialogTitle>Delete Paste</DialogTitle>
                        <DialogDescription>
                            Delete <span className="font-semibold text-foreground">{title}</span>?
                            This removes the paste, its share, and all encrypted files. It cannot be undone.
                        </DialogDescription>
                    </DialogHeader>
                    <DialogFooter className="gap-2 sm:gap-0">
                        <DialogClose asChild>
                            <Button variant="outline" disabled={deleting}>Cancel</Button>
                        </DialogClose>
                        <Button variant="destructive" onClick={handleDelete} disabled={deleting}>
                            {deleting
                                ? <LoaderPinwheelIcon size={16} className="mr-1.5 animate-spin" />
                                : <DeleteIcon size={16} className="mr-1.5" />}
                            Delete
                        </Button>
                    </DialogFooter>
                </DialogContent>
            </Dialog>

            <SharePasteDialog
                open={shareDialogOpen}
                onOpenChange={setShareDialogOpen}
                paste={paste}
                onChanged={onChanged}
            />
        </>
    );
}

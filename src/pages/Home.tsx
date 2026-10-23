import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, ApiError, type PasteSummary } from '@/lib/api';
import { PasteCard } from '@/components/PasteCard';
import { useAuth } from '@/lib/auth';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { FileCode2 } from 'lucide-react';
import { PlusIcon } from '@/components/ui/animated-plus';
import { RefreshCWIcon } from '@/components/ui/animated-refresh-cw';
import { BadgeAlertIcon } from '@/components/ui/animated-badge-alert';

const PAGE_SIZE = 20;

export function Home() {
    const [pastes, setPastes] = useState<PasteSummary[]>([]);
    const [loading, setLoading] = useState(true);
    const [page, setPage] = useState(1);
    const [hasMore, setHasMore] = useState(false);
    const [error, setError] = useState('');
    const [pageError, setPageError] = useState('');
    const [loadTrigger, setLoadTrigger] = useState(0);
    const { isAuthenticated, isLoading: authLoading, configured, error: authError, checkAuth } = useAuth();
    const navigate = useNavigate();
    const hasLoadedOnce = useRef(false);

    useEffect(() => {
        setPage(1);
        hasLoadedOnce.current = false;
        setLoadTrigger((value) => value + 1);
    }, [isAuthenticated]);

    useEffect(() => {
        if (!isAuthenticated) return;
        return api.events.subscribe(() => {
            setLoadTrigger((value) => value + 1);
        });
    }, [isAuthenticated]);

    useEffect(() => {
        let cancelled = false;

        const load = async () => {
            if (!isAuthenticated) {
                setLoading(false);
                return;
            }
            if (!hasLoadedOnce.current) setLoading(true);
            setError('');
            setPageError('');
            try {
                // Walk every loaded page, not just the latest one, so
                // refreshes (SSE events, pin toggles, edits) pick up
                // changes to pastes beyond the first page. First occurrence
                // wins if a paste shifts between pages mid-walk.
                const collected: PasteSummary[] = [];
                const seen = new Set<string>();
                let lastHasMore = false;
                for (let current = 1; current <= page; current += 1) {
                    const result = await api.pastes.list(current, PAGE_SIZE);
                    if (cancelled) return;
                    for (const paste of result.pastes) {
                        if (seen.has(paste.id)) continue;
                        seen.add(paste.id);
                        collected.push(paste);
                    }
                    lastHasMore = result.hasMore;
                }
                setPastes(collected);
                setHasMore(lastHasMore);
                hasLoadedOnce.current = true;
            } catch (loadError) {
                if (cancelled) return;
                if (loadError instanceof ApiError && loadError.status === 401) {
                    void checkAuth();
                    return;
                }
                const message = loadError instanceof Error ? loadError.message : 'Failed to load pastes';
                // Only the very first load gets the full-screen error;
                // later failures keep the loaded grid visible with an
                // inline retry instead of blanking it.
                if (hasLoadedOnce.current) {
                    setPageError(message);
                } else {
                    setError(message);
                }
            } finally {
                if (!cancelled) setLoading(false);
            }
        };

        void load();
        return () => { cancelled = true; };
    }, [page, loadTrigger, isAuthenticated, checkAuth]);

    const handleRetry = useCallback(() => {
        hasLoadedOnce.current = false;
        setLoadTrigger((value) => value + 1);
    }, []);

    const handleChanged = useCallback(() => {
        setLoadTrigger((value) => value + 1);
    }, []);

    const handleDeleted = useCallback((id: string) => {
        setPastes((previous) => previous.filter((paste) => paste.id !== id));
    }, []);

    const showSkeleton = (authLoading || loading) && pastes.length === 0 && isAuthenticated;

    return (
        <div className="mx-auto max-w-[90rem] w-full px-4 sm:px-6 py-4 h-full flex flex-col">
            {showSkeleton ? (
                <div className="grid gap-3 grid-cols-1 md:grid-cols-2 lg:grid-cols-4">
                    {Array.from({ length: 12 }).map((_, index) => (
                        <div key={index} className="rounded-lg border border-border/60 p-3 space-y-2">
                            <div className="flex items-center justify-between">
                                <Skeleton className="h-4 w-32" />
                                <Skeleton className="h-5 w-5 rounded" />
                            </div>
                            <Skeleton className="h-20 w-full rounded-md" />
                            <div className="flex justify-between">
                                <Skeleton className="h-3 w-16" />
                                <Skeleton className="h-3 w-20" />
                            </div>
                        </div>
                    ))}
                </div>
            ) : authLoading ? (
                <div className="flex-1 flex items-center justify-center text-muted-foreground">
                    <RefreshCWIcon size={18} className="animate-spin mr-2" />
                    Connecting…
                </div>
            ) : !isAuthenticated ? (
                <div className="flex-1 flex flex-col items-center justify-center text-center max-w-2xl mx-auto">
                    <div className="rounded-full bg-primary/10 p-5 mb-6">
                        <FileCode2 className="h-10 w-10 text-primary" />
                    </div>
                    <h2 className="text-2xl font-bold tracking-tight">
                        {configured === false ? 'Create your private vault.' : 'It\'s a secret to everybody.'}
                    </h2>
                    <div className="text-base text-muted-foreground mt-3 space-y-1.5">
                        {configured === false ? (
                            <>
                                <p>The server stores only ciphertext. Your passphrase never leaves this browser.</p>
                                <p>There is no password reset. Keep your passphrase safe.</p>
                            </>
                        ) : (
                            <>
                                <p>The server has no idea what you are looking for (and prefers it that way).</p>
                                <p>Unlock your vault, or open a share link from the address bar.</p>
                            </>
                        )}
                    </div>
                    {authError && (
                        <p className="text-sm text-destructive mt-4">{authError}</p>
                    )}
                    <Button
                        className="mt-8 px-8"
                        onClick={() => window.dispatchEvent(new Event('open-login'))}
                        disabled={configured === null}
                    >
                        {configured === false ? 'Create Vault' : 'Unlock Vault'}
                    </Button>
                </div>
            ) : error ? (
                <div className="flex-1 flex flex-col items-center justify-center text-center max-w-2xl mx-auto">
                    <div className="rounded-full bg-destructive/10 p-4 mb-4">
                        <BadgeAlertIcon size={32} className="text-destructive" />
                    </div>
                    <h2 className="text-lg font-semibold">Connection Error</h2>
                    <p className="text-sm text-muted-foreground mt-1 max-w-sm">
                        {error}. Make sure the API server is running.
                    </p>
                    <Button variant="outline" className="mt-4" onClick={handleRetry}>
                        <RefreshCWIcon size={16} className="mr-1.5" />
                        Retry
                    </Button>
                </div>
            ) : pastes.length === 0 ? (
                <div className="flex-1 flex flex-col items-center justify-center text-center max-w-2xl mx-auto">
                    <div className="rounded-full bg-primary/10 p-4 mb-4">
                        <FileCode2 className="h-8 w-8 text-primary" />
                    </div>
                    <h2 className="text-lg font-semibold">No pastes yet</h2>
                    <p className="text-sm text-muted-foreground mt-1">
                        Create your first encrypted paste to get started.
                    </p>
                    <Button className="mt-4" onClick={() => navigate('/new')}>
                        <PlusIcon size={16} className="mr-1.5" />
                        Create a Paste
                    </Button>
                </div>
            ) : (
                <>
                    {pageError && (
                        <div className="flex items-center justify-center gap-3 py-2 text-sm text-destructive">
                            <span>{pageError}</span>
                            <Button
                                size="sm"
                                variant="outline"
                                disabled={loading}
                                onClick={() => setLoadTrigger((value) => value + 1)}
                            >
                                Retry
                            </Button>
                        </div>
                    )}
                    <div
                        className="grid gap-3 grid-cols-1 md:grid-cols-2 lg:grid-cols-4"
                        style={{ gridAutoRows: 'calc((100dvh - 7rem - 1px) / 3)' }}
                    >
                        {pastes.map((paste) => (
                            <PasteCard
                                key={paste.id}
                                paste={paste}
                                onChanged={handleChanged}
                                onDeleted={handleDeleted}
                            />
                        ))}
                    </div>

                    {hasMore && (
                        <div className="flex justify-center mt-8">
                            <Button
                                variant="outline"
                                disabled={loading}
                                onClick={() => setPage((value) => value + 1)}
                            >
                                {loading && <RefreshCWIcon size={16} className="mr-1.5 animate-spin" />}
                                Load More
                            </Button>
                        </div>
                    )}
                </>
            )}
        </div>
    );
}

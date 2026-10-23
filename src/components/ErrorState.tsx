import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { BadgeAlertIcon } from '@/components/ui/animated-badge-alert';
import { HourglassIcon } from '@/components/ui/animated-hourglass';
import { ArrowLeftIcon } from '@/components/ui/animated-arrow-left';
import { cn } from '@/lib/utils';

export function ErrorState({ type = 'not-found', error = '' }: { type?: 'not-found' | 'expired' | 'error', error?: string }) {
    const navigate = useNavigate();
    const expired = type === 'expired';
    const title = expired ? 'Paste expired' : type === 'error' ? 'Cannot open this paste' : 'Paste not found';
    const message = expired
        ? 'This paste has expired and is no longer available.'
        : error || (type === 'error' ? 'An unexpected error occurred.' : 'Paste not found');

    return (
        <div className="w-full h-full flex flex-col items-center justify-center p-6">
            <div className="flex flex-col items-center justify-center text-center max-w-md mx-auto">
                <div className={cn('rounded-full p-4 mb-4', expired ? 'bg-amber-500/10' : 'bg-destructive/10')}>
                    {expired ? (
                        <HourglassIcon size={32} className="text-amber-500" />
                    ) : (
                        <BadgeAlertIcon size={32} className="text-destructive" />
                    )}
                </div>
                <h2 className="text-lg font-semibold">{title}</h2>
                <p className="text-sm text-muted-foreground mt-1">{message}</p>
                <Button variant="outline" className="mt-4" onClick={() => navigate('/')}>
                    <ArrowLeftIcon size={16} className="mr-1.5" />
                    Back to Home
                </Button>
            </div>
        </div>
    );
}

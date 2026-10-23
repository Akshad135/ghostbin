import { useEffect } from 'react';
import { useTheme } from '@/components/ThemeProvider';

/**
 * Generates a ghost SVG favicon with the given stroke color and returns a data URI.
 */
function ghostFaviconDataUri(color: string): string {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 10h.01"/><path d="M15 10h.01"/><path d="M12 2a8 8 0 0 0-8 8v12l3-3 2.5 2.5L12 19l2.5 2.5L17 19l3 3V10a8 8 0 0 0-8-8z"/></svg>`;
    return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}

/**
 * Reads the computed --primary CSS variable (set per palette/mode on the
 * root element) and converts HSL → hex.
 */
function getAccentColor(): string {
    const style = getComputedStyle(document.documentElement);
    const raw = style.getPropertyValue('--primary').trim();
    if (!raw) return '#a78bfa'; // fallback purple

    const parts = raw.split(/\s+/);
    if (parts.length < 3) return '#a78bfa';

    const h = parseFloat(parts[0]);
    const s = parseFloat(parts[1]) / 100;
    const l = parseFloat(parts[2]) / 100;

    // HSL → RGB → hex
    const a = s * Math.min(l, 1 - l);
    const f = (n: number) => {
        const k = (n + h / 30) % 12;
        const color = l - a * Math.max(Math.min(k - 3, 9 - k, 1), -1);
        return Math.round(255 * color).toString(16).padStart(2, '0');
    };
    return `#${f(0)}${f(8)}${f(4)}`;
}

/**
 * Hook: updates the favicon color whenever the palette or mode changes.
 * Only applies when using the default favicon (not a custom one).
 */
export function useDynamicFavicon(enabled: boolean = true) {
    const { palette, mode } = useTheme();

    useEffect(() => {
        if (!enabled) return;
        // Small delay to ensure CSS variables have been applied
        const timer = setTimeout(() => {
            const color = getAccentColor();
            const link = document.querySelector<HTMLLinkElement>('link[rel="icon"]');
            if (link) {
                link.href = ghostFaviconDataUri(color);
            }
        }, 50);

        return () => clearTimeout(timer);
    }, [palette, mode, enabled]);
}

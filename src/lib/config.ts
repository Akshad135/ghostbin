// Centralized config — reads VITE_* env vars with sensible defaults.
// All branding and configurable values go through here.

const appName = import.meta.env.VITE_APP_NAME || 'ghostbin';
const appNameAccent = import.meta.env.VITE_APP_NAME_ACCENT ?? 'bin';

export const config = {
    appName,
    appNameAccent,
    // If appName ends with the accent text, prefix is everything before it
    appNamePrefix: appNameAccent && appName.endsWith(appNameAccent)
        ? appName.slice(0, -appNameAccent.length)
        : appName,
    appDescription: import.meta.env.VITE_APP_DESCRIPTION || 'A simple, private-first ghostbin with syntax highlighting',

    // Icons — fall back to bundled static assets
    faviconUrl: import.meta.env.VITE_FAVICON_URL || '/favicon.svg',
    appleTouchIcon: import.meta.env.VITE_APPLE_TOUCH_ICON || '/icon-192.png',
    // Maximum plaintext paste size in bytes. These defaults apply until the
    // server's limits arrive via /api/auth/params at boot; the server env
    // (MAX_TEXT_SIZE / MAX_FILE_SIZE) is the single source of truth.
    maxTextSize: Number(import.meta.env.VITE_MAX_TEXT_SIZE) || 524_288,
    // Maximum encrypted attachment quota per paste in bytes.
    maxFileSize: Number(import.meta.env.VITE_MAX_FILE_SIZE) || 52_428_800,
};

/** Adopt the server's size limits (called once at boot from checkAuth). */
export function applyServerLimits(limits: {
    maxTextSize?: number;
    maxFileSize?: number;
}) {
    const text = Number(limits.maxTextSize);
    const file = Number(limits.maxFileSize);
    if (Number.isFinite(text) && text > 0) config.maxTextSize = text;
    if (Number.isFinite(file) && file > 0) config.maxFileSize = file;
}

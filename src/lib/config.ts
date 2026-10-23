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
    pwaIcon192: import.meta.env.VITE_PWA_ICON_192 || '/icon-192.png',
    pwaIcon512: import.meta.env.VITE_PWA_ICON_512 || '/icon-512.png',
    pwaIconMaskable: import.meta.env.VITE_PWA_ICON_MASKABLE || '/icon-maskable-512.png',
    pwaIconSvg: import.meta.env.VITE_PWA_ICON_SVG || '/icon.svg',
    pwaIconMaskableSvg: import.meta.env.VITE_PWA_ICON_MASKABLE_SVG || '/icon-maskable.svg',
    appleTouchIcon: import.meta.env.VITE_APPLE_TOUCH_ICON || '/icon-192.png',
    // Maximum plaintext paste size in bytes. Must not exceed the server's
    // MAX_TEXT_SIZE. Default: 524288 (512 KB).
    maxTextSize: Number(import.meta.env.VITE_MAX_TEXT_SIZE) || 524_288,
    // Maximum encrypted attachment quota per paste in bytes. Must match the
    // server's MAX_FILE_SIZE. Default: 52428800 (50 MB).
    maxFileSize: Number(import.meta.env.VITE_MAX_FILE_SIZE) || 52_428_800,
} as const;

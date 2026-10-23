// Supported languages for syntax highlighting
export const LANGUAGES = [
    { value: 'plaintext', label: 'Plain Text' },
    { value: 'javascript', label: 'JavaScript' },
    { value: 'typescript', label: 'TypeScript' },
    { value: 'python', label: 'Python' },
    { value: 'rust', label: 'Rust' },
    { value: 'go', label: 'Go' },
    { value: 'java', label: 'Java' },
    { value: 'c', label: 'C' },
    { value: 'cpp', label: 'C++' },
    { value: 'csharp', label: 'C#' },
    { value: 'html', label: 'HTML' },
    { value: 'css', label: 'CSS' },
    { value: 'json', label: 'JSON' },
    { value: 'yaml', label: 'YAML' },
    { value: 'toml', label: 'TOML' },
    { value: 'xml', label: 'XML' },
    { value: 'markdown', label: 'Markdown' },
    { value: 'bash', label: 'Bash' },
    { value: 'powershell', label: 'PowerShell' },
    { value: 'sql', label: 'SQL' },
    { value: 'graphql', label: 'GraphQL' },
    { value: 'dockerfile', label: 'Dockerfile' },
    { value: 'ruby', label: 'Ruby' },
    { value: 'php', label: 'PHP' },
    { value: 'swift', label: 'Swift' },
    { value: 'kotlin', label: 'Kotlin' },
    { value: 'scala', label: 'Scala' },
    { value: 'r', label: 'R' },
    { value: 'lua', label: 'Lua' },
    { value: 'perl', label: 'Perl' },
    { value: 'haskell', label: 'Haskell' },
    { value: 'elixir', label: 'Elixir' },
    { value: 'clojure', label: 'Clojure' },
    { value: 'dart', label: 'Dart' },
    { value: 'zig', label: 'Zig' },
    { value: 'vue', label: 'Vue' },
    { value: 'svelte', label: 'Svelte' },
    { value: 'astro', label: 'Astro' },
    { value: 'jsx', label: 'JSX' },
    { value: 'tsx', label: 'TSX' },
    { value: 'scss', label: 'SCSS' },
    { value: 'less', label: 'Less' },
    { value: 'ini', label: 'INI' },
    { value: 'nginx', label: 'Nginx' },
    { value: 'diff', label: 'Diff' },
    { value: 'makefile', label: 'Makefile' },
    { value: 'shellscript', label: 'Shell Script' },
    { value: 'terraform', label: 'Terraform' },
    { value: 'proto', label: 'Protobuf' },
];

export const LANG_MAP: Record<string, string> = {
    plaintext: 'text',
    shellscript: 'shellscript',
    cpp: 'cpp',
    csharp: 'csharp',
    dockerfile: 'dockerfile',
    makefile: 'makefile',
    proto: 'protobuf',
    terraform: 'hcl',
    jsx: 'jsx',
    tsx: 'tsx',
    vue: 'vue',
    svelte: 'svelte',
    astro: 'astro',
    nginx: 'nginx',
};

export function getLanguageLabel(value: string): string {
    return LANGUAGES.find((l) => l.value === value)?.label || value;
}

// ─── Burn Rules ─────────────────────────────────────────────────────────────

export type BurnMode = 'time' | 'unlock_count';
export type BurnUnit = 'minute' | 'hour' | 'day';

export const BURN_TRIGGER_OPTIONS = [
    { value: 'off', label: 'Off' },
    { value: 'time', label: 'After time' },
    { value: 'unlock_count', label: 'After unlocks' },
];

export const BURN_UNIT_OPTIONS = [
    { value: 'minute', label: 'Minutes' },
    { value: 'hour', label: 'Hours' },
    { value: 'day', label: 'Days' },
];

/**
 * Client-side validation for burn rule fields.
 * Returns an error string if invalid, or null if valid.
 */
export function validateBurnRule(
    trigger: string,
    value: string,
    unit: BurnUnit,
    unlocks: string,
): string | null {
    if (trigger === 'time') {
        const num = Number(value);
        if (!value || isNaN(num) || num <= 0 || !Number.isInteger(num)) {
            return 'Please enter a valid burn duration (whole number).';
        }
        const multiplier = unit === 'minute' ? 60 : unit === 'hour' ? 3600 : 86400;
        const secs = num * multiplier;
        if (secs < 60) return 'Burn time must be at least 1 minute.';
        if (secs > 30 * 24 * 3600) return 'Burn time cannot exceed 30 days.';
    }
    if (trigger === 'unlock_count') {
        const num = Number(unlocks);
        if (!unlocks || isNaN(num) || num <= 0 || !Number.isInteger(num)) {
            return 'Please enter a valid unlock count (whole number).';
        }
        if (num > 1_000_000) return 'Unlock count cannot exceed 1,000,000.';
    }
    return null;
}

/**
 * Returns a compact human-readable label for a paste's active burn rule.
 * Returns empty string when no burn rule is set.
 */
export function burnStatusLabel(
    paste: {
        burnMode: string | null;
        burnAfter: number | null;
        burnAt: number | null;
    },
    compact = false,
): string {
    if (!paste.burnMode) return '';
    if (paste.burnMode === 'time' && paste.burnAt != null) {
        const remaining = paste.burnAt * 1000 - Date.now();
        if (remaining <= 0) return 'Delete (burned)';
        const label = timeUntil(paste.burnAt);
        return compact ? `Delete in ${label}` : `Delete after ${label}`;
    }
    if (paste.burnMode === 'unlock_count' && paste.burnAfter != null) {
        const count = paste.burnAfter;
        return `Delete after ${count} unlock${count === 1 ? '' : 's'}`;
    }
    return '';
}

export function timeAgo(epochSeconds: number): string {
    if (!Number.isFinite(epochSeconds)) return '';
    const seconds = Math.max(0, Math.floor(Date.now() / 1000 - epochSeconds));

    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    if (seconds < 2592000) return `${Math.floor(seconds / 86400)}d ago`;
    if (seconds < 31536000) return `${Math.floor(seconds / 2592000)}mo ago`;
    return `${Math.floor(seconds / 31536000)}y ago`;
}

// ─── Time helpers ────────────────────────────────────────────────────────────

/** Returns the time remaining until a Unix-seconds timestamp, e.g. "3h left". */
export function timeUntil(epochSeconds: number | null): string {
    if (epochSeconds == null || !Number.isFinite(epochSeconds)) return '';
    const seconds = Math.floor(epochSeconds - Date.now() / 1000);

    if (seconds <= 0) return 'soon';
    if (seconds < 60) return `${seconds}s left`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m left`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h left`;
    if (seconds < 604800) return `${Math.floor(seconds / 86400)}d left`;
    return `${Math.floor(seconds / 604800)}w left`;
}

export function formatTimestamp(epochSeconds: number): string {
    if (!Number.isFinite(epochSeconds)) return '';
    return new Date(epochSeconds * 1000).toLocaleString();
}

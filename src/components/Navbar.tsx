import { config } from '@/lib/config';
import React, { useCallback, useState, useEffect } from 'react';
import { GhostIcon } from '@/components/GhostIcon';
import { useDynamicFavicon } from '@/hooks/useDynamicFavicon';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '@/lib/auth';

import { useTheme, type Mode, type Palette } from '@/components/ThemeProvider';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuSeparator,
    DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { PaletteIcon } from '@/components/ui/animated-palette';


import { MenuIcon } from '@/components/ui/animated-menu';
import { LogoutIcon } from '@/components/ui/animated-logout';
import { PlusIcon } from '@/components/ui/animated-plus';
import { HomeIcon } from '@/components/ui/animated-home';
import { KeyIcon } from '@/components/ui/animated-key';
import { LockIcon } from '@/components/ui/animated-lock';
import { LoaderPinwheelIcon } from '@/components/ui/animated-loader-pinwheel';
import { toast } from 'sonner';

// True when using the bundled ghost icon (not a custom one via env vars)
const faviconEnv = import.meta.env.VITE_FAVICON_URL;
const isDefaultIcon = !faviconEnv || faviconEnv === '/favicon.svg';

const DARK_THEMES: { key: Palette; label: string }[] = [
    { key: 'catppuccin', label: 'catppuccin' },
    { key: 'dracula', label: 'dracula' },
    { key: 'gruvbox', label: 'gruvbox' },
    { key: 'kanagawa', label: 'kanagawa' },
    { key: 'nord', label: 'nord' },
    { key: 'one', label: 'one dark' },
    { key: 'rose-pine', label: 'rose pine' },
    { key: 'solarized', label: 'solarized' },
    { key: 'terminal', label: 'terminal' },
    { key: 'tokyo', label: 'tokyo night' },
    { key: 'vesper', label: 'vesper' }
];

const LIGHT_THEMES: { key: Palette; label: string }[] = [
    { key: 'catppuccin', label: 'catppuccin latte' },
    { key: 'gruvbox', label: 'gruvbox light' },
    { key: 'kanagawa', label: 'kanagawa lotus' },
    { key: 'one', label: 'one light' },
    { key: 'rose-pine', label: 'rose pine dawn' },
    { key: 'solarized', label: 'solarized light' },
    { key: 'tokyo', label: 'tokyo day' }
];

const ALL_THEMES: { key: Palette; label: string; mode: Mode }[] = [
    ...DARK_THEMES.map(t => ({ ...t, mode: 'dark' as const })),
    ...LIGHT_THEMES.map(t => ({ ...t, mode: 'light' as const }))
];

export function Navbar() {
    const {
        isAuthenticated,
        logout,
        lock,
        login,
        setup,
        changePassphrase,
        configured,
        setupTokenRequired,
        isLoading,
    } = useAuth();

    const navigate = useNavigate();
    const location = useLocation();
    const [isLoginOpen, setIsLoginOpen] = useState(false);
    const [isThemeOpen, setIsThemeOpen] = useState(false);
    const [passphrase, setPassphrase] = useState('');
    const [confirmPassphrase, setConfirmPassphrase] = useState('');
    const [setupToken, setSetupToken] = useState('');
    const [loginError, setLoginError] = useState('');
    const [loginLoading, setLoginLoading] = useState(false);
    const [rememberDevice, setRememberDevice] = useState(false);
    const [isChangePassOpen, setIsChangePassOpen] = useState(false);
    const [oldPassphrase, setOldPassphrase] = useState('');
    const [newPassphrase, setNewPassphrase] = useState('');
    const [confirmNewPassphrase, setConfirmNewPassphrase] = useState('');
    const [changeError, setChangeError] = useState('');
    const [changeLoading, setChangeLoading] = useState(false);
    const isSetup = configured === false;

    // Dynamically update favicon color when using the default ghost icon
    useDynamicFavicon(isDefaultIcon);

    // Listen for custom open-login events (e.g. from Home page landing button)
    useEffect(() => {
        const handleOpenLogin = () => setIsLoginOpen(true);
        window.addEventListener('open-login', handleOpenLogin);
        return () => window.removeEventListener('open-login', handleOpenLogin);
    }, []);

    const handleLogout = async () => {
        await logout();
        navigate('/');
    };

    const handleLock = async () => {
        await lock();
        navigate('/');
    };

    const handleLogin = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!passphrase) {
            setLoginError('Passphrase is required');
            return;
        }
        if (isSetup && passphrase !== confirmPassphrase) {
            setLoginError('Passphrases do not match');
            return;
        }
        if (isSetup && passphrase.length < 8) {
            setLoginError('Use at least 8 characters');
            return;
        }
        if (isSetup && setupTokenRequired && !setupToken.trim()) {
            setLoginError('This server requires a setup token to claim it');
            return;
        }
        setLoginLoading(true);
        setLoginError('');
        try {
            if (isSetup) {
                await setup(passphrase, rememberDevice, setupToken.trim() || undefined);
                toast.success('Vault created');
            } else {
                await login(passphrase, rememberDevice);
                toast.success('Vault unlocked');
            }
            setPassphrase('');
            setConfirmPassphrase('');
            setSetupToken('');
            setIsLoginOpen(false);
        } catch (err) {
            setLoginError(err instanceof Error ? err.message : 'Invalid passphrase');
        } finally {
            setLoginLoading(false);
        }
    };

    const handleChangePassphrase = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!oldPassphrase || !newPassphrase || !confirmNewPassphrase) {
            setChangeError('All fields are required');
            return;
        }
        if (newPassphrase.length < 8) {
            setChangeError('New passphrase must be at least 8 characters');
            return;
        }
        if (newPassphrase !== confirmNewPassphrase) {
            setChangeError('New passphrases do not match');
            return;
        }
        if (newPassphrase === oldPassphrase) {
            setChangeError('New passphrase must be different from the current one');
            return;
        }
        setChangeLoading(true);
        setChangeError('');
        try {
            await changePassphrase(oldPassphrase, newPassphrase);
            toast.success('Passphrase changed. Other devices were signed out.');
            setOldPassphrase('');
            setNewPassphrase('');
            setConfirmNewPassphrase('');
            setIsChangePassOpen(false);
        } catch (err) {
            setChangeError(err instanceof Error ? err.message : 'Failed to change passphrase');
        } finally {
            setChangeLoading(false);
        }
    };

    const isActive = (path: string) => location.pathname === path;

    return (
        <>
            <header className="sticky top-0 z-50 border-b border-border/60 bg-background/80 backdrop-blur-lg">
                <div className="mx-auto flex h-14 max-w-[90rem] items-center justify-between px-4 sm:px-6 relative">
                    {/* Logo — left */}
                    <button
                        onClick={() => navigate('/')}
                        className="flex items-center gap-2 font-bold text-lg tracking-tight cursor-pointer z-10"
                    >
                        {isDefaultIcon
                            ? <GhostIcon size={24} className="h-6 w-6 text-primary" />
                            : <img src={config.faviconUrl} alt="" className="h-6 w-6" />
                        }
                        <span>
                            {config.appNamePrefix}
                            <span className="text-primary">{config.appNameAccent}</span>
                        </span>
                    </button>

                    {/* Desktop center nav — hidden on mobile */}
                    <nav className="hidden sm:flex items-center gap-1 absolute left-1/2 -translate-x-1/2">
                        <Button
                            variant={isActive('/') ? 'default' : 'ghost'}
                            size="sm"
                            onClick={() => navigate('/')}
                            className={isActive('/')
                                ? 'bg-primary/15 text-primary hover:bg-primary/20'
                                : 'text-muted-foreground hover:text-foreground hover:bg-muted'
                            }
                        >
                            <HomeIcon size={16} className="mr-1.5" />
                            Home
                        </Button>
                        {isAuthenticated && (
                            <Button
                                variant={isActive('/new') ? 'default' : 'ghost'}
                                size="sm"
                                onClick={() => navigate('/new')}
                                className={isActive('/new')
                                    ? 'bg-primary/15 text-primary hover:bg-primary/20'
                                    : 'text-muted-foreground hover:text-foreground hover:bg-muted'
                                }
                            >
                                <PlusIcon size={16} className="mr-1.5" />
                                New Paste
                            </Button>
                        )}
                    </nav>

                    {/* Right side */}
                    <div className="flex items-center gap-1 z-10">
                        {/* Mobile: icon-only nav buttons */}
                        <Button
                            variant={isActive('/') ? 'default' : 'ghost'}
                            size="icon"
                            onClick={() => navigate('/')}
                            className={`sm:hidden h-9 w-9 ${isActive('/')
                                ? 'bg-primary/15 text-primary hover:bg-primary/20'
                                : 'text-muted-foreground hover:text-foreground hover:bg-muted'
                                }`}
                        >
                            <HomeIcon size={16} />
                        </Button>
                        {isAuthenticated && (
                            <Button
                                variant={isActive('/new') ? 'default' : 'ghost'}
                                size="icon"
                                onClick={() => navigate('/new')}
                                className={`sm:hidden h-9 w-9 ${isActive('/new')
                                    ? 'bg-primary/15 text-primary hover:bg-primary/20'
                                    : 'text-muted-foreground hover:text-foreground hover:bg-muted'
                                    }`}
                            >
                                <PlusIcon size={16} />
                            </Button>
                        )}

                        {/* Desktop controls: palette + theme + auth */}
                        <div className="hidden sm:flex items-center gap-1">
                            {/* Theme Modal Trigger */}
                            <Button
                                variant="ghost"
                                size="icon"
                                onClick={() => setIsThemeOpen(true)}
                                className="h-9 w-9 text-muted-foreground hover:text-primary hover:bg-primary/10"
                            >
                                <PaletteIcon size={16} />
                            </Button>

                            {isAuthenticated && (
                                <DropdownMenu>
                                    <DropdownMenuTrigger asChild>
                                        <Button
                                            variant="ghost"
                                            size="sm"
                                            className="text-muted-foreground hover:text-foreground"
                                        >
                                            <LockIcon size={16} className="mr-1.5" />
                                            Vault
                                        </Button>
                                    </DropdownMenuTrigger>
                                    <DropdownMenuContent align="end" className="w-52">
                                        <DropdownMenuItem onClick={() => setIsChangePassOpen(true)}>
                                            <KeyIcon size={16} className="mr-2" /> Change Passphrase
                                        </DropdownMenuItem>
                                        <DropdownMenuItem onClick={handleLock}>
                                            <LockIcon size={16} className="mr-2" /> Lock Vault
                                        </DropdownMenuItem>
                                        <DropdownMenuSeparator />
                                        <DropdownMenuItem
                                            onClick={handleLogout}
                                            className="text-destructive focus:text-destructive focus:bg-destructive/10"
                                        >
                                            <LogoutIcon size={16} className="mr-2" /> Logout
                                        </DropdownMenuItem>
                                    </DropdownMenuContent>
                                </DropdownMenu>
                            )}
                            {!isAuthenticated && (
                                <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => setIsLoginOpen(true)}
                                    disabled={isLoading}
                                    className="text-muted-foreground hover:text-foreground"
                                >
                                    <KeyIcon size={16} className="mr-1.5" />
                                    {configured === false ? 'Set Up' : 'Login'}
                                </Button>
                            )}
                        </div>

                        {/* Mobile: hamburger menu */}
                        <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="icon" className="sm:hidden h-9 w-9 text-muted-foreground">
                                    <MenuIcon size={16} />
                                </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end" className="w-48">
                                {/* Theme Modal Trigger */}
                                <DropdownMenuItem onClick={() => setIsThemeOpen(true)}>
                                    <PaletteIcon size={16} className="mr-2" /> Change Theme
                                </DropdownMenuItem>
                                <DropdownMenuSeparator />
                                {/* Auth */}
                                {isAuthenticated && (
                                    <>
                                        <DropdownMenuItem onClick={() => setIsChangePassOpen(true)}>
                                            <KeyIcon size={16} className="mr-2" /> Change Passphrase
                                        </DropdownMenuItem>
                                        <DropdownMenuItem onClick={handleLock}>
                                            <LockIcon size={16} className="mr-2" /> Lock Vault
                                        </DropdownMenuItem>
                                        <DropdownMenuSeparator />
                                        <DropdownMenuItem onClick={handleLogout} className="text-destructive focus:text-destructive focus:bg-destructive/10">
                                            <LogoutIcon size={16} className="mr-2" /> Logout
                                        </DropdownMenuItem>
                                    </>
                                )}
                                {!isAuthenticated && (
                                    <DropdownMenuItem
                                        onClick={() => setIsLoginOpen(true)}
                                        disabled={isLoading}
                                    >
                                        <KeyIcon size={16} className="mr-2" /> {configured === false ? 'Set Up Vault' : 'Login'}
                                    </DropdownMenuItem>
                                )}
                            </DropdownMenuContent>
                        </DropdownMenu>
                    </div>
                </div>
            </header>

            {/* Vault access dialog */}
            <Dialog
                open={isLoginOpen}
                onOpenChange={(open) => {
                    setIsLoginOpen(open);
                    if (!open) {
                        setPassphrase('');
                        setConfirmPassphrase('');
                        setSetupToken('');
                        setLoginError('');
                    }
                }}
            >
                <DialogContent className="max-w-sm mx-auto p-5">
                    <DialogHeader>
                        <DialogTitle className="text-center text-base">
                            {isSetup ? 'Create your vault' : 'Unlock your vault'}
                        </DialogTitle>
                    </DialogHeader>
                    <form onSubmit={handleLogin} className="flex flex-col gap-3 mt-1">
                        {isSetup && (
                            <p className="text-xs text-muted-foreground leading-relaxed">
                                Choose a strong passphrase. It derives the only key that can
                                decrypt your content. There is no reset or recovery.
                            </p>
                        )}
                        {isSetup && setupTokenRequired && (
                            <Input
                                type="password"
                                placeholder="Setup token"
                                value={setupToken}
                                onChange={(e) => setSetupToken(e.target.value)}
                                className="h-9"
                                autoComplete="off"
                            />
                        )}
                        <Input
                            type="password"
                            placeholder={isSetup ? 'Choose a passphrase' : 'Enter passphrase'}
                            value={passphrase}
                            onChange={(e) => setPassphrase(e.target.value)}
                            className="h-9"
                            autoFocus
                            autoComplete={isSetup ? 'new-password' : 'current-password'}
                        />
                        {isSetup && (
                            <Input
                                type="password"
                                placeholder="Confirm passphrase"
                                value={confirmPassphrase}
                                onChange={(e) => setConfirmPassphrase(e.target.value)}
                                className="h-9"
                                autoComplete="new-password"
                            />
                        )}
                        <div className="flex items-start gap-2.5 py-0.5">
                            <Switch
                                id="remember-device"
                                checked={rememberDevice}
                                onCheckedChange={setRememberDevice}
                                className="mt-0.5"
                                aria-describedby="remember-device-hint"
                            />
                            <label
                                htmlFor="remember-device"
                                className="text-xs leading-snug cursor-pointer select-none"
                            >
                                Keep this device unlocked
                                <span
                                    id="remember-device-hint"
                                    className="block text-[11px] text-muted-foreground"
                                >
                                    This browser can read all pastes without a passphrase.
                                </span>
                            </label>
                        </div>
                        {loginError && (
                            <p className="text-xs text-destructive" role="alert">{loginError}</p>
                        )}
                        <Button
                            type="submit"
                            size="sm"
                            disabled={loginLoading || isLoading}
                            className="w-full bg-primary hover:bg-primary/90 text-primary-foreground"
                        >
                            {loginLoading && <LoaderPinwheelIcon size={16} className="mr-2 animate-spin" />}
                            {isSetup ? 'Create Vault' : 'Unlock'}
                        </Button>
                    </form>
                </DialogContent>
            </Dialog>

            {/* Change passphrase dialog */}
            <Dialog
                open={isChangePassOpen}
                onOpenChange={(open) => {
                    setIsChangePassOpen(open);
                    if (!open) {
                        setOldPassphrase('');
                        setNewPassphrase('');
                        setConfirmNewPassphrase('');
                        setChangeError('');
                    }
                }}
            >
                <DialogContent className="max-w-sm mx-auto p-5">
                    <DialogHeader>
                        <DialogTitle className="text-center text-base">
                            Change passphrase
                        </DialogTitle>
                        <DialogDescription className="text-center">
                            Your vault is re-wrapped under a new key. All other
                            devices are signed out.
                        </DialogDescription>
                    </DialogHeader>
                    <form onSubmit={handleChangePassphrase} className="flex flex-col gap-3 mt-1">
                        <p className="text-xs text-muted-foreground leading-relaxed">
                            There is no reset or recovery. Keep the new passphrase safe.
                        </p>
                        <Input
                            type="password"
                            placeholder="Current passphrase"
                            value={oldPassphrase}
                            onChange={(e) => setOldPassphrase(e.target.value)}
                            className="h-9"
                            autoFocus
                            autoComplete="current-password"
                        />
                        <Input
                            type="password"
                            placeholder="New passphrase"
                            value={newPassphrase}
                            onChange={(e) => setNewPassphrase(e.target.value)}
                            className="h-9"
                            autoComplete="new-password"
                        />
                        <Input
                            type="password"
                            placeholder="Confirm new passphrase"
                            value={confirmNewPassphrase}
                            onChange={(e) => setConfirmNewPassphrase(e.target.value)}
                            className="h-9"
                            autoComplete="new-password"
                        />
                        {changeError && (
                            <p className="text-xs text-destructive" role="alert">{changeError}</p>
                        )}
                        <Button
                            type="submit"
                            size="sm"
                            disabled={changeLoading || isLoading}
                            className="w-full bg-primary hover:bg-primary/90 text-primary-foreground"
                        >
                            {changeLoading && <LoaderPinwheelIcon size={16} className="mr-2 animate-spin" />}
                            Change Passphrase
                        </Button>
                    </form>
                </DialogContent>
            </Dialog>

            {/* Theme picker dialog */}
            <ThemeModal open={isThemeOpen} onOpenChange={setIsThemeOpen} />
        </>
    );
}

function ThemeModal({ open, onOpenChange }: { open: boolean, onOpenChange: (open: boolean) => void }) {
    const { mode, palette, setMode, setPalette } = useTheme();
    // Null means "follow the current theme"; hovering or arrow keys pick an index.
    const [selected, setSelected] = useState<number | null>(null);
    const defaultIndex = Math.max(
        0,
        ALL_THEMES.findIndex((t) => t.key === palette && t.mode === mode),
    );
    const activeIndex = selected ?? defaultIndex;

    const applyTheme = useCallback((index: number) => {
        const t = ALL_THEMES[index];
        setMode(t.mode);
        setPalette(t.key);
    }, [setMode, setPalette]);

    const close = useCallback((next: boolean) => {
        if (!next) setSelected(null);
        onOpenChange(next);
    }, [onOpenChange]);

    useEffect(() => {
        if (!open) return;
        const handleKeyDown = (e: KeyboardEvent) => {
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                setSelected((prev) => ((prev ?? defaultIndex) + 1) % ALL_THEMES.length);
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setSelected((prev) => ((prev ?? defaultIndex) - 1 + ALL_THEMES.length) % ALL_THEMES.length);
            } else if (e.key === 'Enter') {
                e.preventDefault();
                close(false);
            }
        };
        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, [open, close, defaultIndex]);

    // Apply the highlighted theme live while the picker is open.
    useEffect(() => {
        if (!open) return;
        applyTheme(activeIndex);
    }, [activeIndex, open, applyTheme]);

    return (
        <Dialog open={open} onOpenChange={close}>
            <DialogContent className="max-w-md mx-auto p-0 border border-border/50 bg-background/80 backdrop-blur-2xl overflow-hidden rounded-xl gap-0 shadow-2xl [&>button]:hidden">
                {/* Top Bar with Controls */}
                <div className="flex items-center justify-between px-3 py-2 border-b border-border/50 bg-muted/20 text-xs text-muted-foreground">
                    <div className="flex items-center gap-1 font-medium">
                        ↑↓ select
                    </div>
                    <div className="flex items-center gap-2">
                        <span className="flex items-center gap-1.5 bg-primary/20 text-primary px-1.5 py-0.5 rounded-md font-medium">
                            <span className="text-[10px]">↵</span> apply
                        </span>
                        <span className="text-muted-foreground px-1">
                            esc close
                        </span>
                        <button
                            onClick={() => close(false)}
                            className="ml-1 flex items-center justify-center h-5 w-5 rounded hover:bg-muted-foreground/20 transition-colors"
                        >
                            <PlusIcon size={14} className="rotate-45" />
                        </button>
                    </div>
                </div>

                {/* List */}
                <div className="flex flex-col p-1.5 outline-none">
                    {ALL_THEMES.map((t, i) => {
                        const isFirstDark = i === 0;
                        const isFirstLight = i === DARK_THEMES.length;

                        return (
                            <React.Fragment key={`${t.mode}-${t.key}`}>
                                {isFirstDark && (
                                    <div className="flex items-center gap-3 px-2 py-1.5 mt-0.5 text-[10px] uppercase font-semibold text-muted-foreground tracking-widest">
                                        dark <div className="h-px bg-border/50 flex-1" />
                                    </div>
                                )}
                                {isFirstLight && (
                                    <div className="flex items-center gap-3 px-2 py-1.5 mt-1.5 text-[10px] uppercase font-semibold text-muted-foreground tracking-widest">
                                        light <div className="h-px bg-border/50 flex-1" />
                                    </div>
                                )}
                                <button
                                    onMouseEnter={() => {
                                        setSelected(i);
                                        applyTheme(i);
                                    }}
                                    onClick={() => {
                                        applyTheme(i);
                                        close(false);
                                    }}
                                    className={`flex items-center px-3 py-1 text-sm text-left rounded-md transition-colors duration-75 ${
                                        activeIndex === i 
                                            ? 'bg-primary/15 text-primary font-medium' 
                                            : 'text-muted-foreground hover:text-foreground'
                                    }`}
                                >
                                    <span className="w-4 flex justify-center text-primary font-bold mr-1">
                                        {activeIndex === i ? '•' : ''}
                                    </span>
                                    {t.label}
                                    {activeIndex === i && <span className="ml-auto text-xs">✓</span>}
                                </button>
                            </React.Fragment>
                        );
                    })}
                </div>
            </DialogContent>
        </Dialog>
    );
}


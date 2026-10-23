import type { Theme } from '@pierre/highlights';
import catppuccinLatte from '@pierre/highlights/themes/catppuccin-latte';
import catppuccinMocha from '@pierre/highlights/themes/catppuccin-mocha';
import dracula from '@pierre/highlights/themes/dracula';
import githubDarkDefault from '@pierre/highlights/themes/github-dark-default';
import githubLightDefault from '@pierre/highlights/themes/github-light-default';
import gruvboxDarkMedium from '@pierre/highlights/themes/gruvbox-dark-medium';
import gruvboxLightMedium from '@pierre/highlights/themes/gruvbox-light-medium';
import kanagawaLotus from '@pierre/highlights/themes/kanagawa-lotus';
import kanagawaWave from '@pierre/highlights/themes/kanagawa-wave';
import nord from '@pierre/highlights/themes/nord';
import oneDarkPro from '@pierre/highlights/themes/one-dark-pro';
import oneLight from '@pierre/highlights/themes/one-light';
import rosePine from '@pierre/highlights/themes/rose-pine';
import rosePineDawn from '@pierre/highlights/themes/rose-pine-dawn';
import solarizedDark from '@pierre/highlights/themes/solarized-dark';
import solarizedLight from '@pierre/highlights/themes/solarized-light';
import tokyoNight from '@pierre/highlights/themes/tokyo-night';
import vesper from '@pierre/highlights/themes/vesper';
import type { Mode, Palette } from '@/components/ThemeProvider';

// Highlight themes matched to the app palettes the library ships a
// counterpart for. Palettes without one (terminal), and modes without a
// variant (dracula/nord/tokyo/vesper have no light counterpart), fall
// back to the neutral GitHub themes.
const PALETTE_THEMES: Record<Palette, { light: Theme; dark: Theme }> = {
    catppuccin: { light: catppuccinLatte, dark: catppuccinMocha },
    terminal: { light: githubLightDefault, dark: githubDarkDefault },
    tokyo: { light: githubLightDefault, dark: tokyoNight },
    dracula: { light: githubLightDefault, dark: dracula },
    nord: { light: githubLightDefault, dark: nord },
    gruvbox: { light: gruvboxLightMedium, dark: gruvboxDarkMedium },
    one: { light: oneLight, dark: oneDarkPro },
    solarized: { light: solarizedLight, dark: solarizedDark },
    kanagawa: { light: kanagawaLotus, dark: kanagawaWave },
    'rose-pine': { light: rosePineDawn, dark: rosePine },
    vesper: { light: githubLightDefault, dark: vesper },
};

export function highlightThemeFor(palette: Palette, mode: Mode): Theme {
    return PALETTE_THEMES[palette][mode];
}

<!-- Role: inventories third-party code and points to its license notices. -->
# Third-party notices

- `apps/tracer/vendor/ghostty-web/`: ghostty-web source build and its embedded
  Ghostty VT WebAssembly use MIT; see the included `LICENSE` and
  `GHOSTTY-LICENSE` texts. Source and toolchain pins are recorded in the
  vendored package README.

## Colour schemes (`packages/ui/src/themes.ts`)

The terminal colour schemes added by D329 are palettes: colour values only, no code. Each value is the upstream project's published one, moved in
OKLab lightness where D80's contrast audit required it (the log is `docs/design/THEME-AUDIT.md`). The licence of each upstream was read from its
repository on 2026-11-04; the notice of each MIT licence is "Permission is hereby granted, free of charge, to any person obtaining a copy of this
software ... The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software."

| Scheme | Upstream | Licence | Copyright |
|---|---|---|---|
| Solarized Light, Solarized Dark | github.com/altercation/solarized | MIT | 2011 Ethan Schoonover |
| Everforest Light, Everforest Dark | github.com/sainnhe/everforest | MIT | 2019 sainnhe |
| Kanagawa Lotus, Kanagawa Wave | github.com/rebelot/kanagawa.nvim | MIT | 2021 Tommaso Laurenzi |
| Ayu Light, Ayu Dark | github.com/ayu-theme/ayu-colors | MIT | Konstantin Pschera |
| GitHub Light, GitHub Dark | github.com/primer/primitives | MIT | 2018 GitHub Inc. |
| Flexoki Light, Flexoki Dark | github.com/kepano/flexoki | MIT | 2023 Steph Ango |
| Gruvbox Light | github.com/morhetz/gruvbox | MIT (declared in its package.json; the repository has no licence file) | the Gruvbox authors |
| Tokyo Night Day | github.com/folke/tokyonight.nvim | Apache-2.0 (compatible with AGPL-3.0) | its author, folke |
| Catppuccin Frappé, Catppuccin Macchiato | github.com/catppuccin/catppuccin | MIT | 2021 Catppuccin |
| Light Owl, Night Owl | github.com/sdras/night-owl-vscode-theme | MIT | 2018 Sarah Drasner |

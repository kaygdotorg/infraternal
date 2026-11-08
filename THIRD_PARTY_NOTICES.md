<!-- Role: inventories third-party code and points to its license notices. -->
# Third-party notices

The production web build ships this file at `/THIRD_PARTY_NOTICES.md` and the
complete MIT and Apache-2.0 texts at `/licenses/MIT.txt` and
`/licenses/Apache-2.0.txt`. Copyright notices for each palette are listed
below; the fonts keep their upstream licence files beside the bundled faces.

- `apps/tracer/vendor/ghostty-web/`: ghostty-web source build and its embedded
  Ghostty VT WebAssembly use MIT; see the included `LICENSE` and
  `GHOSTTY-LICENSE` texts. Source and toolchain pins are recorded in the
  vendored package README.

## Colour schemes (`packages/ui/src/themes.ts`)

The schemes are palettes: colour values only, no code. Upstream values are
adjusted in OKLab lightness where D80 and D365 require more text contrast (the
audit is `docs/design/THEME-AUDIT.md`). Each MIT entry below carries its
copyright notice; the complete MIT terms are shipped at `/licenses/MIT.txt`.

### Earlier built-in schemes

| Scheme | Upstream | Licence | Copyright |
|---|---|---|---|
| Paper, Ink | Infraternal | AGPL-3.0-only | Infraternal contributors |
| Catppuccin Latte, Catppuccin Mocha | github.com/catppuccin/catppuccin | MIT | 2021 Catppuccin |
| Rosé Pine Dawn, Rosé Pine | github.com/rose-pine/neovim | MIT | 2023 Rosé Pine |
| Nord | github.com/nordtheme/nord | MIT | Arctic Ice Studio and Sven Greb |
| Tokyo Night | github.com/folke/tokyonight.nvim | Apache-2.0 | folke; full text at `/licenses/Apache-2.0.txt` |
| Gruvbox | github.com/morhetz/gruvbox | MIT | Gruvbox authors |
| Dracula | github.com/dracula/dracula-theme | MIT | 2023 Dracula Theme |

### D329 schemes

| Scheme | Upstream | Licence | Copyright |
|---|---|---|---|
| Solarized Light, Solarized Dark | github.com/altercation/solarized | MIT | 2011 Ethan Schoonover |
| Everforest Light, Everforest Dark | github.com/sainnhe/everforest | MIT | 2019 sainnhe |
| Kanagawa Lotus, Kanagawa Wave | github.com/rebelot/kanagawa.nvim | MIT | 2021 Tommaso Laurenzi |
| Ayu Light, Ayu Dark | github.com/ayu-theme/ayu-colors | MIT | Konstantin Pschera |
| GitHub Light, GitHub Dark | github.com/primer/primitives | MIT | 2018 GitHub Inc. |
| Flexoki Light, Flexoki Dark | github.com/kepano/flexoki | MIT | 2023 Steph Ango |
| Gruvbox Light | github.com/morhetz/gruvbox | MIT (declared in its package.json; the repository has no licence file) | the Gruvbox authors |
| Tokyo Night Day | github.com/folke/tokyonight.nvim | Apache-2.0 | its author, folke; full text at `/licenses/Apache-2.0.txt` |
| Catppuccin Frappé, Catppuccin Macchiato | github.com/catppuccin/catppuccin | MIT | 2021 Catppuccin |
| Light Owl, Night Owl | github.com/sdras/night-owl-vscode-theme | MIT | 2018 Sarah Drasner |

## Fonts added by D329 (`apps/tracer/fonts/`)

Each family is self-hosted as a latin woff2 subset made by `apps/tracer/fonts/subset.sh` from the upstream release named below, whose archive is checked
against a pinned sha256 before use. A subset is a Modified Version, so the internal font names are replaced (the OFL forbids keeping a Reserved Font
Name); the licence text of each family sits next to its files, and the upstream's own copyright line is in it. The licence of each was read from the
release or the repository on 2026-11-04. Each font is fetched by a browser only when a person chooses it.

| Family | Upstream release | Licence |
|---|---|---|
| Iosevka | github.com/be5invis/Iosevka v34.9.1 | SIL OFL 1.1 |
| Victor Mono | github.com/rubjo/victor-mono v1.5.6 | SIL OFL 1.1 |
| Recursive Mono | github.com/arrowtype/recursive v1.085 | SIL OFL 1.1 |
| Martian Mono | github.com/evilmartians/mono v1.1.0 | SIL OFL 1.1 |
| Intel One Mono | github.com/intel/intel-one-mono V1.4.0 | SIL OFL 1.1 |
| Fantasque Sans Mono | github.com/belluzj/fantasque-sans v1.8.0 | SIL OFL 1.1 |
| Hack | github.com/source-foundry/Hack v3.003 | MIT, with the Bitstream Vera licence for the parts it keeps |
| Inconsolata | github.com/googlefonts/Inconsolata v3.000 | SIL OFL 1.1 |
| 0xProto | github.com/0xType/0xProto 2.502 | SIL OFL 1.1 |
| Lilex | github.com/mishamyrt/Lilex 2.630 | SIL OFL 1.1 |
| Monaspace Argon, Xenon, Radon, Krypton | github.com/githubnext/monaspace v1.400 (the archive Monaspace Neon already comes from) | SIL OFL 1.1 |

## Earlier fonts

These families were already bundled before D329. Their complete OFL texts stay
beside their files under `apps/tracer/fonts/`; Hack's MIT and Bitstream Vera
terms are in its `LICENSE.txt`.

| Family | Upstream release | Licence text |
|---|---|---|
| Maple Mono NF | github.com/subframe7536/maple-font v7.9 | SIL OFL 1.1, `fonts/maple-mono-nf/OFL.txt` |
| Nerd Symbols | Prompt glyph subset extracted from the Maple Mono NF v7.9 release | SIL OFL 1.1, `fonts/maple-mono-nf/OFL.txt` |
| Geist Sans, Geist Mono | github.com/vercel/geist-font; npm `geist` 1.9.2 | SIL OFL 1.1, `fonts/geist-mono/OFL.txt` |
| JetBrains Mono | github.com/JetBrains/JetBrainsMono v2.304 | SIL OFL 1.1, `fonts/jetbrains-mono/OFL.txt` |
| Commit Mono | github.com/eigilnikolajsen/commit-mono v1.143 | SIL OFL 1.1, `fonts/commit-mono/OFL.txt` |
| Monaspace Neon | github.com/githubnext/monaspace v1.400 | SIL OFL 1.1, `fonts/monaspace-neon/OFL.txt` |
| IBM Plex Mono | github.com/IBM/plex-mono-variable v1.0.0 | SIL OFL 1.1, `fonts/ibm-plex-mono/OFL.txt` |
| Fira Code | github.com/tonsky/FiraCode v6.2 | SIL OFL 1.1, `fonts/fira-code/OFL.txt` |
| Source Code Pro | github.com/adobe-fonts/source-code-pro 2.042R-u/1.062R-i/1.026R-vf | SIL OFL 1.1, `fonts/source-code-pro/OFL.txt` |
| Cascadia Code | github.com/microsoft/cascadia-code v2407.24 | SIL OFL 1.1, `fonts/cascadia-code/OFL.txt` |
- `gotatun` (Rust crate, built into the infraternal agent's mesh engine on Linux):
  - Licence: MPL-2.0. infraternal builds it, unchanged, from our fork. Under MPL-2.0
    §3.2, its Source Code Form is available from
    <https://github.com/kaygdotorg/gotatun> at commit
    `84b7bb28e385d57dfb80493e78202898fad24d1e`, the commit pinned in
    `crates/plugins/mesh/Cargo.toml`. The licence text is the file `LICENSE`
    there, and at <https://www.mozilla.org/MPL/2.0/>.
  - Code contributed before 5 March 2026 is also under the BSD 3-Clause licence
    (the file `LICENSE-CLOUDFLARE` there). Its notice, reproduced as that licence
    requires:

    ```text
    Copyright (c) 2019 Cloudflare, Inc. All rights reserved.

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
        2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
        3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
    ```

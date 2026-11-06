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

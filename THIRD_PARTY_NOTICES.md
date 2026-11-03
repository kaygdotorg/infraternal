<!-- Role: inventories third-party code and points to its license notices. -->
# Third-party notices

- `apps/tracer/vendor/ghostty-web/`: ghostty-web source build and its embedded
  Ghostty VT WebAssembly use MIT; see the included `LICENSE` and
  `GHOSTTY-LICENSE` texts. Source and toolchain pins are recorded in the
  vendored package README.

- `gotatun` (Rust crate, built into the infraternal agent's mesh engine on Linux):
  - Licence: MPL-2.0. infraternal builds it, unchanged, from our fork. Under MPL-2.0
    §3.2, its Source Code Form is available from
    <https://github.com/kaygdotorg/gotatun> at commit
    `73eb9f1ae185313609d031c644cb4a81f3c927dc`, the commit pinned in
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

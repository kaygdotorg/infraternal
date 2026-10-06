<!-- Role: checksummed index of the phase A screen corpus kept outside the repository. -->

# Phase A screen corpus

Corpus root: `$HOME/.cache/codex-scratch/spike-vnc/corpus/`  
Captured from the shared VM `calternal@10.69.69.21` on 2026-10-06. The VM's
settings were not changed. The temporary Terminal window was closed and Notes
was restored to the foreground after capture.

Still PNGs are 5004×2652. `screencapture -v -V4` movies are H.264 QuickTime at
4096×2170. `idle-headless.mov` has 27 frames over 4 seconds; `terminal-scroll.mov`
has 51 frames over 4.02 seconds; `window-drag.mov` has 45 frames over 4 seconds.
The short video path works through SSH, though its output raster is smaller than
the still capture raster.

`terminal-scroll/timing.csv` records the eight still capture times. The Terminal
ran a generated sequence of `frame-N` lines while screenshots and a four-second
video were captured. `window-drag/timing.csv` records eight AppleScript window
bounds positions captured as stills while the video ran. These bounds changes
produce visible window movement; they do not represent measured pointer events.
The six idle stills were taken about one second apart.

| Scratch relative path | Scenario | Bytes | SHA-256 |
|---|---|---:|---|
| `idle-000.png` | Idle still 0 | 6,397,121 | `ed27815466a595c75a7a76c87ac8f944608a56a0966ade80236d542372a77529` |
| `idle-001.png` | Idle still 1 | 6,397,483 | `d7017354bb238e01e13ec1a4d8d4870dac0b2532abc4eaf4e16fe8eaf3940f00` |
| `idle-002.png` | Idle still 2 | 6,398,336 | `c060ca3278c465ade3a9b53ab362df204d2d186743dcb532f6667f18a0836804` |
| `idle-003.png` | Idle still 3 | 6,397,483 | `88af91e9410899677d1e4f13d146ad1295cd56e791bf67bda1f31948e9d8ac68` |
| `idle-004.png` | Idle still 4 | 6,398,727 | `0a0738be58804065c8a65bcad57fed134381b1d15c82d3e3b0de6ce26969d7e3` |
| `idle-005.png` | Idle still 5 | 6,397,483 | `d7017354bb238e01e13ec1a4d8d4870dac0b2532abc4eaf4e16fe8eaf3940f00` |
| `idle-headless.mov` | Idle video | 631,975 | `a055fd4a578c68aad4b5ac20a6221442d84ef747885f210e1f3ae33caf709d84` |
| `terminal-scroll/terminal-scroll-000.png` | Terminal scroll still 0 | 6,512,589 | `9785481655904c2f65f3ab4841d3e0d1d4f1e978966bef1b4b8e0e611abb0d97` |
| `terminal-scroll/terminal-scroll-001.png` | Terminal scroll still 1 | 6,511,657 | `7df6b89885634e06130b1c08549cb8850c31ce8498ac65e34f2be16e63ed9765` |
| `terminal-scroll/terminal-scroll-002.png` | Terminal scroll still 2 | 6,513,341 | `ffd61e59219c9c8cb7f11dbb3cb6cb1f471e9b6469b7deead3e6fb9975a075ba` |
| `terminal-scroll/terminal-scroll-003.png` | Terminal scroll still 3 | 6,514,123 | `75010c313afbb7ba174f785fc78287e218395a7f05d537808c8b4e571f759c9e` |
| `terminal-scroll/terminal-scroll-004.png` | Terminal scroll still 4 | 6,509,197 | `621cf25a5708e96e2d28f1e2fa0e33f2c1a6e091e16c5741ac7bd1da042a7ca4` |
| `terminal-scroll/terminal-scroll-005.png` | Terminal scroll still 5 | 6,513,172 | `a38bcdc6765fc4d6015e93f2ac548a5ec5f05a46b4f414d1b52015cb12ba5bb8` |
| `terminal-scroll/terminal-scroll-006.png` | Terminal scroll still 6 | 6,511,352 | `01a3ce283486db7540117bb8adf486bae34aea259443fa3d34f9200cf7741a53` |
| `terminal-scroll/terminal-scroll-007.png` | Terminal scroll still 7 | 6,512,854 | `2db0732973a4ab00e450da7d0f6df8b54882359cc6c1ae0153f72ef6a04d3e01` |
| `terminal-scroll/timing.csv` | Terminal still timestamps | 376 | `46613f9e713deb8fe374aaeea48cd00cb8672fbe8c27ba3b56648949f4fd7655` |
| `terminal-scroll.mov` | Terminal scroll video | 2,197,649 | `3d3380926320092eb3a1cef88f1bc08853094330737c0aabf3ed6215b8ce1785` |
| `window-drag/timing.csv` | Window bounds timestamps | 409 | `4a048ae7a3358f26005d30dbf2b44cf83b455ad2cca848de5de0b595031237a3` |
| `window-drag/window-drag-000.png` | Window movement still 0 | 6,517,742 | `9ed5dd335da0ddf1cd5597495483f5ffac7162652d157fb1556243eb92b0988b` |
| `window-drag/window-drag-001.png` | Window movement still 1 | 6,605,110 | `1ec067c896fb9cf589a8ed24618fa9ca606cff771d2e42c429db9733c27e382e` |
| `window-drag/window-drag-002.png` | Window movement still 2 | 6,676,938 | `f8f0cbc0ea5435588ceb55c7068709ee3b2a5a6f9c5c20b907f9f3241b26107b` |
| `window-drag/window-drag-003.png` | Window movement still 3 | 6,702,596 | `a70b9a6b25c394cb4d73c3a32762fc16c0df6a12ebac10c6edc4e14c94551a24` |
| `window-drag/window-drag-004.png` | Window movement still 4 | 6,698,205 | `7dd0bf131f33d5b9b91b19066d9922e96a184aa17808724a2aaa1dd338dc9c43` |
| `window-drag/window-drag-005.png` | Window movement still 5 | 6,709,982 | `0f05e56e2aaabfbe55f590e75ddf231b588ad19c2e524f2de36e2260c9dfa099` |
| `window-drag/window-drag-006.png` | Window movement still 6 | 6,461,251 | `4acd134b33bcc6dcf90d77d307902464ea448b7ecbccf1c3323cfe413ace2e89` |
| `window-drag/window-drag-007.png` | Window movement still 7 | 5,814,505 | `8f9d78fac2d1d2fa58880548adca385d508f2557d107cebb39c84e545020ac42` |
| `window-drag.mov` | Window movement video | 1,237,581 | `e90377e2ba962a13f8d813cd7e45bcd3199853f02b7d94c354430f2b44775576` |

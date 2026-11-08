<!-- Role: the D80 and D365 contrast audits of the colour schemes added by D329 (#323): the rules and recorded palette repairs. -->
# Colour scheme audit (D80, D365)

D80 established the original contrast gate. D365 amends it so every text colour reaches 4.5:1, while primary `fg` keeps 7:1. The current
rules and repair are code (`packages/ui/src/theme-audit.ts`), and `theme-audit.test.ts` runs them across every scheme. The published palettes
and generator are `scripts/theme-palettes.ts` (`bun scripts/theme-palettes.ts` prints the compact scheme declarations and repair log).

| Colour | Needs, on the scheme's background |
|---|---|
| fg (primary text) | 7:1 |
| fg2 (secondary text) | 4.5:1 |
| fg2, fg3, accent, ok, danger (ANSI red), warn (ANSI yellow) | 4.5:1 |
| Every ANSI foreground slot, black and white included, normal and bright | 4.5:1 |
| Every interface text role on the floating-card surface | 4.5:1; primary `fg` remains 7:1 |
| fg over every background a theme can paint (each gradient and solid colour of the scheme) | 4.5:1 |

ANSI black and white are separate slots from the six hues, but they are also foreground text choices and meet the same line when used as text.
Touch targets (44 x 44 pt, the other half of D80) are unchanged by a colour scheme.

Light and dark versions of a scheme are one row of the Colour list with two circles. Catppuccin Frappe and Macchiato are dark only, so each has
a row of its own beside Catppuccin (Latte and Mocha).

## Original D80 repair log

This historical table records the original D80 repair of the D329 palettes. D365 applies the stricter rules above to the complete scheme set;
its current values are in `packages/ui/src/themes.ts`, and the gate checks every role and surface.

| Scheme | Colour | Published (ratio on bg) | Repaired (ratio on bg) |
|---|---|---|---|
| Solarized Light | ansi red | #dc322f (4.29:1) | #d72d2b (4.53:1) |
| Solarized Light | ansi green | #859900 (2.97:1) | #667800 (4.58:1) |
| Solarized Light | ansi yellow | #b58900 (2.98:1) | #946900 (4.55:1) |
| Solarized Light | ansi blue | #268bd2 (3.41:1) | #0075bb (4.57:1) |
| Solarized Light | ansi magenta | #d33682 (4.21:1) | #cd2f7d (4.53:1) |
| Solarized Light | ansi cyan | #2aa198 (2.93:1) | #007f77 (4.53:1) |
| Solarized Light | bright green | #748600 (3.78:1) | #677800 (4.57:1) |
| Solarized Light | bright yellow | #a27700 (3.76:1) | #936900 (4.57:1) |
| Solarized Light | bright blue | #0078be (4.39:1) | #0075bb (4.57:1) |
| Solarized Light | bright cyan | #008e86 (3.73:1) | #007f77 (4.53:1) |
| Solarized Light | fg | #586e75 (4.99:1) | #42575e (7.06:1) |
| Solarized Light | fg2 | #657b83 (4.13:1) | #5f747c (4.55:1) |
| Solarized Light | fg3 | #93a1a1 (2.48:1) | #839191 (3.03:1) |
| Solarized Light | fg (over the background #ffabe3) | #42575e (4.42:1) | #40555c (4.56:1) |
| Solarized Light | fg (over the background #ffae9e) | #40555c (4.42:1) | #3e535a (4.56:1) |
| Solarized Dark | ansi red | #dc322f (3.25:1) | #fa5149 (4.53:1) |
| Solarized Dark | ansi blue | #268bd2 (4.08:1) | #3194db (4.57:1) |
| Solarized Dark | ansi magenta | #d33682 (3.30:1) | #ef5299 (4.53:1) |
| Solarized Dark | bright red | #f24942 (4.15:1) | #fa5149 (4.53:1) |
| Solarized Dark | bright magenta | #e84c94 (4.21:1) | #ef539a (4.56:1) |
| Solarized Dark | fg | #93a1a1 (5.61:1) | #a6b5b4 (7.07:1) |
| Solarized Dark | fg3 | #586e75 (2.79:1) | #5e747b (3.05:1) |
| Solarized Dark | fg (over the background #004a81) | #a6b5b4 (4.31:1) | #abbab9 (4.55:1) |
| Solarized Dark | fg (over the background #00554f) | #abbab9 (4.33:1) | #afbebd (4.53:1) |
| Solarized Dark | fg (on cards) | #afbebd (6.94:1 on the card) | #b1c0bf (7.09:1 on the card) |
| Solarized Dark | fg2 (on cards) | #839496 (4.22:1 on the card) | #899a9c (4.55:1 on the card) |
| Everforest Light | ansi red | #f85552 (3.04:1) | #d43034 (4.56:1) |
| Everforest Light | ansi green | #8da101 (2.69:1) | #677800 (4.57:1) |
| Everforest Light | ansi yellow | #dfa000 (2.12:1) | #9f6300 (4.57:1) |
| Everforest Light | ansi blue | #3a94c5 (3.13:1) | #1378a7 (4.56:1) |
| Everforest Light | ansi magenta | #df69ba (2.83:1) | #b74495 (4.55:1) |
| Everforest Light | ansi cyan | #35a77c (2.79:1) | #008159 (4.54:1) |
| Everforest Light | bright red | #e24040 (3.86:1) | #d43235 (4.52:1) |
| Everforest Light | bright green | #7b8e00 (3.41:1) | #667800 (4.58:1) |
| Everforest Light | bright yellow | #cb8d00 (2.65:1) | #9f6400 (4.53:1) |
| Everforest Light | bright blue | #2382b2 (3.97:1) | #1378a8 (4.55:1) |
| Everforest Light | bright magenta | #ca56a7 (3.60:1) | #b74596 (4.52:1) |
| Everforest Light | bright cyan | #18946a (3.55:1) | #008158 (4.55:1) |
| Everforest Light | fg | #5c6a72 (5.18:1) | #48565d (7.04:1) |
| Everforest Light | fg2 | #829181 (3.08:1) | #667565 (4.53:1) |
| Everforest Light | fg3 | #a6b0a0 (2.08:1) | #889182 (3.03:1) |
| Everforest Light | accent | #8da101 (2.69:1) | #839700 (3.05:1) |
| Everforest Light | fg (over the background #ffafa5) | #48565d (4.31:1) | #45535a (4.52:1) |
| Everforest Dark | fg (over the background #4c5e2c) | #d3c6aa (4.22:1) | #dacdb1 (4.53:1) |
| Everforest Dark | fg (over the background #326340) | #dacdb1 (4.46:1) | #dccfb3 (4.55:1) |
| Kanagawa Lotus | ansi red | #c84053 (4.06:1) | #bf374c (4.53:1) |
| Kanagawa Lotus | ansi green | #6f894e (3.26:1) | #587137 (4.57:1) |
| Kanagawa Lotus | ansi yellow | #77713f (4.15:1) | #716b39 (4.53:1) |
| Kanagawa Lotus | ansi magenta | #b35b79 (3.73:1) | #a34d6b (4.57:1) |
| Kanagawa Lotus | ansi cyan | #597b75 (3.88:1) | #4e706a (4.55:1) |
| Kanagawa Lotus | bright green | #5e773d (4.18:1) | #587137 (4.57:1) |
| Kanagawa Lotus | fg | #545464 (6.19:1) | #4b4b5b (7.12:1) |
| Kanagawa Lotus | fg3 | #8a8980 (2.93:1) | #87867d (3.05:1) |
| Kanagawa Wave | bright red | #e82424 (3.66:1) | #fb3d36 (4.53:1) |
| Ayu Light | ansi red | #e65050 (3.57:1) | #d13c3f (4.54:1) |
| Ayu Light | ansi green | #86b300 (2.38:1) | #567f00 (4.54:1) |
| Ayu Light | ansi yellow | #f2ae49 (1.84:1) | #a46400 (4.57:1) |
| Ayu Light | ansi blue | #399ee6 (2.79:1) | #0078bd (4.55:1) |
| Ayu Light | ansi magenta | #a37acc (3.24:1) | #8a61b1 (4.55:1) |
| Ayu Light | ansi cyan | #4cbf99 (2.18:1) | #008361 (4.55:1) |
| Ayu Light | bright green | #74a000 (2.97:1) | #567f00 (4.54:1) |
| Ayu Light | bright yellow | #de9b32 (2.28:1) | #a46500 (4.53:1) |
| Ayu Light | bright blue | #208bd2 (3.54:1) | #0078be (4.54:1) |
| Ayu Light | bright magenta | #9168b8 (4.13:1) | #8a61b1 (4.55:1) |
| Ayu Light | bright cyan | #35ac87 (2.72:1) | #008360 (4.56:1) |
| Ayu Light | fg | #5c6166 (5.99:1) | #51565b (7.10:1) |
| Ayu Light | fg2 | #787b80 (4.07:1) | #707378 (4.56:1) |
| Ayu Light | accent | #f2ae49 (1.84:1) | #c48303 (3.05:1) |
| Ayu Light | fg (over the background #ffb7af) | #51565b (4.46:1) | #50555a (4.54:1) |
| Ayu Dark | fg3 | #565b66 (2.84:1) | #5b606b (3.06:1) |
| Flexoki Light | ansi green | #66800b (4.39:1) | #637d03 (4.58:1) |
| Flexoki Light | ansi yellow | #ad8301 (3.39:1) | #966d00 (4.56:1) |
| Flexoki Light | ansi cyan | #24837b (4.43:1) | #22817a (4.55:1) |
| Flexoki Light | bright yellow | #9a7100 (4.31:1) | #966d00 (4.56:1) |
| Flexoki Light | fg3 | #b7b5ac (2.00:1) | #94928a (3.03:1) |
| Flexoki Dark | ansi red | #d14d41 (4.42:1) | #d34f42 (4.53:1) |
| Flexoki Dark | fg3 | #575653 (2.61:1) | #61605d (3.04:1) |
| Gruvbox Light | ansi green | #79740e (4.29:1) | #757005 (4.54:1) |
| Gruvbox Light | ansi yellow | #b57614 (3.33:1) | #9c5f00 (4.57:1) |
| Gruvbox Light | ansi cyan | #427b58 (4.40:1) | #407956 (4.53:1) |
| Gruvbox Light | bright green | #98971a (2.73:1) | #737100 (4.52:1) |
| Gruvbox Light | bright yellow | #d79921 (2.19:1) | #9b6000 (4.55:1) |
| Gruvbox Light | bright blue | #458588 (3.73:1) | #36777a (4.54:1) |
| Gruvbox Light | bright magenta | #b16286 (3.73:1) | #a25478 (4.54:1) |
| Gruvbox Light | bright cyan | #689d6a (2.80:1) | #467948 (4.53:1) |
| Tokyo Night Day | ansi red | #f52a65 (3.01:1) | #c90043 (4.55:1) |
| Tokyo Night Day | ansi green | #587539 (4.04:1) | #506d31 (4.54:1) |
| Tokyo Night Day | ansi yellow | #8c6c3e (3.75:1) | #7e5f31 (4.55:1) |
| Tokyo Night Day | ansi blue | #2e7de9 (3.11:1) | #0961cb (4.53:1) |
| Tokyo Night Day | ansi magenta | #9854f1 (3.33:1) | #833bd8 (4.53:1) |
| Tokyo Night Day | ansi cyan | #007197 (4.26:1) | #006c92 (4.56:1) |
| Tokyo Night Day | bright red | #df0054 (3.81:1) | #c90043 (4.55:1) |
| Tokyo Night Day | bright blue | #176ad4 (4.01:1) | #0861cb (4.53:1) |
| Tokyo Night Day | bright magenta | #863fdc (4.32:1) | #823ad8 (4.58:1) |
| Tokyo Night Day | fg | #3760bf (4.52:1) | #1c419d (7.08:1) |
| Tokyo Night Day | fg2 | #6172b0 (3.57:1) | #51619e (4.57:1) |
| Tokyo Night Day | fg3 | #848cb5 (2.54:1) | #777ea7 (3.05:1) |
| Tokyo Night Day | fg (over the background #ff95a6) | #1c419d (4.41:1) | #1b3f9b (4.53:1) |
| Catppuccin Frappé | fg3 | #737994 (2.87:1) | #777d98 (3.03:1) |
| Light Owl | ansi red | #de3d3b (4.20:1) | #d73535 (4.56:1) |
| Light Owl | ansi green | #08916a (3.85:1) | #00845e (4.55:1) |
| Light Owl | ansi yellow | #daaa01 (2.09:1) | #996b00 (4.55:1) |
| Light Owl | ansi blue | #4876d6 (4.19:1) | #4270cf (4.56:1) |
| Light Owl | ansi cyan | #0c969b (3.47:1) | #008186 (4.53:1) |
| Light Owl | bright yellow | #c69700 (2.59:1) | #996b00 (4.55:1) |
| Light Owl | bright cyan | #008489 (4.35:1) | #008186 (4.53:1) |
| Light Owl | fg3 | #989fb1 (2.56:1) | #8a91a3 (3.05:1) |

## D365 repairs

D365 strengthens the text line from 3:1 to 4.5:1 for secondary text, accent, status text and every ANSI foreground slot. Interface roles
are checked on both the scheme background and the floating-card surface. ANSI black and white stay distinct from the six hues, but are no
longer exempt when used as foreground text. The palette changes move only OKLab lightness: light themes move toward darker text and dark
themes toward lighter text, keeping each scheme's hue and chroma.

Ink and Paper show the main difference clearly. Other unchanged roles are retained as authored.

| Scheme | Text role | Before | After |
|---|---|---|---|
| Paper | fg3 | `#8d8d92` | `#707075` |
| Paper | ok | `#1f9d55` | `#00823c` |
| Paper | ANSI white text | `#8d8d93` | `#707076` |
| Ink | fg3 | `#5f5f65` | `#818187` |
| Ink | ANSI black text | `#1b1c1f` | `#797b7e` |
| Ink | bright ANSI black text | `#5c5c62` | `#7a7a80` |

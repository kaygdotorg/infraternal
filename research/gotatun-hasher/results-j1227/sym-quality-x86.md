## 1. probe length, 256 flows in 512 slots, 2000 seeds (mean of means / p99 of max probe)

| candidate | seq ports, v4 | one dst port, ports +1 | v6 | many source hosts |
|---|---|---|---|---|
| canonical + sip13 random key (reference, PRF) | 0.494 / 21 | 0.490 / 22 | 0.497 / 21 | 0.491 / 21 |
| canonical + foldhash fast (J1204 recommendation) | 0.494 / 22 | 0.492 / 20 | 0.472 / 22 | 0.493 / 20 |
| symmetric sum, no final mix (start_symmetric) | 0.497 / 23 | 0.584 / 42 | 0.493 / 21 | 0.489 / 21 |
| symmetric sum + final foldhash mix (start_symmetric_mixed) | 0.493 / 20 | 0.496 / 22 | 0.493 / 21 | 0.494 / 20 |
| manual keyed fold (start_manual) | 0.494 / 20 | 0.496 / 21 | 0.490 / 20 | 0.496 / 20 |

## 2. uniformity: chi-square of 512 buckets over 102,400 flows, 2000 seeds (expect mean ~511, p99 ~590)

| candidate | mean chi2 | p99 chi2 | max chi2 |
|---|---:|---:|---:|
| canonical + sip13 random key (reference, PRF) | 508.0 | 565.9 | 577.8 |
| canonical + foldhash fast (J1204 recommendation) | 510.6 | 595.0 | 597.3 |
| symmetric sum, no final mix (start_symmetric) | 511.9 | 598.0 | 613.2 |
| symmetric sum + final foldhash mix (start_symmetric_mixed) | 512.2 | 575.1 | 590.9 |
| manual keyed fold (start_manual) | 510.1 | 577.1 | 599.7 |

## 3. offline precomputation: 256 flows crafted to slot 0 under seed 0, placed under 2000 other seeds

| candidate | candidates tried | probe under seed 0 (mean / max) | under other seeds: mean of means | p99 of max |
|---|---:|---|---:|---:|
| canonical + sip13 random key (reference, PRF) | 129816 | 127.5 / 255 | 0.491 | 20 |
| canonical + foldhash fast (J1204 recommendation) | 123378 | 127.5 / 255 | 0.493 | 20 |
| symmetric sum, no final mix (start_symmetric) | 132355 | 127.5 / 255 | 0.590 | 23 |
| symmetric sum + final foldhash mix (start_symmetric_mixed) | 116225 | 127.5 / 255 | 0.493 | 21 |
| manual keyed fold (start_manual) | 125411 | 127.5 / 255 | 0.494 | 22 |

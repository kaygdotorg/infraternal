# Hasher micro-bench: perf VM (Ryzen 7 3700X) vs mba (Apple M1), ns per op (median of runs)

## peer_addresses

| peers | hasher | perf VM x86 | mba M1 |
|---|---|---:|---:|
| 1 | sip13_random | 15.58 | 10.41 |
| 1 | foldhash_fast | 2.93 | 2.19 |
| 1 | ahash | 4.13 | 3.26 |
| 1 | fxhash | 2.54 | 1.92 |
| 100 | sip13_random | 15.53 | 11.66 |
| 100 | foldhash_fast | 3.13 | 2.19 |
| 100 | ahash | 4.25 | 3.58 |
| 100 | fxhash | 2.55 | 2.24 |
| 1000 | sip13_random | 15.96 | 10.68 |
| 1000 | foldhash_fast | 3.21 | 2.19 |
| 1000 | ahash | 4.47 | 3.32 |
| 1000 | fxhash | 2.68 | 1.92 |

## peers_by_idx

| peers | hasher | perf VM x86 | mba M1 |
|---|---|---:|---:|
| 1 | sip13_random | 14.71 | 8.88 |
| 1 | foldhash_fast | 8.62 | 7.09 |
| 1 | ahash | 8.56 | 7.10 |
| 1 | fxhash | 8.77 | 7.11 |
| 100 | sip13_random | 14.76 | 9.99 |
| 100 | foldhash_fast | 8.65 | 3.73 |
| 100 | ahash | 8.62 | 3.74 |
| 100 | fxhash | 8.81 | 3.73 |
| 1000 | sip13_random | 16.40 | 9.23 |
| 1000 | foldhash_fast | 8.82 | 3.68 |
| 1000 | ahash | 8.75 | 3.69 |
| 1000 | fxhash | 8.83 | 3.68 |

## peer_ids

| peers | hasher | perf VM x86 | mba M1 |
|---|---|---:|---:|
| 1 | sip13_random | 7.70 | 6.22 |
| 1 | foldhash_fast | 1.89 | 1.43 |
| 1 | ahash | 2.42 | 1.91 |
| 1 | fxhash | 1.68 | 1.30 |
| 100 | sip13_random | 7.88 | 6.79 |
| 100 | foldhash_fast | 1.89 | 1.77 |
| 100 | ahash | 2.60 | 2.36 |
| 100 | fxhash | 2.01 | 1.81 |
| 1000 | sip13_random | 7.71 | 6.29 |
| 1000 | foldhash_fast | 1.96 | 1.55 |
| 1000 | ahash | 2.44 | 1.97 |
| 1000 | fxhash | 1.69 | 1.31 |

## flow_start (canonical + hash + % 512)

| family | hasher | perf VM x86 | mba M1 |
|---|---|---:|---:|
| v4 | sip13_fixed | 25.86 | 15.21 |
| v4 | foldhash_fast | 18.56 | 6.94 |
| v4 | ahash | 21.13 | 8.40 |
| v4 | fxhash | 17.84 | 5.94 |
| v6 | sip13_fixed | 34.51 | 29.19 |
| v6 | foldhash_fast | 26.34 | 7.73 |
| v6 | ahash | 30.56 | 8.43 |
| v6 | fxhash | 26.90 | 7.03 |

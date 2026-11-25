
### flow_start/v4

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_fixed(current) | 23.66 | 1.00x | 1.8% |
| sip13_random | 22.37 | 0.95x | 1.7% |
| sip13_random+symmetric(no canonical) | 35.30 | 1.49x | 1.1% |
| foldhash_fast | 19.50 | 0.82x | 1.8% |
| foldhash_fast+symmetric(no canonical) | 4.78 | 0.20x | 0.8% |
| foldhash_quality | 20.60 | 0.87x | 1.4% |
| foldhash_quality+symmetric(no canonical) | 5.67 | 0.24x | 1.2% |
| ahash | 24.30 | 1.03x | 0.6% |
| ahash+symmetric(no canonical) | 5.21 | 0.22x | 1.1% |
| fxhash | 18.94 | 0.80x | 0.7% |
| fxhash+symmetric(no canonical) | 2.44 | 0.10x | 0.5% |
| foldhash_fast+symmetric_mixed | 5.16 | 0.22x | 0.5% |
| manual_fold(no hasher) | 3.07 | 0.13x | 0.3% |
| canonical_only(floor) | 11.21 | 0.47x | 0.9% |

### flow_start/v6

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_fixed(current) | 35.02 | 1.00x | 0.5% |
| sip13_random | 33.55 | 0.96x | 0.4% |
| sip13_random+symmetric(no canonical) | 43.62 | 1.25x | 1.3% |
| foldhash_fast | 27.17 | 0.78x | 0.7% |
| foldhash_fast+symmetric(no canonical) | 9.45 | 0.27x | 0.3% |
| foldhash_quality | 28.59 | 0.82x | 0.5% |
| foldhash_quality+symmetric(no canonical) | 10.73 | 0.31x | 0.1% |
| ahash | 28.72 | 0.82x | 0.2% |
| ahash+symmetric(no canonical) | 11.05 | 0.32x | 0.2% |
| fxhash | 27.58 | 0.79x | 0.4% |
| fxhash+symmetric(no canonical) | 8.98 | 0.26x | 0.6% |
| foldhash_fast+symmetric_mixed | 10.51 | 0.30x | 0.1% |
| manual_fold(no hasher) | 9.07 | 0.26x | 0.1% |
| canonical_only(floor) | 16.82 | 0.48x | 0.0% |

### allowed_ips/1_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| ip_network_table_trie(current) | 73.89 | 1.00x | 0.3% |
| host_route_hash+sip13_random | 15.60 | 0.21x | 0.1% |
| host_route_hash+foldhash_fast | 2.93 | 0.04x | 0.0% |
| host_route_hash+foldhash_quality | 3.46 | 0.05x | 0.2% |
| host_route_hash+ahash | 4.13 | 0.06x | 0.1% |
| host_route_hash+fxhash | 2.54 | 0.03x | 0.0% |
| direct_index(host routes) | 1.13 | 0.02x | 0.1% |
| trie_only/hit | 74.11 | 1.00x | 0.0% |
| hybrid_foldhash/hit | 6.69 | 0.09x | 0.1% |
| trie_only/subnet_miss_then_trie | 57.33 | 0.78x | 0.0% |
| hybrid_foldhash/subnet_miss_then_trie | 58.57 | 0.79x | 0.9% |
| trie_only/90_10 | 72.90 | 0.99x | 0.0% |
| hybrid_foldhash/90_10 | 11.33 | 0.15x | 0.1% |

### allowed_ips/100_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| ip_network_table_trie(current) | 73.72 | 1.00x | 0.0% |
| host_route_hash+sip13_random | 15.62 | 0.21x | 1.0% |
| host_route_hash+foldhash_fast | 2.99 | 0.04x | 3.2% |
| host_route_hash+foldhash_quality | 3.55 | 0.05x | 4.3% |
| host_route_hash+ahash | 4.32 | 0.06x | 0.1% |
| host_route_hash+fxhash | 2.55 | 0.03x | 0.1% |
| direct_index(host routes) | 1.13 | 0.02x | 0.0% |
| trie_only/hit | 73.94 | 1.00x | 0.2% |
| hybrid_foldhash/hit | 6.68 | 0.09x | 0.0% |
| trie_only/subnet_miss_then_trie | 57.28 | 0.78x | 0.2% |
| hybrid_foldhash/subnet_miss_then_trie | 60.14 | 0.82x | 0.9% |
| trie_only/90_10 | 72.62 | 0.99x | 0.0% |
| hybrid_foldhash/90_10 | 11.42 | 0.15x | 0.4% |

### allowed_ips/1000_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| ip_network_table_trie(current) | 73.65 | 1.00x | 0.1% |
| host_route_hash+sip13_random | 16.12 | 0.22x | 0.8% |
| host_route_hash+foldhash_fast | 3.17 | 0.04x | 0.2% |
| host_route_hash+foldhash_quality | 3.74 | 0.05x | 0.5% |
| host_route_hash+ahash | 4.48 | 0.06x | 1.9% |
| host_route_hash+fxhash | 2.66 | 0.04x | 0.1% |
| direct_index(host routes) | 1.14 | 0.02x | 0.1% |
| trie_only/hit | 73.92 | 1.00x | 0.4% |
| hybrid_foldhash/hit | 6.69 | 0.09x | 0.2% |
| trie_only/subnet_miss_then_trie | 57.19 | 0.78x | 0.1% |
| hybrid_foldhash/subnet_miss_then_trie | 58.87 | 0.80x | 0.4% |
| trie_only/90_10 | 72.62 | 0.99x | 0.3% |
| hybrid_foldhash/90_10 | 11.44 | 0.16x | 0.8% |


### flow_start/v4

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_fixed(current) | 25.86 | 1.00x | 3.6% |
| sip13_random | 24.94 | 0.96x | 4.3% |
| sip13_random+symmetric(no canonical) | 36.86 | 1.43x | 2.6% |
| foldhash_fast | 18.56 | 0.72x | 10.4% |
| foldhash_fast+symmetric(no canonical) | 4.76 | 0.18x | 1.5% |
| foldhash_quality | 19.37 | 0.75x | 8.3% |
| foldhash_quality+symmetric(no canonical) | 5.64 | 0.22x | 1.6% |
| ahash | 21.13 | 0.82x | 32.7% |
| ahash+symmetric(no canonical) | 5.19 | 0.20x | 1.2% |
| fxhash | 17.84 | 0.69x | 11.3% |
| fxhash+symmetric(no canonical) | 2.43 | 0.09x | 0.7% |
| manual_fold(no hasher) | 3.07 | 0.12x | 0.7% |
| canonical_only(floor) | 12.85 | 0.50x | 9.6% |

### flow_start/v6

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_fixed(current) | 34.51 | 1.00x | 0.2% |
| sip13_random | 33.87 | 0.98x | 5.9% |
| sip13_random+symmetric(no canonical) | 45.04 | 1.31x | 2.1% |
| foldhash_fast | 26.34 | 0.76x | 1.8% |
| foldhash_fast+symmetric(no canonical) | 9.37 | 0.27x | 3.8% |
| foldhash_quality | 27.93 | 0.81x | 0.6% |
| foldhash_quality+symmetric(no canonical) | 10.67 | 0.31x | 2.0% |
| ahash | 30.56 | 0.89x | 3.5% |
| ahash+symmetric(no canonical) | 11.08 | 0.32x | 4.3% |
| fxhash | 26.90 | 0.78x | 6.1% |
| fxhash+symmetric(no canonical) | 8.95 | 0.26x | 1.8% |
| manual_fold(no hasher) | 8.82 | 0.26x | 6.9% |
| canonical_only(floor) | 16.56 | 0.48x | 13.1% |

### peer_addresses/1_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 15.58 | 1.00x | 1.4% |
| foldhash_fast | 2.93 | 0.19x | 3.8% |
| foldhash_quality | 3.48 | 0.22x | 4.4% |
| ahash | 4.13 | 0.27x | 0.3% |
| fxhash | 2.54 | 0.16x | 0.3% |
| direct_index(no hash) | 1.19 | 0.08x | 0.3% |

### peer_addresses/100_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 15.53 | 1.00x | 2.5% |
| foldhash_fast | 3.13 | 0.20x | 457.8% |
| foldhash_quality | 3.76 | 0.24x | 11.7% |
| ahash | 4.25 | 0.27x | 6.4% |
| fxhash | 2.55 | 0.16x | 0.3% |
| direct_index(no hash) | 1.19 | 0.08x | 0.4% |

### peer_addresses/1000_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 15.96 | 1.00x | 1.8% |
| foldhash_fast | 3.21 | 0.20x | 3.6% |
| foldhash_quality | 3.73 | 0.23x | 2.8% |
| ahash | 4.47 | 0.28x | 0.8% |
| fxhash | 2.68 | 0.17x | 0.2% |
| direct_index(no hash) | 1.19 | 0.07x | 0.2% |

### peers_by_idx/1_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 14.71 | 1.00x | 0.8% |
| foldhash_fast | 8.62 | 0.59x | 0.2% |
| foldhash_quality | 8.50 | 0.58x | 1.9% |
| ahash | 8.56 | 0.58x | 0.4% |
| fxhash | 8.77 | 0.60x | 0.8% |
| identity(unsafe ceiling) | 8.55 | 0.58x | 0.9% |

### peers_by_idx/100_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 14.76 | 1.00x | 1.6% |
| foldhash_fast | 8.65 | 0.59x | 0.7% |
| foldhash_quality | 8.63 | 0.58x | 1.7% |
| ahash | 8.62 | 0.58x | 0.1% |
| fxhash | 8.81 | 0.60x | 0.4% |
| identity(unsafe ceiling) | 9.30 | 0.63x | 4.4% |

### peers_by_idx/1000_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 16.40 | 1.00x | 0.7% |
| foldhash_fast | 8.82 | 0.54x | 0.2% |
| foldhash_quality | 8.72 | 0.53x | 0.5% |
| ahash | 8.75 | 0.53x | 0.3% |
| fxhash | 8.83 | 0.54x | 9.9% |
| identity(unsafe ceiling) | 8.75 | 0.53x | 2.4% |

### incoming_runs/1_peers_per_batch

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 23.05 | 1.00x | 0.5% |
| foldhash_fast | 13.23 | 0.57x | 2.0% |
| foldhash_quality | 13.82 | 0.60x | 1.2% |
| ahash | 15.89 | 0.69x | 2.1% |
| fxhash | 10.55 | 0.46x | 2.3% |

### incoming_runs/8_peers_per_batch

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 34.74 | 1.00x | 3.0% |
| foldhash_fast | 25.24 | 0.73x | 19.3% |
| foldhash_quality | 24.14 | 0.69x | 5.6% |
| ahash | 25.59 | 0.74x | 11.0% |
| fxhash | 21.98 | 0.63x | 2.8% |

### bulk_recency/1_destinations

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 18.86 | 1.00x | 0.7% |
| foldhash_fast | 3.80 | 0.20x | 1.0% |
| foldhash_quality | 4.22 | 0.22x | 1.1% |
| ahash | 5.05 | 0.27x | 2.3% |
| fxhash | 3.28 | 0.17x | 0.4% |

### bulk_recency/64_destinations

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 18.82 | 1.00x | 1.4% |
| foldhash_fast | 3.78 | 0.20x | 0.9% |
| foldhash_quality | 4.71 | 0.25x | 19.3% |
| ahash | 5.08 | 0.27x | 3.8% |
| fxhash | 3.28 | 0.17x | 0.1% |

### allowed_ips/1_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| ip_network_table_trie(current) | 68.35 | 1.00x | 0.2% |
| host_route_hash/sip13_random | 15.42 | 0.23x | 0.6% |
| host_route_hash/foldhash_fast | 2.93 | 0.04x | 1.4% |
| host_route_hash/foldhash_quality | 3.44 | 0.05x | 0.3% |
| host_route_hash/ahash | 4.10 | 0.06x | 0.3% |
| host_route_hash/fxhash | 2.54 | 0.04x | 0.3% |
| direct_index(host routes) | 1.19 | 0.02x | 0.1% |

### allowed_ips/100_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| ip_network_table_trie(current) | 68.39 | 1.00x | 0.4% |
| host_route_hash/sip13_random | 15.96 | 0.23x | 8.7% |
| host_route_hash/foldhash_fast | 2.94 | 0.04x | 7.5% |
| host_route_hash/foldhash_quality | 3.78 | 0.06x | 10.7% |
| host_route_hash/ahash | 4.21 | 0.06x | 8.3% |
| host_route_hash/fxhash | 2.55 | 0.04x | 0.4% |
| direct_index(host routes) | 1.19 | 0.02x | 0.9% |

### allowed_ips/1000_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| ip_network_table_trie(current) | 68.38 | 1.00x | 0.5% |
| host_route_hash/sip13_random | 15.90 | 0.23x | 0.4% |
| host_route_hash/foldhash_fast | 3.16 | 0.05x | 1.4% |
| host_route_hash/foldhash_quality | 3.69 | 0.05x | 1.7% |
| host_route_hash/ahash | 4.47 | 0.07x | 2.0% |
| host_route_hash/fxhash | 2.68 | 0.04x | 0.7% |
| direct_index(host routes) | 1.19 | 0.02x | 0.1% |

### peer_ids/1_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 7.70 | 1.00x | 0.4% |
| foldhash_fast | 1.89 | 0.25x | 0.2% |
| foldhash_quality | 2.30 | 0.30x | 0.2% |
| ahash | 2.42 | 0.31x | 0.2% |
| fxhash | 1.68 | 0.22x | 0.2% |

### peer_ids/100_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 7.88 | 1.00x | 1.8% |
| foldhash_fast | 1.89 | 0.24x | 0.3% |
| foldhash_quality | 2.49 | 0.32x | 14.0% |
| ahash | 2.60 | 0.33x | 13.7% |
| fxhash | 2.01 | 0.26x | 0.2% |

### peer_ids/1000_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 7.71 | 1.00x | 0.1% |
| foldhash_fast | 1.96 | 0.25x | 1.0% |
| foldhash_quality | 2.37 | 0.31x | 2.6% |
| ahash | 2.44 | 0.32x | 0.6% |
| fxhash | 1.69 | 0.22x | 0.0% |

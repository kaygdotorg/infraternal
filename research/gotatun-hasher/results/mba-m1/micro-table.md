
### flow_start/v4

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_fixed(current) | 15.21 | 1.00x | 1.8% |
| sip13_random | 14.23 | 0.94x | 1.9% |
| sip13_random+symmetric(no canonical) | 29.58 | 1.94x | 1.7% |
| foldhash_fast | 6.94 | 0.46x | 1.9% |
| foldhash_fast+symmetric(no canonical) | 2.37 | 0.16x | 1.3% |
| foldhash_quality | 7.28 | 0.48x | 1.5% |
| foldhash_quality+symmetric(no canonical) | 2.81 | 0.18x | 1.7% |
| ahash | 8.40 | 0.55x | 2.0% |
| ahash+symmetric(no canonical) | 4.50 | 0.30x | 1.8% |
| fxhash | 5.94 | 0.39x | 0.4% |
| fxhash+symmetric(no canonical) | 1.90 | 0.13x | 0.5% |
| manual_fold(no hasher) | 1.82 | 0.12x | 0.7% |
| canonical_only(floor) | 6.48 | 0.43x | 1.2% |

### flow_start/v6

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_fixed(current) | 29.19 | 1.00x | 1.9% |
| sip13_random | 27.74 | 0.95x | 1.9% |
| sip13_random+symmetric(no canonical) | 29.33 | 1.00x | 1.9% |
| foldhash_fast | 7.73 | 0.26x | 0.1% |
| foldhash_fast+symmetric(no canonical) | 2.94 | 0.10x | 0.2% |
| foldhash_quality | 8.09 | 0.28x | 0.4% |
| foldhash_quality+symmetric(no canonical) | 3.36 | 0.12x | 0.3% |
| ahash | 8.43 | 0.29x | 0.5% |
| ahash+symmetric(no canonical) | 4.50 | 0.15x | 1.8% |
| fxhash | 7.03 | 0.24x | 0.2% |
| fxhash+symmetric(no canonical) | 1.91 | 0.07x | 0.6% |
| manual_fold(no hasher) | 2.30 | 0.08x | 0.0% |
| canonical_only(floor) | 5.52 | 0.19x | 0.0% |

### peer_addresses/1_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 10.41 | 1.00x | 0.1% |
| foldhash_fast | 2.19 | 0.21x | 0.4% |
| foldhash_quality | 2.55 | 0.24x | 0.1% |
| ahash | 3.26 | 0.31x | 2.7% |
| fxhash | 1.92 | 0.18x | 0.1% |
| direct_index(no hash) | 0.73 | 0.07x | 0.5% |

### peer_addresses/100_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 11.66 | 1.00x | 5.1% |
| foldhash_fast | 2.19 | 0.19x | 9.7% |
| foldhash_quality | 3.03 | 0.26x | 10.4% |
| ahash | 3.58 | 0.31x | 10.1% |
| fxhash | 2.24 | 0.19x | 0.1% |
| direct_index(no hash) | 0.73 | 0.06x | 0.1% |

### peer_addresses/1000_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 10.68 | 1.00x | 2.8% |
| foldhash_fast | 2.19 | 0.20x | 6.6% |
| foldhash_quality | 2.71 | 0.25x | 3.7% |
| ahash | 3.32 | 0.31x | 3.2% |
| fxhash | 1.92 | 0.18x | 0.1% |
| direct_index(no hash) | 0.73 | 0.07x | 0.1% |

### peers_by_idx/1_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 8.88 | 1.00x | 0.2% |
| foldhash_fast | 7.09 | 0.80x | 0.4% |
| foldhash_quality | 7.09 | 0.80x | 1.1% |
| ahash | 7.10 | 0.80x | 0.8% |
| fxhash | 7.11 | 0.80x | 1.9% |
| identity(unsafe ceiling) | 7.22 | 0.81x | 1.8% |

### peers_by_idx/100_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 9.99 | 1.00x | 5.4% |
| foldhash_fast | 3.73 | 0.37x | 0.1% |
| foldhash_quality | 3.79 | 0.38x | 1.4% |
| ahash | 3.74 | 0.37x | 0.4% |
| fxhash | 3.73 | 0.37x | 0.1% |
| identity(unsafe ceiling) | 4.03 | 0.40x | 0.0% |

### peers_by_idx/1000_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 9.23 | 1.00x | 44.5% |
| foldhash_fast | 3.68 | 0.40x | 0.1% |
| foldhash_quality | 3.69 | 0.40x | 0.0% |
| ahash | 3.69 | 0.40x | 0.9% |
| fxhash | 3.68 | 0.40x | 0.4% |
| identity(unsafe ceiling) | 3.67 | 0.40x | 0.2% |

### peer_ids/1_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 6.22 | 1.00x | 1.5% |
| foldhash_fast | 1.43 | 0.23x | 0.6% |
| foldhash_quality | 1.73 | 0.28x | 0.4% |
| ahash | 1.91 | 0.31x | 0.1% |
| fxhash | 1.30 | 0.21x | 0.1% |

### peer_ids/100_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 6.79 | 1.00x | 2.0% |
| foldhash_fast | 1.77 | 0.26x | 6.9% |
| foldhash_quality | 2.18 | 0.32x | 16.7% |
| ahash | 2.36 | 0.35x | 16.8% |
| fxhash | 1.81 | 0.27x | 0.2% |

### peer_ids/1000_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 6.29 | 1.00x | 2.6% |
| foldhash_fast | 1.55 | 0.25x | 2.9% |
| foldhash_quality | 1.91 | 0.30x | 8.6% |
| ahash | 1.97 | 0.31x | 3.6% |
| fxhash | 1.31 | 0.21x | 0.0% |

### incoming_runs/1_peers_per_batch

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 23.97 | 1.00x | 0.9% |
| foldhash_fast | 5.81 | 0.24x | 0.6% |
| foldhash_quality | 6.12 | 0.26x | 0.6% |
| ahash | 6.16 | 0.26x | 0.6% |
| fxhash | 4.89 | 0.20x | 0.5% |

### incoming_runs/8_peers_per_batch

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 27.25 | 1.00x | 6.0% |
| foldhash_fast | 12.46 | 0.46x | 3.1% |
| foldhash_quality | 12.91 | 0.47x | 2.9% |
| ahash | 13.01 | 0.48x | 3.3% |
| fxhash | 10.97 | 0.40x | 2.8% |

### bulk_recency/1_destinations

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 11.79 | 1.00x | 0.2% |
| foldhash_fast | 2.63 | 0.22x | 0.3% |
| foldhash_quality | 2.91 | 0.25x | 0.3% |
| ahash | 3.87 | 0.33x | 0.2% |
| fxhash | 2.28 | 0.19x | 0.6% |

### bulk_recency/64_destinations

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| sip13_random | 11.80 | 1.00x | 8.5% |
| foldhash_fast | 2.63 | 0.22x | 0.0% |
| foldhash_quality | 3.38 | 0.29x | 15.5% |
| ahash | 3.87 | 0.33x | 0.1% |
| fxhash | 2.29 | 0.19x | 0.1% |

### allowed_ips/1_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| ip_network_table_trie(current) | 44.66 | 1.00x | 0.4% |
| host_route_hash+sip13_random | 10.41 | 0.23x | 0.3% |
| host_route_hash+foldhash_fast | 2.19 | 0.05x | 0.0% |
| host_route_hash+foldhash_quality | 2.55 | 0.06x | 0.1% |
| host_route_hash+ahash | 3.24 | 0.07x | 0.0% |
| host_route_hash+fxhash | 1.92 | 0.04x | 0.1% |
| direct_index(host routes) | 0.73 | 0.02x | 0.1% |

### allowed_ips/100_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| ip_network_table_trie(current) | 44.71 | 1.00x | 0.1% |
| host_route_hash+sip13_random | 11.33 | 0.25x | 7.5% |
| host_route_hash+foldhash_fast | 2.19 | 0.05x | 8.3% |
| host_route_hash+foldhash_quality | 2.75 | 0.06x | 22.5% |
| host_route_hash+ahash | 3.88 | 0.09x | 10.8% |
| host_route_hash+fxhash | 2.14 | 0.05x | 0.1% |
| direct_index(host routes) | 0.73 | 0.02x | 0.1% |

### allowed_ips/1000_peers

| candidate | ns/op | rel. to first row | run spread |
|---|---:|---:|---:|
| ip_network_table_trie(current) | 44.67 | 1.00x | 0.1% |
| host_route_hash+sip13_random | 10.53 | 0.24x | 0.8% |
| host_route_hash+foldhash_fast | 2.19 | 0.05x | 0.1% |
| host_route_hash+foldhash_quality | 2.66 | 0.06x | 3.9% |
| host_route_hash+ahash | 3.25 | 0.07x | 0.8% |
| host_route_hash+fxhash | 1.92 | 0.04x | 0.1% |
| direct_index(host routes) | 0.73 | 0.02x | 0.1% |

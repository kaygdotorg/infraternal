| step | metric | unit | N=10 | N=100 | N=1000 | N=4096 |
|---|---|---|---|---|---|---|
| baseline | rss | KiB | 12252 | 12284 | 12292 | 12232 |
| baseline | hwm | KiB | 12252 | 12284 | 12292 | 12232 |
| baseline | pss | KiB | 12244 | 12276 | 12284 | 12224 |
| baseline | fds |  | 17 | 17 | 17 | 17 |
| baseline | idle_voluntary_per_s | 1/s | 0.35 | 0.35 | 0.35 | 0.35 |
| baseline | idle_involuntary_per_s | 1/s | 0 | 0 | 0 | 0 |
| baseline | idle_cpu_pct | % | 0 | 0 | 0 | 0 |
| baseline | threads |  | 6 | 6 | 6 | 6 |
| apply_full | apply_ms | ms | 33.9 | 39.5 | 126 | 501 |
| apply_full | apply_us_per_peer | us | 3388 | 395 | 126 | 122 |
| configured | rss | KiB | 14036 | 14828 | 21728 | 45024 |
| configured | hwm | KiB | 14036 | 14828 | 21828 | 46924 |
| configured | pss | KiB | 14028 | 14820 | 21720 | 45016 |
| configured | fds |  | 26 | 26 | 26 | 26 |
| configured | rss_per_peer | B | 182682 | 26051 | 9662 | 8198 |
| configured | routes |  | 12 | 102 | 1002 | 4098 |
| configured | nft_lines |  | 51 | 186 | 1536 | 6180 |
| configured | mesh_mtu | B | 1280 | 1280 | 1280 | 1280 |
| configured | idle_voluntary_per_s | 1/s | 0.95 | 1.05 | 1 | 0.85 |
| configured | idle_involuntary_per_s | 1/s | 0 | -0.05 | -0.05 | -5.1 |
| configured | idle_cpu_pct | % | 0 | 0.1 | 0.05 | 0.05 |
| configured | threads |  | 8 | 8 | 8 | 8 |
| cold_storm | established | of 10 | 10 | 100 | 1000 | 4096 |
| cold_storm | wall_ms | ms | 4.8 | 33.4 | 6044 | 28106 |
| cold_storm | hs_p50_ms | ms | 3.74 | 16 | 128 | 11184 |
| cold_storm | hs_p99_ms | ms | 4 | 25.6 | 5975 | 23897 |
| cold_storm | hs_max_ms | ms | 4.05 | 25.6 | 5986 | 28064 |
| cold_storm | peers_retried | of 10 | 0 | 0 | 500 | 3596 |
| cold_storm | max_attempts | initiations | 1 | 1 | 2 | 6 |
| cold_storm | hub_cpu_s | s | 0 | 0.03 | 0.39 | 1.83 |
| cold_storm | sim_cpu_s | s | 0 | 0.02 | 0.32 | 2.14 |
| connected | rss | KiB | 14540 | 15636 | 23856 | 51188 |
| connected | hwm | KiB | 14588 | 15904 | 24260 | 53464 |
| connected | pss | KiB | 14532 | 15628 | 23848 | 51180 |
| connected | fds |  | 26 | 26 | 26 | 26 |
| connected | rss_per_peer | B | 234291 | 34324 | 11842 | 9739 |
| connected | idle_voluntary_per_s | 1/s | 0.95 | 2.15 | 18.9 | 62.2 |
| connected | idle_involuntary_per_s | 1/s | 0 | 0 | -0.05 | -24.8 |
| connected | idle_cpu_pct | % | 0 | 0.05 | 0.05 | 0.2 |
| connected | threads |  | 9 | 8 | 8 | 8 |
| keepalive25 | idle_voluntary_per_s | 1/s | 1.48 | 6.43 | 23.4 | 41.5 |
| keepalive25 | idle_cpu_pct | % | 0.017 | 0.017 | 0.117 | 0.317 |
| send_1_max | offered_mbit | Mbit/s | 2118 | 2105 | 2115 | 2066 |
| send_1_max | delivered_mbit | Mbit/s | 2118 | 2105 | 2115 | 2066 |
| send_1_max | loss_pct | % | 0 | 0 | 0 | 0.03 |
| send_1_max | hub_cpu_s | s | 16.1 | 16.2 | 16.1 | 16.1 |
| send_1_max | hub_cpu_s_per_gbit | cpu-s/Gbit | 0.76 | 0.77 | 0.76 | 0.78 |
| send_1_max | busiest_threads |  | infraternal-mes=8.15s;infraternal-mes=7.85s;gotatun-crypto-=0.01s;gotatun-crypto-=0.01s | infraternal-mes=8.09s;infraternal-mes=8.03s;gotatun-crypto-=0.01s;gotatun-crypto-=0.01s | infraternal-mes=8.04s;infraternal-mes=7.96s;infraternal-mes=0.05s;gotatun-crypto-=0.03s | infraternal-mes=7.83s;infraternal-mes=7.83s;infraternal-mes=0.22s;infraternal-mes=0.07s |
| send_1_max | sim_cpu_s | s | 6.48 | 6.47 | 6.48 | 6.53 |
| send_1_max | hub_ns_counters |  | Ip.InReceives=4137382;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4137382;Udp.InDatagrams=4137382;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=5;Udp.RcvbufErrors=0 | Ip.InReceives=4110888;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4110888;Udp.InDatagrams=4110888;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=45;Udp.RcvbufErrors=0 | Ip.InReceives=4130606;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4130606;Udp.InDatagrams=4130606;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=437;Udp.RcvbufErrors=0 | Ip.InReceives=4035098;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4035098;Udp.InDatagrams=4034480;Udp.NoPorts=0;Udp.InErrors=618;Udp.OutDatagrams=1855;Udp.RcvbufErrors=618 |
| send_1_400mbit | offered_mbit | Mbit/s | 390 | 390 | 390 | 390 |
| send_1_400mbit | delivered_mbit | Mbit/s | 390 | 390 | 390 | 390 |
| send_1_400mbit | loss_pct | % | 0 | 0 | 0 | 0 |
| send_1_400mbit | hub_cpu_s | s | 5.61 | 5.64 | 5.66 | 5.95 |
| send_1_400mbit | hub_cpu_s_per_gbit | cpu-s/Gbit | 1.44 | 1.45 | 1.45 | 1.52 |
| send_1_400mbit | busiest_threads |  | infraternal-mes=3.78s;infraternal-mes=1.83s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=2.85s;infraternal-mes=2.78s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=3.15s;infraternal-mes=2.45s;infraternal-mes=0.05s;infraternal-mes=0.01s | infraternal-mes=3.36s;infraternal-mes=2.27s;infraternal-mes=0.24s;infraternal-mes=0.09s |
| send_1_400mbit | sim_cpu_s | s | 7.98 | 8 | 8.02 | 8.01 |
| send_1_400mbit | hub_ns_counters |  | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=6;Udp.RcvbufErrors=0 | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=43;Udp.RcvbufErrors=0 | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=469;Udp.RcvbufErrors=0 | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=1789;Udp.RcvbufErrors=0 |
| send_10_max | offered_mbit | Mbit/s | 2079 | 2068 | 2072 | 1980 |
| send_10_max | delivered_mbit | Mbit/s | 2079 | 2068 | 2072 | 1980 |
| send_10_max | loss_pct | % | 0 | 0 | 0 | 0 |
| send_10_max | hub_cpu_s | s | 16.6 | 16.8 | 16.8 | 16.5 |
| send_10_max | hub_cpu_s_per_gbit | cpu-s/Gbit | 0.8 | 0.81 | 0.81 | 0.83 |
| send_10_max | busiest_threads |  | infraternal-mes=8.31s;infraternal-mes=8.30s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=8.47s;infraternal-mes=8.29s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=8.34s;infraternal-mes=8.33s;infraternal-mes=0.05s;infraternal-mes=0.03s | infraternal-mes=8.14s;infraternal-mes=8.09s;infraternal-mes=0.23s;infraternal-mes=0.05s |
| send_10_max | sim_cpu_s | s | 6.45 | 6.41 | 6.42 | 6.52 |
| send_10_max | hub_ns_counters |  | Ip.InReceives=4061394;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4061394;Udp.InDatagrams=4061394;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=10;Udp.RcvbufErrors=0 | Ip.InReceives=4039400;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4039400;Udp.InDatagrams=4039400;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=48;Udp.RcvbufErrors=0 | Ip.InReceives=4046990;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4046990;Udp.InDatagrams=4046990;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=444;Udp.RcvbufErrors=0 | Ip.InReceives=3867172;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=3867172;Udp.InDatagrams=3867172;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=1818;Udp.RcvbufErrors=0 |
| send_10_400mbit | offered_mbit | Mbit/s | 390 | 390 | 390 | 390 |
| send_10_400mbit | delivered_mbit | Mbit/s | 390 | 390 | 390 | 390 |
| send_10_400mbit | loss_pct | % | 0 | 0 | 0 | 0 |
| send_10_400mbit | hub_cpu_s | s | 5.62 | 5.64 | 5.72 | 6.04 |
| send_10_400mbit | hub_cpu_s_per_gbit | cpu-s/Gbit | 1.44 | 1.45 | 1.47 | 1.55 |
| send_10_400mbit | busiest_threads |  | infraternal-mes=5.61s;node::many_peer=0.00s;mesh-route-repa=0.00s;mesh-dns-udp=0.00s | infraternal-mes=3.11s;infraternal-mes=2.54s;infraternal-mes=0.02s;node::many_peer=0.00s | infraternal-mes=4.41s;infraternal-mes=1.26s;infraternal-mes=0.06s;node::many_peer=0.00s | infraternal-mes=3.66s;infraternal-mes=2.03s;infraternal-mes=0.25s;infraternal-mes=0.08s |
| send_10_400mbit | sim_cpu_s | s | 7.99 | 7.99 | 8.01 | 7.98 |
| send_10_400mbit | hub_ns_counters |  | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=10;Udp.RcvbufErrors=0 | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=48;Udp.RcvbufErrors=0 | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=472;Udp.RcvbufErrors=0 | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=1853;Udp.RcvbufErrors=0 |
| after_load | rss | KiB | 21576 | 27736 | 85076 | 209236 |
| after_load | hwm | KiB | 21576 | 28084 | 85076 | 209236 |
| after_load | pss | KiB | 21568 | 27728 | 85068 | 209228 |
| after_load | fds |  | 26 | 26 | 26 | 26 |
| after_load | rss_per_peer | B | 954778 | 158228 | 74531 | 49251 |
| after_load_15s | rss | KiB | 16072 | 21880 | 77152 | 196084 |
| after_load_15s | hwm | KiB | 21356 | 28084 | 84956 | 209052 |
| after_load_15s | pss | KiB | 16064 | 21872 | 77144 | 196076 |
| after_load_15s | fds |  | 26 | 26 | 26 | 26 |
| after_load | idle_voluntary_per_s | 1/s | 0.4 | 3.25 | 56 | 248 |
| after_load | idle_involuntary_per_s | 1/s | 0 | 0 | 0.1 | 2.6 |
| after_load | idle_cpu_pct | % | 0.05 | 0.1 | 1.25 | 4.85 |
| after_load | threads |  | 10 | 10 | 10 | 10 |
| rekey_storm | established | of 10 | 10 | 100 | 1000 | 4096 |
| rekey_storm | wall_ms | ms | 4.6 | 64.1 | 936 | 6324 |
| rekey_storm | hs_p50_ms | ms | 3.59 | 31.7 | 701 | 2447 |
| rekey_storm | hs_p99_ms | ms | 3.74 | 55.4 | 854 | 5974 |
| rekey_storm | hs_max_ms | ms | 3.76 | 55.9 | 857 | 6003 |
| rekey_storm | peers_retried | of 10 | 0 | 0 | 0 | 678 |
| rekey_storm | max_attempts | initiations | 1 | 1 | 1 | 2 |
| rekey_storm | hub_cpu_s | s | 0 | 0.05 | 0.52 | 1.6 |
| rekey_storm | busiest_threads |  | infraternal-mes=0.01s;node::many_peer=0.00s;mesh-route-repa=0.00s;mesh-dns-udp=0.00s | infraternal-mes=0.02s;infraternal-mes=0.02s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=0.39s;infraternal-mes=0.12s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=0.97s;infraternal-mes=0.64s;infraternal-mes=0.01s;node::many_peer=0.00s |
| apply_one_change | apply_ms | ms | 45.5 | 63 | 123 | 419 |
| apply_reapply | apply_ms | ms | 55.2 | 82.4 | 113 | 451 |
| apply_same | apply_ms | ms | 1.4 | 5.86 | 52.1 | 212 |
| apply_add_one | apply_ms | ms | 36.8 | 88.7 | 130 | 428 |
| apply_remove_one | apply_ms | ms | 42.6 | 87.7 | 135 | 434 |
| counters | counters_ms | ms | 0.02 | 0.09 | 0.9 | 3.42 |
| final | rss | KiB | 16680 | 22772 | 83524 | 186220 |
| final | hwm | KiB | 21356 | 28084 | 84956 | 220808 |
| final | pss | KiB | 16672 | 22764 | 83516 | 186212 |
| final | fds |  | 26 | 26 | 26 | 26 |
| send_100_max | offered_mbit | Mbit/s |  | 2417 | 2356 | 2244 |
| send_100_max | delivered_mbit | Mbit/s |  | 158 | 164 | 154 |
| send_100_max | loss_pct | % |  | 93.5 | 93 | 93.1 |
| send_100_max | hub_cpu_s | s |  | 13.4 | 13.5 | 13.5 |
| send_100_max | hub_cpu_s_per_gbit | cpu-s/Gbit |  | 8.5 | 8.23 | 8.79 |
| send_100_max | busiest_threads |  |  | infraternal-mes=6.72s;infraternal-mes=6.68s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=6.76s;infraternal-mes=6.64s;infraternal-mes=0.05s;infraternal-mes=0.03s | infraternal-mes=6.64s;infraternal-mes=6.60s;infraternal-mes=0.24s;infraternal-mes=0.05s |
| send_100_max | sim_cpu_s | s |  | 9.49 | 9.47 | 9.49 |
| send_100_max | hub_ns_counters |  |  | Ip.InReceives=2514499;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=2514499;Udp.InDatagrams=2278691;Udp.NoPorts=0;Udp.InErrors=235808;Udp.OutDatagrams=100;Udp.RcvbufErrors=235808 | Ip.InReceives=2460627;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=2460627;Udp.InDatagrams=2297935;Udp.NoPorts=0;Udp.InErrors=162692;Udp.OutDatagrams=501;Udp.RcvbufErrors=162692 | Ip.InReceives=2341981;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=2341981;Udp.InDatagrams=2249135;Udp.NoPorts=0;Udp.InErrors=92846;Udp.OutDatagrams=1948;Udp.RcvbufErrors=92846 |
| send_100_400mbit | offered_mbit | Mbit/s |  | 390 | 390 | 390 |
| send_100_400mbit | delivered_mbit | Mbit/s |  | 390 | 390 | 28.2 |
| send_100_400mbit | loss_pct | % |  | 0 | 0 | 92.8 |
| send_100_400mbit | hub_cpu_s | s |  | 5.65 | 5.71 | 2.72 |
| send_100_400mbit | hub_cpu_s_per_gbit | cpu-s/Gbit |  | 1.45 | 1.46 | 9.64 |
| send_100_400mbit | busiest_threads |  |  | infraternal-mes=5.64s;node::many_peer=0.00s;mesh-route-repa=0.00s;mesh-dns-udp=0.00s | infraternal-mes=2.98s;infraternal-mes=2.67s;infraternal-mes=0.05s;node::many_peer=0.00s | infraternal-mes=1.25s;infraternal-mes=1.17s;infraternal-mes=0.22s;infraternal-mes=0.08s |
| send_100_400mbit | sim_cpu_s | s |  | 7.99 | 8.01 | 9.84 |
| send_100_400mbit | hub_ns_counters |  |  | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=100;Udp.RcvbufErrors=0 | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=509;Udp.RcvbufErrors=0 | Ip.InReceives=409054;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=409054;Udp.InDatagrams=409054;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=2521;Udp.RcvbufErrors=0 |
| all_touched | rss | KiB |  |  | 85076 | 209236 |
| all_touched | hwm | KiB |  |  | 85076 | 209236 |
| all_touched | pss | KiB |  |  | 85068 | 209228 |
| all_touched | fds |  |  |  | 26 | 26 |
| all_touched | rss_per_peer | B |  |  | 74531 | 49251 |

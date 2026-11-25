| step | metric | unit | N=1000 | N=4096 |
|---|---|---|---|---|
| baseline | rss | KiB | 12296 | 12288 |
| baseline | hwm | KiB | 12296 | 12288 |
| baseline | pss | KiB | 12288 | 12280 |
| baseline | fds |  | 17 | 17 |
| baseline | idle_busiest_threads |  | infraternal-mes=0.3/s;infraternal-mes=0.1/s;node::many_peer=0.0/s | infraternal-mes=0.3/s;infraternal-mes=0.1/s;node::many_peer=0.0/s |
| baseline | idle_voluntary_per_s | 1/s | 0.35 | 0.35 |
| baseline | idle_involuntary_per_s | 1/s | 0 | 0 |
| baseline | idle_cpu_pct | % | 0 | 0 |
| baseline | threads |  | 6 | 6 |
| apply_full | apply_ms | ms | 135 | 495 |
| apply_full | apply_us_per_peer | us | 135 | 121 |
| configured | rss | KiB | 21720 | 45228 |
| configured | hwm | KiB | 21968 | 47108 |
| configured | pss | KiB | 21712 | 45220 |
| configured | fds |  | 26 | 26 |
| configured | rss_per_peer | B | 9650 | 8235 |
| configured | routes |  | 1001 | 4097 |
| configured | nft_lines |  | 1536 | 6180 |
| configured | mesh_mtu | B | 1280 | 1280 |
| configured | idle_busiest_threads |  | infraternal-mes=0.6/s;infraternal-mes=0.2/s;mesh-route-repa=0.1/s | infraternal-mes=0.8/s;infraternal-mes=0.2/s;node::many_peer=0.0/s |
| configured | idle_voluntary_per_s | 1/s | 0.85 | 0.95 |
| configured | idle_involuntary_per_s | 1/s | 0 | -19.2 |
| configured | idle_cpu_pct | % | 0 | 0.05 |
| configured | threads |  | 8 | 8 |
| cold_storm | established | of 1000 | 1000 | 4096 |
| cold_storm | wall_ms | ms | 17991 | 43486 |
| cold_storm | hs_p50_ms | ms | 10764 | 22621 |
| cold_storm | hs_p99_ms | ms | 17205 | 43177 |
| cold_storm | hs_max_ms | ms | 17941 | 43452 |
| cold_storm | peers_retried | of 1000 | 800 | 3896 |
| cold_storm | max_attempts | initiations | 4 | 9 |
| cold_storm | hub_cpu_s | s | 0.42 | 2.17 |
| cold_storm | sim_cpu_s | s | 0.46 | 2.88 |
| connected | rss | KiB | 23724 | 51396 |
| connected | hwm | KiB | 24304 | 53352 |
| connected | pss | KiB | 23716 | 51388 |
| connected | fds |  | 26 | 26 |
| connected | rss_per_peer | B | 11702 | 9777 |
| connected | idle_busiest_threads |  | infraternal-mes=8.0/s;infraternal-mes=4.0/s;mesh-route-repa=0.1/s | infraternal-mes=30.2/s;infraternal-mes=21.2/s;mesh-route-repa=0.1/s |
| connected | idle_voluntary_per_s | 1/s | 11.3 | 48.7 |
| connected | idle_involuntary_per_s | 1/s | -1.3 | -7.65 |
| connected | idle_cpu_pct | % | 0.05 | 0.2 |
| connected | threads |  | 8 | 8 |
| connected_2 | idle_busiest_threads |  | infraternal-mes=13.8/s;infraternal-mes=8.5/s;infraternal-mes=0.1/s | infraternal-mes=40.6/s;infraternal-mes=26.4/s;infraternal-mes=0.2/s |
| connected_2 | idle_voluntary_per_s | 1/s | 22.4 | 67.3 |
| connected_2 | idle_involuntary_per_s | 1/s | 0 | 0.1 |
| connected_2 | idle_cpu_pct | % | 0.05 | 0.25 |
| connected_2 | threads |  | 8 | 9 |
| keepalive25 | idle_voluntary_per_s | 1/s | 22.9 | 35.4 |
| keepalive25 | idle_cpu_pct | % | 0.117 | 0.267 |
| send_1_max | offered_mbit | Mbit/s | 2122 | 2114 |
| send_1_max | delivered_mbit | Mbit/s | 2122 | 2114 |
| send_1_max | loss_pct | % | 0 | 0 |
| send_1_max | hub_cpu_s | s | 16.1 | 16.2 |
| send_1_max | hub_cpu_s_per_gbit | cpu-s/Gbit | 0.76 | 0.77 |
| send_1_max | busiest_threads |  | infraternal-mes=8.02s;infraternal-mes=7.99s;infraternal-mes=0.05s;gotatun-crypto-=0.03s | infraternal-mes=7.89s;infraternal-mes=7.89s;infraternal-mes=0.22s;gotatun-crypto-=0.06s |
| send_1_max | sim_cpu_s | s | 6.47 | 6.49 |
| send_1_max | hub_ns_counters |  | Ip.InReceives=4143786;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4143786;Udp.InDatagrams=4143786;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=475;Udp.RcvbufErrors=0 | Ip.InReceives=4129297;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4129297;Udp.InDatagrams=4129297;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=1808;Udp.RcvbufErrors=0 |
| send_1_1000mbit | offered_mbit | Mbit/s | 976 | 976 |
| send_1_1000mbit | delivered_mbit | Mbit/s | 976 | 976 |
| send_1_1000mbit | loss_pct | % | 0 | 0 |
| send_1_1000mbit | hub_cpu_s | s | 9.6 | 9.83 |
| send_1_1000mbit | hub_cpu_s_per_gbit | cpu-s/Gbit | 0.98 | 1.01 |
| send_1_1000mbit | busiest_threads |  | infraternal-mes=5.52s;infraternal-mes=4.02s;infraternal-mes=0.06s;infraternal-mes=0.01s | infraternal-mes=5.81s;infraternal-mes=3.74s;infraternal-mes=0.25s;infraternal-mes=0.05s |
| send_1_1000mbit | sim_cpu_s | s | 6.83 | 6.84 |
| send_1_1000mbit | hub_ns_counters |  | Ip.InReceives=1905490;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1905490;Udp.InDatagrams=1905490;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=419;Udp.RcvbufErrors=0 | Ip.InReceives=1905490;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1905490;Udp.InDatagrams=1905490;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=1862;Udp.RcvbufErrors=0 |
| send_1_400mbit | offered_mbit | Mbit/s | 390 | 390 |
| send_1_400mbit | delivered_mbit | Mbit/s | 390 | 185 |
| send_1_400mbit | loss_pct | % | 0 | 52.5 |
| send_1_400mbit | hub_cpu_s | s | 5.63 | 3.85 |
| send_1_400mbit | hub_cpu_s_per_gbit | cpu-s/Gbit | 1.44 | 2.08 |
| send_1_400mbit | busiest_threads |  | infraternal-mes=3.71s;infraternal-mes=1.87s;infraternal-mes=0.05s;infraternal-mes=0.01s | infraternal-mes=2.52s;infraternal-mes=1.18s;infraternal-mes=0.11s;infraternal-mes=0.02s |
| send_1_400mbit | sim_cpu_s | s | 7.97 | 9.05 |
| send_1_400mbit | hub_ns_counters |  | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=469;Udp.RcvbufErrors=0 | Ip.InReceives=562131;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=562131;Udp.InDatagrams=562131;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=2134;Udp.RcvbufErrors=0 |
| send_10_max | offered_mbit | Mbit/s | 2086 | 2078 |
| send_10_max | delivered_mbit | Mbit/s | 2086 | 1721 |
| send_10_max | loss_pct | % | 0 | 17.2 |
| send_10_max | hub_cpu_s | s | 16.8 | 16 |
| send_10_max | hub_cpu_s_per_gbit | cpu-s/Gbit | 0.81 | 0.93 |
| send_10_max | busiest_threads |  | infraternal-mes=8.39s;infraternal-mes=8.35s;infraternal-mes=0.05s;infraternal-mes=0.01s | infraternal-mes=7.95s;infraternal-mes=7.78s;infraternal-mes=0.21s;infraternal-mes=0.04s |
| send_10_max | sim_cpu_s | s | 6.4 | 6.74 |
| send_10_max | hub_ns_counters |  | Ip.InReceives=4074900;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4074900;Udp.InDatagrams=4074900;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=406;Udp.RcvbufErrors=0 | Ip.InReceives=3711100;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=3711100;Udp.InDatagrams=3711100;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=3100;Udp.RcvbufErrors=0 |
| send_10_1000mbit | offered_mbit | Mbit/s | 976 | 976 |
| send_10_1000mbit | delivered_mbit | Mbit/s | 249 | 976 |
| send_10_1000mbit | loss_pct | % | 74.5 | 0 |
| send_10_1000mbit | hub_cpu_s | s | 5.08 | 10.2 |
| send_10_1000mbit | hub_cpu_s_per_gbit | cpu-s/Gbit | 2.04 | 1.05 |
| send_10_1000mbit | busiest_threads |  | infraternal-mes=2.67s;infraternal-mes=2.40s;infraternal-mes=0.03s;node::many_peer=0.00s | infraternal-mes=5.47s;infraternal-mes=4.46s;infraternal-mes=0.23s;infraternal-mes=0.05s |
| send_10_1000mbit | sim_cpu_s | s | 9.2 | 6.96 |
| send_10_1000mbit | hub_ns_counters |  | Ip.InReceives=1195589;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1195589;Udp.InDatagrams=1195589;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=670;Udp.RcvbufErrors=0 | Ip.InReceives=1906763;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1906763;Udp.InDatagrams=1906763;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=4344;Udp.RcvbufErrors=0 |
| send_10_400mbit | offered_mbit | Mbit/s | 390 | 390 |
| send_10_400mbit | delivered_mbit | Mbit/s | 390 | 390 |
| send_10_400mbit | loss_pct | % | 0.01 | 0 |
| send_10_400mbit | hub_cpu_s | s | 5.77 | 6.24 |
| send_10_400mbit | hub_cpu_s_per_gbit | cpu-s/Gbit | 1.48 | 1.6 |
| send_10_400mbit | busiest_threads |  | infraternal-mes=3.91s;infraternal-mes=1.79s;infraternal-mes=0.04s;infraternal-mes=0.01s | infraternal-mes=3.88s;infraternal-mes=2.09s;infraternal-mes=0.24s;infraternal-mes=0.04s |
| send_10_400mbit | sim_cpu_s | s | 8.02 | 8.06 |
| send_10_400mbit | hub_ns_counters |  | Ip.InReceives=762552;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762552;Udp.InDatagrams=762552;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=1174;Udp.RcvbufErrors=0 | Ip.InReceives=763495;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=763495;Udp.InDatagrams=763495;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=4452;Udp.RcvbufErrors=0 |
| send_100_max | offered_mbit | Mbit/s | 2448 | 2444 |
| send_100_max | delivered_mbit | Mbit/s | 159 | 155 |
| send_100_max | loss_pct | % | 93.5 | 93.7 |
| send_100_max | hub_cpu_s | s | 13.5 | 13.5 |
| send_100_max | hub_cpu_s_per_gbit | cpu-s/Gbit | 8.49 | 8.75 |
| send_100_max | busiest_threads |  | infraternal-mes=6.82s;infraternal-mes=6.61s;infraternal-mes=0.06s;infraternal-mes=0.01s | infraternal-mes=6.68s;infraternal-mes=6.57s;infraternal-mes=0.24s;infraternal-mes=0.04s |
| send_100_max | sim_cpu_s | s | 9.49 | 9.5 |
| send_100_max | hub_ns_counters |  | Ip.InReceives=2546316;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=2546316;Udp.InDatagrams=2280514;Udp.NoPorts=0;Udp.InErrors=265802;Udp.OutDatagrams=1311;Udp.RcvbufErrors=265802 | Ip.InReceives=2538591;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=2538591;Udp.InDatagrams=2222860;Udp.NoPorts=0;Udp.InErrors=315731;Udp.OutDatagrams=3096;Udp.RcvbufErrors=315731 |
| send_100_1000mbit | offered_mbit | Mbit/s | 976 | 976 |
| send_100_1000mbit | delivered_mbit | Mbit/s | 976 | 976 |
| send_100_1000mbit | loss_pct | % | 0 | 0.01 |
| send_100_1000mbit | hub_cpu_s | s | 9.72 | 9.98 |
| send_100_1000mbit | hub_cpu_s_per_gbit | cpu-s/Gbit | 1 | 1.02 |
| send_100_1000mbit | busiest_threads |  | infraternal-mes=5.62s;infraternal-mes=4.03s;infraternal-mes=0.05s;infraternal-mes=0.01s | infraternal-mes=4.85s;infraternal-mes=4.84s;infraternal-mes=0.23s;infraternal-mes=0.05s |
| send_100_1000mbit | sim_cpu_s | s | 6.88 | 6.91 |
| send_100_1000mbit | hub_ns_counters |  | Ip.InReceives=1905584;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1905584;Udp.InDatagrams=1905584;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=670;Udp.RcvbufErrors=0 | Ip.InReceives=1905530;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1905530;Udp.InDatagrams=1905530;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=2243;Udp.RcvbufErrors=0 |
| send_100_400mbit | offered_mbit | Mbit/s | 390 | 390 |
| send_100_400mbit | delivered_mbit | Mbit/s | 390 | 390 |
| send_100_400mbit | loss_pct | % | 0 | 0 |
| send_100_400mbit | hub_cpu_s | s | 5.7 | 5.96 |
| send_100_400mbit | hub_cpu_s_per_gbit | cpu-s/Gbit | 1.46 | 1.53 |
| send_100_400mbit | busiest_threads |  | infraternal-mes=4.51s;infraternal-mes=1.13s;infraternal-mes=0.05s;infraternal-mes=0.01s | infraternal-mes=3.59s;infraternal-mes=2.09s;infraternal-mes=0.24s;infraternal-mes=0.04s |
| send_100_400mbit | sim_cpu_s | s | 8.01 | 8.02 |
| send_100_400mbit | hub_ns_counters |  | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=565;Udp.RcvbufErrors=0 | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=2081;Udp.RcvbufErrors=0 |
| all_touched | rss | KiB | 84880 | 279740 |
| all_touched | hwm | KiB | 84880 | 279740 |
| all_touched | pss | KiB | 84872 | 279732 |
| all_touched | fds |  | 26 | 26 |
| all_touched | rss_per_peer | B | 74326 | 66863 |
| after_load | rss | KiB | 84880 | 279740 |
| after_load | hwm | KiB | 84880 | 279740 |
| after_load | pss | KiB | 84872 | 279732 |
| after_load | fds |  | 26 | 26 |
| after_load | rss_per_peer | B | 74326 | 66863 |
| after_load_15s | rss | KiB | 77864 | 269556 |
| after_load_15s | hwm | KiB | 84660 | 279568 |
| after_load_15s | pss | KiB | 77856 | 269548 |
| after_load_15s | fds |  | 26 | 26 |
| after_load | idle_busiest_threads |  | infraternal-mes=12.2/s;infraternal-mes=0.1/s;infraternal-mes=0.1/s | infraternal-mes=50.0/s;infraternal-mes=14.8/s;mesh-route-repa=0.1/s |
| after_load | idle_voluntary_per_s | 1/s | 12.3 | 65 |
| after_load | idle_involuntary_per_s | 1/s | 0 | 0.05 |
| after_load | idle_cpu_pct | % | 0.05 | 0.2 |
| after_load | threads |  | 10 | 10 |
| after_load_2 | idle_busiest_threads |  | infraternal-mes=2.8/s;infraternal-mes=0.2/s;mesh-route-repa=0.1/s | infraternal-mes=37.7/s;infraternal-mes=19.1/s;infraternal-mes=0.1/s |
| after_load_2 | idle_voluntary_per_s | 1/s | 3.1 | 56.8 |
| after_load_2 | idle_involuntary_per_s | 1/s | 0 | 0 |
| after_load_2 | idle_cpu_pct | % | 0 | 0.2 |
| after_load_2 | threads |  | 10 | 10 |
| after_load_3 | idle_busiest_threads |  | infraternal-mes=0.5/s;infraternal-mes=0.1/s;mesh-route-repa=0.1/s | infraternal-mes=2.4/s;infraternal-mes=1.6/s;infraternal-mes=0.1/s |
| after_load_3 | idle_voluntary_per_s | 1/s | 0.6 | 4.1 |
| after_load_3 | idle_involuntary_per_s | 1/s | 0 | 0 |
| after_load_3 | idle_cpu_pct | % | 0 | 0.1 |
| after_load_3 | threads |  | 10 | 10 |
| rekey_storm | established | of 1000 | 1000 | 4096 |
| rekey_storm | wall_ms | ms | 6047 | 22924 |
| rekey_storm | hs_p50_ms | ms | 127 | 10496 |
| rekey_storm | hs_p99_ms | ms | 5966 | 22671 |
| rekey_storm | hs_max_ms | ms | 5978 | 22865 |
| rekey_storm | peers_retried | of 1000 | 300 | 3353 |
| rekey_storm | max_attempts | initiations | 2 | 5 |
| rekey_storm | hub_cpu_s | s | 0.35 | 1.43 |
| rekey_storm | busiest_threads |  | infraternal-mes=0.29s;infraternal-mes=0.05s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=0.78s;infraternal-mes=0.64s;node::many_peer=0.00s;mesh-route-repa=0.00s |
| apply_one_change | apply_ms | ms | 125 | 388 |
| apply_reapply | apply_ms | ms | 102 | 415 |
| apply_same | apply_ms | ms | 52.1 | 215 |
| apply_add_one | apply_ms | ms | 116 | 408 |
| apply_remove_one | apply_ms | ms | 121 | 377 |
| counters | counters_ms | ms | 0.84 | 3.41 |
| final | rss | KiB | 36220 | 292936 |
| final | hwm | KiB | 84660 | 292936 |
| final | pss | KiB | 36212 | 292928 |
| final | fds |  | 26 | 26 |

| step | metric | unit | N=1000 | N=4096 |
|---|---|---|---|---|
| baseline | rss | KiB | 12256 | 12288 |
| baseline | hwm | KiB | 12256 | 12288 |
| baseline | pss | KiB | 12248 | 12280 |
| baseline | fds |  | 17 | 17 |
| baseline | idle_busiest_threads |  | infraternal-mes=0.3/s;infraternal-mes=0.1/s;node::many_peer=0.0/s | infraternal-mes=0.3/s;infraternal-mes=0.1/s;node::many_peer=0.0/s |
| baseline | idle_voluntary_per_s | 1/s | 0.35 | 0.35 |
| baseline | idle_involuntary_per_s | 1/s | 0 | 0 |
| baseline | idle_cpu_pct | % | 0 | 0 |
| baseline | threads |  | 6 | 6 |
| apply_full | apply_ms | ms | 219 | 865 |
| apply_full | apply_us_per_peer | us | 219 | 211 |
| configured | rss | KiB | 22636 | 47624 |
| configured | hwm | KiB | 22756 | 50384 |
| configured | pss | KiB | 22628 | 47616 |
| configured | fds |  | 26 | 26 |
| configured | rss_per_peer | B | 10629 | 8834 |
| configured | routes |  | 1002 | 4098 |
| configured | nft_lines |  | 1536 | 6180 |
| configured | mesh_mtu | B | 1408 | 1408 |
| configured | idle_busiest_threads |  | infraternal-mes=30.9/s;infraternal-mes=30.4/s;infraternal-mes=0.2/s | infraternal-mes=207.9/s;infraternal-mes=97.3/s;infraternal-mes=0.2/s |
| configured | idle_voluntary_per_s | 1/s | 61.5 | 305 |
| configured | idle_involuntary_per_s | 1/s | -30.8 | -159 |
| configured | idle_cpu_pct | % | 1.3 | 5.35 |
| configured | threads |  | 8 | 8 |
| cold_storm | established | of 1000 | 1000 | 4096 |
| cold_storm | wall_ms | ms | 343 | 1557 |
| cold_storm | hs_p50_ms | ms | 137 | 545 |
| cold_storm | hs_p99_ms | ms | 261 | 982 |
| cold_storm | hs_max_ms | ms | 263 | 1277 |
| cold_storm | peers_retried | of 1000 | 0 | 0 |
| cold_storm | max_attempts | initiations | 1 | 1 |
| cold_storm | hub_cpu_s | s | 0.37 | 1.66 |
| cold_storm | sim_cpu_s | s | 0.27 | 1.42 |
| connected | rss | KiB | 24140 | 53108 |
| connected | hwm | KiB | 24652 | 54632 |
| connected | pss | KiB | 24132 | 53100 |
| connected | fds |  | 26 | 26 |
| connected | rss_per_peer | B | 12169 | 10205 |
| connected | idle_busiest_threads |  | infraternal-mes=30.2/s;infraternal-mes=0.2/s;infraternal-mes=0.2/s | infraternal-mes=32.2/s;infraternal-mes=26.9/s;infraternal-mes=0.2/s |
| connected | idle_voluntary_per_s | 1/s | 30.8 | 58.9 |
| connected | idle_involuntary_per_s | 1/s | 0 | -0.15 |
| connected | idle_cpu_pct | % | 0.1 | 0.3 |
| connected | threads |  | 9 | 8 |
| connected_2 | idle_busiest_threads |  | infraternal-mes=0.5/s;infraternal-mes=0.1/s;mesh-route-repa=0.1/s | infraternal-mes=29.4/s;infraternal-mes=26.2/s;mesh-route-repa=0.1/s |
| connected_2 | idle_voluntary_per_s | 1/s | 0.55 | 55.9 |
| connected_2 | idle_involuntary_per_s | 1/s | 0 | 0 |
| connected_2 | idle_cpu_pct | % | 0 | 0.25 |
| connected_2 | threads |  | 8 | 8 |
| keepalive25 | idle_voluntary_per_s | 1/s | 29.6 | 30.7 |
| keepalive25 | idle_cpu_pct | % | 0.133 | 0.3 |
| send_1_max | offered_mbit | Mbit/s | 2281 | 2269 |
| send_1_max | delivered_mbit | Mbit/s | 2281 | 2269 |
| send_1_max | loss_pct | % | 0 | 0.03 |
| send_1_max | hub_cpu_s | s | 16 | 16 |
| send_1_max | hub_cpu_s_per_gbit | cpu-s/Gbit | 0.7 | 0.71 |
| send_1_max | busiest_threads |  | infraternal-mes=7.94s;infraternal-mes=7.93s;infraternal-mes=0.06s;gotatun-crypto-=0.03s | infraternal-mes=7.80s;infraternal-mes=7.75s;infraternal-mes=0.22s;gotatun-crypto-=0.08s |
| send_1_max | sim_cpu_s | s | 6.54 | 6.56 |
| send_1_max | hub_ns_counters |  | Ip.InReceives=4050145;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4050145;Udp.InDatagrams=4050145;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=440;Udp.RcvbufErrors=0 | Ip.InReceives=4028748;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4028748;Udp.InDatagrams=4028131;Udp.NoPorts=0;Udp.InErrors=617;Udp.OutDatagrams=1864;Udp.RcvbufErrors=617 |
| send_1_1000mbit | offered_mbit | Mbit/s | 978 | 978 |
| send_1_1000mbit | delivered_mbit | Mbit/s | 978 | 978 |
| send_1_1000mbit | loss_pct | % | 0 | 0 |
| send_1_1000mbit | hub_cpu_s | s | 9.11 | 9.31 |
| send_1_1000mbit | hub_cpu_s_per_gbit | cpu-s/Gbit | 0.93 | 0.95 |
| send_1_1000mbit | busiest_threads |  | infraternal-mes=4.57s;infraternal-mes=4.45s;infraternal-mes=0.06s;infraternal-mes=0.01s | infraternal-mes=4.69s;infraternal-mes=4.31s;infraternal-mes=0.24s;infraternal-mes=0.07s |
| send_1_1000mbit | sim_cpu_s | s | 6.9 | 6.92 |
| send_1_1000mbit | hub_ns_counters |  | Ip.InReceives=1736114;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1736114;Udp.InDatagrams=1736114;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=458;Udp.RcvbufErrors=0 | Ip.InReceives=1736114;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1736114;Udp.InDatagrams=1736114;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=1820;Udp.RcvbufErrors=0 |
| send_1_400mbit | offered_mbit | Mbit/s | 391 | 391 |
| send_1_400mbit | delivered_mbit | Mbit/s | 391 | 391 |
| send_1_400mbit | loss_pct | % | 0 | 0 |
| send_1_400mbit | hub_cpu_s | s | 5.4 | 5.59 |
| send_1_400mbit | hub_cpu_s_per_gbit | cpu-s/Gbit | 1.38 | 1.43 |
| send_1_400mbit | busiest_threads |  | infraternal-mes=3.20s;infraternal-mes=2.14s;infraternal-mes=0.05s;infraternal-mes=0.01s | infraternal-mes=2.75s;infraternal-mes=2.59s;infraternal-mes=0.23s;infraternal-mes=0.01s |
| send_1_400mbit | sim_cpu_s | s | 8.31 | 8.31 |
| send_1_400mbit | hub_ns_counters |  | Ip.InReceives=694448;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=694448;Udp.InDatagrams=694448;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=450;Udp.RcvbufErrors=0 | Ip.InReceives=694448;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=694448;Udp.InDatagrams=694448;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=1816;Udp.RcvbufErrors=0 |
| send_10_max | offered_mbit | Mbit/s | 2229 | 2189 |
| send_10_max | delivered_mbit | Mbit/s | 2229 | 2188 |
| send_10_max | loss_pct | % | 0 | 0.01 |
| send_10_max | hub_cpu_s | s | 16.6 | 16.5 |
| send_10_max | hub_cpu_s_per_gbit | cpu-s/Gbit | 0.75 | 0.76 |
| send_10_max | busiest_threads |  | infraternal-mes=8.29s;infraternal-mes=8.28s;infraternal-mes=0.05s;node::many_peer=0.00s | infraternal-mes=8.13s;infraternal-mes=8.10s;infraternal-mes=0.23s;infraternal-mes=0.07s |
| send_10_max | sim_cpu_s | s | 6.46 | 6.51 |
| send_10_max | hub_ns_counters |  | Ip.InReceives=3957852;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=3957852;Udp.InDatagrams=3957852;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=455;Udp.RcvbufErrors=0 | Ip.InReceives=3886002;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=3886002;Udp.InDatagrams=3886002;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=1826;Udp.RcvbufErrors=0 |
| send_10_1000mbit | offered_mbit | Mbit/s | 978 | 978 |
| send_10_1000mbit | delivered_mbit | Mbit/s | 978 | 978 |
| send_10_1000mbit | loss_pct | % | 0 | 0 |
| send_10_1000mbit | hub_cpu_s | s | 9.26 | 9.46 |
| send_10_1000mbit | hub_cpu_s_per_gbit | cpu-s/Gbit | 0.95 | 0.97 |
| send_10_1000mbit | busiest_threads |  | infraternal-mes=5.47s;infraternal-mes=3.71s;infraternal-mes=0.06s;infraternal-mes=0.02s | infraternal-mes=6.07s;infraternal-mes=3.11s;infraternal-mes=0.24s;infraternal-mes=0.02s |
| send_10_1000mbit | sim_cpu_s | s | 6.96 | 6.95 |
| send_10_1000mbit | hub_ns_counters |  | Ip.InReceives=1736114;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1736114;Udp.InDatagrams=1736114;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=444;Udp.RcvbufErrors=0 | Ip.InReceives=1736114;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1736114;Udp.InDatagrams=1736114;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=1895;Udp.RcvbufErrors=0 |
| send_10_400mbit | offered_mbit | Mbit/s | 391 | 391 |
| send_10_400mbit | delivered_mbit | Mbit/s | 241 | 188 |
| send_10_400mbit | loss_pct | % | 38.3 | 52.1 |
| send_10_400mbit | hub_cpu_s | s | 4.1 | 3.89 |
| send_10_400mbit | hub_cpu_s_per_gbit | cpu-s/Gbit | 1.7 | 2.08 |
| send_10_400mbit | busiest_threads |  | infraternal-mes=2.57s;infraternal-mes=1.48s;infraternal-mes=0.03s;node::many_peer=0.00s | infraternal-mes=1.90s;infraternal-mes=1.83s;infraternal-mes=0.12s;infraternal-mes=0.01s |
| send_10_400mbit | sim_cpu_s | s | 8.95 | 9.18 |
| send_10_400mbit | hub_ns_counters |  | Ip.InReceives=561584;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=561584;Udp.InDatagrams=561584;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=784;Udp.RcvbufErrors=0 | Ip.InReceives=514339;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=514339;Udp.InDatagrams=514339;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=3233;Udp.RcvbufErrors=0 |
| send_100_max | offered_mbit | Mbit/s | 2614 | 2464 |
| send_100_max | delivered_mbit | Mbit/s | 1232 | 1108 |
| send_100_max | loss_pct | % | 52.9 | 55 |
| send_100_max | hub_cpu_s | s | 10.9 | 11.2 |
| send_100_max | hub_cpu_s_per_gbit | cpu-s/Gbit | 0.88 | 1.01 |
| send_100_max | busiest_threads |  | infraternal-mes=5.75s;infraternal-mes=5.05s;infraternal-mes=0.05s;infraternal-mes=0.02s | infraternal-mes=6.27s;infraternal-mes=4.68s;infraternal-mes=0.21s;infraternal-mes=0.06s |
| send_100_max | sim_cpu_s | s | 7.68 | 7.83 |
| send_100_max | hub_ns_counters |  | Ip.InReceives=3414652;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=3414652;Udp.InDatagrams=3414652;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=1389;Udp.RcvbufErrors=0 | Ip.InReceives=3173254;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=3173254;Udp.InDatagrams=3173254;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=5973;Udp.RcvbufErrors=0 |
| send_100_1000mbit | offered_mbit | Mbit/s | 978 | 978 |
| send_100_1000mbit | delivered_mbit | Mbit/s | 881 | 925 |
| send_100_1000mbit | loss_pct | % | 9.87 | 5.37 |
| send_100_1000mbit | hub_cpu_s | s | 8.82 | 9.52 |
| send_100_1000mbit | hub_cpu_s_per_gbit | cpu-s/Gbit | 1 | 1.03 |
| send_100_1000mbit | busiest_threads |  | infraternal-mes=4.58s;infraternal-mes=4.18s;infraternal-mes=0.06s;infraternal-mes=0.01s | infraternal-mes=4.80s;infraternal-mes=4.47s;infraternal-mes=0.23s;infraternal-mes=0.04s |
| send_100_1000mbit | sim_cpu_s | s | 7.26 | 7.21 |
| send_100_1000mbit | hub_ns_counters |  | Ip.InReceives=1650798;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1650798;Udp.InDatagrams=1650798;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=1194;Udp.RcvbufErrors=0 | Ip.InReceives=1690847;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1690847;Udp.InDatagrams=1690847;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=4392;Udp.RcvbufErrors=0 |
| send_100_400mbit | offered_mbit | Mbit/s | 391 | 391 |
| send_100_400mbit | delivered_mbit | Mbit/s | 391 | 391 |
| send_100_400mbit | loss_pct | % | 0 | 0 |
| send_100_400mbit | hub_cpu_s | s | 5.49 | 5.76 |
| send_100_400mbit | hub_cpu_s_per_gbit | cpu-s/Gbit | 1.4 | 1.47 |
| send_100_400mbit | busiest_threads |  | infraternal-mes=3.11s;infraternal-mes=2.31s;infraternal-mes=0.05s;infraternal-mes=0.01s | infraternal-mes=3.80s;infraternal-mes=1.65s;infraternal-mes=0.24s;infraternal-mes=0.06s |
| send_100_400mbit | sim_cpu_s | s | 8.31 | 8.29 |
| send_100_400mbit | hub_ns_counters |  | Ip.InReceives=694446;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=694446;Udp.InDatagrams=694446;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=540;Udp.RcvbufErrors=0 | Ip.InReceives=694448;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=694448;Udp.InDatagrams=694448;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=2107;Udp.RcvbufErrors=0 |
| all_touched | rss | KiB | 85324 | 281468 |
| all_touched | hwm | KiB | 85324 | 281468 |
| all_touched | pss | KiB | 85316 | 281460 |
| all_touched | fds |  | 26 | 26 |
| all_touched | rss_per_peer | B | 74822 | 67295 |
| after_load | rss | KiB | 85324 | 281468 |
| after_load | hwm | KiB | 85324 | 281468 |
| after_load | pss | KiB | 85316 | 281460 |
| after_load | fds |  | 26 | 26 |
| after_load | rss_per_peer | B | 74822 | 67295 |
| after_load_15s | rss | KiB | 77836 | 268796 |
| after_load_15s | hwm | KiB | 85028 | 281404 |
| after_load_15s | pss | KiB | 77828 | 268788 |
| after_load_15s | fds |  | 26 | 26 |
| after_load | idle_busiest_threads |  | infraternal-mes=15.2/s;infraternal-mes=0.2/s;mesh-route-repa=0.1/s | infraternal-mes=90.0/s;infraternal-mes=7.3/s;mesh-route-repa=0.1/s |
| after_load | idle_voluntary_per_s | 1/s | 15.6 | 97.4 |
| after_load | idle_involuntary_per_s | 1/s | 0.05 | 0 |
| after_load | idle_cpu_pct | % | 0.05 | 0.25 |
| after_load | threads |  | 10 | 10 |
| after_load_2 | idle_busiest_threads |  | infraternal-mes=27.7/s;infraternal-mes=0.2/s;mesh-route-repa=0.1/s | infraternal-mes=45.2/s;infraternal-mes=21.5/s;mesh-route-repa=0.1/s |
| after_load_2 | idle_voluntary_per_s | 1/s | 28.1 | 66.8 |
| after_load_2 | idle_involuntary_per_s | 1/s | 0 | 0 |
| after_load_2 | idle_cpu_pct | % | 0.05 | 0.2 |
| after_load_2 | threads |  | 10 | 10 |
| after_load_3 | idle_busiest_threads |  | infraternal-mes=0.5/s;infraternal-mes=0.1/s;node::many_peer=0.0/s | infraternal-mes=0.6/s;infraternal-mes=0.1/s;infraternal-mes=0.1/s |
| after_load_3 | idle_voluntary_per_s | 1/s | 0.6 | 0.7 |
| after_load_3 | idle_involuntary_per_s | 1/s | 0 | 0 |
| after_load_3 | idle_cpu_pct | % | 0 | 0.05 |
| after_load_3 | threads |  | 10 | 10 |
| rekey_storm | established | of 1000 | 1000 | 4096 |
| rekey_storm | wall_ms | ms | 326 | 17533 |
| rekey_storm | hs_p50_ms | ms | 127 | 5877 |
| rekey_storm | hs_p99_ms | ms | 244 | 17337 |
| rekey_storm | hs_max_ms | ms | 246 | 17452 |
| rekey_storm | peers_retried | of 1000 | 0 | 3096 |
| rekey_storm | max_attempts | initiations | 1 | 4 |
| rekey_storm | hub_cpu_s | s | 0.33 | 1.44 |
| rekey_storm | busiest_threads |  | infraternal-mes=0.32s;infraternal-mes=0.02s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=0.83s;infraternal-mes=0.61s;infraternal-mes=0.01s;node::many_peer=0.00s |
| apply_one_change | apply_ms | ms | 138 | 478 |
| apply_reapply | apply_ms | ms | 141 | 468 |
| apply_same | apply_ms | ms | 74.4 | 245 |
| apply_add_one | apply_ms | ms | 148 | 457 |
| apply_remove_one | apply_ms | ms | 139 | 487 |
| counters | counters_ms | ms | 0.83 | 3.4 |
| final | rss | KiB | 34436 | 292540 |
| final | hwm | KiB | 85028 | 292540 |
| final | pss | KiB | 34428 | 292532 |
| final | fds |  | 26 | 26 |

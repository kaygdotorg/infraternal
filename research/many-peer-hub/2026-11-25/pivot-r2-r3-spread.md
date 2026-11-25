| step | metric | unit | N=10 | N=100 | N=1000 | N=4096 |
|---|---|---|---|---|---|---|
| baseline | rss | KiB | 12284 | 12242 [12204-12280] | 12292 [12288-12296] | 12288 |
| baseline | hwm | KiB | 12284 | 12242 [12204-12280] | 12292 [12288-12296] | 12288 |
| baseline | pss | KiB | 12276 | 12234 [12196-12272] | 12284 [12280-12288] | 12280 |
| baseline | fds |  | 17 | 17 | 17 | 17 |
| baseline | idle_busiest_threads |  | infraternal-mes=0.3/s;infraternal-mes=0.1/s;node::many_peer=0.0/s | infraternal-mes=0.3/s;infraternal-mes=0.1/s;node::many_peer=0.0/s | infraternal-mes=0.3/s;infraternal-mes=0.1/s;node::many_peer=0.0/s | infraternal-mes=0.3/s;infraternal-mes=0.1/s;node::many_peer=0.0/s |
| baseline | idle_voluntary_per_s | 1/s | 0.35 | 0.35 | 0.35 | 0.35 |
| baseline | idle_involuntary_per_s | 1/s | 0 | 0 | 0 | 0 |
| baseline | idle_cpu_pct | % | 0 | 0 | 0 | 0 |
| baseline | threads |  | 6 | 6 | 6 | 6 |
| apply_full | apply_ms | ms | 36.1 [34.1-38.1] | 41.1 [39.8-42.4] | 126 [124-128] | 501 [492-510] |
| apply_full | apply_us_per_peer | us | 3612 [3415-3808] | 411 [398-424] | 126 [124-128] | 122 [120-124] |
| configured | rss | KiB | 14132 | 14730 [14704-14756] | 21718 [21704-21732] | 45154 [45152-45156] |
| configured | hwm | KiB | 14132 | 14730 [14704-14756] | 21820 [21808-21832] | 47006 [46980-47032] |
| configured | pss | KiB | 14124 | 14722 [14696-14748] | 21710 [21696-21724] | 45146 [45144-45148] |
| configured | fds |  | 26 | 26 | 26 | 26 |
| configured | rss_per_peer | B | 189235 | 25477 [25354-25600] | 9652 [9634-9671] | 8216 [8216-8217] |
| configured | routes |  | 12 | 102 | 1002 | 4098 |
| configured | nft_lines |  | 51 | 186 | 1536 | 6180 |
| configured | mesh_mtu | B | 1280 | 1280 | 1280 | 1280 |
| configured | idle_busiest_threads |  | infraternal-mes=0.7/s;infraternal-mes=0.2/s;mesh-route-repa=0.1/s | infraternal-mes=0.8/s;infraternal-mes=0.2/s;mesh-route-repa=0.1/s | infraternal-mes=0.6/s;infraternal-mes=0.2/s;mesh-route-repa=0.1/s | infraternal-mes=0.7/s;infraternal-mes=0.2/s;node::many_peer=0.0/s |
| configured | idle_voluntary_per_s | 1/s | 0.95 | 1.02 [1-1.05] | 0.925 [0.85-1] | 0.8 |
| configured | idle_involuntary_per_s | 1/s | 0 | -0.1 [-0.2-0] | -0.075 [-0.15-0] | -5.9 [-5.95--5.85] |
| configured | idle_cpu_pct | % | 0.05 | 0.05 | 0.025 [0-0.05] | 0.05 |
| configured | threads |  | 8 | 8 | 8 | 8 |
| cold_storm | established | of 10 | 10 | 100 | 1000 | 4096 |
| cold_storm | wall_ms | ms | 4.45 [4.3-4.6] | 33.6 [33.5-33.7] | 6045 [6045-6046] | 28201 [28114-28288] |
| cold_storm | hs_p50_ms | ms | 3.08 [2.47-3.69] | 16.2 [16.1-16.4] | 128 [127-128] | 11225 [11175-11275] |
| cold_storm | hs_p99_ms | ms | 3.64 [3.42-3.85] | 25.8 [25.6-25.9] | 5974 [5974-5975] | 25973 [23895-28051] |
| cold_storm | hs_max_ms | ms | 3.67 [3.46-3.89] | 25.8 [25.7-25.9] | 5987 [5987-5987] | 28159 [28073-28245] |
| cold_storm | peers_retried | of 10 | 0 | 0 | 500 | 3596 |
| cold_storm | max_attempts | initiations | 1 | 1 | 2 | 6 |
| cold_storm | hub_cpu_s | s | 0 | 0.03 | 0.38 | 1.86 |
| cold_storm | sim_cpu_s | s | 0 | 0.02 | 0.32 | 2.1 [2.03-2.17] |
| connected | rss | KiB | 14634 [14632-14636] | 15592 [15564-15620] | 23954 [23892-24016] | 51420 [51364-51476] |
| connected | hwm | KiB | 14634 [14632-14636] | 15718 [15664-15772] | 24572 [24412-24732] | 53682 [53552-53812] |
| connected | pss | KiB | 14626 [14624-14628] | 15584 [15556-15612] | 23946 [23884-24008] | 51412 [51356-51468] |
| connected | fds |  | 26 | 26 | 26 | 26 |
| connected | rss_per_peer | B | 240640 [240435-240845] | 34304 [33628-34980] | 11942 [11882-12001] | 9783 [9769-9797] |
| connected | idle_busiest_threads |  | infraternal-mes=0.6/s;infraternal-mes=0.2/s;mesh-route-repa=0.1/s | infraternal-mes=1.6/s;infraternal-mes=0.6/s;infraternal-mes=0.2/s | infraternal-mes=18.2/s;infraternal-mes=5.2/s;mesh-route-repa=0.1/s | infraternal-mes=33.0/s;infraternal-mes=22.2/s;mesh-route-repa=0.1/s |
| connected | idle_voluntary_per_s | 1/s | 0.9 | 2.45 | 23.7 [23.2-24.2] | 58.8 [53.8-63.7] |
| connected | idle_involuntary_per_s | 1/s | 0 | 0 | -0.025 [-0.05-0] | -45.6 [-48.8--42.5] |
| connected | idle_cpu_pct | % | 0 | 0.025 [0-0.05] | 0.05 | 0.2 |
| connected | threads |  | 9 | 8.5 [8-9] | 8 | 8 |
| connected_2 | idle_busiest_threads |  | infraternal-mes=0.3/s;infraternal-mes=0.1/s;mesh-route-repa=0.1/s | infraternal-mes=0.3/s;infraternal-mes=0.1/s;mesh-route-repa=0.1/s | infraternal-mes=20.1/s;infraternal-mes=6.0/s;infraternal-mes=0.1/s | infraternal-mes=42.8/s;infraternal-mes=17.2/s;infraternal-mes=0.2/s |
| connected_2 | idle_voluntary_per_s | 1/s | 0.475 [0.45-0.5] | 0.475 [0.45-0.5] | 26.1 [26-26.2] | 65.2 [60.4-70] |
| connected_2 | idle_involuntary_per_s | 1/s | 0.05 [0-0.1] | 0 | 0 | 0.05 [0-0.1] |
| connected_2 | idle_cpu_pct | % | 0 | 0 | 0.1 | 0.375 [0.35-0.4] |
| connected_2 | threads |  | 8 | 8 | 8 | 8.5 [8-9] |
| keepalive25 | idle_voluntary_per_s | 1/s | 1.6 [1.55-1.65] | 6.66 [6.2-7.12] | 22.5 [22.1-22.9] | 42.7 [40.9-44.5] |
| keepalive25 | idle_cpu_pct | % | 0 | 0.0335 [0.017-0.05] | 0.1 | 0.283 |
| send_1_max | offered_mbit | Mbit/s | 2131 [2114-2148] | 2106 [2093-2119] | 2116 [2110-2121] | 2066 [2066-2066] |
| send_1_max | delivered_mbit | Mbit/s | 2131 [2114-2148] | 2106 [2093-2119] | 2116 [2110-2121] | 2066 [2066-2066] |
| send_1_max | loss_pct | % | 0 | 0 | 0 | 0 |
| send_1_max | hub_cpu_s | s | 16.2 [16.1-16.2] | 16.1 [16.1-16.1] | 16.2 [16.1-16.2] | 16.1 [16.1-16.1] |
| send_1_max | hub_cpu_s_per_gbit | cpu-s/Gbit | 0.76 | 0.765 [0.76-0.77] | 0.76 | 0.78 |
| send_1_max | busiest_threads |  | infraternal-mes=8.11s;infraternal-mes=7.99s;gotatun-crypto-=0.01s;gotatun-crypto-=0.01s | infraternal-mes=8.06s;infraternal-mes=8.00s;gotatun-crypto-=0.01s;gotatun-crypto-=0.01s | infraternal-mes=8.00s;infraternal-mes=8.00s;infraternal-mes=0.05s;gotatun-crypto-=0.03s | infraternal-mes=7.87s;infraternal-mes=7.82s;infraternal-mes=0.22s;infraternal-mes=0.08s |
| send_1_max | sim_cpu_s | s | 6.46 [6.45-6.46] | 6.49 [6.48-6.49] | 6.49 | 6.54 [6.53-6.55] |
| send_1_max | hub_ns_counters |  | Ip.InReceives=4128444;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4128444;Udp.InDatagrams=4128444;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=6;Udp.RcvbufErrors=0 | Ip.InReceives=4138330;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4138330;Udp.InDatagrams=4138330;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=39;Udp.RcvbufErrors=0 | Ip.InReceives=4121805;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4121805;Udp.InDatagrams=4121805;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=442;Udp.RcvbufErrors=0 | Ip.InReceives=4035917;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4035917;Udp.InDatagrams=4035917;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=1860;Udp.RcvbufErrors=0 |
| send_1_1000mbit | offered_mbit | Mbit/s | 976 | 976 | 976 | 976 |
| send_1_1000mbit | delivered_mbit | Mbit/s | 976 | 976 | 976 | 976 |
| send_1_1000mbit | loss_pct | % | 0 | 0 | 0 | 0 |
| send_1_1000mbit | hub_cpu_s | s | 9.52 [9.51-9.53] | 9.54 [9.52-9.56] | 9.64 [9.63-9.64] | 9.91 [9.91-9.92] |
| send_1_1000mbit | hub_cpu_s_per_gbit | cpu-s/Gbit | 0.975 [0.97-0.98] | 0.98 | 0.99 | 1.02 |
| send_1_1000mbit | busiest_threads |  | infraternal-mes=8.34s;infraternal-mes=1.19s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=5.71s;infraternal-mes=3.81s;infraternal-mes=0.01s;node::many_peer=0.00s | infraternal-mes=5.59s;infraternal-mes=3.98s;infraternal-mes=0.05s;infraternal-mes=0.02s | infraternal-mes=6.00s;infraternal-mes=3.58s;infraternal-mes=0.24s;infraternal-mes=0.08s |
| send_1_1000mbit | sim_cpu_s | s | 6.84 [6.82-6.86] | 6.85 [6.83-6.87] | 6.88 [6.87-6.88] | 6.91 [6.89-6.93] |
| send_1_1000mbit | hub_ns_counters |  | Ip.InReceives=1905490;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1905490;Udp.InDatagrams=1905490;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=5;Udp.RcvbufErrors=0 | Ip.InReceives=1905490;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1905490;Udp.InDatagrams=1905490;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=56;Udp.RcvbufErrors=0 | Ip.InReceives=1905490;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1905490;Udp.InDatagrams=1905490;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=455;Udp.RcvbufErrors=0 | Ip.InReceives=1905490;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1905490;Udp.InDatagrams=1905490;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=1875;Udp.RcvbufErrors=0 |
| send_1_400mbit | offered_mbit | Mbit/s | 390 | 390 | 390 | 390 |
| send_1_400mbit | delivered_mbit | Mbit/s | 390 | 390 | 390 | 390 |
| send_1_400mbit | loss_pct | % | 0 | 0 | 0 | 0 |
| send_1_400mbit | hub_cpu_s | s | 5.61 [5.59-5.63] | 5.61 [5.57-5.64] | 5.71 | 5.94 [5.93-5.95] |
| send_1_400mbit | hub_cpu_s_per_gbit | cpu-s/Gbit | 1.44 [1.43-1.44] | 1.44 [1.43-1.45] | 1.46 | 1.52 |
| send_1_400mbit | busiest_threads |  | infraternal-mes=4.33s;infraternal-mes=1.29s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=4.88s;infraternal-mes=0.69s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=3.67s;infraternal-mes=1.97s;infraternal-mes=0.05s;infraternal-mes=0.02s | infraternal-mes=3.92s;infraternal-mes=1.75s;infraternal-mes=0.24s;infraternal-mes=0.04s |
| send_1_400mbit | sim_cpu_s | s | 7.97 [7.96-7.98] | 8.02 | 8 [8-8.01] | 8.01 [8-8.02] |
| send_1_400mbit | hub_ns_counters |  | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=6;Udp.RcvbufErrors=0 | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=38;Udp.RcvbufErrors=0 | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=431;Udp.RcvbufErrors=0 | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=1882;Udp.RcvbufErrors=0 |
| send_10_max | offered_mbit | Mbit/s | 2092 [2080-2104] | 2075 [2064-2087] | 2065 [2062-2068] | 2458 [2328-2587] |
| send_10_max | delivered_mbit | Mbit/s | 2092 [2080-2104] | 2075 [2064-2087] | 2065 [2062-2068] | 734 [648-820] |
| send_10_max | loss_pct | % | 0 | 0 | 0 | 69.9 [64.8-74.9] |
| send_10_max | hub_cpu_s | s | 16.7 [16.7-16.8] | 16.7 [16.7-16.7] | 16.7 [16.7-16.7] | 10.8 [10.7-10.9] |
| send_10_max | hub_cpu_s_per_gbit | cpu-s/Gbit | 0.8 | 0.805 [0.8-0.81] | 0.81 | 1.49 [1.33-1.65] |
| send_10_max | busiest_threads |  | infraternal-mes=8.37s;infraternal-mes=8.32s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=8.39s;infraternal-mes=8.34s;infraternal-mes=0.01s;node::many_peer=0.00s | infraternal-mes=8.35s;infraternal-mes=8.31s;infraternal-mes=0.05s;infraternal-mes=0.01s | infraternal-mes=6.22s;infraternal-mes=4.40s;infraternal-mes=0.24s;infraternal-mes=0.04s |
| send_10_max | sim_cpu_s | s | 6.39 [6.38-6.41] | 6.4 [6.39-6.41] | 6.42 [6.42-6.43] | 8.32 [7.78-8.87] |
| send_10_max | hub_ns_counters |  | Ip.InReceives=4062514;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4062514;Udp.InDatagrams=4062514;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=10;Udp.RcvbufErrors=0 | Ip.InReceives=4075832;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4075832;Udp.InDatagrams=4075832;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=61;Udp.RcvbufErrors=0 | Ip.InReceives=4027186;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=4027186;Udp.InDatagrams=4027186;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=474;Udp.RcvbufErrors=0 | Ip.InReceives=3074351;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=3074351;Udp.InDatagrams=3074351;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=2288;Udp.RcvbufErrors=0 |
| send_10_1000mbit | offered_mbit | Mbit/s | 976 | 976 | 976 | 976 |
| send_10_1000mbit | delivered_mbit | Mbit/s | 976 | 976 | 976 | 974 [972-976] |
| send_10_1000mbit | loss_pct | % | 0 | 0 | 0 | 0.165 [0-0.33] |
| send_10_1000mbit | hub_cpu_s | s | 9.59 | 9.61 [9.59-9.63] | 9.71 [9.7-9.73] | 10.2 [10.2-10.2] |
| send_10_1000mbit | hub_cpu_s_per_gbit | cpu-s/Gbit | 0.98 | 0.985 [0.98-0.99] | 0.995 [0.99-1] | 1.05 |
| send_10_1000mbit | busiest_threads |  | infraternal-mes=4.80s;infraternal-mes=4.77s;infraternal-mes=0.01s;node::many_peer=0.00s | infraternal-mes=6.36s;infraternal-mes=3.21s;infraternal-mes=0.01s;node::many_peer=0.00s | infraternal-mes=5.55s;infraternal-mes=4.06s;infraternal-mes=0.06s;infraternal-mes=0.01s | infraternal-mes=5.04s;infraternal-mes=4.86s;infraternal-mes=0.23s;infraternal-mes=0.09s |
| send_10_1000mbit | sim_cpu_s | s | 6.87 [6.86-6.87] | 6.89 [6.86-6.92] | 6.94 [6.9-6.97] | 7.02 [7-7.04] |
| send_10_1000mbit | hub_ns_counters |  | Ip.InReceives=1905490;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1905490;Udp.InDatagrams=1905490;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=10;Udp.RcvbufErrors=0 | Ip.InReceives=1905490;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1905490;Udp.InDatagrams=1905490;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=44;Udp.RcvbufErrors=0 | Ip.InReceives=1905490;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1905490;Udp.InDatagrams=1905490;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=431;Udp.RcvbufErrors=0 | Ip.InReceives=1906597;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1906597;Udp.InDatagrams=1906597;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=3983;Udp.RcvbufErrors=0 |
| send_10_400mbit | offered_mbit | Mbit/s | 390 | 390 | 390 | 390 |
| send_10_400mbit | delivered_mbit | Mbit/s | 254 [254-254] | 255 [253-256] | 24.9 [20.8-29] | 390 |
| send_10_400mbit | loss_pct | % | 35 [35-35] | 34.8 [34.5-35.1] | 93.6 [92.6-94.7] | 0 |
| send_10_400mbit | hub_cpu_s | s | 4.34 [4.32-4.36] | 4.37 [4.36-4.37] | 2.24 [2.2-2.28] | 6.37 [6.36-6.37] |
| send_10_400mbit | hub_cpu_s_per_gbit | cpu-s/Gbit | 1.71 [1.7-1.72] | 1.71 [1.71-1.72] | 9.22 [7.86-10.6] | 1.63 |
| send_10_400mbit | busiest_threads |  | infraternal-mes=2.48s;infraternal-mes=1.85s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=2.38s;infraternal-mes=1.98s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=1.19s;infraternal-mes=1.09s;infraternal-mes=0.01s;node::many_peer=0.00s | infraternal-mes=4.32s;infraternal-mes=1.78s;infraternal-mes=0.23s;infraternal-mes=0.04s |
| send_10_400mbit | sim_cpu_s | s | 8.68 [8.68-8.69] | 8.71 | 9.88 [9.86-9.9] | 8.05 |
| send_10_400mbit | hub_ns_counters |  | Ip.InReceives=628763;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=628763;Udp.InDatagrams=628763;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=10;Udp.RcvbufErrors=0 | Ip.InReceives=630795;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=630795;Udp.InDatagrams=630795;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=80;Udp.RcvbufErrors=0 | Ip.InReceives=409717;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=409717;Udp.InDatagrams=409717;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=1002;Udp.RcvbufErrors=0 | Ip.InReceives=763914;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=763914;Udp.InDatagrams=763914;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=5191;Udp.RcvbufErrors=0 |
| after_load | rss | KiB | 21674 [21600-21748] | 27364 [27216-27512] | 85314 [85184-85444] | 280374 [280052-280696] |
| after_load | hwm | KiB | 21674 [21600-21748] | 27364 [27216-27512] | 85314 [85184-85444] | 280374 [280052-280696] |
| after_load | pss | KiB | 21666 [21592-21740] | 27356 [27208-27504] | 85306 [85176-85436] | 280366 [280044-280688] |
| after_load | fds |  | 26 | 26 | 26 | 26 |
| after_load | rss_per_peer | B | 961536 [953958-969114] | 154850 [152945-156754] | 74774 [74637-74912] | 67022 [66941-67102] |
| after_load_15s | rss | KiB | 16208 [16176-16240] | 21716 [21700-21732] | 77960 [77892-78028] | 269782 [269276-270288] |
| after_load_15s | hwm | KiB | 21502 [21388-21616] | 27206 [27156-27256] | 85082 [84984-85180] | 280220 [279968-280472] |
| after_load_15s | pss | KiB | 16200 [16168-16232] | 21708 [21692-21724] | 77952 [77884-78020] | 269774 [269268-270280] |
| after_load_15s | fds |  | 26 | 26 | 26 | 26 |
| after_load | idle_busiest_threads |  | infraternal-mes=1.8/s;infraternal-mes=1.2/s;infraternal-mes=0.1/s | infraternal-mes=0.9/s;infraternal-mes=0.2/s;infraternal-mes=0.1/s | infraternal-mes=22.3/s;infraternal-mes=3.8/s;mesh-route-repa=0.1/s | infraternal-mes=24.2/s;infraternal-mes=10.5/s;mesh-route-repa=0.1/s |
| after_load | idle_voluntary_per_s | 1/s | 3.25 [3.05-3.45] | 1.32 [1.25-1.4] | 26.5 [26.2-26.9] | 51.7 [34.9-68.5] |
| after_load | idle_involuntary_per_s | 1/s | 0 | 0 | 0 | 0.025 [0-0.05] |
| after_load | idle_cpu_pct | % | 0 | 0.025 [0-0.05] | 0.05 | 0.2 |
| after_load | threads |  | 10 | 10 | 10 | 10 |
| after_load_2 | idle_busiest_threads |  | infraternal-mes=0.6/s;infraternal-mes=0.2/s;mesh-route-repa=0.1/s | infraternal-mes=0.7/s;mesh-route-repa=0.1/s;infraternal-mes=0.1/s | infraternal-mes=20.6/s;infraternal-mes=4.4/s;mesh-route-repa=0.1/s | infraternal-mes=34.2/s;infraternal-mes=11.8/s;mesh-route-repa=0.1/s |
| after_load_2 | idle_voluntary_per_s | 1/s | 0.6 [0.4-0.8] | 0.975 [0.8-1.15] | 26.6 [25.1-28.1] | 53.4 [46-60.8] |
| after_load_2 | idle_involuntary_per_s | 1/s | 0 | 0 | 0.025 [0-0.05] | 0.05 |
| after_load_2 | idle_cpu_pct | % | 0 | 0 | 0.075 [0.05-0.1] | 0.2 |
| after_load_2 | threads |  | 10 | 10 | 10 | 10 |
| after_load_3 | idle_busiest_threads |  | infraternal-mes=0.5/s;infraternal-mes=0.1/s;mesh-route-repa=0.1/s | infraternal-mes=0.2/s;infraternal-mes=0.2/s;mesh-route-repa=0.1/s | infraternal-mes=0.5/s;infraternal-mes=0.1/s;node::many_peer=0.0/s | infraternal-mes=0.4/s;infraternal-mes=0.1/s;node::many_peer=0.0/s |
| after_load_3 | idle_voluntary_per_s | 1/s | 0.825 [0.6-1.05] | 0.575 [0.55-0.6] | 0.6 | 0.525 [0.5-0.55] |
| after_load_3 | idle_involuntary_per_s | 1/s | 0 | 0 | 0 | 0 |
| after_load_3 | idle_cpu_pct | % | 0 | 0 | 0 | 0.075 [0.05-0.1] |
| after_load_3 | threads |  | 10 | 10 | 10 | 10 |
| rekey_storm | established | of 10 | 10 | 100 | 1000 | 4096 |
| rekey_storm | wall_ms | ms | 4.55 [4.5-4.6] | 32.8 [32.6-32.9] | 325 [323-327] | 17538 [17537-17539] |
| rekey_storm | hs_p50_ms | ms | 3.59 [3.57-3.61] | 14.1 [13.5-14.8] | 128 [127-129] | 5878 [5876-5880] |
| rekey_storm | hs_p99_ms | ms | 3.69 [3.65-3.73] | 25 [24.7-25.2] | 244 [243-245] | 17336 [17336-17337] |
| rekey_storm | hs_max_ms | ms | 3.72 [3.69-3.75] | 25 [24.7-25.3] | 246 [245-247] | 17452 [17450-17454] |
| rekey_storm | peers_retried | of 10 | 0 | 0 | 0 | 3096 |
| rekey_storm | max_attempts | initiations | 1 | 1 | 1 | 4 |
| rekey_storm | hub_cpu_s | s | 0.005 [0-0.01] | 0.03 | 0.34 | 1.44 [1.44-1.45] |
| rekey_storm | busiest_threads |  | infraternal-mes=0.01s;node::many_peer=0.00s;mesh-route-repa=0.00s;mesh-dns-udp=0.00s | infraternal-mes=0.01s;infraternal-mes=0.01s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=0.17s;infraternal-mes=0.16s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=0.76s;infraternal-mes=0.67s;node::many_peer=0.00s;mesh-route-repa=0.00s |
| apply_one_change | apply_ms | ms | 49.3 [43.5-55] | 50.1 [49.7-50.5] | 116 [108-123] | 424 [401-447] |
| apply_reapply | apply_ms | ms | 53.9 [45.3-62.6] | 45.8 [45.3-46.2] | 123 [101-144] | 413 [411-416] |
| apply_same | apply_ms | ms | 1.42 [1.4-1.44] | 5.78 | 58.7 [49.5-67.9] | 214 [214-214] |
| apply_add_one | apply_ms | ms | 38.5 [32.1-44.8] | 45.4 [44.9-45.9] | 129 [128-130] | 412 [408-415] |
| apply_remove_one | apply_ms | ms | 42.3 [37.9-46.8] | 51.2 [46.8-55.7] | 144 [144-145] | 408 [408-409] |
| counters | counters_ms | ms | 0.025 [0.02-0.03] | 0.08 | 0.885 [0.88-0.89] | 3.44 [3.42-3.46] |
| final | rss | KiB | 16832 [16804-16860] | 22020 [21356-22684] | 83868 [83764-83972] | 293636 [293212-294060] |
| final | hwm | KiB | 21502 [21388-21616] | 27206 [27156-27256] | 85082 [84984-85180] | 293636 [293212-294060] |
| final | pss | KiB | 16824 [16796-16852] | 22012 [21348-22676] | 83860 [83756-83964] | 293628 [293204-294052] |
| final | fds |  | 26 | 26 | 26 | 26 |
| send_100_max | offered_mbit | Mbit/s |  | 2503 [2484-2522] | 2037 [1945-2128] | 2204 [2198-2211] |
| send_100_max | delivered_mbit | Mbit/s |  | 1146 [1122-1169] | 1488 [1420-1557] | 204 [184-225] |
| send_100_max | loss_pct | % |  | 54.2 [52.9-55.5] | 26.6 [20-33.3] | 90.7 [89.8-91.7] |
| send_100_max | hub_cpu_s | s |  | 10.6 [10.5-10.8] | 15.1 [14.2-16] | 13.6 [13.6-13.7] |
| send_100_max | hub_cpu_s_per_gbit | cpu-s/Gbit |  | 0.925 [0.92-0.93] | 1.02 [1-1.03] | 6.74 [6.07-7.4] |
| send_100_max | busiest_threads |  |  | infraternal-mes=6.15s;infraternal-mes=4.31s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=7.07s;infraternal-mes=7.03s;infraternal-mes=0.05s;infraternal-mes=0.03s | infraternal-mes=6.69s;infraternal-mes=6.57s;infraternal-mes=0.23s;infraternal-mes=0.08s |
| send_100_max | sim_cpu_s | s |  | 7.68 [7.65-7.7] | 6.84 [6.62-7.06] | 9.37 [9.32-9.42] |
| send_100_max | hub_ns_counters |  |  | Ip.InReceives=3558661;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=3558661;Udp.InDatagrams=3558661;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=148;Udp.RcvbufErrors=0 | Ip.InReceives=3465444;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=3465444;Udp.InDatagrams=3465444;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=1362;Udp.RcvbufErrors=0 | Ip.InReceives=2326558;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=2326558;Udp.InDatagrams=2201509;Udp.NoPorts=0;Udp.InErrors=125049;Udp.OutDatagrams=3667;Udp.RcvbufErrors=125049 |
| send_100_1000mbit | offered_mbit | Mbit/s |  | 976 | 976 | 976 |
| send_100_1000mbit | delivered_mbit | Mbit/s |  | 874 [856-891] | 975 [975-975] | 976 [975-976] |
| send_100_1000mbit | loss_pct | % |  | 10.5 [8.72-12.2] | 0.07 [0.06-0.08] | 0.01 [0-0.02] |
| send_100_1000mbit | hub_cpu_s | s |  | 9.07 [8.96-9.17] | 9.77 [9.77-9.78] | 9.98 [9.97-9.99] |
| send_100_1000mbit | hub_cpu_s_per_gbit | cpu-s/Gbit |  | 1.04 [1.03-1.05] | 1 | 1.02 |
| send_100_1000mbit | busiest_threads |  |  | infraternal-mes=6.31s;infraternal-mes=2.66s;infraternal-mes=0.01s;node::many_peer=0.00s | infraternal-mes=5.68s;infraternal-mes=4.01s;infraternal-mes=0.05s;node::many_peer=0.00s | infraternal-mes=5.10s;infraternal-mes=4.59s;infraternal-mes=0.23s;infraternal-mes=0.04s |
| send_100_1000mbit | sim_cpu_s | s |  | 7.18 [7.15-7.21] | 6.96 [6.96-6.97] | 6.99 [6.98-7] |
| send_100_1000mbit | hub_ns_counters |  |  | Ip.InReceives=1789134;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1789134;Udp.InDatagrams=1789134;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=174;Udp.RcvbufErrors=0 | Ip.InReceives=1905011;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1905011;Udp.InDatagrams=1905011;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=998;Udp.RcvbufErrors=0 | Ip.InReceives=1905392;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=1905392;Udp.InDatagrams=1905392;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=2262;Udp.RcvbufErrors=0 |
| send_100_400mbit | offered_mbit | Mbit/s |  | 390 | 390 | 390 |
| send_100_400mbit | delivered_mbit | Mbit/s |  | 390 | 390 | 390 |
| send_100_400mbit | loss_pct | % |  | 0 | 0 | 0 |
| send_100_400mbit | hub_cpu_s | s |  | 5.65 [5.64-5.67] | 5.75 [5.74-5.77] | 6.01 |
| send_100_400mbit | hub_cpu_s_per_gbit | cpu-s/Gbit |  | 1.45 | 1.48 [1.47-1.48] | 1.54 |
| send_100_400mbit | busiest_threads |  |  | infraternal-mes=3.14s;infraternal-mes=2.47s;node::many_peer=0.00s;mesh-route-repa=0.00s | infraternal-mes=3.53s;infraternal-mes=2.17s;infraternal-mes=0.06s;infraternal-mes=0.01s | infraternal-mes=2.98s;infraternal-mes=2.75s;infraternal-mes=0.24s;infraternal-mes=0.05s |
| send_100_400mbit | sim_cpu_s | s |  | 8.01 [8-8.02] | 8.01 | 7.98 [7.97-7.99] |
| send_100_400mbit | hub_ns_counters |  |  | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=109;Udp.RcvbufErrors=0 | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=518;Udp.RcvbufErrors=0 | Ip.InReceives=762198;Ip.InAddrErrors=0;Ip.ForwDatagrams=0;Ip.InDiscards=0;Ip.InDelivers=762198;Udp.InDatagrams=762198;Udp.NoPorts=0;Udp.InErrors=0;Udp.OutDatagrams=2070;Udp.RcvbufErrors=0 |
| all_touched | rss | KiB |  |  | 85314 [85184-85444] | 280374 [280052-280696] |
| all_touched | hwm | KiB |  |  | 85314 [85184-85444] | 280374 [280052-280696] |
| all_touched | pss | KiB |  |  | 85306 [85176-85436] | 280366 [280044-280688] |
| all_touched | fds |  |  |  | 26 | 26 |
| all_touched | rss_per_peer | B |  |  | 74774 [74637-74912] | 67022 [66941-67102] |

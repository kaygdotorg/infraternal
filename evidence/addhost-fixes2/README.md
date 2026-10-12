<!-- Records reviewed continuation evidence for host provisioning #169. -->
# Host provisioning continuation

R1: 10/10 fresh supported-target runs reached Done after the drain repair.
The ordinary baseline and frozen pre-fix samples also reached Done 10/10 in
this load window; these samples do not estimate a production failure rate.
The delayed-credit live regression fails before the repair and passes after it.
The real socket regression reproduces the mechanism on b4ae9e22.

Per-step timings (milliseconds, range of ten samples; detailed load and machine
records in each log). Network discovery refusal is expected before key sign-in.

| Setup step | b4ae9e22 | Frozen pre-fix | Drain repair |
| --- | --- | --- | --- |
| network_discovery | 116.337–172.841 | 118.097–171.324 | 100.332–160.512 |
| key_sign_in | 167.301–207.047 | 171.068–267.897 | 143.945–201.025 |
| check | 119.194–164.251 | 94.489–215.418 | 70.096–106.806 |
| upload | 307.621–1778.055 | 615.057–1313.084 | 303.577–920.620 |
| join | 104.917–567.107 | 103.587–681.248 | 92.918–204.910 |
| install | 80.001–116.852 | 91.869–125.496 | 58.662–136.822 |
| start | 217.573–317.025 | 243.170–362.184 | 153.156–257.324 |
| linger | 36.421–62.103 | 38.712–80.857 | 25.605–50.599 |
| commit | 23.078–66.415 | 23.178–63.246 | 16.969–28.427 |

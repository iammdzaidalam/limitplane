# Azure flood test

Measures what the XDP fast path buys on real NICs: one VM floods another with UDP, first with no XDP,
then with `limitplane-xdp` in native mode (pps guard), then with the flood source banned through the
gateway API. A well-behaved client measures the gateway's p99 the whole time.

```
attacker VM (Standard_D4s_v5)                      target VM (Standard_D2s_v5)
  10.42.0.5  probe: 20 req/s, demo-pro-key  ---->  10.42.0.4:9090  limitplane (demo mode)
  10.42.0.6  udpflood, all cores            ---->  10.42.0.4:9999  udpflood --listen (counts arrivals)
                                                   eth0: limitplane-xdp --mode native
```

Both VMs get accelerated networking when the size supports it (both defaults do). Traffic stays on
private IPs inside one VNet; SSH is open only to the public IP of the machine that ran `provision.sh`.

## Cost

Pay-as-you-go list prices for Linux in East US, rounded. Check the
[pricing calculator](https://azure.microsoft.com/pricing/calculator/) for your region.

| Resource | Per hour |
| --- | --- |
| Standard_D2s_v5 target (2 vCPU, 8 GiB) | ~$0.096 |
| Standard_D4s_v5 attacker (4 vCPU, 16 GiB) | ~$0.192 |
| 2 Standard public IPv4 | ~$0.010 |
| 2 StandardSSD 30 GiB OS disks | ~$0.007 |
| Traffic inside one VNet | free |
| **Total** | **~$0.31/hour** |

A full run (provision about 5 minutes, test about 3, teardown) costs a few cents if you tear down
straight after. Stopped-but-not-deleted VMs still bill for disks and IPs, so use `teardown.sh`.

## Steps

Needs the [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli), Go 1.26 and `ssh`.
The scripts build the binaries locally and copy them over, so the VMs need no toolchain.

```bash
az login
az account set --subscription <id>   # if you have several

cd xdp/azure
./provision.sh     # resource group limitplane-xdp, VNet, NSG, 2 VMs; prints their public IPs
./run-test.sh      # about 3 minutes; prints a table and saves it to results/
./teardown.sh      # deletes the resource group (NO_WAIT=1 to return immediately)
```

All three are idempotent: rerunning `provision.sh` keeps what exists (and refreshes the SSH rule if your IP
changed), `run-test.sh` resets the target before and after, and `teardown.sh` is a no-op once the group is gone.

Settings live in `common.sh` and can be overridden from the environment, for example:

```bash
LOCATION=westeurope ./provision.sh
TARGET_SIZE=Standard_D2ps_v5 ATTACKER_SIZE=Standard_D4ps_v5 ARCH=arm64 ./provision.sh   # Arm (Ampere)
DUR=60 GUARD_PPS=5000 ./run-test.sh
MODE=generic ./run-test.sh      # if native attach fails on your image or NIC
```

If `az vm create` fails with a quota error, request vCPU quota for the Dsv5 family in that region, or pick
other sizes.

## Reading the results

```
phase       sent_pps nic_rx_pps app_rx_pps   ban_drop  rate_drop   cpu% softirq%   p99_ms  errors
no-xdp           ...
xdp-rate         ...
xdp-ban          ...
```

- `sent_pps`: what the attacker managed to send.
- `nic_rx_pps`: `eth0` rx_packets on the target. With accelerated networking most packets arrive on the
  VF (`enP*`), which hv_netvsc folds into eth0's counters; whether XDP-dropped packets are counted there
  depends on the VF driver, so treat the XDP columns as the source of truth for drops.
- `app_rx_pps`: datagrams the UDP sink read, i.e. what got through the whole kernel stack.
- `ban_drop`, `rate_drop`: per-second deltas of `limitplane_xdp_packets_total`.
- `cpu%`, `softirq%`: target CPU over the flood, from `/proc/stat`. The win shows up here: without XDP the
  flood burns softirq time on every core that takes interrupts; with XDP the drop costs a map lookup.
- `p99_ms`, `errors`: the probe's view of the gateway. Timeouts count as errors, not latency.

What to expect: `no-xdp` has high softirq and a worse p99; `xdp-rate` passes about `GUARD_PPS` from the
flood source and drops the rest; `xdp-ban` drops everything from the flood source and `app_rx_pps`
falls to about zero. The flood never touches the gateway port, so any p99 change is pure CPU contention.

Native mode attaches to `eth0` (hv_netvsc), which installs the program on the accelerated-networking VF
too. Newer sizes with the MANA NIC need a kernel whose `mana` driver supports XDP; Ubuntu 24.04 has one.

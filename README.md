# Dynamic Host Blocking System
### SDN Mininet Simulation — OpenFlow 1.3 / Ryu Controller

---

## Problem Statement

Implement an SDN-based system that dynamically detects and blocks suspicious hosts based on real-time traffic behaviour, without any manual administrator intervention. The system monitors per-source-IP packet rates, flags hosts exceeding a flood threshold, installs OpenFlow DROP rules automatically, and logs all events.

---

## Architecture

```
 ┌──────────────────────────────────────────┐
 │           Ryu SDN Controller             │
 │  packet_in handler:                      │
 │    1. MAC learning                       │
 │    2. IP rate tracking (sliding window)  │
 │    3. Suspicious host detection          │
 │    4. DROP rule installation (p=100)     │
 │  Background monitor (every 5s)           │
 └───────────────────┬──────────────────────┘
       OpenFlow 1.3  │  TCP 6633
 ┌─────────────────────────────────┐
 │        OVS Switch  s1           │
 │  Flow Table:                    │
 │  priority=100 → DROP            │
 │  priority=  0 → CONTROLLER      │
 └──┬────┬────┬────┬───────────────┘
    h1   h2   h3   h4
10.0.0.1  .2  .3  .4
```

---

## Flow Rule Design (Match-Action)

| Priority | Match | Action | Purpose |
|---|---|---|---|
| 100 | `eth_type=0x0800, ipv4_src=<blocked_ip>` | DROP (empty list) | Block suspicious host |
| 0 | `*` (wildcard — table-miss) | `CONTROLLER` | Send all packets to controller |

> Note: Forwarding flow rules (priority 10) were intentionally removed so every packet reaches the controller, keeping rate-tracking counters accurate. Packets are forwarded via packet-out messages instead.

---

## Setup

```bash
# Install Mininet from source
git clone https://github.com/mininet/mininet
cd mininet
sudo ./util/install.sh -a

# Install Ryu
pip3 install eventlet==0.30.2 --break-system-packages
pip3 install ryu --break-system-packages
```

---

## Execution Order

**Terminal 1 — Start controller:**
```bash
cd ~/sdn-project
~/.local/bin/ryu-manager dynamic_blocking_controller.py
```

**Terminal 2 — Start topology:**
```bash
cd ~/sdn-project
sudo python3 topology.py
```

**Inside Mininet CLI:**
```
mininet> pingall
mininet> h1 ping -c 5 10.0.0.2
mininet> h3 ping -f -c 50 10.0.0.1
mininet> h3 ping -c 5 10.0.0.2
mininet> h4 ping -c 5 10.0.0.2
mininet> h2 iperf -s &
mininet> h1 iperf -c 10.0.0.2
mininet> h2 iperf -s &
mininet> h4 iperf -c 10.0.0.2 &
mininet> h3 ping -f -c 50 10.0.0.1
mininet> h4 iperf -c 10.0.0.2
```

**Terminal 3 — Flow table (immediately after h3 gets blocked):**
```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

---

## Expected Results

| Test | Result |
|---|---|
| pingall | 0% dropped (12/12 received) |
| h1 ping h2 (normal) | 0% packet loss |
| h3 flood → block triggers | 62% packet loss mid-flood |
| h3 ping after block | 100% packet loss |
| h4 ping (unaffected) | 0% packet loss |
| iperf h1 → h2 | ~200 Kbits/sec |
| QoS: h4 iperf during attack | ~131 Kbits/sec (maintained) |

---

## Configuration

| Parameter | Default | Description |
|---|---|---|
| `BLOCK_THRESHOLD` | 20 pkts | Packets per window before blocking |
| `PACKET_RATE_WINDOW` | 10 s | Sliding window duration |
| `BLOCK_DURATION` | 60 s | DROP rule hard timeout |
| `MONITOR_INTERVAL` | 5 s | Background sweep frequency |

---

## Proof of Execution

### Topology Startup + Normal Traffic (Scenario 1)
![Topology and pingall](screenshots/topology_pingall.png)

- Mininet topology starts with 4 hosts (h1–h4), 1 switch (s1), TCLink 100 Mbps / 2ms delay
- `pingall` → **0% dropped (12/12 received)** — all hosts reachable
- `h1 ping -c 5 10.0.0.2` → **0% packet loss, avg RTT ~10.7 ms**

---

### Block Case — Flood Attack (Scenario 2)
![Block case](screenshots/block_case.png)

- `h3 ping -f -c 50 10.0.0.1` → **62% packet loss** — block triggers mid-flood
- `h3 ping -c 5 10.0.0.2` → **100% packet loss** — h3 fully blocked
- `h4 ping -c 5 10.0.0.2` → **0% packet loss** — innocent host unaffected

---

### Performance Testing (iperf)
![iperf result](screenshots/iperf.png)

- `h1 iperf -c 10.0.0.2` → **200 Kbits/sec** throughput
- Lower than 100 Mbps link capacity because every packet goes through the controller (no forwarding rules) — deliberate SDN visibility-vs-performance tradeoff

---

### QoS — Legitimate Host Unaffected During Attack
![QoS test](screenshots/qos.png)

- `h4 iperf -c 10.0.0.2` during h3's flood → **131 Kbits/sec maintained**
- Proves QoS preservation: attacker isolated at priority 100, legitimate host continues at full available bandwidth

---

### Flow Table — DROP Rules Installed
![Flow table](screenshots/flowtable.png)

```
priority=100, ip, nw_src=10.0.0.3  actions=drop   ← h3 blocked
priority=100, ip, nw_src=10.0.0.4  actions=drop   ← h4 blocked (QoS test)
priority=100, ip, nw_src=10.0.0.1  actions=drop   ← h1 blocked (QoS test)
priority=0                          actions=CONTROLLER:65535  ← table-miss
```

All DROP rules carry `hard_timeout=60` — automatically removed after 60 seconds.

---

### Controller Event Log (Terminal 1)
![Controller log](screenshots/controller_log.png)

Key log entries:
```
[SWITCH CONNECTED] dpid=0x1  table-miss rule installed
[MONITOR]  10.0.0.3   20 pkts/10s  [OK]
[BLOCKED]  Suspicious host 10.0.0.3  DROP rule installed  priority=100  TTL=60s
[MONITOR]  10.0.0.3   20 pkts/10s  [BLOCKED]
[UNBLOCKED] 10.0.0.3  (block expired after 60s)
```

---

## Files

```
dynamic_blocking_controller.py   # Ryu SDN controller (core logic)
topology.py                      # Mininet star topology (4 hosts, 1 switch)
test_scenarios.sh                # Test guide with commands
README.md                        # This file
screenshots/                     # Proof of execution screenshots
```

---

## References

1. Mininet Overview — http://mininet.org/overview/
2. Ryu SDN Framework — https://ryu.readthedocs.io/
3. OpenFlow 1.3 Specification — https://opennetworking.org/
4. Open vSwitch — https://www.openvswitch.org/
5. Mininet GitHub — https://github.com/mininet/mininet
6. Feamster, N., Rexford, J., & Zegura, E. (2014). The Road to SDN. ACM Queue, 11(12).

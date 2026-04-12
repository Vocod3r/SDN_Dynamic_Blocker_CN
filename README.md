# Dynamic Host Blocking System
### SDN Mininet Simulation — OpenFlow 1.3 / Ryu Controller

---

## Problem Statement

Implement an SDN-based system that dynamically detects and blocks suspicious hosts based on real-time traffic behaviour, without any manual administrator intervention.

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
 │    5. FORWARD rule installation (p=10)   │
 │  Background monitor (every 5s)           │
 └───────────────────┬──────────────────────┘
       OpenFlow 1.3  │  TCP 6633
 ┌─────────────────────────────────┐
 │        OVS Switch  s1           │
 │  Flow Table:                    │
 │  priority=100 → DROP            │
 │  priority= 10 → FORWARD         │
 │  priority=  0 → CONTROLLER      │
 └──┬────┬────┬────┬───────────────┘
    h1   h2   h3   h4
10.0.0.1  .2  .3  .4
```

---

## Flow Rule Design (Match-Action)

| Priority | Match | Action | Purpose |
|---|---|---|---|
| 100 | `eth_type=0x0800, ipv4_src=<blocked_ip>` | DROP (empty) | Block suspicious host |
| 10 | `in_port=X, eth_dst=Y` | `OUTPUT Z` | Forward known traffic |
| 0 | `*` (wildcard) | `CONTROLLER` | Table-miss, send to controller |

---

## Setup

```bash
# Install dependencies
sudo apt install mininet -y
pip3 install eventlet==0.30.2 --break-system-packages
pip3 install ryu --break-system-packages
```

---

## Execution

**Terminal 1 — Controller:**
```bash
~/.local/bin/ryu-manager dynamic_blocking_controller.py
```

**Terminal 2 — Topology:**
```bash
sudo python3 topology.py
```

**Mininet CLI — Tests:**
```
mininet> pingall
mininet> h1 ping -c 5 10.0.0.2
mininet> h3 ping -f -c 50 10.0.0.1
mininet> h3 ping -c 5 10.0.0.2
mininet> h4 ping -c 5 10.0.0.2
```

**Terminal 3 — Evidence:**
```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
cat ~/sdn-project/blocking_events.log
```

---

## Expected Results

| Test | Result |
|---|---|
| pingall | 0% dropped (12/12) |
| h1 ping h2 (normal) | 0% packet loss |
| h3 flood h1 | Block triggers mid-flood |
| h3 ping after block | 100% packet loss |
| h4 ping (unaffected) | 0% packet loss |

---

## Configuration

| Parameter | Default | Description |
|---|---|---|
| `BLOCK_THRESHOLD` | 20 pkts | Packets per window before blocking |
| `PACKET_RATE_WINDOW` | 10 s | Sliding window duration |
| `BLOCK_DURATION` | 60 s | DROP rule hard timeout |
| `FLOW_IDLE_TIMEOUT` | 5 s | Forwarding rule idle timeout |

---

## Files

```
dynamic_blocking_controller.py   # Ryu SDN controller
topology.py                      # Mininet star topology
test_scenarios.sh                # Test guide
README.md                        # This file
```

---

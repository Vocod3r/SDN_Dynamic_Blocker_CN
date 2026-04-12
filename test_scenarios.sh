#!/usr/bin/env bash
# =============================================================================
# Dynamic Host Blocking System – Test Scenarios & Screenshot Guide
# =============================================================================
# Run commands manually inside the Mininet CLI and separate terminals.
#
# Pre-requisites:
#   Terminal 1: ~/.local/bin/ryu-manager dynamic_blocking_controller.py
#   Terminal 2: sudo python3 topology.py
# =============================================================================

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║   Dynamic Host Blocking System – Test Guide          ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

echo "─── SCENARIO 1: Normal Traffic (should be ALLOWED) ───"
echo ""
echo "Inside Mininet CLI (Terminal 2):"
echo "  mininet> pingall"
echo "  mininet> h1 ping -c 5 10.0.0.2"
echo ""
echo "Expected: 0% packet loss on both. No blocking triggered."
echo "Screenshot: pingall result + h1 ping output"
echo ""

echo "─── SCENARIO 2: Flood Attack (h3 should be BLOCKED) ──"
echo ""
echo "Inside Mininet CLI (Terminal 2):"
echo "  mininet> h3 ping -f -c 50 10.0.0.1"
echo "  mininet> h3 ping -c 5 10.0.0.2"
echo "  mininet> h4 ping -c 5 10.0.0.2"
echo ""
echo "Expected:"
echo "  h3 flood  -> partial loss as block triggers mid-flood"
echo "  h3 follow -> 100% packet loss (blocked)"
echo "  h4 follow -> 0% packet loss  (unaffected)"
echo "Screenshot: all three ping outputs"
echo ""

echo "─── FLOW TABLE (Terminal 3) ───────────────────────────"
echo ""
echo "  sudo ovs-ofctl -O OpenFlow13 dump-flows s1"
echo ""
echo "Expected entries:"
echo "  priority=100  ipv4_src=10.0.0.3  actions=drop"
echo "  priority= 10  in_port=X,dl_dst=Y actions=output:Z"
echo "  priority=  0  (table-miss)        actions=CONTROLLER"
echo "Screenshot: full flow table output"
echo ""

echo "─── EVENT LOG ─────────────────────────────────────────"
echo ""
echo "  cat ~/sdn-project/blocking_events.log"
echo "  (or scroll up Terminal 1 to see controller output)"
echo ""
echo "Screenshot: lines showing [BLOCKED] entry for 10.0.0.3"
echo ""

echo "─── CLEANUP ───────────────────────────────────────────"
echo ""
echo "  mininet> exit"
echo "  sudo mn -c"
echo ""

"""
Dynamic Host Blocking System - Ryu SDN Controller
===================================================
Detects suspicious traffic (flood/scan) based on packet rate per source IP,
dynamically installs OpenFlow drop rules, and logs all events.

Flow Table Structure:
  Priority 100  ->  DROP    (blocked suspicious hosts)
  Priority  10  ->  FORWARD (learned unicast destinations, short idle timeout)
  Priority   0  ->  SEND TO CONTROLLER (table-miss)

Author  : [Your Name]
Date    : 2025
Requires: Ryu controller  (pip install ryu)
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, icmp
from ryu.lib import hub

import time
import logging
import os

# ── Tunable thresholds ──────────────────────────────────────────────────────
PACKET_RATE_WINDOW   = 10   # seconds — sliding window for rate measurement
BLOCK_THRESHOLD      = 20   # packets / window -> host flagged suspicious
BLOCK_DURATION       = 60   # seconds before DROP rule expires (0 = permanent)
MONITOR_INTERVAL     = 5    # seconds between background rate-check sweeps

# Forwarding rule timeouts (kept short so controller stays in the loop)
FLOW_IDLE_TIMEOUT    = 5    # idle timeout — rule expires after 5s of inactivity
FLOW_HARD_TIMEOUT    = 0    # no hard timeout on forwarding rules
# ────────────────────────────────────────────────────────────────────────────

LOG_FILE = "blocking_events.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("DynamicBlocker")


class DynamicHostBlockingController(app_manager.RyuApp):
    """
    Ryu application implementing a Dynamic Host Blocking System.

    Behaviour:
      1. Table-miss rule sends all unknown packets to the controller.
      2. MAC learning table maps MAC addresses to switch ports.
      3. Per-source-IP packet timestamps are maintained in a sliding window.
      4. Any host exceeding BLOCK_THRESHOLD packets / PACKET_RATE_WINDOW seconds
         is flagged as suspicious and a high-priority DROP rule is installed.
      5. Safe hosts receive a short-lived forwarding rule (priority 10).
      6. All events are logged to console and blocking_events.log.

    Flow Table at runtime:
      priority=100  match: eth_type=0x0800, ipv4_src=<blocked>  action: DROP
      priority= 10  match: in_port + eth_dst                     action: OUTPUT <port>
      priority=  0  match: * (wildcard)                          action: CONTROLLER
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # MAC learning table  {dpid: {mac: port}}
        self.mac_to_port = {}

        # Packet rate tracker  {dpid: {src_ip: [timestamp, ...]}}
        self.packet_timestamps = {}

        # Currently blocked hosts  {dpid: {src_ip: blocked_at_epoch}}
        self.blocked_hosts = {}

        # Background monitor greenlet
        self.monitor_thread = hub.spawn(self._monitor_loop)

        logger.info("=" * 60)
        logger.info("Dynamic Host Blocking Controller STARTED")
        logger.info(f"  Threshold     : {BLOCK_THRESHOLD} pkts / {PACKET_RATE_WINDOW}s")
        logger.info(f"  Block TTL     : {BLOCK_DURATION}s  (0 = permanent)")
        logger.info(f"  Fwd idle TTL  : {FLOW_IDLE_TIMEOUT}s")
        logger.info(f"  Log file      : {os.path.abspath(LOG_FILE)}")
        logger.info("=" * 60)

    # ─────────────────────────────────────────────────────────────────────────
    # Switch handshake
    # ─────────────────────────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install the table-miss flow entry when a switch connects."""
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        dpid     = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.packet_timestamps.setdefault(dpid, {})
        self.blocked_hosts.setdefault(dpid, {})

        # Priority 0 — table-miss: match everything, send to controller
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)

        logger.info(f"[SWITCH CONNECTED] dpid={dpid:#018x}  table-miss rule installed")

    # ─────────────────────────────────────────────────────────────────────────
    # Packet-in handler
    # ─────────────────────────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Central packet processing pipeline:
          1. Parse packet layers
          2. MAC learning
          3. Extract source IP
          4. Check if blocked -> drop
          5. Rate tracking
          6. Suspicious check -> install DROP rule
          7. Forward + install forwarding flow rule
        """
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        dpid     = datapath.id
        in_port  = msg.match["in_port"]

        # Parse packet layers
        pkt      = packet.Packet(msg.data)
        eth_pkt  = pkt.get_protocol(ethernet.ethernet)
        ip_pkt   = pkt.get_protocol(ipv4.ipv4)
        arp_pkt  = pkt.get_protocol(arp.arp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if eth_pkt is None:
            return

        dst_mac = eth_pkt.dst
        src_mac = eth_pkt.src

        # ── Step 1: MAC learning ───────────────────────────────────────────
        # Record which port this MAC address arrived on
        self.mac_to_port[dpid][src_mac] = in_port

        # ── Step 2: Extract source IP ──────────────────────────────────────
        src_ip = None
        if ip_pkt:
            # For ICMP: only count echo REQUESTS (type 8), not replies (type 0)
            # This prevents h1's reply packets from also being rate-counted
            if icmp_pkt:
                if icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                    src_ip = ip_pkt.src
            else:
                # Non-ICMP IP traffic — count normally
                src_ip = ip_pkt.src
        elif arp_pkt:
            # ARP packets carry IP in the payload
            src_ip = arp_pkt.src_ip

        # ── Step 3: Check if already blocked ──────────────────────────────
        if src_ip and self._is_blocked(dpid, src_ip):
            logger.debug(f"[DROPPED] {src_ip} is currently blocked on dpid={dpid:#x}")
            return  # silently discard; DROP rule handles this in hardware

        # ── Step 4: Rate tracking & suspicious detection ───────────────────
        if src_ip:
            self._record_packet(dpid, src_ip)

            if self._is_suspicious(dpid, src_ip):
                # Install DROP rule and stop processing this packet
                self._block_host(datapath, src_ip)
                return

        # ── Step 5: Normal forwarding ──────────────────────────────────────
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        # Send current packet out immediately (before rule takes effect)
        self._send_packet(datapath, msg, in_port, actions)

    # ─────────────────────────────────────────────────────────────────────────
    # Rate tracking helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _record_packet(self, dpid, src_ip):
        """
        Append current timestamp for src_ip and prune old entries.
        The list always contains only timestamps within PACKET_RATE_WINDOW.
        """
        now = time.time()
        ts  = self.packet_timestamps[dpid].setdefault(src_ip, [])
        ts.append(now)
        self.packet_timestamps[dpid][src_ip] = [
            t for t in ts if now - t <= PACKET_RATE_WINDOW
        ]

    def _is_suspicious(self, dpid, src_ip):
        """
        Return True if src_ip has sent >= BLOCK_THRESHOLD packets
        within the last PACKET_RATE_WINDOW seconds.
        """
        count = len(self.packet_timestamps[dpid].get(src_ip, []))
        return count >= BLOCK_THRESHOLD

    def _is_blocked(self, dpid, src_ip):
        """
        Return True if src_ip is currently in the blocked set.
        Automatically removes expired blocks (after BLOCK_DURATION seconds).
        """
        if src_ip not in self.blocked_hosts.get(dpid, {}):
            return False
        if BLOCK_DURATION == 0:
            return True     # permanent block
        elapsed = time.time() - self.blocked_hosts[dpid][src_ip]
        if elapsed > BLOCK_DURATION:
            del self.blocked_hosts[dpid][src_ip]
            logger.info(
                f"[UNBLOCKED] {src_ip} on dpid={dpid:#x}  "
                f"(block expired after {BLOCK_DURATION}s)"
            )
            return False
        return True

    # ─────────────────────────────────────────────────────────────────────────
    # Blocking
    # ─────────────────────────────────────────────────────────────────────────

    def _block_host(self, datapath, src_ip):
        """
        Install a high-priority DROP flow rule for src_ip.

        Match    : IPv4 (eth_type=0x0800) with ipv4_src == src_ip
        Action   : empty list -> DROP
        Priority : 100 — overrides all forwarding rules (priority 10)
        Timeout  : hard_timeout = BLOCK_DURATION (switch removes automatically)
        """
        parser = datapath.ofproto_parser
        dpid   = datapath.id

        self.blocked_hosts[dpid][src_ip] = time.time()

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        self._add_flow(datapath,
                       priority=100,
                       match=match,
                       actions=[],           # empty action list = DROP
                       idle_timeout=0,
                       hard_timeout=BLOCK_DURATION)

        logger.warning(
            f"[BLOCKED] Suspicious host {src_ip} on dpid={dpid:#x}  "
            f"(>{BLOCK_THRESHOLD} pkts/{PACKET_RATE_WINDOW}s)  "
            f"DROP rule installed  priority=100  TTL={BLOCK_DURATION}s"
        )

    # ─────────────────────────────────────────────────────────────────────────
    # OpenFlow helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0, buffer_id=None):
        """
        Send an OFPFlowMod message to install a flow rule in the switch.
        This is the core SDN control operation — pushing match-action rules
        from the controller down to the data plane.
        """
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions
        )]

        kwargs = dict(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        if buffer_id is not None:
            kwargs["buffer_id"] = buffer_id

        datapath.send_msg(parser.OFPFlowMod(**kwargs))

    def _send_packet(self, datapath, msg, in_port, actions):
        """Send a packet-out to forward the current packet immediately."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    # ─────────────────────────────────────────────────────────────────────────
    # Background monitor
    # ─────────────────────────────────────────────────────────────────────────

    def _monitor_loop(self):
        """
        Background greenlet — logs per-host packet rates every MONITOR_INTERVAL
        seconds so traffic trends are visible in the controller output.
        """
        while True:
            hub.sleep(MONITOR_INTERVAL)
            now = time.time()
            for dpid, ip_map in self.packet_timestamps.items():
                for src_ip, timestamps in ip_map.items():
                    recent = [t for t in timestamps if now - t <= PACKET_RATE_WINDOW]
                    if recent:
                        status = "BLOCKED" if self._is_blocked(dpid, src_ip) else "OK"
                        logger.info(
                            f"[MONITOR] dpid={dpid:#x}  {src_ip:>15s}  "
                            f"{len(recent):>3d} pkts/{PACKET_RATE_WINDOW}s  [{status}]"
                        )

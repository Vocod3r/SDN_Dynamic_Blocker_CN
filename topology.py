"""
Dynamic Host Blocking System – Mininet Topology
================================================
Star topology: 4 hosts connected to 1 OVS switch, controlled by remote Ryu.

        h1 (10.0.0.1) ──┐
        h2 (10.0.0.2) ──┤── s1 (OpenFlow 1.3 switch) ── Ryu Controller (6633)
        h3 (10.0.0.3) ──┤
        h4 (10.0.0.4) ──┘

Usage (run as root):
    sudo python3 topology.py

Start the controller first:
    ~/.local/bin/ryu-manager dynamic_blocking_controller.py
"""

from mininet.net    import Mininet
from mininet.node   import RemoteController, OVSKernelSwitch
from mininet.cli    import CLI
from mininet.log    import setLogLevel, info
from mininet.link   import TCLink


CONTROLLER_IP   = "127.0.0.1"
CONTROLLER_PORT = 6633

# Realistic link parameters
LINK_BW    = 100    # Mbps
LINK_DELAY = "2ms"


def build_topology():
    """Instantiate and return a configured Mininet object."""

    net = Mininet(
        controller=None,            # added manually below
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=True,           # deterministic MACs: 00:00:00:00:00:0X
    )

    info("*** Adding remote Ryu controller\n")
    net.addController(
        "c0",
        controller=RemoteController,
        ip=CONTROLLER_IP,
        port=CONTROLLER_PORT,
    )

    info("*** Adding switch\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    info("*** Adding hosts\n")
    hosts = []
    for i in range(1, 5):
        h = net.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
        hosts.append(h)

    info("*** Creating star topology links\n")
    for h in hosts:
        net.addLink(h, s1, bw=LINK_BW, delay=LINK_DELAY)

    return net


def run():
    setLogLevel("info")
    net = build_topology()

    info("*** Starting network\n")
    net.start()

    # Ensure OVS uses OpenFlow 1.3 and points at our controller
    for sw in net.switches:
        sw.cmd(f"ovs-vsctl set bridge {sw.name} protocols=OpenFlow13")
        sw.cmd(
            f"ovs-vsctl set-controller {sw.name} "
            f"tcp:{CONTROLLER_IP}:{CONTROLLER_PORT}"
        )

    info("\n")
    info("=" * 60 + "\n")
    info("Topology ready  –  4 hosts, 1 switch, 1 remote controller\n")
    info("Hosts:\n")
    for h in net.hosts:
        info(f"  {h.name}  IP={h.IP()}  MAC={h.MAC()}\n")
    info("\n")
    info("Test commands (run inside CLI):\n")
    info("  pingall                         # basic reachability\n")
    info("  h1 ping -c 5 10.0.0.2          # normal ping (allowed)\n")
    info("  h3 ping -f -c 50 10.0.0.1      # flood ping -> triggers block\n")
    info("  h3 ping -c 5 10.0.0.2          # verify h3 blocked\n")
    info("  h4 ping -c 5 10.0.0.2          # verify h4 unaffected\n")
    info("=" * 60 + "\n\n")

    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == "__main__":
    run()

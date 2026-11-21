#!/usr/bin/env python3
"""Unit tests for the pure parts of the rootless NAT and censorship matrix (#483).

They check the profile catalogue and the nft programs each router gets, without
creating namespaces. `nft --check` on a real kernel is the harness's own first
step for every profile, so these tests pin the intent of each rule instead.
Run: python3 scripts/test_mesh_nat_censorship_proof.py
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mesh_nat_censorship_proof as proof  # noqa: E402


def router(nat, inside=None, edge=True, lan_subnet="10.1.0.0/24"):
    """A router serving `inside` (address to port) with the given NAT behaviour."""
    return proof.Router("r", nat, "lan", "wan", lan_subnet, "198.51.100.21", edge,
                        dict(inside or {"10.1.0.2": 10254}))


class Catalogue(unittest.TestCase):
    """The owner's list (#483) is present and every name is unique."""

    def test_requested_profiles_are_present(self):
        """Each requested NAT and censorship case has a named profile."""
        names = {scenario.name for scenario in proof.SCENARIOS}
        for name in ("full-cone-both", "address-restricted-both", "port-restricted-both",
                     "symmetric-one-side-vs-port-restricted", "symmetric-both", "cgnat-both",
                     "double-nat-one-side", "double-nat-both", "same-nat-hairpin-on",
                     "same-nat-hairpin-off", "udp-blocked", "tcp-80-443-only",
                     "dpi-wireguard-handshake", "mtu-576-icmp-blocked", "mapping-expiry-10s"):
            self.assertIn(name, names)
        self.assertEqual(len(names), len(proof.SCENARIOS))

    def test_cgnat_uses_carrier_space_and_a_30_second_timeout(self):
        """CGNAT tiers sit on 100.64/10, translate ports, and expire UDP after 30 s."""
        scenario = proof.scenario_named("cgnat-both")
        self.assertEqual(scenario.cgnat_tiers, (0,))
        self.assertEqual(scenario.side_a[0].udp_timeout, 30)
        self.assertNotEqual(scenario.side_a[0].port_offset, 0)
        self.assertFalse(scenario.side_a[0].hairpin)


class Mapping(unittest.TestCase):
    """Outside ports follow the profile's mapping rule."""

    def test_port_preserving_nat_keeps_the_inside_port(self):
        """A home router with a free port keeps it."""
        self.assertEqual(router(proof.HOME).outside_port("10.1.0.2"), 10254)

    def test_translating_nat_and_rebinds_move_the_port(self):
        """A CGNAT offset and every rebind give a different outside port."""
        cgnat = router(proof.CGNAT)
        first = cgnat.outside_port("10.1.0.2")
        self.assertNotEqual(first, 10254)
        cgnat.rebinds += 1
        self.assertNotEqual(cgnat.outside_port("10.1.0.2"), first)

    def test_two_hosts_on_one_port_get_distinct_outside_ports(self):
        """Behind one NAT, the second host on the same port is moved, as a real NAT must."""
        shared = router(proof.HOME, {"10.9.0.2": 10254, "10.9.0.3": 10254})
        self.assertEqual(shared.outside_port("10.9.0.2"), 10254)
        self.assertEqual(shared.outside_port("10.9.0.3"), 10255)


class Rules(unittest.TestCase):
    """Each filtering, hairpin and censorship choice renders the rule it promises."""

    def render(self, nat, scenario="port-restricted-both", **kwargs):
        """Render one router's table for a profile."""
        return proof.render_router(router(nat, **kwargs), proof.scenario_named(scenario))

    def test_port_restricted_has_no_inbound_forward(self):
        """APDF relies on conntrack only: no DNAT from the WAN."""
        self.assertNotIn("dnat", self.render(proof.HOME))

    def test_full_cone_forwards_any_sender(self):
        """EIF forwards every sender to the mapping."""
        program = self.render(proof.FULL_CONE)
        self.assertIn('iifname "wan" ip daddr 198.51.100.21 udp dport 10254 dnat ip to 10.1.0.2:10254', program)

    def test_address_restricted_requires_a_contacted_address(self):
        """ADF forwards only senders whose address the host has contacted."""
        program = self.render(proof.ADDRESS_RESTRICTED)
        self.assertIn("update @contacted { ip daddr }", program)
        self.assertIn("ip saddr @contacted udp dport 10254 dnat", program)

    def test_symmetric_nat_randomises_every_mapping(self):
        """APDM uses a fresh random port per destination."""
        self.assertIn("masquerade fully-random", self.render(proof.SYMMETRIC))

    def test_hairpin_translates_lan_to_lan_traffic(self):
        """Hairpin turns LAN traffic for the public address back into the LAN, sourced from the mapping."""
        program = self.render(proof.Nat(hairpin=True), "same-nat-hairpin-on")
        self.assertIn('iifname "lan" ip daddr 198.51.100.21 udp dport 10254 dnat ip to 10.1.0.2:10254', program)
        self.assertIn('iifname "lan" oifname "lan" ct status dnat', program)

    def test_routers_never_answer_unsolicited_udp(self):
        """Real routers drop silently instead of sending port unreachable."""
        self.assertIn('iifname "wan" meta l4proto udp drop', self.render(proof.HOME))

    def test_dpi_matches_handshake_shape_on_any_port(self):
        """The censor keys on size and type, not on the mesh port."""
        for rule in proof.dpi_drop_rules():
            self.assertNotIn("dport", rule)
        self.assertIn("udp length 156 @th,64,32 0x01000000 drop", proof.dpi_drop_rules())
        self.assertIn("udp length 100 @th,64,32 0x02000000 drop", proof.dpi_drop_rules())

    def test_tcp_only_network_drops_everything_but_web_ports(self):
        """Only TCP 80/443 leave; the forward policy drops the rest."""
        program = self.render(proof.HOME, "tcp-80-443-only")
        self.assertIn("policy drop", program)
        self.assertIn("tcp dport { 80, 443 } accept", program)

    def test_icmp_black_hole_also_silences_the_router(self):
        """With ICMP blocked the router cannot even send fragmentation-needed itself."""
        program = self.render(proof.HOME, "mtu-576-icmp-blocked")
        self.assertIn("chain output", program)
        self.assertIn("ip protocol icmp drop", program)

    def test_censorship_applies_only_at_the_edge(self):
        """An inner home router behind a CGNAT is not the censor."""
        program = proof.render_router(router(proof.HOME, edge=False), proof.scenario_named("udp-blocked"))
        self.assertNotIn("meta l4proto udp drop\n }", program.split("chain forward")[1].split("chain input")[0])


class Candidates(unittest.TestCase):
    """The measured "candidates" option publishes what an observer would really see."""

    def topology(self, name, ports):
        """A topology with routers filled in but no namespaces created."""
        topology = proof.Topology(proof.scenario_named(name))
        for side, index in (("A", 1), ("B", 2)):
            tiers = topology.scenario.side_a if side == "A" else topology.scenario.side_b
            topology.public_address[side] = f"198.51.100.2{index}"
            topology.node_address[side] = f"10.{index}.0.2"
            inner = topology.node_address[side]
            for depth, nat in enumerate(tiers):
                outside = topology.public_address[side] if depth == len(tiers) - 1 else f"100.64.{index}{depth + 1}.2"
                topology.routers[side].append(proof.Router(f"r{side}{depth}", nat, "lan", "wan", "x", outside, depth == len(tiers) - 1))
                inner = outside
        topology.configure = proof.Topology.configure.__get__(topology)
        topology.install = lambda: None
        topology.unique_routers = lambda: []
        topology.configure(ports)
        return topology

    def test_cgnat_publishes_the_translated_port(self):
        """Behind a port-translating CGNAT the observer sees the CGNAT's port, not the local one."""
        topology = self.topology("double-nat-one-side", {"A": 10254, "B": 10254})
        a, b = topology.reflexive_endpoints({"A": 10254, "B": 10254})
        self.assertEqual(a, f"198.51.100.21:{topology.routers['A'][1].outside_port('100.64.11.2')}")
        self.assertNotEqual(a, "198.51.100.21:10254")
        self.assertEqual(b, "198.51.100.22:10254")

    def test_symmetric_nat_has_no_usable_reflexive_port(self):
        """A symmetric NAT's observation is useless to the peer, so the local port stays."""
        topology = self.topology("symmetric-both", {"A": 40000, "B": 40001})
        self.assertEqual(topology.reflexive_endpoints({"A": 40000, "B": 40001})[0], "198.51.100.21:40000")


class Percentile(unittest.TestCase):
    """The latency summary uses nearest-rank percentiles."""

    def test_nearest_rank(self):
        """p99 of 1..100 is 99; no samples is None."""
        self.assertEqual(proof.percentile([float(v) for v in range(1, 101)], 0.99), 99.0)
        self.assertIsNone(proof.percentile([], 0.99))


if __name__ == "__main__":
    unittest.main()

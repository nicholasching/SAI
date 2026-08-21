# Copyright (c) 2026 Microsoft Open Technologies, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
#    THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
#    CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
#    LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
#    FOR A PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.

"""Opt-in SAI notification tests with a VPP-specific BFD fixture."""

import re
import os
import threading
import time

from ptf.testutils import test_params_get
from unittest import SkipTest

from sai_thrift.sai_adapter import *
from sai_test_base import T0TestBase
from sai_utils import sai_ipaddress, sai_ipprefix


PORT_NOTIFICATION_TYPE = 0
BFD_NOTIFICATION_TYPE = 1
NOTIFICATION_TEST_PARAM = "notification_test"
NOTIFICATION_TEST_VALUE = "true"
PLATFORM_PARAM = "platform"
VPP_PLATFORM = "vpp"
NOTIFICATION_TIMEOUT = 5.0
NOTIFICATION_POLL_INTERVAL = 0.5
# RFC 5880 holds the control-packet interval at one second until a session is
# up, so a fresh BFD session needs several round trips before it transitions.
# Measured bring-up against the scapy responder is around 5.5s, on top of which
# the notification still has to clear the VPP event poll.
BFD_NOTIFICATION_TIMEOUT = 25.0
VPPCTL_TIMEOUT = 10
BFD_EPHEMERAL_SRC_PORT = 49152
BFD_STATE_INIT = 2
BFD_STATE_UP = 3
# A scapy responder cannot sustain a sub-second reply cadence reliably, and at
# the SAI default the negotiated interval drops the session within 300ms of a
# missed reply. One second with a multiplier of three keeps the session stable
# while still detecting a broken path in about three seconds.
BFD_INTERVAL_USEC = 1000000
BFD_MULTIPLIER = 3


class NotificationTestBase(T0TestBase):
    """Common setup for the opt-in server-owned notification bridge."""

    def setUp(self, **kwargs):
        self.pending_events = []
        params = test_params_get() or {}
        if params.get(NOTIFICATION_TEST_PARAM) != NOTIFICATION_TEST_VALUE:
            super().setUp(skip_reason="SAI notification tests are opt-in")
            return

        T0TestBase.setUp(self, **kwargs)
        status = self.client.sai_thrift_enable_notifications()
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        self.discard_pending_notifications()

    def tearDown(self):
        try:
            if self.client is not None:
                self.discard_pending_notifications()
        finally:
            super().tearDown()

    def discard_pending_notifications(self):
        self.pending_events = []
        self.client.sai_thrift_drain_notifications()

    def wait_for_notification(self, predicate, timeout=NOTIFICATION_TIMEOUT):
        """Return the first queued event matching predicate, keeping the rest.

        Events the caller is not waiting for yet are retained so that a drain
        which returns several transitions at once cannot lose the one a later
        assertion depends on.
        """
        deadline = time.monotonic() + timeout
        while True:
            for index, event in enumerate(self.pending_events):
                if predicate(event):
                    return self.pending_events.pop(index)

            if time.monotonic() >= deadline:
                break

            self.pending_events.extend(
                self.client.sai_thrift_drain_notifications()
            )
            time.sleep(NOTIFICATION_POLL_INTERVAL)

        self.fail(
            "timed out waiting for the expected SAI notification; observed {}".format(
                [
                    (event.notification_type, hex(event.object_id), event.state)
                    for event in self.pending_events
                ]
            )
        )

class PortNotificationTestBase(NotificationTestBase):
    """Port notification setup without unrelated L3 configuration."""

    def setUp(self):
        super().setUp(
            is_remove_default_vlan=False,
            is_create_vlan=False,
            is_create_fdb=False,
            is_create_default_route=False,
            is_create_lag=False,
            is_create_vlan_itf=False,
            is_create_route_for_vlan_itf=False,
            is_create_route_for_lag=False,
            wait_sec=1,
        )
        self.port = self.dut.port_obj_list[0]
        attributes = sai_thrift_get_port_attribute(
            self.client,
            port_oid=self.port.oid,
            admin_state=True,
            oper_status=True,
        )
        self.initial_admin_state = attributes["admin_state"]
        self.initial_oper_status = attributes["oper_status"]
        self.port_skip_reason = None
        if not self.initial_admin_state:
            self.port_skip_reason = "test fixture must provide an administratively up port"
        elif self.initial_oper_status != SAI_PORT_OPER_STATUS_UP:
            self.port_skip_reason = "test fixture must provide an operationally up port"
        self.discard_pending_notifications()

    def require_port_ready(self):
        if self.port_skip_reason:
            raise SkipTest(self.port_skip_reason)

    def port_event(self, state):
        return self.wait_for_notification(
            lambda event: event.notification_type == PORT_NOTIFICATION_TYPE
            and event.object_id == self.port.oid
            and event.state == state
        )

    def set_admin_state(self, admin_state):
        status = sai_thrift_set_port_attribute(
            self.client,
            port_oid=self.port.oid,
            admin_state=admin_state,
        )
        self.assertEqual(status, SAI_STATUS_SUCCESS)


class PortStateChangeTest(PortNotificationTestBase):
    """Verify a port admin-down event reaches the SAI callback bridge."""

    def runTest(self):
        self.require_port_ready()
        try:
            self.set_admin_state(False)
            self.port_event(SAI_PORT_OPER_STATUS_DOWN)
        finally:
            self.set_admin_state(self.initial_admin_state)


class PortStateRecoveryTest(PortNotificationTestBase):
    """Verify a port admin-down/admin-up sequence reaches SAI in order."""

    def runTest(self):
        self.require_port_ready()
        try:
            self.set_admin_state(False)
            self.port_event(SAI_PORT_OPER_STATUS_DOWN)
            self.set_admin_state(True)
            self.port_event(SAI_PORT_OPER_STATUS_UP)
        finally:
            self.set_admin_state(self.initial_admin_state)


class BfdResponder:
    """Small Scapy responder for one single-hop or multihop BFD session.

    The session is anchored on a LAG router interface, and VPP picks the egress
    member by hashing the flow, so every member peer is watched rather than
    guessing which one carries the control packets. Replies go back out the
    member the request arrived on.
    """

    def __init__(self, interface_names, local_ip, remote_ip, udp_port, discriminator):
        self.interface_names = list(interface_names)
        self.local_ip = local_ip
        self.remote_ip = remote_ip
        self.udp_port = udp_port
        self.discriminator = discriminator
        from scapy.all import get_if_hwaddr

        self.source_macs = {
            name: get_if_hwaddr(name) for name in self.interface_names
        }
        self.stop_event = threading.Event()
        self.threads = [
            threading.Thread(target=self._run, args=(name,), daemon=True)
            for name in self.interface_names
        ]

    def start(self):
        for thread in self.threads:
            thread.start()

    def stop(self):
        self.stop_event.set()
        for thread in self.threads:
            thread.join(timeout=2)

    def _run(self, interface_name):
        from scapy.all import sniff

        while not self.stop_event.is_set():
            sniff(
                iface=interface_name,
                filter="udp",
                timeout=0.5,
                store=False,
                prn=lambda packet: self._respond(interface_name, packet),
            )

    def _respond(self, interface_name, packet):
        from scapy.all import Ether, IP, UDP, sendp
        from scapy.contrib.bfd import BFD

        if not packet.haslayer(Ether) or not packet.haslayer(IP):
            return
        if not packet.haslayer(UDP):
            return

        udp = packet[UDP]
        if udp.dport != self.udp_port:
            return

        bfd = packet.getlayer(BFD)
        if bfd is None:
            try:
                bfd = BFD(bytes(udp.payload))
            except Exception:
                return

        # Follow the RFC 5880 state machine. A peer sitting in Down only leaves
        # it when it hears Down or Init, so a responder that always advertises
        # Up leaves the session stuck with VPP Down and remote Up forever.
        response_state = (
            BFD_STATE_UP
            if bfd.sta in (BFD_STATE_INIT, BFD_STATE_UP)
            else BFD_STATE_INIT
        )

        response = (
            Ether(src=self.source_macs[interface_name], dst=packet[Ether].src)
            # Single-hop BFD is GTSM protected, so the reply has to arrive with
            # TTL 255. RFC 5880 also fixes the destination port at 3784 (4784 for
            # multihop) in both directions, with an ephemeral source port; VPP
            # silently ignores a reply that mirrors the ports instead.
            / IP(src=self.remote_ip, dst=self.local_ip, ttl=255)
            / UDP(sport=BFD_EPHEMERAL_SRC_PORT, dport=self.udp_port)
            / BFD(
                version=1,
                diag=0,
                sta=response_state,
                flags=0,
                detect_mult=BFD_MULTIPLIER,
                my_discriminator=self.discriminator,
                your_discriminator=bfd.my_discriminator,
                min_tx_interval=BFD_INTERVAL_USEC,
                min_rx_interval=BFD_INTERVAL_USEC,
                echo_rx_interval=0,
            )
        )
        sendp(response, iface=interface_name, verbose=False)


class BfdNotificationTestBase(NotificationTestBase):
    """Build a LAG-backed BFD session with a real connected local address."""

    local_ip = "10.1.1.1"
    remote_ip = "10.1.1.2"
    gateway_ip = "10.1.1.2"
    local_discriminator = 0x1001
    remote_discriminator = 0x2001
    udp_port = 3784
    multihop = False

    @staticmethod
    def peer_interface(port_index):
        from ptf import config as ptf_config

        for _, configured_port, interface_name in ptf_config.get("interfaces", []):
            if configured_port == port_index:
                if not re.fullmatch(r"OEth[0-9]+_peer", interface_name):
                    raise AssertionError(
                        "unexpected VPP PTF peer interface: {}".format(interface_name)
                    )
                return interface_name
        raise AssertionError(
            "PTF interface for port {} was not configured".format(port_index)
        )

    @staticmethod
    def vppctl(*command):
        """Return VPP state as independent evidence for the BFD assertion."""
        import subprocess

        result = subprocess.run(
            ["vppctl"] + list(command),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=VPPCTL_TIMEOUT,
        )
        return result.stdout.decode("utf-8", "replace")

    def log_vpp_state(self, *command):
        output = self.vppctl(*command)
        print("vppctl {}:\n{}".format(" ".join(command), output))
        return output

    def setUp(self):
        params = test_params_get() or {}
        if params.get(PLATFORM_PARAM) != VPP_PLATFORM:
            super().setUp(
                skip_reason="BFD notification tests require platform='vpp'"
            )
            return

        if os.environ.get("SIMULATE_SONIC") != "1":
            super().setUp(skip_reason="BFD notification tests require SIMULATE_SONIC=1")
            return

        self.bfd_session = None
        self.lag_rif = None
        self.owns_lag_rif = False
        self.neighbor_entry = None
        self.next_hop = None
        self.route_entry = None
        self.responder = None

        super().setUp(
            is_remove_default_vlan=False,
            is_create_vlan=False,
            is_create_fdb=False,
            is_create_default_route=False,
            is_create_lag=True,
            is_create_vlan_itf=False,
            is_create_route_for_vlan_itf=False,
            is_create_route_for_lag=False,
            wait_sec=1,
        )

        if not self.dut.default_vrf:
            self.route_configer.get_default_virtual_router()

        lag = self.dut.lag_list[0]
        existing_rifs = set(lag.rif_list or [])
        self.lag_rif = self.route_configer.create_router_interface(lag)
        self.owns_lag_rif = self.lag_rif not in existing_rifs
        self.peers = [
            self.peer_interface(port_index)
            for port_index in lag.member_port_indexs
        ]
        from scapy.all import get_if_hwaddr

        self.peer_mac = get_if_hwaddr(self.peers[0])

        self.neighbor_entry = sai_thrift_neighbor_entry_t(
            rif_id=self.lag_rif,
            ip_address=sai_ipaddress(self.gateway_ip),
        )
        status = sai_thrift_create_neighbor_entry(
            self.client,
            self.neighbor_entry,
            dst_mac_address=self.peer_mac,
            no_host_route=False,
        )
        self.assertEqual(status, SAI_STATUS_SUCCESS)

        if self.multihop:
            self.next_hop = sai_thrift_create_next_hop(
                self.client,
                ip=sai_ipaddress(self.gateway_ip),
                router_interface_id=self.lag_rif,
                type=SAI_NEXT_HOP_TYPE_IP,
            )
            self.assertEqual(self.status(), SAI_STATUS_SUCCESS)
            self.route_entry = sai_thrift_route_entry_t(
                vr_id=self.dut.default_vrf,
                destination=sai_ipprefix(self.remote_ip + "/32"),
            )
            status = sai_thrift_create_route_entry(
                self.client,
                self.route_entry,
                next_hop_id=self.next_hop,
            )
            self.assertEqual(status, SAI_STATUS_SUCCESS)

    def start_session(self):
        self.responder = BfdResponder(
            self.peers,
            self.local_ip,
            self.remote_ip,
            self.udp_port,
            self.remote_discriminator,
        )
        self.responder.start()

        self.bfd_session = sai_thrift_create_bfd_session(
            self.client,
            type=SAI_BFD_SESSION_TYPE_ASYNC_ACTIVE,
            virtual_router=self.dut.default_vrf,
            local_discriminator=self.local_discriminator,
            remote_discriminator=self.remote_discriminator,
            udp_src_port=49152,
            bfd_encapsulation_type=SAI_BFD_ENCAPSULATION_TYPE_NONE,
            iphdr_version=4,
            src_ip_address=sai_ipaddress(self.local_ip),
            dst_ip_address=sai_ipaddress(self.remote_ip),
            min_tx=BFD_INTERVAL_USEC,
            min_rx=BFD_INTERVAL_USEC,
            multiplier=BFD_MULTIPLIER,
            hw_lookup_valid=True,
            multihop=self.multihop,
            cbit=False,
            admin_state=True,
        )
        self.assertNotEqual(self.bfd_session, SAI_NULL_OBJECT_ID)
        self.assertEqual(self.status(), SAI_STATUS_SUCCESS)

    def bfd_event(self, state):
        return self.wait_for_notification(
            lambda event: event.notification_type == BFD_NOTIFICATION_TYPE
            and event.object_id == self.bfd_session
            and event.state == state,
            timeout=BFD_NOTIFICATION_TIMEOUT,
        )

    def assert_bfd_state(self, state):
        attributes = sai_thrift_get_bfd_session_attribute(
            self.client,
            self.bfd_session,
            state=True,
        )
        self.assertEqual(attributes["state"], state)

    def assert_vpp_bfd_state(self, expected_state_word):
        """Corroborate the SAI state against VPP's own session table.

        SAI_BFD_SESSION_ATTR_STATE is written by the same code path that emits
        the notification, so it cannot on its own show that VPP really moved.
        """
        output = self.log_vpp_state("show", "bfd", "sessions")
        self.assertIn(
            self.remote_ip,
            output,
            "VPP has no BFD session towards {}".format(self.remote_ip),
        )
        self.assertRegex(
            output,
            r"(?i)\b{}\b".format(expected_state_word),
            "VPP did not report BFD state {}".format(expected_state_word),
        )

    def tearDown(self):
        try:
            if self.responder is not None:
                self.responder.stop()
            if self.bfd_session is not None:
                sai_thrift_remove_bfd_session(self.client, self.bfd_session)
            if self.route_entry is not None:
                sai_thrift_remove_route_entry(self.client, self.route_entry)
            if self.next_hop is not None:
                sai_thrift_remove_next_hop(self.client, self.next_hop)
            if self.neighbor_entry is not None:
                sai_thrift_remove_neighbor_entry(self.client, self.neighbor_entry)
            if self.owns_lag_rif:
                sai_thrift_remove_router_interface(self.client, self.lag_rif)
        finally:
            super().tearDown()


    def bring_session_up(self):
        self.start_session()
        self.bfd_event(SAI_BFD_SESSION_STATE_UP)
        self.assert_bfd_state(SAI_BFD_SESSION_STATE_UP)
        self.assert_vpp_bfd_state("up")

    def break_path(self):
        """Silence the peer so VPP misses detect_mult consecutive intervals."""
        self.responder.stop()
        self.responder = None
        self.bfd_event(SAI_BFD_SESSION_STATE_DOWN)
        self.assert_bfd_state(SAI_BFD_SESSION_STATE_DOWN)
        self.assert_vpp_bfd_state("down")


class BfdSessionUpTest(BfdNotificationTestBase):
    """Verify that a responder-driven BFD session emits an UP notification."""

    def runTest(self):
        self.bring_session_up()


class BfdSessionDownTest(BfdNotificationTestBase):
    """Verify that stopping the responder emits a BFD DOWN notification."""

    def runTest(self):
        self.bring_session_up()
        self.break_path()


class BfdMultihopTest(BfdNotificationTestBase):
    """Verify multihop BFD uses UDP/4784 and a routed lookup."""

    remote_ip = "10.1.2.2"
    gateway_ip = "10.1.1.2"
    udp_port = 4784
    multihop = True

    def runTest(self):
        self.bring_session_up()
        self.break_path()

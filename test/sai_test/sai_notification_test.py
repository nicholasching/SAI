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

"""Opt-in VPP SAI notification tests."""

import re
import os
import subprocess
import threading
import time

from ptf import config as ptf_config
from ptf.testutils import test_params_get
from unittest import SkipTest

from scapy.all import Ether, IP, UDP, get_if_hwaddr, sendp, sniff
from scapy.contrib.bfd import BFD

from sai_thrift.sai_adapter import *
from sai_test_base import T0TestBase
from sai_utils import sai_ipaddress, sai_ipprefix


PORT_NOTIFICATION_TYPE = 0
BFD_NOTIFICATION_TYPE = 1
NOTIFICATION_TEST_PARAM = "vpp_notification_test"
NOTIFICATION_TEST_VALUE = "true"
NOTIFICATION_TIMEOUT = 5.0
NOTIFICATION_POLL_INTERVAL = 0.5


class NotificationTestBase(T0TestBase):
    """Common setup for the opt-in server-owned notification bridge."""

    def setUp(self, **kwargs):
        params = test_params_get() or {}
        if params.get(NOTIFICATION_TEST_PARAM) != NOTIFICATION_TEST_VALUE:
            super().setUp(skip_reason="VPP notification tests are opt-in")
            return

        T0TestBase.setUp(self, **kwargs)
        status = self.client.sai_thrift_enable_notifications()
        self.assertEqual(status, SAI_STATUS_SUCCESS)
        self.client.sai_thrift_drain_notifications()

    def tearDown(self):
        try:
            if self.client is not None:
                self.client.sai_thrift_drain_notifications()
        finally:
            super().tearDown()

    def wait_for_notification(self, predicate):
        deadline = time.monotonic() + NOTIFICATION_TIMEOUT
        while time.monotonic() < deadline:
            for event in self.client.sai_thrift_drain_notifications():
                if predicate(event):
                    return event
            time.sleep(NOTIFICATION_POLL_INTERVAL)
        self.fail("timed out waiting for the expected SAI notification")

    @staticmethod
    def peer_interface(port_index):
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
    def vpp_interface(peer_name):
        match = re.fullmatch(r"OEth([0-9]+)_peer", peer_name)
        if match is None:
            raise AssertionError(
                "unexpected VPP PTF peer interface: {}".format(peer_name)
            )
        return "OEthernet{}".format(match.group(1))

    @staticmethod
    def set_peer_state(interface_name, is_up):
        state = "up" if is_up else "down"
        subprocess.run(
            ["ip", "link", "set", "dev", interface_name, state],
            check=True,
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
        self.peer = self.peer_interface(self.port.dev_port_index)
        self.vpp_peer = self.vpp_interface(self.peer)
        self.set_peer_state(self.peer, True)
        self.set_peer_state(self.vpp_peer, True)
        self.client.sai_thrift_drain_notifications()

    def port_event(self, state):
        return self.wait_for_notification(
            lambda event: event.notification_type == PORT_NOTIFICATION_TYPE
            and event.object_id == self.port.oid
            and event.state == state
        )


class PortStateChangeTest(PortNotificationTestBase):
    """Verify a VPP carrier-down event reaches the SAI callback bridge."""

    def runTest(self):
        try:
            self.set_peer_state(self.peer, False)
            self.port_event(SAI_PORT_OPER_STATUS_DOWN)
        finally:
            self.set_peer_state(self.peer, True)


class PortStateRecoveryTest(PortNotificationTestBase):
    """Verify a carrier-down/carrier-up sequence reaches SAI in order."""

    def runTest(self):
        try:
            self.set_peer_state(self.peer, False)
            self.port_event(SAI_PORT_OPER_STATUS_DOWN)
            self.set_peer_state(self.peer, True)
            self.port_event(SAI_PORT_OPER_STATUS_UP)
        finally:
            self.set_peer_state(self.peer, True)


class BfdResponder:
    """Small Scapy responder for one single-hop or multihop BFD session."""

    def __init__(self, interface_name, local_ip, remote_ip, udp_port, discriminator):
        self.interface_name = interface_name
        self.local_ip = local_ip
        self.remote_ip = remote_ip
        self.udp_port = udp_port
        self.discriminator = discriminator
        self.source_mac = get_if_hwaddr(interface_name)
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=2)

    def _run(self):
        while not self.stop_event.is_set():
            sniff(
                iface=self.interface_name,
                filter="udp",
                timeout=0.5,
                store=False,
                prn=self._respond,
            )

    def _respond(self, packet):
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

        response = (
            Ether(src=self.source_mac, dst=packet[Ether].src)
            / IP(src=self.remote_ip, dst=self.local_ip, ttl=255)
            / UDP(sport=self.udp_port, dport=udp.sport)
            / BFD(
                version=1,
                diag=0,
                sta=3,
                flags=0,
                detect_mult=3,
                my_discriminator=self.discriminator,
                your_discriminator=bfd.my_discriminator,
                min_tx_interval=100000,
                min_rx_interval=100000,
                echo_rx_interval=0,
            )
        )
        sendp(response, iface=self.interface_name, verbose=False)


class BfdNotificationTestBase(NotificationTestBase):
    """Build a LAG-backed BFD session with a real connected local address."""

    local_ip = "10.1.1.1"
    remote_ip = "10.1.1.2"
    gateway_ip = "10.1.1.2"
    local_discriminator = 0x1001
    remote_discriminator = 0x2001
    udp_port = 3784
    multihop = False

    def setUp(self):
        if os.environ.get("SIMULATE_SONIC") != "1":
            super().setUp(skip_reason="BFD notification tests require SIMULATE_SONIC=1")
            return

        self.bfd_session = None
        self.lag_rif = None
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
        self.lag_rif = self.route_configer.create_router_interface(lag)
        peer_port = lag.member_port_indexs[0]
        self.peer = self.peer_interface(peer_port)
        self.peer_mac = get_if_hwaddr(self.peer)

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
            self.peer,
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
            min_tx=100000,
            min_rx=100000,
            multiplier=3,
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
            and event.state == state
        )

    def assert_bfd_state(self, state):
        attributes = sai_thrift_get_bfd_session_attribute(
            self.client,
            self.bfd_session,
            state=True,
        )
        self.assertEqual(attributes["state"], state)

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
        finally:
            super().tearDown()


class BfdSessionUpTest(BfdNotificationTestBase):
    """Verify that a responder-driven BFD session emits an UP notification."""

    def runTest(self):
        self.start_session()
        self.bfd_event(SAI_BFD_SESSION_STATE_UP)
        self.assert_bfd_state(SAI_BFD_SESSION_STATE_UP)


class BfdSessionDownTest(BfdNotificationTestBase):
    """Verify that stopping the responder emits a BFD DOWN notification."""

    def runTest(self):
        self.start_session()
        self.bfd_event(SAI_BFD_SESSION_STATE_UP)
        self.assert_bfd_state(SAI_BFD_SESSION_STATE_UP)
        self.responder.stop()
        self.responder = None
        self.bfd_event(SAI_BFD_SESSION_STATE_DOWN)
        self.assert_bfd_state(SAI_BFD_SESSION_STATE_DOWN)


class BfdMultihopTest(BfdNotificationTestBase):
    """Verify multihop BFD uses UDP/4784 and a routed lookup."""

    remote_ip = "10.1.2.2"
    gateway_ip = "10.1.1.2"
    udp_port = 4784
    multihop = True

    def runTest(self):
        self.start_session()
        self.bfd_event(SAI_BFD_SESSION_STATE_UP)
        self.assert_bfd_state(SAI_BFD_SESSION_STATE_UP)

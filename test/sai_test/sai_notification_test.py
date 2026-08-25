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

"""Opt-in SAI notification tests with a provider-backed BFD fixture."""

import importlib
import time

from ptf.testutils import test_params_get
from unittest import SkipTest

from sai_thrift.sai_adapter import *
from sai_test_base import T0TestBase


PORT_NOTIFICATION_TYPE = (
    sai_thrift_notification_type_t.SAI_THRIFT_NOTIFICATION_TYPE_PORT_STATE_CHANGE
)
BFD_NOTIFICATION_TYPE = (
    sai_thrift_notification_type_t.SAI_THRIFT_NOTIFICATION_TYPE_BFD_SESSION_STATE_CHANGE
)
NOTIFICATION_TEST_PARAM = "notification_test"
NOTIFICATION_TEST_VALUE = "true"
BFD_FIXTURE_PARAM = "bfd_fixture"
NOTIFICATION_TIMEOUT = 5.0
NOTIFICATION_POLL_INTERVAL = 0.5


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


class BfdNotificationTestBase(NotificationTestBase):
    """Run generic BFD notification checks against a platform-supplied fixture.

    The fixture module is named by the ``bfd_fixture`` test parameter and must
    expose ``create_fixture(test_obj, multihop)`` returning an object with
    ``common_config_kwargs()``, ``setup()``, ``start_session()`` returning the
    BFD session OID, ``stop_peer()`` and ``teardown()``. It may also provide
    ``notification_timeout`` and ``assert_external_state(state_word)`` to
    corroborate the transition against the platform's own state.
    """

    multihop = False

    def setUp(self):
        params = test_params_get() or {}
        fixture_name = params.get(BFD_FIXTURE_PARAM)
        self.bfd_fixture = None
        if not fixture_name:
            super().setUp(skip_reason="BFD notification fixture is not configured")
            return

        fixture_module = importlib.import_module(fixture_name)
        self.bfd_fixture = fixture_module.create_fixture(self, self.multihop)

        try:
            super().setUp(**self.bfd_fixture.common_config_kwargs())
            self.bfd_fixture.setup()
        except Exception:
            self.bfd_fixture.teardown()
            raise

    def tearDown(self):
        try:
            if self.bfd_fixture is not None:
                self.bfd_fixture.teardown()
        finally:
            super().tearDown()

    def bfd_event(self, state):
        timeout = getattr(
            self.bfd_fixture,
            "notification_timeout",
            NOTIFICATION_TIMEOUT,
        )
        return self.wait_for_notification(
            lambda event: event.notification_type == BFD_NOTIFICATION_TYPE
            and event.object_id == self.bfd_session
            and event.state == state,
            timeout=timeout,
        )

    def assert_bfd_state(self, state):
        attributes = sai_thrift_get_bfd_session_attribute(
            self.client,
            self.bfd_session,
            state=True,
        )
        self.assertEqual(attributes["state"], state)

    def bring_session_up(self):
        self.bfd_session = self.bfd_fixture.start_session()
        self.bfd_event(SAI_BFD_SESSION_STATE_UP)
        self.assert_bfd_state(SAI_BFD_SESSION_STATE_UP)
        assert_external_state = getattr(
            self.bfd_fixture,
            "assert_external_state",
            None,
        )
        if assert_external_state is not None:
            assert_external_state("up")

    def break_path(self):
        self.bfd_fixture.stop_peer()
        self.bfd_event(SAI_BFD_SESSION_STATE_DOWN)
        self.assert_bfd_state(SAI_BFD_SESSION_STATE_DOWN)
        assert_external_state = getattr(
            self.bfd_fixture,
            "assert_external_state",
            None,
        )
        if assert_external_state is not None:
            assert_external_state("down")


class BfdSessionUpTest(BfdNotificationTestBase):
    """Verify that a fixture-driven BFD session emits an UP notification."""

    def runTest(self):
        self.bring_session_up()


class BfdSessionDownTest(BfdNotificationTestBase):
    """Verify that stopping the peer emits a BFD DOWN notification."""

    def runTest(self):
        self.bring_session_up()
        self.break_path()


class BfdMultihopTest(BfdNotificationTestBase):
    """Verify a fixture-provided multihop BFD session transition."""

    multihop = True

    def runTest(self):
        self.bring_session_up()
        self.break_path()

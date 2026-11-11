import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.packet import Raw


SPEC = importlib.util.spec_from_file_location("fnet_app", Path(__file__).parents[1] / "app.py")
fnet = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fnet)


class TrafficMonitorTests(unittest.TestCase):
    def test_counts_internet_packet_once_and_ignores_relay_and_blocked_attempts(self):
        monitor = fnet.TrafficMonitor()
        target = "192.168.1.10"
        our_mac = "02:00:00:00:00:99"
        original = Ether(src="02:00:00:00:00:10", dst=our_mac) / IP(
            src=target, dst="8.8.8.8") / Raw(b"x" * 100)
        relayed = Ether(src=our_mac, dst="02:00:00:00:00:01") / original[IP]

        monitor.packet_handler(original, {target}, set(), our_mac)
        expected = len(original)
        self.assertEqual(monitor.total_bytes(), expected)
        self.assertEqual(monitor.snapshot_bytes()[target], expected)

        monitor.packet_handler(relayed, {target}, set(), our_mac)
        monitor.packet_handler(original, {target}, {target}, our_mac)
        self.assertEqual(monitor.total_bytes(), expected)

    def test_lan_packet_is_visible_but_not_added_to_quota(self):
        monitor = fnet.TrafficMonitor()
        packet = Ether(src="02:00:00:00:00:10", dst="02:00:00:00:00:11") / IP(
            src="192.168.1.10", dst="192.168.1.11") / Raw(b"x" * 50)
        monitor.packet_handler(packet, {"192.168.1.10", "192.168.1.11"}, set(), None)
        self.assertEqual(monitor.total_bytes(), 0)
        self.assertEqual(set(monitor.snapshot_bytes()), {"192.168.1.10", "192.168.1.11"})


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        fnet.DATA_FILE = Path(self.temp_dir.name) / "devices.json"
        self.controller = fnet.NetCutController()
        self.controller.gateway_ip = "192.168.1.1"
        self.controller.gateway_mac = "02:00:00:00:00:01"
        self.controller.our_mac = "02:00:00:00:00:99"
        self.controller.interface = "test"
        self.controller._restore = Mock()
        self.controller._start_spoof = Mock()
        self.controller._stop_spoof = Mock()

        self.gateway = fnet.Device(self.controller.gateway_ip, self.controller.gateway_mac)
        self.gateway.state = "Router (Connected)"
        self.first = fnet.Device("192.168.1.10", "02:00:00:00:00:10")
        self.second = fnet.Device("192.168.1.11", "02:00:00:00:00:11")
        self.second.state = "Throttled"
        self.second.throttle_kbps = 500
        self.controller.devices = [self.gateway, self.first, self.second]

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_quota_transitions_and_restores_previous_states(self):
        quota = self.controller.quota
        quota.enabled = True
        quota.limit_gb = 1
        quota.throttle_pct = 80
        quota.block_pct = 95
        quota.throttle_kbps = 300
        quota.used_bytes = 850_000_000

        self.controller._enforce_quota()
        self.assertEqual(quota.mode, "throttle")
        self.assertEqual(self.first.state, "Throttled")
        self.assertEqual(self.second.throttle_kbps, 300)

        quota.used_bytes = 960_000_000
        self.controller._enforce_quota()
        self.assertEqual(quota.mode, "block")
        self.assertEqual(self.first.state, "Disconnected")
        self.assertEqual(self.second.state, "Disconnected")

        quota.enabled = False
        self.controller._enforce_quota()
        self.assertIsNone(quota.mode)
        self.assertEqual(self.first.state, "Connected")
        self.assertEqual(self.second.state, "Throttled")
        self.assertEqual(self.second.throttle_kbps, 500)
        self.assertEqual(quota.managed_devices, {})

    def test_cutting_throttled_device_really_blocks_and_clears_display_usage(self):
        self.controller.traffic.traffic[self.second.ip] = 12345
        ok, state = self.controller.toggle_device(self.second.mac)
        self.assertTrue(ok)
        self.assertEqual(state, "Disconnected")
        self.assertEqual(self.second.state, "Disconnected")
        self.assertIsNone(self.second.throttle_kbps)
        self.assertNotIn(self.second.ip, self.controller.traffic.snapshot_bytes())

    def test_restore_all_keeps_services_running_and_disables_auto_mode(self):
        self.controller.quota.enabled = True
        self.controller.forwarder.set_stop = Mock()
        self.controller.restore_all(stop_services=False)
        self.assertFalse(self.controller.quota.enabled)
        self.controller.forwarder.set_stop.assert_not_called()
        self.assertFalse(self.controller.auto_scan_stop.is_set())

    def test_api_rejects_inverted_quota_thresholds_and_hides_blocked_usage(self):
        old_controller = fnet.controller
        fnet.controller = self.controller
        try:
            client = fnet.app.test_client()
            response = client.post("/api/quota", json={
                "enabled": True, "limit_gb": 10, "throttle_kbps": 300,
                "throttle_pct": 90, "block_pct": 80,
            })
            self.assertEqual(response.status_code, 400)
            self.assertIn("lower", response.get_json()["error"])

            self.first.state = "Disconnected"
            self.controller.traffic.traffic[self.first.ip] = 99999
            devices = client.get("/api/devices").get_json()
            blocked = next(d for d in devices if d["mac"] == self.first.mac)
            self.assertEqual(blocked["traffic_kb"], 0)
        finally:
            fnet.controller = old_controller


if __name__ == "__main__":
    unittest.main()

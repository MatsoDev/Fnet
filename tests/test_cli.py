import importlib.util
import unittest
from pathlib import Path
from unittest.mock import Mock


SPEC = importlib.util.spec_from_file_location("fnet_cli", Path(__file__).parents[1] / "netcut.py")
cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cli)


class CliRestoreTests(unittest.TestCase):
    def test_restore_all_stops_poisoning_and_repairs_device(self):
        controller = cli.NetCutController()
        controller.gateway_ip = "192.168.1.1"
        controller.gateway_mac = "02:00:00:00:00:01"
        controller.restore_target = Mock()
        device = cli.Device("192.168.1.10", "02:00:00:00:00:10")
        device.state = "Disconnected"
        device.stop_event = Mock()
        controller.devices = [device]

        controller.restore_all()

        device.stop_event.set.assert_called_once_with()
        controller.restore_target.assert_called_once_with(
            device.ip, device.mac, controller.gateway_ip, controller.gateway_mac)
        self.assertEqual(device.state, "Connected")


if __name__ == "__main__":
    unittest.main()

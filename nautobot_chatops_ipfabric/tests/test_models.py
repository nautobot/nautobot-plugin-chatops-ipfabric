"""Test IP Fabric models."""
import unittest

from nautobot_chatops_ipfabric import ipfabric_models


class TestIPFabricModels(unittest.TestCase):
    """Test Models of IP Fabric."""

    def test_snapshot(self):
        """Verify the snapshot model works."""
        snap_json = {
            "name": None,
            "state": "loaded",
            "locked": False,
            "tsEnd": 1642608948957,
            "tsStart": 1642607756999,
            "id": "1980e282-df63-4b09-b7fb-701a966040f3",
        }
        snap = ipfabric_models.Snapshot(**snap_json)
        self.assertEqual(hash(snap), hash(snap_json["id"]))
        self.assertIn(snap_json["id"], str(snap))

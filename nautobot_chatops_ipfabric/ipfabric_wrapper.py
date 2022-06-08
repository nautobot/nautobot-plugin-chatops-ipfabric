"""IPFabric API integration."""

import logging
import requests
from .ipfabric_models import Snapshot

from django.conf import settings

from ipfabric_diagrams import IPFDiagram, Unicast
from ipfabric import IPFClient

# Default IP Fabric API pagination limit
DEFAULT_PAGE_LIMIT = 100
LAST = "$last"
PREV = "$prev"
LAST_LOCKED = "$lastLocked"

CHATOPS_IPFABRIC = "nautobot_chatops_ipfabric"
IPFABRIC_HOST = "IPFABRIC_HOST"
IPFABRIC_API_TOKEN = "IPFABRIC_API_TOKEN"
IPFABRIC_VERIFY = "IPFABRIC_VERIFY"
IPFABRIC_TIMEOUT = "IPFABRIC_TIMEOUT"

# COLUMNS
DEVICE_INFO_COLUMNS = ["hostname", "siteName", "vendor", "platform", "model"]
INTERFACE_LOAD_COLUMNS = ["intName", "inBytes", "outBytes"]

logger = logging.getLogger("rq.worker")

try:
    ipfabric_client = IPFClient(
        base_url=settings.PLUGINS_CONFIG[CHATOPS_IPFABRIC].get(IPFABRIC_HOST),
        token=settings.PLUGINS_CONFIG[CHATOPS_IPFABRIC].get(IPFABRIC_API_TOKEN),
        verify=settings.PLUGINS_CONFIG[CHATOPS_IPFABRIC].get(IPFABRIC_VERIFY),
    )

    ipfabric_diagram_client = IPFDiagram(
        base_url=settings.PLUGINS_CONFIG[CHATOPS_IPFABRIC].get(IPFABRIC_HOST),
        token=settings.PLUGINS_CONFIG[CHATOPS_IPFABRIC].get(IPFABRIC_API_TOKEN),
        verify=settings.PLUGINS_CONFIG[CHATOPS_IPFABRIC].get(IPFABRIC_VERIFY),
        timeout=settings.PLUGINS_CONFIG[CHATOPS_IPFABRIC].get(IPFABRIC_TIMEOUT),
    )
except:
    logger.error("Could not load IP Fabric client. Please verify HTTP access to the IP Fabric instance")


# pylint: disable=R0904
class IpFabric:
    """IpFabric will provide a wrapper for python-ipfabric clients that contain all the necessary API methods."""

    # TODO: remove
    EMPTY = "(empty)"

    def __init__(self, host_url, token, verify=True, timeout=10):
        self.client = IPFClient(
            base_url=host_url,
            token=token,
            verify=verify,
        )
        self.diagram = IPFDiagram(
            base_url=host_url,
            token=token,
            verify=verify,
            timeout=timeout,
        )

    def _get_snapshots(self):
        """Return Snapshots."""

        snap_dict = {}
        for snapshot in self.client.snapshots:
            if snapshot["state"] != "loaded":
                continue
            snap = Snapshot(**snapshot)
            snap_dict[snap.snapshot_id] = snap
            if LAST_LOCKED not in snap_dict and snap.locked:
                snap.last_locked = True
                snap_dict[LAST_LOCKED] = snap
            if LAST not in snap_dict:
                snap.last = True
                snap_dict[LAST] = snap
                continue
            if PREV not in snap_dict:
                snap.prev = True
                snap_dict[PREV] = snap
        return snap_dict

    @property
    def snapshots(self):
        """This gets all Snapshots, places them in Objects, and returns a dict {ID: Snapshot}."""
        choices = [(LAST, LAST)]
        named_snap_ids = set()
        snapshots = self._get_snapshots()

        if LAST in snapshots:
            named_snap_ids.add(snapshots[LAST].snapshot_id)
            choices[0] = (snapshots[LAST].description, snapshots[LAST].snapshot_id)
            snapshots.pop(snapshots[LAST].snapshot_id, None)
            snapshots.pop(LAST, None)
        if PREV in snapshots:
            choices.append((snapshots[PREV].description, snapshots[PREV].snapshot_id))
            named_snap_ids.add(snapshots[PREV].snapshot_id)
            snapshots.pop(snapshots[PREV].snapshot_id, None)
            snapshots.pop(PREV, None)
        if LAST_LOCKED in snapshots:
            if snapshots[LAST_LOCKED].snapshot_id not in named_snap_ids:
                choices.append((snapshots[LAST_LOCKED].description, snapshots[LAST_LOCKED].snapshot_id))
            snapshots.pop(snapshots[LAST_LOCKED].snapshot_id, None)
            snapshots.pop(LAST_LOCKED, None)

        for snapshot_id, snapshot in snapshots.items():
            choices.append((snapshot.description, snapshot_id))
        return choices
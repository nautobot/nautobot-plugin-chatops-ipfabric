"""IPFabric API integration."""

import logging

from ipfabric_diagrams import IPFDiagram
from ipfabric import IPFClient

# Default IP Fabric API pagination limit
DEFAULT_PAGE_LIMIT = 100
LAST = "$last"
PREV = "$prev"
LAST_LOCKED = "$lastLocked"

logger = logging.getLogger("rq.worker")


# pylint: disable=R0904, disable=R0903
class IpFabric:
    """IpFabric will provide a wrapper for python-ipfabric clients that contain all the necessary API methods."""

    def __init__(self, base_url, token, verify=False, timeout=10):
        """Initialise the IP Fabric wrapper object to provide access to the client and diagram API from the python-ipfabric library.

        Args:
            base_url (str): URL of the IP Fabric host.
            token (str): API token for the IP Fabric client to access the server.
            verify (bool, optional): Verify identity of requested host when using HTTPS. Defaults to False. Enable with verify='path/to/client.pem'.
            timeout (int, optional): HTTP timeout connection (seconds). Defaults to 10.
        """
        self.client = IPFClient(
            base_url=base_url,
            token=token,
            verify=verify,
        )
        self.diagram = IPFDiagram(
            base_url=base_url,
            token=token,
            verify=verify,
            timeout=timeout,
        )

    def get_formatted_snapshots(self):
        """Get all snapshots and format them for display in chatops choice menu.

        Returns:
            list: Snapshot objects as tuple (description, snapshot_id)
        """
        formatted_snapshots = []
        for snapshot_ref, snapshot in self.client.snapshots.items():
            if snapshot.state != "loaded":
                continue
            description = "🔒 " if snapshot.locked else ""
            if snapshot_ref in [LAST, PREV, LAST_LOCKED]:
                description += f"{snapshot_ref}: "
            if snapshot.name:
                description += snapshot.name + " - " + snapshot.end.strftime("%d-%b-%y %H:%M:%S")
            else:
                description += snapshot.end.strftime("%d-%b-%y %H:%M:%S") + " - " + snapshot.snapshot_id
            formatted_snapshots.append((description, snapshot.snapshot_id))
        return formatted_snapshots

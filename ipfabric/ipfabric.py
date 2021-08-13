"""IPFabric API integration."""

import logging
import requests

logger = logging.getLogger("ipfabric")


class IpFabric:
    """IpFabric will contain all the necessary API methods."""

    def __init__(self, host_url, token):
        """Auth is contained in the 'X-API-Token' in the header."""
        self.headers = {"Accept": "application/json", "Content-Type": "application/json", "X-API-Token": token}
        self.host_url = host_url

    def get_response(self, url, payload, method="POST"):
        """Get request and return response dict."""
        return self.get_response_json(method, url, payload).get("data", {})

    def get_response_json(self, method, url, payload, params=None):
        """Get request and return response dict."""
        response = requests.request(method, self.host_url + url, json=payload, params=params, headers=self.headers)
        return response.json()

    def get_devices_info(self):
        """Return Device info."""
        logger.debug("Received device list request")

        # columns and snapshot required
        payload = {
            "columns": ["hostname", "siteName", "vendor", "platform", "model"],
            "filters": {},
            "pagination": {"limit": 15, "start": 0},
            "snapshot": "$last",
        }
        return self.get_response("/api/v1/tables/inventory/devices", payload)

    def get_interfaces_load_info(self, device):
        """Return Interface load info."""
        logger.debug("Received interface counters request")

        # columns and snapshot required
        payload = {
            "columns": ["intName", "inBytes", "outBytes"],
            "filters": {"hostname": ["eq", device]},
            "pagination": {"limit": 48, "start": 0},
            "snapshot": "$last",
            "sort": {"order": "desc", "column": "intName"},
        }

        return self.get_response("/api/v1/tables/interfaces/load", payload)

    def get_snapshots(self):
        """Return Snapshots."""
        logger.debug("Received snapshot request")

        # no payload required
        payload = {}
        return self.get_response_json("GET", "/api/v1/snapshots", payload)

    def get_path_simulation(
        self, src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id
    ):  # pylint: disable=too-many-arguments
        """Return End to End Path Simulation."""
        params = {
            "source": src_ip,
            "destination": dst_ip,
            "sourcePort": src_port,
            "destinationPort": dst_port,
            "protocol": protocol,
            "snapshot": snapshot_id,
            # "asymmetric": asymmetric,
            # "rpf": rpf,
        }
        logger.debug("Received end-to-end path simulation request: ", params)  # pylint: disable=logging-too-many-args

        # no payload required
        payload = {}
        return self.get_response_json("GET", "/api/v1/graph/end-to-end-path", payload, params)

    def get_interfaces_errors_info(self, device):
        """Return bi-directional interface errors info."""
        logger.debug("Received interface error counters request")

        # columns and snapshot required
        payload = {
            "columns": ["intName", "errPktsPct", "errRate"],
            "filters": {"hostname": ["eq", device]},
            "pagination": {"limit": 48, "start": 0},
            "snapshot": "$last",
            "sort": {"order": "desc", "column": "intName"},
        }

        return self.get_response("/api/v1/tables/interfaces/errors/bidirectional", payload)

    def get_interfaces_drops_info(self, device):
        """Return interface drops info."""
        logger.debug("Received interface drop counters request")

        # columns and snapshot required
        payload = {
            "columns": ["intName", "dropsPktsPct", "dropsRate"],
            "filters": {"hostname": ["eq", device]},
            "pagination": {"limit": 48, "start": 0},
            "snapshot": "$last",
            "sort": {"order": "desc", "column": "intName"},
        }

        return self.get_response("/api/v1/tables/interfaces/drops/bidirectional", payload)

    def get_bgp_neighbors(self, device, state):
        """Retrieve BGP neighbors in IP Fabric for a specific device."""
        logger.debug("Received BGP neighbor request")

        payload = {
            "columns": [
                "hostname",
                "localAs",
                "srcInt",
                "localAddress",
                "vrf",
                "neiHostname",
                "neiAddress",
                "neiAs",
                "state",
                "totalReceivedPrefixes",
            ],
            "snapshot": "$last",
            "filters": {"hostname": ["eq", device]},
        }

        if state != "any":
            payload["filters"] = {"and": [{"hostname": ["eq", device]}, {"state": ["eq", state]}]}
        return self.get_response("/api/v1/tables/routing/protocols/bgp/neighbors", payload)

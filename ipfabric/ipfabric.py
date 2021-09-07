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

    def get_devices_info(self, snapshot_id="$last"):
        """Return Device info."""
        logger.debug("Received device list request")

        # columns and snapshot required
        payload = {
            "columns": ["hostname", "siteName", "vendor", "platform", "model"],
            "filters": {},
            "snapshot": snapshot_id,
        }
        return self.get_response("/api/v1/tables/inventory/devices", payload)

    def get_device_inventory(self, search_key, search_value, snapshot_id="$last"):
        """Return Device info."""
        logger.debug("Received device inventory request")

        # columns and snapshot required
        payload = {
            "columns": [
                "hostname",
                "siteName",
                "vendor",
                "platform",
                "model",
                "memoryUtilization",
                "version",
                "sn",
                "loginIp",
            ],
            "filters": {},
            "snapshot": snapshot_id,
        }
        payload["filters"][search_key] = ["eq", search_value]
        logger.debug("Requesting inventory with payload: %s", payload)
        return self.get_response("/api/v1/tables/inventory/devices", payload)

    def get_interfaces_load_info(self, device, snapshot_id="$last"):
        """Return Interface load info."""
        logger.debug("Received interface counters request")

        # columns and snapshot required
        payload = {
            "columns": ["intName", "inBytes", "outBytes"],
            "filters": {"hostname": ["eq", device]},
            "pagination": {"limit": 48, "start": 0},
            "snapshot": snapshot_id,
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
        # end-to-end-path don't support $last as snapshot_id, getting the actual ID
        if snapshot_id == "$last":
            loaded_snapshots = [snap_id["id"] for snap_id in self.get_snapshots() if snap_id["state"] == "loaded"]
            if not loaded_snapshots:
                return []

            snapshot_id = loaded_snapshots[-1]

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

    def get_interfaces_errors_info(self, device, snapshot_id="$last"):
        """Return bi-directional interface errors info."""
        logger.debug("Received interface error counters request")

        # columns and snapshot required
        payload = {
            "columns": ["intName", "errPktsPct", "errRate"],
            "filters": {"hostname": ["eq", device]},
            "pagination": {"limit": 48, "start": 0},
            "snapshot": snapshot_id,
            "sort": {"order": "desc", "column": "intName"},
        }

        return self.get_response("/api/v1/tables/interfaces/errors/bidirectional", payload)

    def get_interfaces_drops_info(self, device, snapshot_id="$last"):
        """Return interface drops info."""
        logger.debug("Received interface drop counters request")

        # columns and snapshot required
        payload = {
            "columns": ["intName", "dropsPktsPct", "dropsRate"],
            "filters": {"hostname": ["eq", device]},
            "pagination": {"limit": 48, "start": 0},
            "snapshot": snapshot_id,
            "sort": {"order": "desc", "column": "intName"},
        }

        return self.get_response("/api/v1/tables/interfaces/drops/bidirectional", payload)

    def get_bgp_neighbors(self, device, state, snapshot_id="$last"):
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
            "snapshot": snapshot_id,
            "filters": {"hostname": ["eq", device]},
        }

        if state != "any":
            payload["filters"] = {"and": [{"hostname": ["eq", device]}, {"state": ["eq", state]}]}
        return self.get_response("/api/v1/tables/routing/protocols/bgp/neighbors", payload)

    def get_parsed_path_simulation(
        self, src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id="$last"
    ):  # pylint: disable=too-many-arguments, too-many-locals
        """Path Simulation from source to destination IP.

        Args:
            src_ip ([string]): Source IP
            dst_ip ([string]): Destination IP
            src_port ([string]): Source Port
            dst_port ([string]): Destination Port
            protocol ([string]): Transport Protocol
            snapshot_id ([string]): Snapshot ID

        Returns:
            [list]: Parsed end-to-end path
        """
        response = self.get_path_simulation(src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id)
        graph = response.get("graph", {})
        nodes = {graph_node["id"]: graph_node for graph_node in graph.get("nodes", {})}
        edges = {edge["id"]: edge for edge in graph.get("edges", {})}
        path = []

        # ipfabric returns the source of the path as the last element in the nodes list
        for idx, node in enumerate(graph.get("nodes", [])[::-1]):
            edge_id = node["forwarding"][0]["dstIntList"][0]["id"]
            edge = edges.get(edge_id)
            if not edge or idx == len(nodes) - 1:
                continue  # don't add to path as the edge for the penultimate node will contain the 'target' node
            path.append(
                (
                    idx + 1,
                    node.get("hostname"),
                    edge["slabel"],
                    edge["srcAddr"],
                    edge["dstAddr"],
                    edge["tlabel"],
                    nodes.get(edge["target"], {}).get("hostname"),
                )
            )
        return path

    def get_src_dst_endpoint(
        self, src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id="$last"
    ):  # pylint: disable=too-many-arguments, too-many-locals
        """Get the source/destination interface and source/destination node for the path.

        Args:
            src_ip ([string]): Source IP
            dst_ip ([string]): Destination IP
            src_port ([string]): Source Port
            dst_port ([string]): Destination Port
            protocol ([string]): Transport Protocol
            snapshot_id ([string]): Snapshot ID

        Returns:
            [dict]: Src and Dst interface and node strings
        """
        response = self.get_path_simulation(src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id)
        graph = response.get("graph", {})

        endpoints = {}
        src_intf = ""
        dst_intf = ""
        src_node = ""
        dst_node = ""

        # ipfabric returns the source of the path as the last element in the nodes list
        for idx, node in enumerate(graph.get("nodes", [])[::-1]):
            if idx == 0:
                src_intf = node["forwarding"][0]["srcIntList"][0]["int"]
                src_node = node.get("hostname")
                endpoints["src"] = f"{src_intf} - {src_node}"
            if idx == len(graph.get("nodes", [])) - 1:
                dst_intf = node["forwarding"][0]["dstIntList"][0]["int"]
                dst_node = node.get("hostname")
                endpoints["dst"] = f"{dst_intf} - {dst_node}"
        return endpoints

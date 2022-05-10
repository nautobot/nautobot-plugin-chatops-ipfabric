"""IPFabric API integration."""

import logging
import requests
from .ipfabric_models import Snapshot

# Default IP Fabric API pagination limit
DEFAULT_PAGE_LIMIT = 100
LAST = "$last"
PREV = "$prev"
LAST_LOCKED = "$lastLocked"

logger = logging.getLogger("rq.worker")


def create_regex(string: str) -> str:
    """Takes a string and returns a case insensitive regex."""
    regex = "^"
    for i in string.upper():
        if i.isalpha():
            regex += f"[{i}{i.lower()}]"
        else:
            regex += i
    return regex + "$"


# pylint: disable=R0904
class IpFabric:
    """IpFabric will contain all the necessary API methods."""

    EMPTY = "(empty)"

    def __init__(self, host_url, token, verify=True):
        """Auth is contained in the 'X-API-Token' in the header."""
        self.headers = {"Accept": "application/json", "Content-Type": "application/json", "X-API-Token": token}
        self.host_url = host_url
        self.verify = verify

    def get_response(self, url, payload, method="POST"):
        """Get request and return response dict."""
        return self.get_response_json(method, url, payload).get("data", {})

    def get_response_json(self, method, url, payload, params=None):
        """Get request and return response dict."""
        response = requests.request(
            method, self.host_url + url, json=payload, params=params, headers=self.headers, verify=self.verify
        )
        return response.json()

    def get_response_raw(self, method, url, payload, params=None):
        """Get request and return response dict."""
        headers = {**self.headers, "Accept": "*/*"}
        return requests.request(
            method, self.host_url + url, json=payload, params=params, headers=headers, verify=self.verify
        )

    def get_devices_info(self, snapshot_id=LAST, limit=DEFAULT_PAGE_LIMIT):
        """Return Device info."""
        logger.debug("Received device list request")

        # columns and snapshot required
        payload = {
            "columns": ["hostname", "siteName", "vendor", "platform", "model"],
            "filters": {},
            "pagination": {"limit": limit, "start": 0},
            "snapshot": snapshot_id,
        }
        return self.get_response("/api/v1/tables/inventory/devices", payload)

    def get_os_version(self):
        """Return IP Fabric OS version info."""
        logger.debug("Received OS version request")

        payload = {}
        response = self.get_response_json("GET", "/api/v1/os/version", payload)
        os_version = float(response.get("version", "0.0").rpartition(".")[0])
        logger.debug("Your IP Fabric OS version is: %s", os_version)
        return os_version

    def get_device_inventory(self, search_key, search_value, snapshot_id=LAST, limit=DEFAULT_PAGE_LIMIT):
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
            "filters": {search_key: ["eq", search_value]},
            "pagination": {"limit": limit, "start": 0},
            "snapshot": snapshot_id,
        }
        logger.debug("Requesting inventory with payload: %s", payload)
        return self.get_response("/api/v1/tables/inventory/devices", payload)

    def get_interfaces_load_info(self, device, snapshot_id=LAST, limit=DEFAULT_PAGE_LIMIT):
        """Return Interface load info."""
        logger.debug("Received interface counters request")

        # columns and snapshot required
        payload = {
            "columns": ["intName", "inBytes", "outBytes"],
            "filters": {"hostname": ["reg", create_regex(device)]},
            "pagination": {"limit": limit, "start": 0},
            "snapshot": snapshot_id,
            "sort": {"order": "desc", "column": "intName"},
        }

        return self.get_response("/api/v1/tables/interfaces/load", payload)

    def get_snapshots(self):
        """Return Snapshots."""
        logger.debug("Received snapshot request")

        # no payload required
        response = self.get_response_json("GET", "/api/v1/snapshots", payload={})
        snap_dict = {}
        for snapshot in response:
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
        snapshots = self.get_snapshots()

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

    def get_path_simulation(
        self, src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id
    ):  # pylint: disable=too-many-arguments
        """Return End to End Path Simulation."""
        # end-to-end-path don't support $last as snapshot_id, getting the actual ID
        loaded_snapshots = self.get_snapshots()
        if snapshot_id not in loaded_snapshots:
            logger.debug("Invalid snapshot_id: %s", snapshot_id)
            return {}
        snapshot_id = loaded_snapshots[snapshot_id].snapshot_id

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

    def get_interfaces_errors_info(self, device, snapshot_id=LAST, limit=DEFAULT_PAGE_LIMIT):
        """Return bi-directional interface errors info."""
        logger.debug("Received interface error counters request")

        # columns and snapshot required
        payload = {
            "columns": ["intName", "errPktsPct", "errRate"],
            "filters": {"hostname": ["reg", create_regex(device)]},
            "pagination": {"limit": limit, "start": 0},
            "snapshot": snapshot_id,
            "sort": {"order": "desc", "column": "intName"},
        }

        return self.get_response("/api/v1/tables/interfaces/errors/bidirectional", payload)

    def get_interfaces_drops_info(self, device, snapshot_id=LAST, limit=DEFAULT_PAGE_LIMIT):
        """Return interface drops info."""
        logger.debug("Received interface drop counters request")

        # columns and snapshot required
        payload = {
            "columns": ["intName", "dropsPktsPct", "dropsRate"],
            "filters": {"hostname": ["reg", create_regex(device)]},
            "pagination": {"limit": limit, "start": 0},
            "snapshot": snapshot_id,
            "sort": {"order": "desc", "column": "intName"},
        }

        return self.get_response("/api/v1/tables/interfaces/drops/bidirectional", payload)

    def get_bgp_neighbors(self, device, state, snapshot_id=LAST, limit=DEFAULT_PAGE_LIMIT):
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
            "filters": {"hostname": ["reg", create_regex(device)]},
            "pagination": {"limit": limit, "start": 0},
        }

        if state != "any":
            payload["filters"] = {"and": [{"hostname": ["reg", create_regex(device)]}, {"state": ["eq", state]}]}
        return self.get_response("/api/v1/tables/routing/protocols/bgp/neighbors", payload)

    def get_parsed_path_simulation(
        self, src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id=LAST
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
        path = []
        nodes = {graph_node["id"]: graph_node for graph_node in graph.get("nodes", {})}

        # ipfabric returns the source of the path as the last element in the nodes list
        for idx, edge in enumerate(graph.get("edges", [])[::-1]):
            forwarding_type = ""
            edge_id = edge.get("id")

            src_name = edge.get("source")
            src_node = nodes.get(src_name, {})
            src_forwarding = src_node.get("forwarding")
            src_type = src_node.get("devType")
            src_fwd = edge.get("srcAddr", "")
            if src_forwarding:
                forwarding_type = src_forwarding[0].get("search")

            dst_name = edge.get("target")
            dst_node = nodes.get(dst_name, {})
            dst_forwarding = dst_node.get("forwarding")
            dst_type = dst_node.get("devType")
            dst_fwd = edge.get("dstAddr", "")
            if dst_forwarding:
                forwarding_type = dst_forwarding[0].get("search")

            if forwarding_type == "mpls":
                if src_forwarding:
                    # edge src tag
                    src_node_int_list = [*src_forwarding[0].get("srcIntList"), *src_forwarding[0].get("dstIntList")]
                    for intf in src_node_int_list:
                        if intf.get("id") == edge_id:
                            src_fwd = intf.get("labelStack")

                if dst_forwarding:
                    # edge dst tag
                    dst_node_int_list = [*dst_forwarding[0].get("srcIntList"), *dst_forwarding[0].get("dstIntList")]
                    for intf in dst_node_int_list:
                        if edge.get("tlabel") and intf.get("int") == edge.get("tlabel"):
                            dst_fwd = intf.get("labelStack")

            path.append(
                (
                    idx + 1,
                    forwarding_type or IpFabric.EMPTY,
                    src_node.get("hostname") or IpFabric.EMPTY,
                    src_type or IpFabric.EMPTY,
                    edge.get("slabel") or IpFabric.EMPTY,
                    src_fwd or IpFabric.EMPTY,
                    dst_fwd or IpFabric.EMPTY,
                    edge.get("tlabel") or IpFabric.EMPTY,
                    dst_type or IpFabric.EMPTY,
                    dst_node.get("hostname") or IpFabric.EMPTY,
                )
            )
        return path

    def get_src_dst_endpoint(
        self, src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id=LAST
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
        endpoints = {"src": "Unknown", "dst": "Unknown"}

        # ipfabric returns the source of the path as the last element in the nodes list
        for idx, node in enumerate(graph.get("nodes", [])[::-1]):
            node_forwarding = node.get("forwarding")
            if node_forwarding:
                if idx == 0:
                    src_intf = node_forwarding[0]["srcIntList"][0]["int"]
                    endpoints["src"] = f"{src_intf} -- {node.get('hostname')}"
                elif idx == len(graph.get("nodes", [])) - 1:
                    dst_intf = node_forwarding[0]["dstIntList"][0]["int"]
                    endpoints["dst"] = f"{dst_intf} -- {node.get('hostname')}"
        return endpoints

    def get_wireless_clients(self, ssid=None, snapshot_id=LAST, limit=DEFAULT_PAGE_LIMIT):
        """Get details of wireless clients associated with access points."""
        logger.debug("Received wireless client request")

        payload = {
            "columns": [
                "controller",
                "siteName",
                "apName",
                "client",
                "clientIp",
                "ssid",
                "rssi",
                "signalToNoiseRatio",
                "state",
            ],
            "snapshot": snapshot_id,
            "pagination": {"limit": limit, "start": 0},
            "filters": {},
        }

        if ssid:
            payload["filters"] = {"ssid": ["eq", ssid]}

        return self.get_response("/api/v1/tables/wireless/clients", payload)

    def get_wireless_ssids(self, snapshot_id=LAST, limit=DEFAULT_PAGE_LIMIT):
        """Get details of wireless SSIDs."""
        logger.debug("Received wireless SSID request")

        payload = {
            "columns": [
                "wlanSsid",
                "siteName",
                "apName",
                "radioDscr",
                "radioStatus",
                "clientCount",
            ],
            "snapshot": snapshot_id,
            "filters": {},
            "pagination": {"limit": limit, "start": 0},
        }

        return self.get_response("/api/v1/tables/wireless/radio", payload)

    def validate_version(self, operator_func, version):
        """Validate the IP Fabric OS version."""
        logger.debug("Validate IP Fabric OS version is %s %s", operator_func, version)

        ipfabric_version = self.get_os_version()
        return operator_func(ipfabric_version, version)

    def get_host(self, search_key, search_value, snapshot_id=LAST, limit=DEFAULT_PAGE_LIMIT):
        """Return inventory host information."""
        logger.debug("Received host inventory request - %s %s", search_key, search_value)

        # columns and snapshot required
        payload = {
            "columns": [
                "ip",
                "vrf",
                "dnsName",
                "siteName",
                "edges",
                "gateways",
                "accessPoints",
                "mac",
                "vendor",
                "vlan",
            ],
            "filters": {search_key: ["eq", search_value]},
            "pagination": {"limit": limit, "start": 0},
            "snapshot": snapshot_id,
        }
        logger.debug("Requesting host inventory with payload: %s", payload)
        return self.get_response("/api/v1/tables/addressing/hosts", payload)

    def find_host(self, search_key, search_value, snapshot_id=LAST, limit=DEFAULT_PAGE_LIMIT):
        """Get and parse inventory host information."""
        logger.debug("Received host inventory request - %s %s", search_key, search_value)

        hosts = self.get_host(search_key, search_value, snapshot_id, limit)
        logger.debug("Parsing hosts: %s", hosts)
        parsed_hosts = []

        for host in hosts:
            parsed_edges = []
            parsed_gws = []
            parsed_aps = []

            for edge in host.get("edges"):
                parsed_edges.append(f"{edge.get('hostname', '')} ({edge.get('intName', '')})")

            for gateway in host.get("gateways"):
                parsed_gws.append(f"{gateway.get('hostname', '')} ({gateway.get('intName', '')})")

            for access_point in host.get("accessPoints"):
                parsed_aps.append(f"{access_point.get('hostname', '')} ({access_point.get('intName', '')})")

            host["edges"] = ";".join(parsed_edges) if parsed_edges else ""
            host["gateways"] = ";".join(parsed_gws) if parsed_gws else ""
            host["accessPoints"] = ";".join(parsed_aps) if parsed_aps else ""

            parsed_hosts.append(host)
        return parsed_hosts

"""Worker functions implementing Nautobot "ipfabric" command and subcommands."""
import logging
import requests

from django.conf import settings
from django_rq import job
from nautobot_chatops.choices import CommandStatusChoices
from nautobot_chatops.workers import subcommand_of, handle_subcommands

IPFABRIC_LOGO_PATH = "ipfabric/ipfabric_logo.png"
IPFABRIC_LOGO_ALT = "IPFabric Logo"

logger = logging.getLogger("rq.worker")


def ipfabric_logo(dispatcher):
    """Construct an image_element containing the locally hosted IP Fabric logo."""
    return dispatcher.image_element(dispatcher.static_url(IPFABRIC_LOGO_PATH), alt_text=IPFABRIC_LOGO_ALT)


@job("default")
def ipfabric(subcommand, **kwargs):
    """Interact with ipfabric plugin."""
    return handle_subcommands("ipfabric", subcommand, **kwargs)


def prompt_hello_input(action_id, help_text, dispatcher, choices=None):
    """Prompt the user for input."""
    welcome_choices = ["Hi", "Hello", "Hola", "Ciao"]
    choices = [(welcome, welcome.lower()) for welcome in welcome_choices]
    dispatcher.prompt_from_menu(action_id, help_text, choices)
    return False


class IpFabric:
    """IpFabric will contain all the necessary API methods."""

    def __init__(self, host_url, token):
        """Auth is contained in the 'X-API-Token' in the header."""
        self.headers = {"Accept": "application/json", "Content-Type": "application/json", "X-API-Token": token}
        self.host_url = host_url

    def get_response(self, url, payload):
        """Post request and return response dict."""
        response = requests.post(self.host_url + url, json=payload, headers=self.headers)
        return response.json().get("data", {})

    def get_response_json(self, method, url, payload, params=None):
        """GET request and return response dict."""
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

    def get_path_simulation(self, src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id):
        """Return End to End Path Simulation."""
        logger.debug("Received end-to-end path simulation request")

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
        # no payload required
        payload = {}
        return self.get_response_json("GET", "/api/v1/graph/end-to-end-path", payload, params)


ipfabric_api = IpFabric(
    host_url=settings.PLUGINS_CONFIG["ipfabric"].get("IPFABRIC_HOST"),
    token=settings.PLUGINS_CONFIG["ipfabric"].get("IPFABRIC_API_TOKEN"),
)


def prompt_device_input(action_id, help_text, dispatcher, choices=None):
    """Prompt the user for input."""
    choices = [(device["hostname"], device["hostname"].lower()) for device in ipfabric_api.get_devices_info()]
    dispatcher.prompt_from_menu(action_id, help_text, choices)
    return False


@subcommand_of("ipfabric")
def get_int_load(dispatcher, device=None):
    """Get interfaces load per device '/ipfabric get-int-load $device'."""
    if not device:
        prompt_device_input("ipfabric get-int-load", "Which device are you interested in", dispatcher)
        return False

    dispatcher.send_markdown(f"Load in interfaces for {device}.")
    interfaces = ipfabric_api.get_interfaces_load_info(device)

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                "ipfabric",
                "get-int-load",
                [],
                "Interfaces Current Data",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.host_url}/technology/interfaces/rate/inbound"),
        ]
    )

    dispatcher.send_large_table(
        ["IntName", "IN bps", "OUT bps"],
        [
            (
                interface["intName"],
                interface["inBytes"],
                interface["outBytes"],
            )
            for interface in interfaces
        ],
    )

    return True


@subcommand_of("ipfabric")
def hello_world(dispatcher, arg1=None):
    """Run logic and return to user via client command '/ipfabric hello-world arg1'."""
    if not arg1:
        prompt_hello_input("ipfabric hello-world", "What would you like to say?", dispatcher)
        return False

    logger.debug("Received arg1 %s", arg1)
    dispatcher.send_markdown(f"Just wanted to say {arg1}")
    return True


@subcommand_of("ipfabric")
def device_list(dispatcher):
    """IP Fabric Inventory device list."""
    devices = ipfabric_api.get_devices_info()

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                "ipfabric",
                "device-list",
                [],
                "Inventory Device List",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.host_url}/inventory/devices"),
        ]
    )

    dispatcher.send_large_table(
        ["Hostname", "Site", "Vendor", "Platform", "Model"],
        [
            (device["hostname"], device["siteName"], device["vendor"], device["platform"], device["model"])
            for device in devices
        ],
    )
    return True


@subcommand_of("ipfabric")
def end_to_end_path(dispatcher, src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id):
    """Execute end-to-end path simulation between source and target IP address."""
    snapshots = [(snapshot.get("id", ""), snapshot.get("id", "")) for snapshot in ipfabric_api.get_snapshots()]

    logger.info("Snapshots %s", snapshots)

    dialog_list = [
        {
            "type": "text",
            "label": "Source IP",
        },
        {
            "type": "text",
            "label": "Destination IP",
        },
        {
            "type": "text",
            "label": "Source Port",
            "default": "1000",
        },
        {
            "type": "text",
            "label": "Destination Port",
            "default": "22",
        },
        {
            "type": "select",
            "label": "Protocol",
            "choices": [("TCP", "tcp"), ("UDP", "udp"), ("ICMP", "icmp")],
            "default": ("TCP", "tcp"),
        },
        {
            "type": "select",
            "label": "Snapshot ID",
            "choices": snapshots,
            "default": snapshots[0],
        },
    ]

    if not all([src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id]):
        dispatcher.multi_input_dialog("ipfabric", "end-to-end-path", "Path Simulation", dialog_list)
        return CommandStatusChoices.STATUS_SUCCEEDED

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                "ipfabric",
                "end-to-end-path",
                [],
                "Path Simulation",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.host_url}/graph/end-to-end-path"),
        ]
    )

    # request simulation
    response = ipfabric_api.get_path_simulation(src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id)
    graph = response.get("graph", {})
    nodes = {graph_node["id"]: graph_node for graph_node in graph.get("nodes", {})}
    edges = {edge["id"]: edge for edge in graph.get("edges", {})}

    path = []
    src_intf = ""
    dst_intf = ""
    src_node = ""
    dst_node = ""
    src_node_idx = 0
    dst_node_idx = len(nodes) - 1

    # ipfabric returns the source of the path as the last element in the nodes list
    for idx, node in enumerate(graph.get("nodes", [])[::-1]):
        edge_id = node["forwarding"][0]["dstIntList"][0]["id"]
        edge = edges.get(edge_id)
        if idx == src_node_idx:
            src_intf = node["forwarding"][0]["srcIntList"][0]["int"]
            src_node = node.get("hostname")
        if idx == dst_node_idx:
            dst_intf = node["forwarding"][0]["dstIntList"][0]["int"]
            dst_node = node.get("hostname")
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
    dispatcher.send_markdown(
        f"{dispatcher.bold('Source: ')} {src_ip} [{src_intf} - {src_node}]\n"
        f"{dispatcher.bold('Destination: ')} {dst_ip} [{dst_intf} - {dst_node}]\n"
    )
    dispatcher.send_large_table(
        ["Hop", "Src Host", "Src Intf", "Src IP", "Dst IP", "Dst Intf", "Dst Host"],
        path,
    )

    return True

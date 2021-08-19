"""Worker functions implementing Nautobot "ipfabric" command and subcommands."""
import logging

from django.conf import settings
from django_rq import job
from nautobot_chatops.choices import CommandStatusChoices
from nautobot_chatops.workers import subcommand_of, handle_subcommands
from .ipfabric import IpFabric
from .models import IpFabricChatopsContext

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


def prompt_snapshot(action_id, help_text, dispatcher, choices=None):
    """Prompt the user for snapshot input."""
    choices = [(snapshot.get("id", ""), snapshot.get("id", "")) for snapshot in ipfabric_api.get_snapshots()]
    dispatcher.prompt_from_menu(action_id, help_text, choices)
    return False


def path_simulation(src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id):  # pylint: disable=too-many-arguments
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
    response = ipfabric_api.get_path_simulation(src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id)
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
    src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id
):  # pylint: disable=too-many-arguments
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
    response = ipfabric_api.get_path_simulation(src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id)
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
def get_int_errors(dispatcher, device=None):
    """Get interfaces errors per device '/ipfabric get-int-load $device'."""
    if not device:
        prompt_device_input("ipfabric get-int-errors", "Which device are you interested in", dispatcher)
        return False

    dispatcher.send_markdown(f"Load in interfaces for {device}.")
    interfaces = ipfabric_api.get_interfaces_errors_info(device)

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                "ipfabric",
                "get-int-errors",
                [],
                "Interfaces Current Error Data",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.host_url}/technology/interfaces/error-rates/bidirectional"),
        ]
    )

    dispatcher.send_large_table(
        ["IntName", "Error %", "Error Rate"],
        [
            (
                interface["intName"],
                interface["errPktsPct"],
                interface["errRate"],
            )
            for interface in interfaces
        ],
    )

    return True


@subcommand_of("ipfabric")
def get_int_drops(dispatcher, device=None):
    """Get bi-directional interfaces drops per device '/ipfabric get-int-drops $device'."""
    if not device:
        prompt_device_input("ipfabric get-int-drops", "Which device are you interested in", dispatcher)
        return False

    dispatcher.send_markdown(f"Load in interfaces for {device}.")
    interfaces = ipfabric_api.get_interfaces_drops_info(device)

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                "ipfabric",
                "get-int-drops",
                [],
                "Interfaces Average Drop Data",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.host_url}/technology/interfaces/drop-rates/bidirectional"),
        ]
    )

    dispatcher.send_large_table(
        ["IntName", "% Drops", "Drop Rate"],
        [
            (
                interface["intName"],
                interface["dropsPktsPct"],
                interface["dropsRate"],
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
def set_snapshot(dispatcher, snapshot=None):
    """Set snapshot as reference for commands."""
    if not snapshot:
        prompt_snapshot("ipfabric set-snapshot", "What snapshot are you interested in?", dispatcher)
        return False

    snapshots = [(snapshot.get("id", ""), snapshot.get("id", "")) for snapshot in ipfabric_api.get_snapshots()]
    if snapshot not in snapshots:
        dispatcher.send_markdown(f"Snapshot *{snapshot}* does not exist in IP Fabric.")
        return False

    context = IpFabricChatopsContext.objects.first()
    if not context:
        context = IpFabricChatopsContext.objects.create(snapshot=snapshot)
    else:
        context.snapshot = snapshot
        IpFabricChatopsContext.save()

    dispatcher.send_markdown(f"Snapshot *{snapshot}* is now used as the default for the subsequent commands.")
    return True


@subcommand_of("ipfabric")
def get_snapshot(dispatcher, snapshot=None):
    """Get snapshot as reference for commands."""
    context = IpFabricChatopsContext.objects.first()
    if not context or not context.snapshot:
        dispatcher.send_markdown("No snapshot not defined yet. Use 'ipfabric set-snapshot' to define one.")
    else:
        dispatcher.send_markdown(f"Snapshot *{context.snapshot}* is defined.")

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
def end_to_end_path(
    dispatcher, src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id
):  # pylint: disable=too-many-arguments, too-many-locals
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
    path = path_simulation(src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id)
    endpoints = get_src_dst_endpoint(src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id)

    dispatcher.send_markdown(
        f"{dispatcher.bold('Source: ')} {src_ip} [{endpoints.get('src')}]\n"
        f"{dispatcher.bold('Destination: ')} {dst_ip} [{endpoints.get('dst')}]\n"
    )
    dispatcher.send_large_table(
        ["Hop", "Src Host", "Src Intf", "Src IP", "Dst IP", "Dst Intf", "Dst Host"],
        path,
    )

    return True


@subcommand_of("ipfabric")
def get_bgp_neighbors(dispatcher, device=None, state=None):
    """Get BGP neighbors by device."""
    if not device:
        prompt_device_input("ipfabric get-bgp-neighbors", "Which device are you interested in", dispatcher)
        return False

    if not state:
        dispatcher.prompt_from_menu(
            f"ipfabric get-bgp-neighbors {device}",
            "BGP peer state",
            [
                ("Any", "any"),
                ("Established", "established"),
                ("Idle", "idle"),
                ("Active", "active"),
                ("Openconfirm", "openconfirm"),
                ("Opensent", "opensent"),
                ("Connect", "connect"),
            ],
            default=("Any", "any"),
        )
        return False

    devices = [device["hostname"] for device in ipfabric_api.get_devices_info()]
    if device not in devices:
        dispatcher.send_markdown(f"Device *{device}* does not exist in IP Fabric.")
        return False

    bgp_neighbors = ipfabric_api.get_bgp_neighbors(device, state)

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                "ipfabric",
                "get-bgp-neighbors",
                [("Device", device), ("State", state)],
                "BGP neighbor data",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.host_url}/technology/routing/bgp/neighbors"),
        ]
    )

    dispatcher.send_large_table(
        [
            "hostname",
            "local As",
            "src Int",
            "local Address",
            "vrf",
            "nei Hostname",
            "nei Address",
            "nei As",
            "state",
            "total Received Prefixes",
        ],
        [
            (
                neighbor["hostname"],
                neighbor["localAs"],
                neighbor["srcInt"],
                neighbor["localAddress"],
                neighbor["vrf"],
                neighbor["neiHostname"],
                neighbor["neiAddress"],
                neighbor["neiAs"],
                neighbor["state"],
                neighbor["totalReceivedPrefixes"],
            )
            for neighbor in bgp_neighbors
        ],
    )

    return True

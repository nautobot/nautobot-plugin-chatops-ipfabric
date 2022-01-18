"""Worker functions implementing Nautobot "ipfabric" command and subcommands."""
import logging
import tempfile
import os
from datetime import datetime
from operator import ge

from django.conf import settings
from django_rq import job
from nautobot_chatops.choices import CommandStatusChoices
from nautobot_chatops.workers import subcommand_of, handle_subcommands
from netutils.ip import is_ip
from netutils.mac import is_valid_mac
from .ipfabric import IpFabric
from .context import get_context, set_context

BASE_CMD = "ipfabric"
IPFABRIC_LOGO_PATH = "ipfabric/ipfabric_logo.png"
IPFABRIC_LOGO_ALT = "IPFabric Logo"

logger = logging.getLogger("rq.worker")

ipfabric_api = IpFabric(
    host_url=settings.PLUGINS_CONFIG["nautobot_chatops_ipfabric"].get("IPFABRIC_HOST"),
    token=settings.PLUGINS_CONFIG["nautobot_chatops_ipfabric"].get("IPFABRIC_API_TOKEN"),
)

inventory_field_mapping = {
    "site": "siteName",
    "model": "model",
    "platform": "platform",
    "vendor": "vendor",
}

inventory_host_fields = ["ip", "mac"]
inventory_host_func_mapper = {inventory_host_fields[0]: is_ip, inventory_host_fields[1]: is_valid_mac}


def ipfabric_logo(dispatcher):
    """Construct an image_element containing the locally hosted IP Fabric logo."""
    return dispatcher.image_element(dispatcher.static_url(IPFABRIC_LOGO_PATH), alt_text=IPFABRIC_LOGO_ALT)


@job("default")
def ipfabric(subcommand, **kwargs):
    """Interact with ipfabric plugin."""
    return handle_subcommands("ipfabric", subcommand, **kwargs)


# PROMPTS


def prompt_device_input(action_id, help_text, dispatcher, choices=None):
    """Prompt the user for input."""
    choices = [
        (device["hostname"], device["hostname"].lower())
        for device in ipfabric_api.get_devices_info(get_user_snapshot(dispatcher))
    ]
    dispatcher.prompt_from_menu(action_id, help_text, choices)
    return False


def prompt_snapshot_id(action_id, help_text, dispatcher, choices=None):
    """Prompt the user for snapshot ID."""
    snapshots = []
    for snapshot in ipfabric_api.get_snapshots():
        if snapshot["state"] == "loaded":
            snapshot_id = snapshot["id"]
            snapshot_name = snapshot["name"] or snapshot_id
            snapshots.append((snapshot_name, snapshot_id))
    choices = snapshots + [("$last", "$last")]
    return dispatcher.prompt_from_menu(action_id, help_text, choices, default=("$last", "$last"))


def prompt_inventory_filter_values(action_id, help_text, dispatcher, filter_key, choices=None):
    """Prompt the user for input inventory search value selection."""
    column_name = inventory_field_mapping.get(filter_key.lower())
    choices = {
        (device[column_name], device[column_name])
        for device in ipfabric_api.get_devices_info(get_user_snapshot(dispatcher))
        if device.get(column_name)
    }
    dispatcher.prompt_from_menu(action_id, help_text, list(choices))
    return False


def prompt_inventory_filter_keys(action_id, help_text, dispatcher, choices=None):
    """Prompt the user for input inventory search criteria."""
    choices = [("Site", "site"), ("Model", "model"), ("Vendor", "vendor"), ("Platform", "platform")]
    dispatcher.prompt_from_menu(action_id, help_text, choices)
    return False


def prompt_find_host_filter_keys(action_id, help_text, dispatcher, choices=None):
    """Prompt the user for find host search criteria."""
    choices = [("Host IP address", inventory_host_fields[0]), ("Host MAC address", inventory_host_fields[1])]
    dispatcher.prompt_from_menu(action_id, help_text, choices)
    return False


# SNAPSHOT COMMANDS


def get_user_snapshot(dispatcher):
    """Lookup user snapshot setting in cache."""
    context = get_context(dispatcher.context["user_id"])
    snapshot = context.get("snapshot")
    if not snapshot:
        snapshot = "$last"
        set_context(dispatcher.context["user_id"], {"snapshot": snapshot})

    return snapshot


@subcommand_of("ipfabric")
def set_snapshot(dispatcher, snapshot=None):
    """Set snapshot as reference for commands."""
    if not snapshot:
        prompt_snapshot_id(f"{BASE_CMD} set-snapshot", "What snapshot are you interested in?", dispatcher)
        return False

    user = dispatcher.context["user_id"]
    snapshots = [snapshot.get("id", "") for snapshot in ipfabric_api.get_snapshots()]
    if snapshot not in snapshots and snapshot != "$last":
        dispatcher.send_markdown(f"<@{user}>, snapshot *{snapshot}* does not exist in IP Fabric.")
        return False
    set_context(user, {"snapshot": snapshot})

    dispatcher.send_markdown(
        f"<@{user}>, snapshot *{snapshot}* is now used as the default for the subsequent commands."
    )
    return True


@subcommand_of("ipfabric")
def get_snapshot(dispatcher):
    """Get snapshot as reference for commands."""
    user = dispatcher.context["user_id"]
    context = get_context(user)
    snapshot = context.get("snapshot")
    if snapshot:
        dispatcher.send_markdown(f"<@{user}>, your current snapshot is *{snapshot}*.")
    else:
        dispatcher.send_markdown(
            f"<@{user}>, your snapshot is not defined yet. Use 'ipfabric set-snapshot' to define one."
        )

    return True


# DEVICES COMMAND


@subcommand_of("ipfabric")
def get_inventory(dispatcher, filter_key=None, filter_value=None):
    """IP Fabric Inventory device list."""
    if not filter_key:
        prompt_inventory_filter_keys(
            f"{BASE_CMD} get-inventory", "Select column name to filter inventory by:", dispatcher
        )
        return False

    if not filter_value:
        prompt_inventory_filter_values(
            f"{BASE_CMD} get-inventory {filter_key}",
            f"Select specific {filter_key} to filter by:",
            dispatcher,
            filter_key,
        )
        return False

    col_name = inventory_field_mapping.get(filter_key.lower())
    devices = ipfabric_api.get_device_inventory(col_name, filter_value, get_user_snapshot(dispatcher))

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                "ipfabric",
                "get-inventory",
                [("Filter key", filter_key), ("Filter value", filter_value)],
                "Device Inventory",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.host_url}/inventory/devices"),
        ]
    )

    dispatcher.send_large_table(
        ["Hostname", "Site", "Vendor", "Platform", "Model", "Memory Utilization", "S/W Version", "Serial", "Mgmt IP"],
        [
            (
                device.get("hostname") or "(empty)",
                device.get("siteName") or "(empty)",
                device.get("vendor") or "(empty)",
                device.get("platform") or "(empty)",
                device.get("model") or "(empty)",
                device.get("memoryUtilization") or "(empty)",
                device.get("version") or "(empty)",
                device.get("sn") or "(empty)",
                device.get("loginIp") or "(empty)",
            )
            for device in devices
        ],
    )
    return True


# INTERFACES COMMAND


@subcommand_of("ipfabric")
def interfaces(dispatcher, device=None, metric=None):
    """Get interface metrics for a device."""
    snapshot_id = get_user_snapshot(dispatcher)
    logger.debug("Getting devices")
    devices = [
        (device["hostname"], device["hostname"].lower()) for device in ipfabric_api.get_devices_info(snapshot_id)
    ]

    if not devices:
        dispatcher.send_blocks(
            [
                *dispatcher.command_response_header(
                    "ipfabric",
                    "routing",
                    [(" "), (" ")],
                    "Device interface metric data",
                    ipfabric_logo(dispatcher),
                ),
                dispatcher.markdown_block(
                    f"Sorry, but your current snapshot {snapshot_id} has no devices defined yet."
                ),
            ]
        )
        return True

    dialog_list = [
        {
            "type": "select",
            "label": "Device",
            "choices": devices,
            "default": devices[0],
        },
        {
            "type": "select",
            "label": "Metric",
            "choices": [("Load", "load"), ("Errors", "errors"), ("Drops", "drops")],
            "default": ("Load", "load"),
        },
    ]

    if not all([metric, device]):
        dispatcher.multi_input_dialog(f"{BASE_CMD}", "interfaces", "Interface Metrics", dialog_list)
        return CommandStatusChoices.STATUS_SUCCEEDED

    cmd_map = {"load": get_int_load, "errors": get_int_errors, "drops": get_int_drops}
    cmd_map[metric](dispatcher, device, snapshot_id)
    return True


def get_int_load(dispatcher, device, snapshot_id):
    """Get interface load per device."""
    dispatcher.send_markdown(f"Load in interfaces for *{device}* in snapshot *{snapshot_id}*.")
    int_load = ipfabric_api.get_interfaces_load_info(device, snapshot_id)
    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                "ipfabric",
                "interfaces",
                [("Device", device), ("Metric", "load")],
                "interface load data",
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
            for interface in int_load
        ],
    )

    return True


def get_int_errors(dispatcher, device, snapshot_id):
    """Get interface errors per device."""
    dispatcher.send_markdown(f"Load in interfaces for *{device}* in snapshot *{snapshot_id}*.")
    int_errors = ipfabric_api.get_interfaces_errors_info(device, snapshot_id)

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                "ipfabric",
                "interfaces",
                [("Device", device), ("Metric", "errors")],
                "interface error data",
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
            for interface in int_errors
        ],
    )

    return True


def get_int_drops(dispatcher, device, snapshot_id):
    """Get bi-directional interface drops per device."""
    dispatcher.send_markdown(f"Load in interfaces for *{device}* in snapshot *{snapshot_id}*.")
    int_drops = ipfabric_api.get_interfaces_drops_info(device, snapshot_id)

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                "ipfabric",
                "interfaces",
                [("Device", device), ("Metric", "drops")],
                "interface average drop data",
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
            for interface in int_drops
        ],
    )

    return True


# END-TO-END PATH COMMMAND


@subcommand_of("ipfabric")
def end_to_end_path(
    dispatcher, src_ip, dst_ip, src_port, dst_port, protocol
):  # pylint: disable=too-many-arguments, too-many-locals
    """Execute end-to-end path simulation between source and target IP address."""
    snapshot_id = get_user_snapshot(dispatcher)
    sub_cmd = "end-to-end-path"

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
    ]

    if not all([src_ip, dst_ip, src_port, dst_port, protocol]):
        dispatcher.multi_input_dialog(f"{BASE_CMD}", f"{sub_cmd}", "Path Simulation", dialog_list)
        return CommandStatusChoices.STATUS_SUCCEEDED

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                f"{BASE_CMD}",
                f"{sub_cmd}",
                [
                    ("src_ip", src_ip),
                    ("dst_ip", dst_ip),
                    ("src_port", src_port),
                    ("dst_port", dst_port),
                    ("protocol", protocol),
                ],
                "Path Simulation",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.host_url}/graph/end-to-end-path"),
        ]
    )

    # request simulation
    path = ipfabric_api.get_parsed_path_simulation(src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id)
    endpoints = ipfabric_api.get_src_dst_endpoint(src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id)

    dispatcher.send_markdown(
        f"{dispatcher.bold('Source: ')} {src_ip} [{endpoints.get('src')}]\n"
        f"{dispatcher.bold('Destination: ')} {dst_ip} [{endpoints.get('dst')}]\n"
    )
    dispatcher.send_large_table(
        [
            "Hop",
            "Fwd Type",
            "Src Host",
            "Src Type",
            "Src Intf",
            "Src Fwd",
            "Dst Fwd",
            "Dst Intf",
            "Dst Type",
            "Dst Host",
        ],
        path,
    )

    return True


@subcommand_of("ipfabric")
def pathlookup(
    dispatcher, src_ip, dst_ip, src_port, dst_port, protocol
):  # pylint: disable=too-many-arguments, too-many-locals
    """Path simulation diagram lookup between source and target IP address."""
    snapshot_id = get_user_snapshot(dispatcher)
    sub_cmd = "pathlookup"
    supported_protocols = ["tcp", "udp", "icmp"]
    protocols = [(protocol.upper(), protocol) for protocol in supported_protocols]

    # identical to dialog_list in end-to-end-path; consolidate dialog_list if maintaining both cmds
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
            "choices": protocols,
            "default": protocols[0],
        },
    ]

    if not all([src_ip, dst_ip, src_port, dst_port, protocol]):
        dispatcher.multi_input_dialog(f"{BASE_CMD}", f"{sub_cmd}", "Path Lookup", dialog_list)
        return CommandStatusChoices.STATUS_SUCCEEDED

    # verify IP address and protocol is valid
    if not is_ip(src_ip) or not is_ip(dst_ip):
        dispatcher.send_error("You've entered an invalid IP address")
        return CommandStatusChoices.STATUS_FAILED
    if protocol not in supported_protocols:
        dispatcher.send_error(f"You've entered an unsupported protocol: {protocol}")
        return CommandStatusChoices.STATUS_FAILED

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                f"{BASE_CMD}",
                f"{sub_cmd}",
                [
                    ("src_ip", src_ip),
                    ("dst_ip", dst_ip),
                    ("src_port", src_port),
                    ("dst_port", dst_port),
                    ("protocol", protocol),
                ],
                "Path Lookup",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.host_url}/diagrams/pathlookup"),
        ]
    )

    # only supported in IP Fabric OS version 4.0+
    try:
        if ipfabric_api.validate_version(ge, 4.0):
            raw_png = ipfabric_api.get_pathlookup(src_ip, dst_ip, src_port, dst_port, protocol, snapshot_id)
            if not raw_png:
                raise RuntimeError(
                    "An error occurred while retrieving the path lookup. Please verify the path using the link above."
                )
            with tempfile.TemporaryDirectory() as tempdir:
                # Note: Microsoft Teams will silently fail if we have ":" in our filename, so the timestamp has to skip them.
                time_str = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
                img_path = os.path.join(tempdir, f"{sub_cmd}_{time_str}.png")
                with open(img_path, "wb") as img_file:
                    img_file.write(raw_png)
                dispatcher.send_image(img_path)
        else:
            raise RuntimeError(
                "Your IP Fabric OS version does not support PNG output. Please try the end-to-end-path command."
            )
    except (RuntimeError, OSError) as error:
        dispatcher.send_error(error)
        return CommandStatusChoices.STATUS_FAILED
    return True


# ROUTING COMMAND


@subcommand_of("ipfabric")
def routing(dispatcher, device=None, protocol=None, filter_opt=None):
    """Get routing information for a device."""
    snapshot_id = get_user_snapshot(dispatcher)
    logger.debug("Getting devices")
    devices = [
        (device["hostname"], device["hostname"].lower()) for device in ipfabric_api.get_devices_info(snapshot_id)
    ]

    if not devices:
        dispatcher.send_blocks(
            [
                *dispatcher.command_response_header(
                    "ipfabric",
                    "routing",
                    [(" ", " ")],
                    "Routing data",
                    ipfabric_logo(dispatcher),
                ),
                dispatcher.markdown_block(
                    f"Sorry, but your current snapshot {snapshot_id} has no devices defined yet."
                ),
            ]
        )
        return True

    dialog_list = [
        {
            "type": "select",
            "label": "Device",
            "choices": devices,
            "default": devices[0],
        },
        {"type": "select", "label": "Protocol", "choices": [("BGP Neighbors", "bgp-neighbors")]},
    ]

    if not all([protocol, device]):
        dispatcher.multi_input_dialog(f"{BASE_CMD}", "routing", "Routing Info", dialog_list)
        return False

    cmd_map = {"bgp-neighbors": get_bgp_neighbors}
    cmd_map[protocol](dispatcher, device, snapshot_id, filter_opt)
    return True


def get_bgp_neighbors(dispatcher, device=None, snapshot_id=None, state=None):
    """Get BGP neighbors by device."""
    if not state:
        dispatcher.prompt_from_menu(
            f"{BASE_CMD} routing {device} bgp-neighbors",
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

    bgp_neighbors = ipfabric_api.get_bgp_neighbors(device, state, snapshot_id)

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                "ipfabric",
                "routing",
                [("Device", device), ("Protocol", "bgp-neighbors"), ("State", state)],
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

    return CommandStatusChoices.STATUS_SUCCEEDED


@subcommand_of("ipfabric")
def wireless(dispatcher, option=None, ssid=None):
    """Get wireless information by client or ssid."""
    snapshot_id = get_user_snapshot(dispatcher)
    logger.debug("Getting SSIDs")
    ssids = [(ssidi["wlanSsid"].lower()) for ssidi in ipfabric_api.get_wireless_ssids(snapshot_id)]

    if not ssids:
        dispatcher.send_blocks(
            [
                *dispatcher.command_response_header(
                    f"{BASE_CMD}",
                    "wireless",
                    [(" ", " ")],
                    "IPFabric Wireless",
                    ipfabric_logo(dispatcher),
                ),
                dispatcher.markdown_block(f"Sorry, but your current snapshot {snapshot_id} has no SSIDs defined yet."),
            ]
        )
        return True

    if not option:
        dispatcher.prompt_from_menu(
            f"{BASE_CMD} wireless",
            "Wireless Info",
            choices=[("ssids", "ssids"), ("clients", "clients")],
            default=("clients", "clients"),
        )
        return False

    cmd_map = {"clients": get_wireless_clients, "ssids": get_wireless_ssids}
    cmd_map[option](dispatcher, ssid, snapshot_id)
    return False


def get_wireless_ssids(dispatcher, ssid=None, snapshot_id=None):
    """Get All Wireless SSID Information."""
    ssids = [(ssid_["wlanSsid"].lower()) for ssid_ in ipfabric_api.get_wireless_ssids(snapshot_id)]
    if not ssids:
        dispatcher.send_blocks(
            [
                *dispatcher.command_response_header(
                    "ipfabric",
                    "wireless ssids",
                    [("Error")],
                    "IPFabric Wireless",
                    ipfabric_logo(dispatcher),
                ),
                dispatcher.markdown_block(f"Sorry, but your current snapshot {snapshot_id} has no SSIDs defined yet."),
            ]
        )
        return True

    ssids = ipfabric_api.get_wireless_ssids(snapshot_id)

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                "ipfabric",
                "wireless",
                [("Option", "ssids")],
                "Wireless info for SSIDs",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.host_url}api/v1/tables/wireless/clients"),
        ]
    )
    dispatcher.send_large_table(
        [
            "SSID",
            "Site",
            "AP",
            "Radio",
            "Radio Status",
            "Client Count",
        ],
        [
            (
                ssid["wlanSsid"],
                ssid["siteName"],
                ssid["apName"],
                ssid["radioDscr"],
                ssid["radioStatus"],
                ssid["clientCount"],
            )
            for ssid in ssids
        ],
    )
    return CommandStatusChoices.STATUS_SUCCEEDED


def get_wireless_clients(dispatcher, ssid=None, snapshot_id=None):
    """Get Wireless Clients."""
    ssids = [
        (f"{ssid_['wlanSsid']}-{ssid_['radioDscr']}", ssid_["wlanSsid"])
        for ssid_ in ipfabric_api.get_wireless_ssids(snapshot_id)
    ]
    if not ssids:
        dispatcher.send_blocks(
            [
                *dispatcher.command_response_header(
                    f"{BASE_CMD}",
                    "wireless clients",
                    [(" ", " ")],
                    "IPFabric Wireless",
                    ipfabric_logo(dispatcher),
                ),
                dispatcher.markdown_block(f"Sorry, but your current snapshot {snapshot_id} has no SSIDs defined yet."),
            ]
        )
        return True

    # prompt for ssid or all
    if not ssid:
        dispatcher.prompt_from_menu(
            f"{BASE_CMD} wireless clients", "Clients attached to an SSID", choices=ssids, default=ssids[0]
        )
        return False

    clients = ipfabric_api.get_wireless_clients(ssid, snapshot_id)

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                f"{BASE_CMD}",
                "wireless",
                [("Option", "clients"), ("SSID", ssid)],
                "Wireless Client info by SSID",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.host_url}api/v1/tables/wireless/clients"),
        ]
    )

    dispatcher.send_large_table(
        [
            "Controller",
            "Site Name",
            "AP",
            "Client",
            "Client IP",
            "SSID",
            "RSSI (dBm)",
            "SNR (dB)",
            "State",
        ],
        [
            (
                client["controller"],
                client["siteName"],
                client["apName"],
                client["client"],
                client["clientIp"],
                client["ssid"],
                client["rssi"],
                client["signalToNoiseRatio"],
                client["state"],
            )
            for client in clients
        ],
    )
    return CommandStatusChoices.STATUS_SUCCEEDED


@subcommand_of("ipfabric")
def find_host(dispatcher, filter_key=None, filter_value=None):
    """Get host information using the inventory host table."""
    sub_cmd = "find-host"

    if not filter_key:
        prompt_find_host_filter_keys(f"{BASE_CMD} {sub_cmd}", "Select filter criteria:", dispatcher)
        return False

    if not filter_value:
        dispatcher.prompt_for_text(
            f"{BASE_CMD} {sub_cmd} {filter_key}",
            f"Enter a specific {filter_key} to filter by:",
            f"{filter_key.upper()}",
        )
        return False

    is_valid_input_func = inventory_host_func_mapper.get(filter_key)
    if not is_valid_input_func(filter_value):
        dispatcher.send_error(f"You've entered an invalid {filter_key.upper()}")
        return CommandStatusChoices.STATUS_FAILED

    hosts = ipfabric_api.find_host(filter_key, filter_value, get_user_snapshot(dispatcher))

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                f"{BASE_CMD}",
                f"{sub_cmd}",
                [("Filter key", filter_key), ("Filter value", filter_value)],
                "Host Inventory",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.host_url}/inventory/hosts"),
        ]
    )

    dispatcher.send_large_table(
        ["Host IP", "VRF", "Host DNS", "Site", "Edges", "Gateways", "Access Points", "Host MAC", "Vendor", "VLAN"],
        [
            (
                host.get("ip") or "(empty)",
                host.get("vrf") or "(empty)",
                host.get("dnsName") or "(empty)",
                host.get("siteName") or "(empty)",
                host.get("edges") or "(empty)",
                host.get("gateways") or "(empty)",
                host.get("accessPoints") or "(empty)",
                host.get("mac") or "(empty)",
                host.get("vendor") or "(empty)",
                host.get("vlan") or "(empty)",
            )
            for host in hosts
        ],
    )
    return True

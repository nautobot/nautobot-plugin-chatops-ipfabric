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
from ipfabric_diagrams import Unicast

from .ipfabric_wrapper import IpFabric

from .context import get_context, set_context
from .utils import parse_hosts

BASE_CMD = "ipfabric"
IPFABRIC_LOGO_PATH = "ipfabric/ipfabric_logo.png"
IPFABRIC_LOGO_ALT = "IPFabric Logo"
CHATOPS_IPFABRIC = "nautobot_chatops_ipfabric"

logger = logging.getLogger("rq.worker")

inventory_field_mapping = {
    "site": "siteName",
    "model": "model",
    "platform": "platform",
    "vendor": "vendor",
}
inventory_host_fields = ["ip", "mac"]
inventory_host_func_mapper = {inventory_host_fields[0]: is_ip, inventory_host_fields[1]: is_valid_mac}

try:
    ipfabric_api = IpFabric(
        base_url=settings.PLUGINS_CONFIG[CHATOPS_IPFABRIC].get("IPFABRIC_HOST"),
        token=settings.PLUGINS_CONFIG[CHATOPS_IPFABRIC].get("IPFABRIC_API_TOKEN"),
        verify=settings.PLUGINS_CONFIG[CHATOPS_IPFABRIC].get("IPFABRIC_VERIFY"),
    )
except Exception as exp:  # pylint: disable=W0703
    logger.error("Could not load IP Fabric client. Please verify HTTP access to the IP Fabric instance %s", exp)


def ipfabric_logo(dispatcher):
    """Construct an image_element containing the locally hosted IP Fabric logo."""
    return dispatcher.image_element(dispatcher.static_url(IPFABRIC_LOGO_PATH), alt_text=IPFABRIC_LOGO_ALT)


@job("default")
def ipfabric(subcommand, **kwargs):
    """Interact with ipfabric plugin."""
    return handle_subcommands("ipfabric", subcommand, **kwargs)


# PROMPTS


def prompt_snapshot_id(action_id, help_text, dispatcher, choices=None):
    """Prompt the user for snapshot ID."""
    formatted_snapshots = ipfabric_api.get_formatted_snapshots()
    choices = list(formatted_snapshots.values())
    default = choices[0]
    dispatcher.prompt_from_menu(action_id, help_text, choices, default=default)
    return False


def prompt_inventory_filter_values(action_id, help_text, dispatcher, filter_key, choices=None):
    """Prompt the user for input inventory search value selection."""
    column_name = inventory_field_mapping.get(filter_key.lower())
    inventory_data = ipfabric_api.client.fetch(
        IpFabric.INVENTORY_DEVICES_URL,
        columns=IpFabric.DEVICE_INFO_COLUMNS,
        limit=IpFabric.DEFAULT_PAGE_LIMIT,
        snapshot_id=get_user_snapshot(dispatcher),
    )
    choices = {(device[column_name], device[column_name]) for device in inventory_data if device.get(column_name)}
    dispatcher.prompt_from_menu(action_id, help_text, list(choices))
    return False


def prompt_inventory_filter_keys(action_id, help_text, dispatcher, choices=None):
    """Prompt the user for input inventory search criteria."""
    choices = [(column.capitalize(), column) for column in inventory_field_mapping]
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
        snapshot = ipfabric_api.client.snapshots[IpFabric.LAST].snapshot_id
        set_context(dispatcher.context["user_id"], {"snapshot": snapshot})

    return snapshot


def get_snapshots_table(dispatcher, formatted_snapshots=None):
    """IP Fabric Loaded Snapshot list."""
    sub_cmd = "get-loaded-snapshots"
    snapshot_table = ipfabric_api.get_snapshots_table(formatted_snapshots)

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                f"{BASE_CMD}",
                f"{sub_cmd}",
                [("Loaded Snapshots", " ")],
                "loaded snapshots",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.ui_url}snapshot-management"),
        ]
    )

    dispatcher.send_large_table(
        ["Snapshot ID", "Name", "Start", "End", "Device Count", "Licensed Count", "Locked", "Version", "Note"],
        snapshot_table,
        title="Available IP Fabric Snapshots",
    )

    return True


@subcommand_of("ipfabric")
def set_snapshot(dispatcher, snapshot: str = None):
    """Set snapshot as reference for commands."""
    ipfabric_api.client.update()
    if not snapshot:
        prompt_snapshot_id(f"{BASE_CMD} set-snapshot", "What snapshot are you interested in?", dispatcher)
        return False

    snapshot = snapshot.lower()
    snapshot = IpFabric.LAST_LOCKED if snapshot == "$lastlocked" else snapshot
    user = dispatcher.context["user_id"]

    if snapshot not in ipfabric_api.client.snapshots:
        dispatcher.send_markdown(f"<@{user}>, snapshot *{snapshot}* does not exist in IP Fabric.")
        return False
    snapshot_id = ipfabric_api.client.snapshots[snapshot].snapshot_id
    set_context(user, {"snapshot": snapshot_id})

    dispatcher.send_markdown(
        f"<@{user}>, snapshot *{snapshot_id}* is now used as the default for the subsequent commands."
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


@subcommand_of("ipfabric")
def get_loaded_snapshots(dispatcher):
    """IP Fabric Loaded Snapshot list."""
    return get_snapshots_table(dispatcher)


# DEVICES COMMAND


@subcommand_of("ipfabric")
def get_inventory(dispatcher, filter_key=None, filter_value=None):
    """IP Fabric Inventory device list."""
    sub_cmd = "get-inventory"
    if not filter_key:
        prompt_inventory_filter_keys(f"{BASE_CMD} {sub_cmd}", "Select column name to filter inventory by:", dispatcher)
        return False

    if not filter_value:
        prompt_inventory_filter_values(
            f"{BASE_CMD} {sub_cmd} {filter_key}",
            f"Select specific {filter_key} to filter by:",
            dispatcher,
            filter_key,
        )
        return False

    col_name = inventory_field_mapping.get(filter_key.lower())
    filter_api = {col_name: [IpFabric.IEQ, filter_value]}
    devices = ipfabric_api.client.fetch(
        IpFabric.INVENTORY_DEVICES_URL,
        columns=IpFabric.INVENTORY_COLUMNS,
        filters=filter_api,
        limit=IpFabric.DEFAULT_PAGE_LIMIT,
        snapshot_id=get_user_snapshot(dispatcher),
    )

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                f"{BASE_CMD}",
                f"{sub_cmd}",
                [("Filter key", filter_key), ("Filter value", filter_value)],
                "Device Inventory",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.ui_url}inventory/devices"),
        ]
    )

    dispatcher.send_large_table(
        ["Hostname", "Site", "Vendor", "Platform", "Model", "Memory Utilization", "S/W Version", "Serial", "Mgmt IP"],
        [
            [device.get(IpFabric.INVENTORY_COLUMNS[i], IpFabric.EMPTY) for i in range(len(IpFabric.INVENTORY_COLUMNS))]
            for device in devices
        ],
        title="Device Inventory",
    )
    return True


# INTERFACES COMMAND


@subcommand_of("ipfabric")
def interfaces(dispatcher, device=None, metric=None):
    """Get interface metrics for a device."""
    snapshot_id = get_user_snapshot(dispatcher)
    logger.debug("Getting devices")
    sub_cmd = "interfaces"
    inventory_data = ipfabric_api.client.fetch(
        IpFabric.INVENTORY_DEVICES_URL,
        columns=IpFabric.DEVICE_INFO_COLUMNS,
        limit=IpFabric.DEFAULT_PAGE_LIMIT,
        snapshot_id=get_user_snapshot(dispatcher),
    )
    devices = [
        (inventory_device["hostname"], inventory_device["hostname"].lower()) for inventory_device in inventory_data
    ]
    metrics = ["load", "errors", "drops"]
    metric_choices = [(intf_metric.capitalize(), intf_metric) for intf_metric in metrics]

    if not devices:
        dispatcher.send_blocks(
            [
                *dispatcher.command_response_header(
                    f"{BASE_CMD}",
                    f"{sub_cmd}",
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
            "choices": metric_choices,
            "default": metric_choices[0],
        },
    ]

    if not all([metric, device]):
        dispatcher.multi_input_dialog(f"{BASE_CMD}", f"{sub_cmd}", "Interface Metrics", dialog_list)
        return CommandStatusChoices.STATUS_SUCCEEDED

    cmd_map = {metrics[0]: get_int_load, metrics[1]: get_int_errors, metrics[2]: get_int_drops}
    cmd_map[metric](dispatcher, device, snapshot_id)
    return True


def get_int_load(dispatcher, device, snapshot_id):
    """Get interface load per device."""
    sub_cmd = "interfaces"
    dispatcher.send_markdown(f"Load in interfaces for *{device}* in snapshot *{snapshot_id}*.")
    filter_api = {"hostname": [IpFabric.IEQ, device]}
    int_load = ipfabric_api.client.fetch(
        IpFabric.INTERFACE_LOAD_URL,
        columns=IpFabric.INTERFACE_LOAD_COLUMNS,
        filters=filter_api,
        limit=IpFabric.DEFAULT_PAGE_LIMIT,
        snapshot_id=get_user_snapshot(dispatcher),
        sort=IpFabric.INTERFACE_SORT,
    )
    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                f"{BASE_CMD}",
                f"{sub_cmd}",
                [("Device", device), ("Metric", "load")],
                "interface load data",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{str(ipfabric_api.ui_url)}technology/interfaces/rate/inbound"),
        ]
    )

    dispatcher.send_large_table(
        ["IntName", "IN bps", "OUT bps"],
        [
            [
                interface.get(IpFabric.INTERFACE_LOAD_COLUMNS[i], IpFabric.EMPTY)
                for i in range(len(IpFabric.INTERFACE_LOAD_COLUMNS))
            ]
            for interface in int_load
        ],
        title="Interface Load",
    )

    return True


def get_int_errors(dispatcher, device, snapshot_id):
    """Get interface errors per device."""
    sub_cmd = "interfaces"
    dispatcher.send_markdown(f"Load in interfaces for *{device}* in snapshot *{snapshot_id}*.")
    filter_api = {"hostname": [IpFabric.IEQ, device]}
    int_errors = ipfabric_api.client.fetch(
        IpFabric.INTERFACE_ERRORS_URL,
        columns=IpFabric.INTERFACE_ERRORS_COLUMNS,
        filters=filter_api,
        limit=IpFabric.DEFAULT_PAGE_LIMIT,
        snapshot_id=get_user_snapshot(dispatcher),
        sort=IpFabric.INTERFACE_SORT,
    )

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                f"{BASE_CMD}",
                f"{sub_cmd}",
                [("Device", device), ("Metric", "errors")],
                "interface error data",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{str(ipfabric_api.ui_url)}technology/interfaces/error-rates/bidirectional"),
        ]
    )

    dispatcher.send_large_table(
        ["IntName", "Error %", "Error Rate"],
        [
            [
                interface.get(IpFabric.INTERFACE_ERRORS_COLUMNS[i], IpFabric.EMPTY)
                for i in range(len(IpFabric.INTERFACE_ERRORS_COLUMNS))
            ]
            for interface in int_errors
        ],
        title="Interface Errors",
    )

    return True


def get_int_drops(dispatcher, device, snapshot_id):
    """Get bi-directional interface drops per device."""
    sub_cmd = "interfaces"
    dispatcher.send_markdown(f"Load in interfaces for *{device}* in snapshot *{snapshot_id}*.")
    filter_api = {"hostname": [IpFabric.IEQ, device]}
    int_drops = ipfabric_api.client.fetch(
        IpFabric.INTERFACE_DROPS_URL,
        columns=IpFabric.INTERFACE_DROPS_COLUMNS,
        filters=filter_api,
        limit=IpFabric.DEFAULT_PAGE_LIMIT,
        snapshot_id=get_user_snapshot(dispatcher),
        sort=IpFabric.INTERFACE_SORT,
    )

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                f"{BASE_CMD}",
                f"{sub_cmd}",
                [("Device", device), ("Metric", "drops")],
                "interface average drop data",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{str(ipfabric_api.ui_url)}technology/interfaces/drop-rates/bidirectional"),
        ]
    )

    dispatcher.send_large_table(
        ["IntName", "% Drops", "Drop Rate"],
        [
            [
                interface.get(IpFabric.INTERFACE_DROPS_COLUMNS[i], IpFabric.EMPTY)
                for i in range(len(IpFabric.INTERFACE_DROPS_COLUMNS))
            ]
            for interface in int_drops
        ],
        title="Interface Drops",
    )

    return True


# PATH LOOKUP COMMMAND


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
            "label": "Source Ports",
            "default": "1000",
        },
        {
            "type": "text",
            "label": "Destination Ports",
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
            dispatcher.markdown_block(f"{ipfabric_api.ui_url}diagrams/pathlookup"),
        ]
    )

    # diagrams for 4.0 - 4.2 are not supported due to attribute changes in 4.3+
    try:
        os_version = ipfabric_api.client.os_version
        if os_version and ge(os_version, "4.3"):
            unicast = Unicast(
                startingPoint=src_ip,
                destinationPoint=dst_ip,
                protocol=protocol,
                srcPorts=src_port,
                dstPorts=dst_port,
            )
            raw_png = ipfabric_api.diagram.diagram_png(unicast, snapshot_id)
            if not raw_png:
                raise RuntimeError(
                    "An error occurred while retrieving the path lookup. Please verify the path using the link above."
                )
            with tempfile.TemporaryDirectory() as tempdir:
                # Note: Microsoft Teams will silently fail if we have ":" in our filename, so the timestamp has to skip them.
                time_str = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
                img_path = os.path.join(tempdir, f"{sub_cmd}_{time_str}.png")
                # MS Teams requires permission to upload files.
                if dispatcher.needs_permission_to_send_image():
                    dispatcher.ask_permission_to_send_image(
                        f"{sub_cmd}_{time_str}.png",
                        f"{BASE_CMD} {sub_cmd} {src_ip} {dst_ip} {src_port} {dst_port} {protocol}",
                    )
                    return False

                with open(img_path, "wb") as img_file:
                    img_file.write(raw_png)
                dispatcher.send_image(img_path)
        else:
            raise RuntimeError(
                "PNG output for this chatbot is only supported on IP Fabric version 4.3 and above. Please try the end-to-end-path command."
            )
    except (RuntimeError, OSError) as error:
        dispatcher.send_error(error)
        return CommandStatusChoices.STATUS_FAILED
    return True


# ROUTING COMMAND


@subcommand_of("ipfabric")
def routing(dispatcher, device=None, protocol=None, filter_opt=None):
    """Get routing information for a device."""
    sub_cmd = "routing"
    snapshot_id = get_user_snapshot(dispatcher)
    logger.debug("Getting devices")

    inventory_devices = ipfabric_api.client.fetch(
        IpFabric.INVENTORY_DEVICES_URL,
        columns=IpFabric.DEVICE_INFO_COLUMNS,
        limit=IpFabric.DEFAULT_PAGE_LIMIT,
        snapshot_id=get_user_snapshot(dispatcher),
    )
    devices = [(device["hostname"], device["hostname"]) for device in inventory_devices]

    if not devices:
        dispatcher.send_blocks(
            [
                *dispatcher.command_response_header(
                    f"{BASE_CMD}",
                    f"{sub_cmd}",
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
        dispatcher.multi_input_dialog(f"{BASE_CMD}", f"{sub_cmd}", "Routing Info", dialog_list)
        return False

    cmd_map = {"bgp-neighbors": get_bgp_neighbors}
    cmd_map[protocol](dispatcher, device, snapshot_id, filter_opt)
    return True


def get_bgp_neighbors(dispatcher, device=None, snapshot_id=None, state=None):
    """Get BGP neighbors by device."""
    sub_cmd = "routing"
    if not state:
        dispatcher.prompt_from_menu(
            f"{BASE_CMD} {sub_cmd} {device} bgp-neighbors",
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

    if state != "any":
        filter_api = {"and": [{"hostname": [IpFabric.IEQ, device]}, {"state": [IpFabric.IEQ, state]}]}
    else:
        filter_api = {"hostname": ["reg", device]}

    bgp_neighbors = ipfabric_api.client.fetch(
        IpFabric.BGP_NEIGHBORS_URL,
        columns=IpFabric.BGP_NEIGHBORS_COLUMNS,
        filters=filter_api,
        limit=IpFabric.DEFAULT_PAGE_LIMIT,
        snapshot_id=snapshot_id,
    )

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                f"{BASE_CMD}",
                f"{sub_cmd}",
                [("Device", device), ("Protocol", "bgp-neighbors"), ("State", state)],
                "BGP neighbor data",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.ui_url}technology/routing/bgp/neighbors"),
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
            [
                neighbor.get(IpFabric.BGP_NEIGHBORS_COLUMNS[i], IpFabric.EMPTY)
                for i in range(len(IpFabric.BGP_NEIGHBORS_COLUMNS))
            ]
            for neighbor in bgp_neighbors
        ],
        title=f"BGP Neighbors State: {state}",
    )

    return CommandStatusChoices.STATUS_SUCCEEDED


@subcommand_of("ipfabric")
def wireless(dispatcher, option=None, ssid=None):
    """Get wireless information by client or ssid."""
    sub_cmd = "wireless"
    snapshot_id = get_user_snapshot(dispatcher)
    logger.debug("Getting SSIDs")
    ssids = ipfabric_api.client.fetch(
        IpFabric.WIRELESS_SSID_URL,
        columns=IpFabric.WIRELESS_SSID_COLUMNS,
        limit=IpFabric.DEFAULT_PAGE_LIMIT,
        snapshot_id=snapshot_id,
    )

    if not ssids:
        dispatcher.send_blocks(
            [
                *dispatcher.command_response_header(
                    f"{BASE_CMD}",
                    f"{sub_cmd}",
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
            f"{BASE_CMD} {sub_cmd}",
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
    sub_cmd = "wireless"
    ssids = ipfabric_api.client.fetch(
        IpFabric.WIRELESS_SSID_URL,
        columns=IpFabric.WIRELESS_SSID_COLUMNS,
        limit=IpFabric.DEFAULT_PAGE_LIMIT,
        snapshot_id=snapshot_id,
    )
    if not ssids:
        dispatcher.send_blocks(
            [
                *dispatcher.command_response_header(
                    f"{BASE_CMD}",
                    f"{sub_cmd} ssids",
                    [("Error")],
                    "IPFabric Wireless",
                    ipfabric_logo(dispatcher),
                ),
                dispatcher.markdown_block(f"Sorry, but your current snapshot {snapshot_id} has no SSIDs defined yet."),
            ]
        )
        return True

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                f"{BASE_CMD}",
                f"{sub_cmd}",
                [("Option", "ssids")],
                "Wireless info for SSIDs",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.ui_url}api/v1/tables/wireless/clients"),
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
            [
                ssid.get(IpFabric.WIRELESS_SSID_COLUMNS[i], IpFabric.EMPTY)
                for i in range(len(IpFabric.WIRELESS_SSID_COLUMNS))
            ]
            for ssid in ssids
        ],
        title="Wireless SSIDs",
    )
    return CommandStatusChoices.STATUS_SUCCEEDED


def get_wireless_clients(dispatcher, ssid=None, snapshot_id=None):
    """Get Wireless Clients."""
    sub_cmd = "wireless"
    wireless_ssids = ipfabric_api.client.fetch(
        IpFabric.WIRELESS_SSID_URL,
        columns=IpFabric.WIRELESS_SSID_COLUMNS,
        limit=IpFabric.DEFAULT_PAGE_LIMIT,
        snapshot_id=snapshot_id,
    )
    ssids = [
        (f"{ssid_['wlanSsid']}-{ssid_['radioDscr']}", ssid_["wlanSsid"])
        for ssid_ in wireless_ssids
        if ssid_["wlanSsid"]
    ]
    if not ssids:
        dispatcher.send_blocks(
            [
                *dispatcher.command_response_header(
                    f"{BASE_CMD}",
                    f"{sub_cmd} clients",
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
            f"{BASE_CMD} {sub_cmd} clients", "Clients attached to an SSID", choices=ssids, default=ssids[0]
        )
        return False

    filter_api = {"ssid": [IpFabric.IEQ, ssid]} if ssid else {}
    clients = ipfabric_api.client.fetch(
        IpFabric.WIRELESS_CLIENT_URL,
        columns=IpFabric.WIRELESS_CLIENT_COLUMNS,
        filters=filter_api,
        limit=IpFabric.DEFAULT_PAGE_LIMIT,
        snapshot_id=snapshot_id,
    )

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                f"{BASE_CMD}",
                f"{sub_cmd}",
                [("Option", "clients"), ("SSID", ssid)],
                "Wireless Client info by SSID",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.ui_url}api/v1/tables/wireless/clients"),
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
            [
                client.get(IpFabric.WIRELESS_CLIENT_COLUMNS[i], IpFabric.EMPTY)
                for i in range(len(IpFabric.WIRELESS_CLIENT_COLUMNS))
            ]
            for client in clients
        ],
        title="Wireless Clients",
    )
    return CommandStatusChoices.STATUS_SUCCEEDED


@subcommand_of("ipfabric")
def find_host(dispatcher, filter_key=None, filter_value=None):
    """Get host information using the inventory host table."""
    sub_cmd = "find-host"
    snapshot_id = get_user_snapshot(dispatcher)

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

    filter_api = {filter_key: [IpFabric.EQ, filter_value]}
    inventory_hosts = ipfabric_api.client.fetch(
        IpFabric.ADDRESSING_HOSTS_URL,
        columns=IpFabric.ADDRESSING_HOSTS_COLUMNS,
        filters=filter_api,
        limit=IpFabric.DEFAULT_PAGE_LIMIT,
        snapshot_id=snapshot_id,
    )
    hosts = parse_hosts(inventory_hosts)

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                f"{BASE_CMD}",
                f"{sub_cmd}",
                [("Filter key", filter_key), ("Filter value", filter_value)],
                "Host Inventory",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.ui_url}inventory/hosts"),
        ]
    )

    dispatcher.send_large_table(
        ["Host IP", "VRF", "Host DNS", "Site", "Edges", "Gateways", "Access Points", "Host MAC", "Vendor", "VLAN"],
        [
            [
                host.get(IpFabric.ADDRESSING_HOSTS_COLUMNS[i], IpFabric.EMPTY)
                for i in range(len(IpFabric.ADDRESSING_HOSTS_COLUMNS))
            ]
            for host in hosts
        ],
        title=f"Inventory Host with {filter_key.upper()} {filter_value}",
    )
    return True


@subcommand_of("ipfabric")
def compare_routing_tables(
    dispatcher,
    snapshot_a: str = None,
    snapshot_b: str = None,
    device: str = None,
    vrf: str = None,
):
    """Compare the routing table for a device between two snapshots

    Args:
        dispatcher (_type_): _description_
    """
    sub_cmd = "compare-routing-tables"
    user = dispatcher.context["user_id"]

    # Get first snapshot
    if not snapshot_a:
        prompt_snapshot_id(f"{BASE_CMD} {sub_cmd}", "Select first snapshot to compare", dispatcher)
        return False
    snapshot_a = snapshot_a.lower()
    print(f"snapshot_a: {snapshot_a}")

    # Get second snapshot
    # TODO: make it so you can't select same snapshot as 1st
    if not snapshot_b:
        prompt_snapshot_id(f"{BASE_CMD} {sub_cmd} {snapshot_a}", "Select second snapshot to compare", dispatcher)
        return False
    snapshot_b = snapshot_b.lower()
    print(f"snapshot_b: {snapshot_b}")

    if snapshot_a == snapshot_b:
        dispatcher.send_error(f"You must select different snapshots")
        return CommandStatusChoices.STATUS_FAILED
        return

    # Get device
    # TODO: make sure device list is only devices present in BOTH snapshots
    # TODO: split this this out into a separate function
    inventory_data_a = ipfabric_api.client.fetch(
        IpFabric.INVENTORY_DEVICES_URL,
        columns=IpFabric.DEVICE_INFO_COLUMNS,
        limit=IpFabric.DEFAULT_PAGE_LIMIT,
        snapshot_id=snapshot_a,
    )
    devices_a = [
        (inventory_device["hostname"], inventory_device["hostname"].lower()) for inventory_device in inventory_data_a
    ]
    print(f"devices_a: {devices_a}")

    inventory_data_b = ipfabric_api.client.fetch(
        IpFabric.INVENTORY_DEVICES_URL,
        columns=IpFabric.DEVICE_INFO_COLUMNS,
        limit=IpFabric.DEFAULT_PAGE_LIMIT,
        snapshot_id=snapshot_b,
    )
    devices_b = [
        (inventory_device["hostname"], inventory_device["hostname"].lower()) for inventory_device in inventory_data_b
    ]
    print(f"devices_b {devices_b}")

    choices = list(set(devices_a).intersection(devices_b))
    print(f"choices: {choices}")
    default = choices[0]
    if not device:
        dispatcher.prompt_from_menu(
            f"{BASE_CMD} {sub_cmd} {snapshot_a} {snapshot_b}",
            "Select a device - NOTE: only devices that exist in both snapshots are listed",
            choices,
            default=default,
        )
        return CommandStatusChoices.STATUS_SUCCEEDED
    print(f"device: {device}")

    # Get list of VRFs and allow to choose from a menu
    # TODO: make the device vrf choices a union of those found in both snapshots
    # TODO: test this against demo8.ipfabric.com, right now it only seems to work against NTC IPFabric instance
    if not vrf:
        filter_api = {"hostname": [IpFabric.EQ, device]}
        device_vrf_detail = ipfabric_api.client.fetch(
            IpFabric.VRF_DETAIL_URL,
            columns=IpFabric.VRF_DETAIL_COLUMNS,
            filters=filter_api,
            limit=IpFabric.DEFAULT_PAGE_LIMIT,
            snapshot_id=snapshot_a,
        )

        choices = [(v["vrf"], v["vrf"]) for v in device_vrf_detail]
        print(f"choices: {choices}")
        default = choices[0]
        dispatcher.prompt_from_menu(
            f"{BASE_CMD} {sub_cmd} {snapshot_a} {snapshot_b} {device}",
            "Select a VRF",
            choices,
            default=default,
        )
        return CommandStatusChoices.STATUS_SUCCEEDED
        print(f"vrf: {vrf}")

    # send mock return table
    dispatcher.send_large_table(
        ["Test Heading 1", "Test Heading 2"],
        [
            ["data row 1, column 1", "data row 1, column 2"],
            ["data row 2, column 1", "data row 2, column 2"],
        ],
        title="compare_route_table test output",
    )

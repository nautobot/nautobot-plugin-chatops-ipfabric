"""Worker functions implementing Nautobot "ipfabric" command and subcommands."""
import logging
import requests

from django.conf import settings
from django_rq import job

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

    def get_bgp_neighbors(self, device):
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
        return self.get_response("/api/v1/tables/routing/protocols/bgp/neighbors", payload)


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
def get_bgp_neighbors(dispatcher, device=None):
    """Get BGP neighbors by device."""
    if not device:
        prompt_device_input("ipfabric get-bgp-neighbors", "Which device are you interested in", dispatcher)
        return False

    devices = [device["hostname"] for device in ipfabric_api.get_devices_info()]
    if device not in devices:
        dispatcher.send_markdown(f"Device *{device}* does not exist in IP Fabric.")
        return False

    bgp_neighbors = ipfabric_api.get_bgp_neighbors(device)

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                "ipfabric",
                "get-bgp-neighbors",
                [("Device", device)],
                "BGP neighbor data",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{ipfabric_api.host_url}/technology/routing/bgp/neighbors"),
        ]
    )

    dispatcher.send_large_table(
        [
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

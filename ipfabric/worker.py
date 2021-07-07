"""Worker functions implementing Nautobot "ipfabric" command and subcommands."""
import logging
import requests

from django.conf import settings
from django_rq import job

from nautobot_chatops.workers import subcommand_of, handle_subcommands

# Import config vars from nautobot_config.py
API_TOKEN = settings.PLUGINS_CONFIG["ipfabric"].get("IPFABRIC_API_TOKEN")
IPFABRIC_HOST = settings.PLUGINS_CONFIG["ipfabric"].get("IPFABRIC_HOST")
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


@subcommand_of("ipfabric")
def hello_world(dispatcher, arg1=None):
    """Run logic and return to user via client command '/ipfabric hello-world arg1'."""
    if not arg1:
        prompt_hello_input("ipfabric hello-world", "What would you like to say?", dispatcher)
        return False

    logger.info("Received arg1 %s", arg1)
    dispatcher.send_markdown(f"Just wanted to say {arg1}")
    return True


@subcommand_of("ipfabric")
def device_list(dispatcher):
    """IP Fabric Inventory device list."""
    url = IPFABRIC_HOST + "/api/v1/tables/inventory/devices"

    logger.info("Received device list request")

    # columns and snapshot required
    payload = {
        "columns": ["hostname", "siteName", "vendor", "platform", "model"],
        "filters": {},
        "pagination": {"limit": 15, "start": 0},
        "snapshot": "$last",
    }
    # auth is contained in the 'X-API-Token' in the header
    headers = {"Accept": "application/json", "Content-Type": "application/json", "X-API-Token": API_TOKEN}

    response = requests.post(url, json=payload, headers=headers)
    devices = response.json().get("data", {})

    dispatcher.send_blocks(
        [
            *dispatcher.command_response_header(
                "ipfabric",
                "device-list",
                [],
                "Inventory Device List",
                ipfabric_logo(dispatcher),
            ),
            dispatcher.markdown_block(f"{IPFABRIC_HOST}/inventory/devices"),
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

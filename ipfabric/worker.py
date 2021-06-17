"""Worker functions implementing Nautobot "ipfabric" command and subcommands."""

import json

from django.conf import settings
from django_rq import job

import requests
import yaml

from nautobot_chatops.workers import subcommand_of, handle_subcommands
from nautobot_chatops.choices import CommandStatusChoices

# Import config vars from nautobot_config.py
EXAMPLE_VAR = settings.PLUGINS_CONFIG["ipfabric"].get("example_var")


@job("default")
def ipfabric(subcommand, **kwargs):
    """Interact with ipfabric plugin."""
    return handle_subcommands("ipfabric", subcommand, **kwargs)


@subcommand_of("ipfabric")
def hello_world(dispatcher, arg1):
    """Run logic and return to user via client command '/ipfabric hello-world arg1'."""

    dispatcher.send_markdown(f"Command /ipfabric hello-world received with arg1={arg1}")

    # Logic/external API calls go here

    # Send Markdown formatted text
    # dispatcher.send_markdown(f"Markdown formatted text goes here.")

    # Send block of text
    # dispatcher.send_blocks(
    #     [
    #         *dispatcher.command_response_header(
    #             "ipfabric", "hello-world",
    #         ),
    #         dispatcher.markdown_block(f"example-return-string"),
    #     ]
    # )

    # Send large table
    # dispatcher.send_large_table(
    #     ["Name", "Description"],
    #     ["name1", "description1"],
    # )
    return True

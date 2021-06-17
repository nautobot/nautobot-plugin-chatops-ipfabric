"""Plugin declaration for ipfabric."""

__version__ = "0.1.0"

from nautobot.extras.plugins import PluginConfig


class IPFabricConfig(PluginConfig):
    """Plugin configuration for the ipfabric plugin."""

    name = "ipfabric"
    verbose_name = "IPFabric"
    version = __version__
    author = "Network to Code, LLC"
    description = "IPFabric."
    base_url = "ipfabric.io"
    required_settings = []
    min_version = "1.0.0"
    max_version = "1.9999"
    default_settings = {}
    caching_config = {}


config = IPFabricConfig  # pylint:disable=invalid-name

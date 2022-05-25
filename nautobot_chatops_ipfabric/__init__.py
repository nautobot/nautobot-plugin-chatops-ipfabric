"""Plugin declaration for ipfabric."""
try:
    from importlib import metadata
except ImportError:
    # Python version < 3.8
    import importlib_metadata as metadata

__version__ = metadata.version(__name__)

from nautobot.extras.plugins import PluginConfig


class IPFabricConfig(PluginConfig):
    """Plugin configuration for the ipfabric plugin."""

    name = "nautobot_chatops_ipfabric"
    verbose_name = "IPFabric"
    version = __version__
    author = "Network to Code, LLC"
    description = "Nautobot Chatops IPFabric"
    base_url = "nautobot-chatops-ipfabric"
    required_settings = []
    min_version = "1.0.0"
    max_version = "1.9999"
    default_settings = {}
    caching_config = {}


config = IPFabricConfig  # pylint:disable=invalid-name

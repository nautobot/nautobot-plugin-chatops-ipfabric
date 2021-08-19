"""Models for IPFabric chatops."""
from django.db import models

from nautobot.core.models.generics import PrimaryModel


class IpFabricChatopsContext(PrimaryModel):
    """Model for IPFabric chatops context data."""

    snapshot_id = models.CharField(max_length=100, default="", unique=True, blank=False)

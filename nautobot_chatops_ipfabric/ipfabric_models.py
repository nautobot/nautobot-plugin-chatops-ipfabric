"""IP Fabric data models."""

from datetime import datetime


class Snapshot:
    """IP Fabric Snapshot model."""

    def __init__(self, **kwargs):
        """Initialize Snapshot class."""
        self.name = kwargs.get("name", None)
        self.snapshot_id = kwargs.get("id")
        self.end = datetime.fromtimestamp(int(kwargs.get("tsEnd", 0) / 1000))
        self.locked = kwargs.get("locked", False)
        self.last = kwargs.get("last", False)
        self.prev = kwargs.get("prev", False)
        self.last_locked = kwargs.get("last_locked", False)

    def __hash__(self):
        """Snapshot ID is unique so return it's hash."""
        return hash(self.snapshot_id)

    def __repr__(self):
        """Return Description to represent the class."""
        return self.description

    @property
    def description(self):
        """Create a description for Slack menu."""
        desc = "🔒 " if self.locked else ""
        if self.last:
            desc += "$last: "
        elif self.prev:
            desc += "$prev: "
        elif self.last_locked:
            desc += "$lastLocked: "
        if self.name:
            desc += self.name + " - " + self.end.ctime()
        else:
            desc += self.end.ctime() + " - " + self.snapshot_id
        return desc

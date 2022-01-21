"""IP Fabric data models."""

from datetime import datetime


class Snapshot:
    def __init__(self, **kwargs):
        self.name = kwargs.get("name", None)
        self.snapshot_id = kwargs.get("id")
        self.end = datetime.fromtimestamp(int(kwargs.get("tsEnd", 0) / 1000))
        self.locked = kwargs.get("locked", False)
        self.last = kwargs.get("last", False)
        self.prev = kwargs.get("prev", False)
        self.last_locked = kwargs.get("last_locked", False)

    def __hash__(self):
        return hash(self.snapshot_id)

    def __repr__(self):
        return self.description

    @property
    def description(self):
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

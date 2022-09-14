"""Utility functions for Nautobot "ipfabric" command and subcommands."""

from nautobot_chatops_ipfabric.ipfabric_wrapper import IpFabric
from jdiff import CheckType, extract_data_from_json

# This expression will flatten and join the list items under the 'nexthop' key for each route entry from IPFabric's
# device routing table. This makes the data much easier to compare with jdiff.
ROUTE_JMESPATH = (
    "[*].{"
    "network: network, "
    "prefix: prefix, "
    "protocol: protocol, "
    "vrf: vrf, "
    "nhCount: nhCount, "
    "nexthop_ad: (nexthop[*].ad).join(`, `, @), "
    "nexthop_intName: (nexthop[*].intName).join(`, `, @), "
    "nexthop_ip: (nexthop[*].ip).join(`, `, @), "
    "nexthop_labels: (nexthop[*].labels).join(`, `, @), "
    "nexthop_metric: (nexthop[*].metric).join(`, `, @), "
    "nexthop_vni: (nexthop[*].vni).join(`, `, @), "
    "nexthop_vrfLeak: (nexthop[*].vrfLeak).join(`, `, @), "
    "nexthop_vtepIp: (nexthop[*].vtepIp).join(`, `, @)"
    "}"
)

ROUTE_TABLE_POST_EXTRACTION_KEYS = [
    "network",
    "prefix",
    "protocol",
    "vrf",
    "nhCount",
    "nexthop_ad",
    "nexthop_intName",
    "nexthop_ip",
    "nexthop_labels",
    "nexthop_metric",
    "nexthop_vni",
    "nexthop_vrfLeak",
    "nexthop_vtepIp",
]


class DeviceRouteTableDiff:
    """Provides routing table diff functionality between two route tables for a given vrf."""

    def __init__(self, reference_route_table=None, comparison_route_table=None, vrf=None) -> None:
        self.reference_route_table = reference_route_table
        self.comparison_route_table = comparison_route_table
        self.vrf = vrf
        print(
            f"extract_data_from_json(reference_route_table, ROUTE_JMESPATH)= {extract_data_from_json(reference_route_table, ROUTE_JMESPATH)}"
        )
        self._route_table_jdiff_results = None
        self.reference_route_dict = None
        self.comparison_route_dict = None

    def _convert_route_table_to_dict_by_vrf(self, route_table: list) -> dict:
        """Converts IP Fabric route table lists to a dictionary by vrf and network.

        Args:
            route_table (list): A device routing table from the IPFabric API.

        Returns:
            dict: A dictionary of routing table entries with top level keys being the vrfs and second level keys being networks.
        """
        vrfs_set = {route["vrf"] for route in route_table}
        route_dict_by_vrf = {}
        for vrf in vrfs_set:
            routes_in_vrf = {route["network"]: route for route in route_table if route["vrf"] == vrf}
            route_dict_by_vrf[vrf] = routes_in_vrf
        return route_dict_by_vrf

    def convert_route_table_to_dict_by_vrf(self):
        """Public method to execute the routing table conversion to dictionaries.
        Includes JMESPATH data extraction provided by jdiff.
        """
        self.reference_route_dict = self._convert_route_table_to_dict_by_vrf(
            extract_data_from_json(self.reference_route_table, ROUTE_JMESPATH)
        )
        self.comparison_route_dict = self._convert_route_table_to_dict_by_vrf(
            extract_data_from_json(self.comparison_route_table, ROUTE_JMESPATH)
        )

    def _jdiff_routes_by_vrf(self):
        """Performs the diff between the routing tables using jdiff and updates the results object."""
        match = CheckType.create("exact_match")
        self._route_table_jdiff_results = match.evaluate(
            (self.reference_route_dict.get(self.vrf, {})), (self.comparison_route_dict.get(self.vrf, {}))
        )

    def _get_routing_diff_summary(self) -> dict:
        """Parses the jdiff results into a simple dictionary containing new, missing and changed routes.

        Returns:
            dict: A dictionary with new_routes, missing_routes and changed_routes as keys and lists of network routes as values.
        """
        if not self._route_table_jdiff_results:
            self._jdiff_routes_by_vrf()
        _jdiff_sets_match = self._route_table_jdiff_results[1]
        _jdiff_items = self._route_table_jdiff_results[0].items()
        routes_diff_summary = {}
        # Objects returned by Jdiff will have False as the last element if the set had differences
        if not _jdiff_sets_match:
            routes_diff_summary["new_routes"] = [k for k, v in _jdiff_items if v == "new"]
            routes_diff_summary["missing_routes"] = [k for k, v in _jdiff_items if v == "missing"]
            routes_diff_summary["changed_routes"] = [k for k, v in _jdiff_items if v not in ["new", "missing"]]
        print(f"route_diff = {routes_diff_summary}")
        return routes_diff_summary

    def _generate_route_detail_table_for_changes(
        self,
        table_type: str,
    ) -> list:
        """Generates a list with headers and route entries for new, missing or changed routes to be sent back to user via the chat platform.

        Args:
            table_type (str): Either new_routes, missing_routes or changed_routes.

        Raises:
            ValueError: Error is raised if invalid table type is passed.

        Returns:
            list: A table of routing entries with a header for each column.
        """
        if not self._route_table_jdiff_results:
            self._jdiff_routes_by_vrf()
        routes_diff_summary = self._get_routing_diff_summary()
        valid_table_types = ["new_routes", "missing_routes", "changed_routes"]
        route_detail_table = []

        if table_type not in valid_table_types:
            raise ValueError(f"table_type must be one of {valid_table_types}, not {table_type}")
        if table_type in ["new_routes", "missing_routes"]:
            if table_type == "new_routes":
                route_detail_dict = self.comparison_route_dict
            elif table_type == "missing_routes":
                route_detail_dict = self.reference_route_dict
            # Add header as first row
            route_detail_table.append(ROUTE_TABLE_POST_EXTRACTION_KEYS)
            for route in routes_diff_summary.get(table_type):
                route_detail = route_detail_dict.get(self.vrf).get(route)
                route_detail_table.append([route_detail.get(key) for key in ROUTE_TABLE_POST_EXTRACTION_KEYS])
            return route_detail_table
        if table_type == "changed_routes":
            # Add header as first row
            route_detail_table.append(["Route Prefix", "Change Details"])
            replace_empty_values = lambda x: "null" if not x else x
            for route in routes_diff_summary.get(table_type):
                route_changes = [
                    f"{k}: -{replace_empty_values(v.get('old_value'))}, +{replace_empty_values(v.get('new_value'))}"
                    for k, v in self._route_table_jdiff_results[0].get(route).items()
                ]
                print(f"route_changes = {route_changes}")
                route_changes_str = " | ".join(route_changes)
                print(f"route_changes_str = {route_changes_str}")
                route_detail_table.append([route, route_changes_str])
            return route_detail_table

    def get_routing_diff_summary(self):
        """Get method to get the routing diff summary"""
        return self._get_routing_diff_summary()

    def get_new_routes_detail_table(self):
        """Get method to get detailed table for new routes"""
        return self._generate_route_detail_table_for_changes(
            table_type="new_routes",
        )

    def get_missing_routes_detail_table(self):
        """Get method to get detailed table for missing routes"""
        return self._generate_route_detail_table_for_changes(
            table_type="missing_routes",
        )

    def get_changed_routes_detail_table(self):
        """Get method to get detailed table for changed routes"""
        return self._generate_route_detail_table_for_changes(
            table_type="changed_routes",
        )


def parse_hosts(hosts: dict) -> list:
    """Parse inventory host information."""
    parsed_hosts = []

    for host in hosts:
        parsed_edges = []
        parsed_gws = []
        parsed_aps = []

        for edge in host.get("edges"):
            parsed_edges.append(f"{edge.get('hostname', '')} ({edge.get('intName', '')})")

        for gateway in host.get("gateways"):
            parsed_gws.append(f"{gateway.get('hostname', '')} ({gateway.get('intName', '')})")

        for access_point in host.get("accessPoints"):
            parsed_aps.append(f"{access_point.get('hostname', '')} ({access_point.get('intName', '')})")

        host["edges"] = ";".join(parsed_edges) if parsed_edges else ""
        host["gateways"] = ";".join(parsed_gws) if parsed_gws else ""
        host["accessPoints"] = ";".join(parsed_aps) if parsed_aps else ""

        parsed_hosts.append(host)
    return parsed_hosts


def get_route_table_vrf_set(route_table_1: list, route_table_2: list) -> set:
    """Extracts the union of a set of all vrfs from two routing tables.

    Args:
        route_table_1 (list): A routing table from IPFabric.
        route_table_2 (list): Another routing table from IPFabric.

    Returns:
        set: A set containing all the vrfs found in both routing tables.
    """
    vrfs_set_1 = {route["vrf"] for route in route_table_1}
    vrfs_set_2 = {route["vrf"] for route in route_table_2}
    return vrfs_set_1.union(vrfs_set_2)

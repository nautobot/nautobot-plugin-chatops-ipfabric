"""Utility functions for Nautobot "ipfabric" command and subcommands."""

from nautobot_chatops_ipfabric.ipfabric_wrapper import IpFabric
from jdiff import CheckType, extract_data_from_json

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


def get_route_table_vrf_set(route_list_1, route_list_2) -> set:
    vrfs_set_1 = {route["vrf"] for route in route_list_1}
    vrfs_set_2 = {route["vrf"] for route in route_list_2}
    return vrfs_set_1.union(vrfs_set_2)


def filter_route_list_by_vrf(route_list, vrf) -> list:
    return [route for route in route_list if route["vrf"] == vrf]


def diff_routes_by_vrf(reference_data: dict, comparison_data: dict, vrf: str):
    match = CheckType.create("exact_match")
    return match.evaluate((reference_data.get(vrf, {})), (comparison_data.get(vrf, {})))


def convert_route_list_to_dict_by_vrf(route_list) -> dict:
    vrfs_set = {route["vrf"] for route in route_list}
    route_dict_by_vrf = {}
    for vrf in vrfs_set:
        # TODO: Add conditional to check for empty string vrf and change to "Unnamed VRF"
        routes_in_vrf = {route["network"]: route for route in route_list if route["vrf"] == vrf}
        route_dict_by_vrf[vrf] = routes_in_vrf
    return route_dict_by_vrf


def diff_routing_tables(reference_data: dict, comparison_data: dict, route_table_jdiff_result: tuple, vrf: str) -> dict:
    routes_diff = {}
    # Objects returned by Jdiff will have False as the last element if the set had differences
    if not route_table_jdiff_result[-1]:
        routes_diff["new_routes"] = [k for k, v in route_table_jdiff_result[0].items() if v == "new"]
        routes_diff["missing_routes"] = [k for k, v in route_table_jdiff_result[0].items() if v == "missing"]
        routes_diff["changed_routes"] = [
            k for k, v in route_table_jdiff_result[0].items() if v not in ["new", "missing"]
        ]
    print(f"route_diff = {routes_diff}")
    return routes_diff


def generate_route_detail_table_for_changes(
    reference_data: dict,
    comparison_data: dict,
    route_table_jdiff_result: tuple,
    routes_diff: dict,
    vrf: str,
    table_type: str,
) -> dict:
    valid_table_types = ["new_routes", "missing_routes", "changed_routes"]
    route_table = []

    if table_type not in valid_table_types:
        raise ValueError(f"table_type must be one of {valid_table_types}, not {table_type}")
    if table_type in ["new_routes", "missing_routes"]:
        if table_type == "new_routes":
            route_detail_dict = comparison_data
        elif table_type == "missing_routes":
            route_detail_dict = reference_data
        # Add header as first row
        route_table.append(ROUTE_TABLE_POST_EXTRACTION_KEYS)
        for route in routes_diff.get(table_type):
            route_detail = route_detail_dict.get(vrf).get(route)
            route_table.append([route_detail.get(key) for key in ROUTE_TABLE_POST_EXTRACTION_KEYS])
        return route_table
    if table_type == "changed_routes":
        # Add header as first row
        route_table.append(["Route Prefix", "Change Details"])
        replace_empty_values = lambda x: "null" if not x else x
        for route in routes_diff.get(table_type):
            route_changes = [
                f"{k}: -{replace_empty_values(v.get('old_value'))}, +{replace_empty_values(v.get('new_value'))}"
                for k, v in route_table_jdiff_result[0].get(route).items()
            ]
            print(f"route_changes = {route_changes}")
            route_changes_str = " | ".join(route_changes)
            print(f"route_changes_str = {route_changes_str}")
            route_table.append([route, route_changes_str])
        return route_table

    # new_routes = [comparison_data.get(vrf).get(r) for r in _new_routes]
    # new_routes_table["header"] = list(new_routes[0].keys())
    # new_routes_table["rows"] = [list(r.values()) for r in new_routes]

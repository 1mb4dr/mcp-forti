# mcp_fortigate_server/tools/__init__.py

# This file makes the 'tools' directory a Python package.
# You can import tool functions here if you want to make them directly accessible
# from the tools package.

# Centralize imports for easier management and to avoid circular dependencies (if any)

# FortiGate Client Utilities
from .fortigate_client import get_fortigate_client, FortiGateClientError, FORTIGATE_VDOM

# Tool Modules
from .traffic_logs import get_traffic_logs
from .policies import get_policy_details, create_policy, get_all_policies, delete_policy, reorder_policy
from .interfaces import get_interfaces_details, create_interface
from .static_routes import get_static_routes, create_static_route
from .address_objects import create_address_object, get_address_object
from .service_objects import (
    create_service_object, 
    get_service_object, 
    create_service_group,
    get_service_group
)

# Ensure all desired functions are explicitly listed for external use.
__all__ = [
    # Client
    "get_fortigate_client",
    "FortiGateClientError",
    "FORTIGATE_VDOM",
    # Traffic Logs
    "get_traffic_logs",
    # Policies
    "get_policy_details",
    "create_policy",
    "get_all_policies",
    "delete_policy",
    "reorder_policy",
    # Interfaces
    "get_interfaces_details",
    "create_interface",
    # Static Routes
    "get_static_routes",
    "create_static_route",
    # Address Objects
    "create_address_object",
    "get_address_object",
    # Service Objects & Groups
    "create_service_object",
    "get_service_object",
    "create_service_group",
    "get_service_group",
]
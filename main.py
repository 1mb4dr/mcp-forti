import logging
import json # Keep for potential use, though direct dict passing is now preferred for config
from dotenv import load_dotenv
from mcp.server.fastmcp  import FastMCP, Context # MCP SDK
from typing import Optional, Dict, List, Any # For type hinting

# Import tool functions and the FortiGate client factory
from tools import (
    get_fortigate_client,
    FortiGateClientError,
    get_traffic_logs,
    get_policy_details,
    create_policy,
    get_interfaces_details,
    create_interface,
    get_static_routes,
    create_static_route,
    create_address_object,
    get_address_object,
    create_service_object,
    get_service_object,
    create_service_group,
    get_service_group
)

# Configure logging for the MCP server
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("FortiGateMCPServer")

# Load environment variables (e.g., for FORTIGATE_HOST, FORTIGATE_API_TOKEN)
load_dotenv()

# Initialize the MCP server application
app = FastMCP("FortiGateManager")

# Global FortiGate client instance
try:
    fgt_client_global = get_fortigate_client()
    logger.info("Global FortiGate client initialized successfully for MCP server.")
except FortiGateClientError as e:
    logger.error(f"Failed to initialize global FortiGate client on server startup: {e}. Some tools may not work.")
    fgt_client_global = None
except Exception as e:
    logger.error(f"Unexpected error initializing global FortiGate client: {e}", exc_info=True)
    fgt_client_global = None


# --- MCP Tool Definitions ---

@app.tool()
async def get_fortigate_traffic_logs(
    ctx: Context,
    log_filter: Optional[str] = None,
    max_logs: int = 20,
    time_range: Optional[str] = "1hour"
) -> Dict[str, Any]:
    """
    Retrieves traffic logs from the FortiGate device.
    You can specify a filter (e.g., "srcip=1.2.3.4 and dstport=443"),
    the maximum number of logs, and a time range (e.g., "1hour", "24hours").
    Note: Log filtering capabilities are dependent on the FortiGate API and this is a simplified interface.
    """
    logger.info(f"MCP Tool: get_fortigate_traffic_logs called with filter='{log_filter}', max_logs={max_logs}, time_range='{time_range}'")
    if not fgt_client_global:
        return {"error": "FortiGate client is not available."}
    try:
        result = get_traffic_logs(fgt_client_global, log_filter=log_filter, max_logs=max_logs, time_range=time_range)
        if isinstance(result, dict) and "error" in result:
            logger.error(f"Error from get_traffic_logs: {result['error']}")
        return {"logs": result} 
    except Exception as e:
        logger.error(f"Unexpected error in MCP tool get_fortigate_traffic_logs: {e}", exc_info=True)
        return {"error": f"An unexpected server error occurred: {str(e)}"}

@app.tool()
async def get_fortigate_policy_details(ctx: Context, policy_id: int) -> Dict[str, Any]:
    """
    Retrieves detailed information for a specific firewall policy ID from FortiGate.
    Provide the numeric ID of the policy.
    """
    logger.info(f"MCP Tool: get_fortigate_policy_details called for policy_id: {policy_id}")
    if not fgt_client_global:
        return {"error": "FortiGate client is not available."}
    try:
        result = get_policy_details(fgt_client_global, policy_id=policy_id)
        return result 
    except Exception as e:
        logger.error(f"Unexpected error in MCP tool get_fortigate_policy_details: {e}", exc_info=True)
        return {"error": f"An unexpected server error occurred: {str(e)}"}

@app.tool()
async def create_fortigate_firewall_policy(ctx: Context, policy_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Creates a new firewall policy on the FortiGate.
    Input: policy_config - A dictionary representing the policy configuration.
    Example:
    {
        "name": "MCP_Policy_01",
        "srcintf": [{"name": "port1"}],
        "dstintf": [{"name": "port2"}],
        "srcaddr": [{"name": "all"}],
        "dstaddr": [{"name": "all"}],
        "action": "accept",
        "schedule": "always",
        "service": [{"name": "HTTPS"}],
        "logtraffic": "utm",
        "status": "enable",
        "nat": "disable"
    }
    Ensure interface names, address/service object names are valid on your FortiGate.
    """
    logger.info(f"MCP Tool: create_fortigate_firewall_policy called with config: {policy_config}")
    if not fgt_client_global:
        return {"error": "FortiGate client is not available."}
    try:
        # Basic validation that it's a dictionary is now handled by Pydantic via type hint
        if not isinstance(policy_config, dict): # Should be redundant due to type hint but good for clarity
            return {"error": "Invalid policy_config: Must be a dictionary."}
            
        result = create_policy(fgt_client_global, policy_config=policy_config)
        return result
    except Exception as e: # Catch any other unexpected errors
        logger.error(f"Unexpected error in MCP tool create_fortigate_firewall_policy: {e}", exc_info=True)
        return {"error": f"An unexpected server error occurred: {str(e)}"}

@app.tool()
async def get_fortigate_interface_details(ctx: Context, interface_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieves details for all network interfaces or a specific interface by name from FortiGate.
    If 'interface_name' is omitted, all interfaces are returned.
    """
    logger.info(f"MCP Tool: get_fortigate_interface_details called for interface_name: {interface_name}")
    if not fgt_client_global:
        return {"error": "FortiGate client is not available."}
    try:
        result = get_interfaces_details(fgt_client_global, interface_name=interface_name)
        if isinstance(result, dict) and "error" in result:
            return result
        elif isinstance(result, list):
            return {"interfaces": result}
        elif isinstance(result, dict): 
            return {"interface": result}
        else: 
            return {"error": "Unexpected data format from interface tool."}
    except Exception as e:
        logger.error(f"Unexpected error in MCP tool get_fortigate_interface_details: {e}", exc_info=True)
        return {"error": f"An unexpected server error occurred: {str(e)}"}

@app.tool()
async def create_fortigate_network_interface(ctx: Context, interface_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Creates a new network interface (e.g., VLAN, loopback) on the FortiGate.
    Input: interface_config - A dictionary for the interface configuration.
    Example for VLAN:
    {
        "name": "mcp_vlan99",
        "ip": "192.168.99.1 255.255.255.0",
        "allowaccess": "ping https",
        "type": "vlan",
        "vlanid": 99,
        "interface": "port3",
        "description": "MCP Created VLAN"
    }
    Ensure 'name' is unique and 'interface' (for VLANs) exists.
    """
    logger.info(f"MCP Tool: create_fortigate_network_interface called with config: {interface_config}")
    if not fgt_client_global:
        return {"error": "FortiGate client is not available."}
    try:
        if not isinstance(interface_config, dict): # Should be redundant
            return {"error": "Invalid interface_config: Must be a dictionary."}

        result = create_interface(fgt_client_global, interface_config=interface_config)
        return result
    except Exception as e:
        logger.error(f"Unexpected error in MCP tool create_fortigate_network_interface: {e}", exc_info=True)
        return {"error": f"An unexpected server error occurred: {str(e)}"}

@app.tool()
async def get_fortigate_static_routes(ctx: Context, route_seq_num: Optional[int] = None) -> Dict[str, Any]:
    """
    Retrieves all static routes or a specific static route by its sequence number (seq-num) from FortiGate.
    If 'route_seq_num' is omitted, all static routes are returned.
    """
    logger.info(f"MCP Tool: get_fortigate_static_routes called for route_seq_num: {route_seq_num}")
    if not fgt_client_global:
        return {"error": "FortiGate client is not available."}
    try:
        result = get_static_routes(fgt_client_global, route_seq_num=route_seq_num)
        if isinstance(result, dict) and "error" in result:
            return result
        elif isinstance(result, list):
            return {"static_routes": result}
        elif isinstance(result, dict): 
            return {"static_route": result}
        else:
            return {"error": "Unexpected data format from static route tool."}
    except Exception as e:
        logger.error(f"Unexpected error in MCP tool get_fortigate_static_routes: {e}", exc_info=True)
        return {"error": f"An unexpected server error occurred: {str(e)}"}

@app.tool()
async def create_fortigate_static_route(ctx: Context, route_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Creates a new static route on the FortiGate.
    Input: route_config - A dictionary for the static route configuration.
    Example:
    {
        "dst": "10.150.0.0 255.255.0.0",
        "gateway": "192.168.1.254",
        "device": "port1",
        "status": "enable",
        "comment": "Route created by MCP"
    }
    'seq-num' is usually auto-assigned by FortiGate if omitted.
    """
    logger.info(f"MCP Tool: create_fortigate_static_route called with config: {route_config}")
    if not fgt_client_global:
        return {"error": "FortiGate client is not available."}
    try:
        if not isinstance(route_config, dict):
            return {"error": "Invalid route_config: Must be a dictionary."}

        result = create_static_route(fgt_client_global, route_config=route_config)
        return result
    except Exception as e:
        logger.error(f"Unexpected error in MCP tool create_fortigate_static_route: {e}", exc_info=True)
        return {"error": f"An unexpected server error occurred: {str(e)}"}

@app.tool()
async def create_fortigate_address_object(ctx: Context, object_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Creates a new firewall address object on the FortiGate.
    Input: object_config - A dictionary representing the address object configuration.
    Examples:
    FQDN: {"name": "mysite", "type": "fqdn", "fqdn": "mysite.example.com"}
    IP Range: {"name": "myrange", "type": "iprange", "start-ip": "10.0.0.1", "end-ip": "10.0.0.10"}
    Subnet: {"name": "mysubnet", "type": "ipmask", "subnet": "10.0.1.0 255.255.255.0"}
    """
    logger.info(f"MCP Tool: create_fortigate_address_object called with config: {object_config}")
    if not fgt_client_global:
        return {"error": "FortiGate client is not available."}
    try:
        if not isinstance(object_config, dict):
            return {"error": "Invalid object_config: Must be a dictionary."}
        
        result = create_address_object(fgt_client_global, object_config=object_config)
        return result
    except Exception as e:
        logger.error(f"Unexpected error in MCP tool create_fortigate_address_object: {e}", exc_info=True)
        return {"error": f"An unexpected server error occurred: {str(e)}"}

@app.tool()
async def get_fortigate_address_object(ctx: Context, object_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieves details for all address objects or a specific address object by name from FortiGate.
    If 'object_name' is omitted, all address objects are returned.
    """
    logger.info(f"MCP Tool: get_fortigate_address_object called for object_name: {object_name}")
    if not fgt_client_global:
        return {"error": "FortiGate client is not available."}
    try:
        result = get_address_object(fgt_client_global, object_name=object_name)
        if isinstance(result, dict) and "error" in result:
            return result
        elif isinstance(result, list): 
            return {"address_objects": result}
        elif isinstance(result, dict): 
            return {"address_object": result}
        else:
            return {"error": "Unexpected data format from address object tool."}
    except Exception as e:
        logger.error(f"Unexpected error in MCP tool get_fortigate_address_object: {e}", exc_info=True)
        return {"error": f"An unexpected server error occurred: {str(e)}"}

@app.tool()
async def create_fortigate_service_object(ctx: Context, service_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Creates a new custom firewall service object on the FortiGate.
    Input: service_config - A dictionary representing the service object configuration.
    Examples:
    TCP: {"name": "MyWebApp", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "8080-8081", "comment": "My custom web app"}
    UDP: {"name": "MyGameServer", "protocol": "TCP/UDP/SCTP", "udp-portrange": "27015"}
    ICMP: {"name": "MyCustomPing", "protocol": "ICMP", "icmptype": 8, "icmpcode": 0}
    """
    logger.info(f"MCP Tool: create_fortigate_service_object called with config: {service_config}")
    if not fgt_client_global:
        return {"error": "FortiGate client is not available."}
    try:
        if not isinstance(service_config, dict):
            return {"error": "Invalid service_config: Must be a dictionary."}
            
        result = create_service_object(fgt_client_global, service_config=service_config)
        return result
    except Exception as e:
        logger.error(f"Unexpected error in MCP tool create_fortigate_service_object: {e}", exc_info=True)
        return {"error": f"An unexpected server error occurred: {str(e)}"}

@app.tool()
async def get_fortigate_service_object(ctx: Context, service_name: Optional[str] = None, service_type: str = "custom") -> Dict[str, Any]:
    """
    Retrieves details for custom firewall service objects or a specific one by name from FortiGate.
    If 'service_name' is omitted, all services of 'service_type' (default 'custom') are returned.
    'service_type' can be 'custom' or 'predefined' (predefined listing may be limited).
    """
    logger.info(f"MCP Tool: get_fortigate_service_object called for service_name: {service_name}, type: {service_type}")
    if not fgt_client_global:
        return {"error": "FortiGate client is not available."}
    try:
        result = get_service_object(fgt_client_global, service_name=service_name, service_type=service_type)
        if isinstance(result, dict) and "error" in result:
            return result
        elif isinstance(result, list): 
            return {"service_objects": result}
        elif isinstance(result, dict): 
            return {"service_object": result}
        else:
            return {"error": "Unexpected data format from service object tool."}
    except Exception as e:
        logger.error(f"Unexpected error in MCP tool get_fortigate_service_object: {e}", exc_info=True)
        return {"error": f"An unexpected server error occurred: {str(e)}"}

@app.tool()
async def create_fortigate_service_group(ctx: Context, group_config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Creates a new firewall service group on the FortiGate.
    Input: group_config - A dictionary for the service group configuration.
    Example:
    {
        "name": "MyWebApp_Group",
        "member": [
            {"name": "MyWebApp_HTTP"}, 
            {"name": "MyWebApp_HTTPS"}
        ],
        "comment": "Group for MyWebApp services"
    }
    Ensure member service object names are valid on your FortiGate.
    """
    logger.info(f"MCP Tool: create_fortigate_service_group called with config: {group_config}")
    if not fgt_client_global:
        return {"error": "FortiGate client is not available."}
    try:
        if not isinstance(group_config, dict):
            return {"error": "Invalid group_config: Must be a dictionary."}
            
        result = create_service_group(fgt_client_global, group_config=group_config)
        return result
    except Exception as e:
        logger.error(f"Unexpected error in MCP tool create_fortigate_service_group: {e}", exc_info=True)
        return {"error": f"An unexpected server error occurred: {str(e)}"}

@app.tool()
async def get_fortigate_service_group(ctx: Context, group_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieves details for all firewall service groups or a specific group by name from FortiGate.
    If 'group_name' is omitted, all service groups are returned.
    """
    logger.info(f"MCP Tool: get_fortigate_service_group called for group_name: {group_name}")
    if not fgt_client_global:
        return {"error": "FortiGate client is not available."}
    try:
        result = get_service_group(fgt_client_global, group_name=group_name)
        if isinstance(result, dict) and "error" in result: # Error from the tool
            return result
        elif isinstance(result, list): # Multiple groups
            return {"service_groups": result}
        elif isinstance(result, dict): # Single group or could be an empty result if not found by name
            return {"service_group": result} 
        else:
            return {"error": "Unexpected data format from service group tool."}
    except Exception as e:
        logger.error(f"Unexpected error in MCP tool get_fortigate_service_group: {e}", exc_info=True)
        return {"error": f"An unexpected server error occurred: {str(e)}"}


# To run this server:
# 1. Ensure you have the MCP Python SDK installed 
#    and other dependencies from requirements.txt.
# 2. Create a `.env` file with your FortiGate credentials.
# 3. Run from the command line in the `mcp_fortigate_server` directory:
#    `mcp dev main.py`
#
# Or, if you want to run it as a simple Python script (less common for MCP servers,
# which usually rely on the `mcp` CLI for proper execution and discovery):
#
# if __name__ == "__main__":
#     logger.info("Starting FortiGate MCP Server (basic execution, use 'mcp dev main.py' for full features)...")
#     # This basic execution might not fully work as expected for an MCP server,
#     # as the `mcp` CLI handles aspects like transport (stdio/SSE) and discovery.
#     # For development and testing, `mcp dev main.py` is the standard.
#     # app.run() # This method might not exist or work this way directly.
#     print("FortiGate MCP Server defined. To run, use: mcp dev main.py")
#     print("Ensure your .env file is configured with FortiGate credentials.")
#     if not fgt_client_global:
#         print("WARNING: Global FortiGate client failed to initialize. Check .env and connectivity.")


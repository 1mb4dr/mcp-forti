# mcp_fortigate_server/tools/interfaces.py

import logging
from .fortigate_client import FortiGateClientError, FORTIGATE_VDOM

# Configure logging
logger = logging.getLogger(__name__)

def get_interfaces_details(fgt_client, interface_name: str = None):
    """
    Retrieves details for all interfaces or a specific interface.

    Args:
        fgt_client: An initialized FortiGateAPI client instance.
        interface_name (str, optional): The name (mkey) of the interface to retrieve.
                                       If None, retrieves all interfaces.

    Returns:
        list or dict: A list of interface details if no name is specified,
                      or a dict with a single interface's details if a name is provided.
                      Returns an error message dict on failure.
    """
    action_desc = "all interfaces"
    if interface_name:
        action_desc = f"interface '{interface_name}'"
    logger.info(f"Attempting to fetch details for {action_desc} in VDOM: {FORTIGATE_VDOM}")

    try:
        if interface_name:
            # `get(mkey=...)` is used for fetching a single object by its primary key (name for interfaces)
            interface_data = fgt_client.cmdb.system.interface.get(mkey=interface_name)
            if interface_data: # Should return a dict if found
                logger.info(f"Successfully fetched interface '{interface_name}': {interface_data}")
                return interface_data
            else:
                # This case might not be reached if fortigate-api raises an exception for 404
                logger.warning(f"Interface '{interface_name}' not found in VDOM {FORTIGATE_VDOM}.")
                return {"error": f"Interface '{interface_name}' not found."}
        else:
            # `get()` without mkey fetches all objects
            interfaces_data = fgt_client.cmdb.system.interface.get()
            logger.info(f"Successfully fetched {len(interfaces_data)} interfaces.")
            return interfaces_data
    except FortiGateClientError as e:
        logger.error(f"FortiGate client error fetching {action_desc}: {e}")
        return {"error": f"FortiGate client error: {e}"}
    except Exception as e:
        logger.error(f"An error occurred fetching {action_desc}: {e}", exc_info=True)
        if "404" in str(e) or "not found" in str(e).lower():
             return {"error": f"Interface '{interface_name}' not found (API error)."}
        return {"error": f"An unexpected error occurred: {str(e)}"}


def create_interface(fgt_client, interface_config: dict):
    """
    Creates a new network interface (e.g., VLAN, loopback).
    For VLANs, 'interface' (physical parent), 'vlanid', 'ip' (with mask) are crucial.
    Example VLAN:
    {
        "name": "mcp_vlan99", "type": "vlan", "vdom": "root", 
        "ip": "192.168.99.1 255.255.255.0", "allowaccess": "ping https", 
        "vlanid": 99, "interface": "port3", "description": "MCP Created VLAN"
    }
    """
    if "name" not in interface_config:
        logger.error("Missing 'name' (mkey) in interface configuration.")
        return {"error": "Missing 'name' (mkey) in interface configuration."}
    
    interface_name_for_log = interface_config['name']
    logger.info(f"Attempting to create interface '{interface_name_for_log}' with config in VDOM: {FORTIGATE_VDOM}")
    logger.debug(f"Interface creation payload for '{interface_name_for_log}': {interface_config}")

    required_fields = ["name", "type"] # Base required fields
    # Add type-specific required fields validation
    if interface_config.get("type") == "vlan":
        required_fields.extend(["vlanid", "interface", "ip"]) # 'ip' includes mask
    elif interface_config.get("type") == "loopback":
        required_fields.extend(["ip"])
    # Add other types as needed

    for field in required_fields:
        if field not in interface_config:
            msg = f"Missing required field '{field}' for interface type '{interface_config.get('type')}' (name: '{interface_name_for_log}')."
            logger.error(msg)
            return {"error": msg}

    try:
        # The API client should handle VDOM context if `fgt_client` is VDOM-specific,
        # or VDOM should be in `interface_config` if `fgt_client` is global (e.g. for 'root' VDOM).
        # The `FORTIGATE_VDOM` variable in `fortigate_client.py` usually handles this.
        # If "vdom" is required in the payload, it should be added like:
        # if "vdom" not in interface_config and FORTIGATE_VDOM:
        #    interface_config["vdom"] = FORTIGATE_VDOM # Only if API client doesn't manage context
        
        api_response_object = fgt_client.cmdb.system.interface.create(data=interface_config)
        
        # Standardized response handling
        if hasattr(api_response_object, 'status_code') and hasattr(api_response_object, 'text'):
            status_code = api_response_object.status_code
            response_text = api_response_object.text
            try:
                parsed_json = api_response_object.json()
                response_text = parsed_json
            except ValueError:
                pass # Not JSON
            
            logger.debug(f"API response for interface '{interface_name_for_log}': HTTP {status_code}, Data: {response_text}")

            if 200 <= status_code < 300:
                if isinstance(response_text, dict) and response_text.get("status") == "error":
                    logger.error(f"FortiGate API indicated an error for interface '{interface_name_for_log}' despite HTTP {status_code}: {response_text}")
                    cli_error = response_text.get("cli_error", str(response_text))
                    error_code = response_text.get("error", "N/A") # e.g. -5
                    return {"error": f"FortiGate API error for '{interface_name_for_log}' (Error code: {error_code})", "details": cli_error}

                logger.info(f"Successfully created interface '{interface_name_for_log}' (HTTP {status_code}). Details: {response_text}")
                return {"status": "success", "message": f"Interface '{interface_name_for_log}' created successfully.", "details": response_text}
            else:
                cli_error = response_text
                error_code = "N/A"
                if isinstance(response_text, dict):
                    cli_error = response_text.get("cli_error", str(response_text))
                    error_code = response_text.get("error", "N/A")
                logger.error(f"FortiGate API error (HTTP {status_code}, Code: {error_code}) for interface '{interface_name_for_log}': {cli_error}")
                return {"error": f"FortiGate API error (HTTP {status_code}, Code: {error_code}) for '{interface_name_for_log}'", "details": cli_error}

        elif isinstance(api_response_object, dict): # Fallback for direct dict responses
            logger.debug(f"API response (dict) for interface '{interface_name_for_log}': {api_response_object}")
            if api_response_object.get("http_status") == 200 and api_response_object.get("status") == "success":
                logger.info(f"Successfully created interface '{interface_name_for_log}'. Full response: {api_response_object}")
                return {"status": "success", "message": f"Interface '{interface_name_for_log}' created successfully.", "details": api_response_object}
            else:
                cli_error = api_response_object.get("cli_error", str(api_response_object))
                error_code = api_response_object.get("error", "N/A")
                logger.error(f"FortiGate API error (parsed dict, Code: {error_code}) for interface '{interface_name_for_log}': {cli_error}")
                return {"error": f"FortiGate API error (parsed dict, Code: {error_code}) for '{interface_name_for_log}'", "details": api_response_object}
        
        else: 
            logger.error(f"Interface creation for '{interface_name_for_log}' returned an unexpected response type: {type(api_response_object)}, {api_response_object}")
            return {"error": "Unexpected response type from API library.", "details": str(api_response_object)}

    except Exception as e:
        logger.error(f"An API error occurred creating interface '{interface_name_for_log}': {e}", exc_info=True)
        error_details = str(e)
        if hasattr(e, 'response') and e.response is not None and hasattr(e.response, 'text'):
            try:
                error_details = e.response.json()
            except ValueError:
                error_details = e.response.text
        elif hasattr(e, 'message'):
             error_details = e.message
        return {"error": f"An API error occurred during interface '{interface_name_for_log}' creation.", "details": error_details}

if __name__ == '__main__':
    from .fortigate_client import get_fortigate_client 
    logging.basicConfig(level=logging.INFO) 
    try:
        logger.info("Testing interfaces module...")
        client = get_fortigate_client()
        if client:
            print("\n--- Testing Get All Interfaces ---")
            all_interfaces = get_interfaces_details(client)
            if isinstance(all_interfaces, dict) and "error" in all_interfaces:
                logger.error(f"Error getting all interfaces: {all_interfaces['error']}")
            else:
                logger.info(f"Fetched {len(all_interfaces)} interfaces. First few names: {[iface.get('name') for iface in all_interfaces[:3]]}")

            test_interface_name = "port1" 
            print(f"\n--- Testing Get Interface '{test_interface_name}' ---")
            specific_interface = get_interfaces_details(client, interface_name=test_interface_name)
            if isinstance(specific_interface, dict) and "error" in specific_interface:
                logger.error(f"Error getting interface '{test_interface_name}': {specific_interface['error']}")
            else:
                logger.info(f"Details for interface '{test_interface_name}': {specific_interface}")

            print("\n--- Testing Create VLAN Interface ---")
            physical_if_for_vlan = "port2" 
            vlan_name_to_create = "mcp_vlan779" # Changed ID to avoid conflict if previous test ran
            vlan_config = {
                "name": vlan_name_to_create,
                "type": "vlan",
                "vdom": "root",
                "ip": "192.168.79.1 255.255.255.0",
                "allowaccess": "ping",
                "vlanid": 779,
                "interface": physical_if_for_vlan,
                "description": "VLAN created by MCP tool test"
            }
            logger.info(f"Create VLAN interface test for '{vlan_name_to_create}' is commented out. Uncomment to run.")
            # create_vlan_response = create_interface(client, vlan_config) 
            # if isinstance(create_vlan_response, dict) and "error" in create_vlan_response:
            #     logger.error(f"Error creating VLAN interface '{vlan_name_to_create}': {create_vlan_response.get('error')}, Details: {create_vlan_response.get('details')}")
            # else:
            #     logger.info(f"VLAN interface '{vlan_name_to_create}' creation response: {create_vlan_response}")
            #     if create_vlan_response.get("status") == "success":
            #         logger.info(f"--- Test: Attempting to delete created VLAN interface '{vlan_name_to_create}' ---")
            #         try:
            #             del_response = client.cmdb.system.interface.delete(mkey=vlan_name_to_create)
            #             logger.info(f"Deletion response for interface '{vlan_name_to_create}': {del_response}")
            #         except Exception as del_e:
            #             logger.error(f"Error deleting interface '{vlan_name_to_create}': {del_e}")
        else:
            logger.error("Could not get FortiGate client for testing interfaces.")
    except FortiGateClientError as e:
        logger.error(f"Client setup error during interfaces test: {e}")
    except Exception as e:
        logger.error(f"General error in interfaces test: {e}", exc_info=True)
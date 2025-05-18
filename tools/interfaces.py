# mcp_fortigate_server/tools/interfaces.py

import logging
from .fortigate_client import FortiGateClientError, FORTIGATE_VDOM # FORTIGATE_VDOM used in logging
# Re-using the helper from policies or define locally if preferred
# from .policies import _parse_api_error_details
# For now, let's define it locally to keep modules more independent or assume a common utils later
def _parse_api_error_details(response_obj_or_text):
    """Helper to extract error details from various response types."""
    if hasattr(response_obj_or_text, 'text'): # requests.Response like
        try:
            data = response_obj_or_text.json()
            # FortiOS often has 'cli_error' or 'error' (numeric code) or 'message'
            return data.get("cli_error", data.get("message", str(data)))
        except ValueError:
            return response_obj_or_text.text
    elif isinstance(response_obj_or_text, dict):
        return response_obj_or_text.get("cli_error", response_obj_or_text.get("message", str(response_obj_or_text)))
    return str(response_obj_or_text)


logger = logging.getLogger(__name__)

def get_interfaces_details(fgt_client, interface_name: str = None):
    """
    Retrieves details for all interfaces or a specific interface.
    """
    action_desc = f"interface '{interface_name}'" if interface_name else "all interfaces"
    logger.info(f"Attempting to fetch details for {action_desc} in VDOM: {FORTIGATE_VDOM}")

    try:
        if interface_name:
            interface_data = fgt_client.cmdb.system.interface.get(mkey=interface_name)
            if interface_data:
                logger.info(f"Successfully fetched {action_desc}.")
                logger.debug(f"Interface '{interface_name}' data: {interface_data}")
                return interface_data
            else:
                logger.warning(f"Interface '{interface_name}' not found in VDOM {FORTIGATE_VDOM} (empty response).")
                return {"error": f"Interface '{interface_name}' not found (empty response from API)."}
        else:
            interfaces_data = fgt_client.cmdb.system.interface.get()
            logger.info(f"Successfully fetched {len(interfaces_data) if isinstance(interfaces_data, list) else 'unknown number of'} interfaces.")
            return interfaces_data
    except Exception as e:
        logger.error(f"Error fetching {action_desc}: {e}", exc_info=True)
        if interface_name and ("404" in str(e) or "not found" in str(e).lower() or "entry not found" in str(e).lower()):
             return {"error": f"Interface '{interface_name}' not found (API error)."}
        return {"error": f"An unexpected error occurred while fetching {action_desc}: {str(e)}"}

def create_interface(fgt_client, interface_config: dict):
    """
    Creates a new network interface (e.g., VLAN, loopback).
    """
    interface_name_for_log = interface_config.get('name', 'UnnamedInterface')
    logger.info(f"Attempting to create interface '{interface_name_for_log}' in VDOM: {FORTIGATE_VDOM}")
    logger.debug(f"Interface creation payload for '{interface_name_for_log}': {interface_config}")

    required_fields = ["name", "type"]
    if "name" not in interface_config or "type" not in interface_config:
        msg = f"Missing 'name' or 'type' in interface configuration for '{interface_name_for_log}'."
        logger.error(msg)
        return {"error": msg}

    if interface_config.get("type") == "vlan":
        required_fields.extend(["vlanid", "interface", "ip"])
    elif interface_config.get("type") == "loopback":
        required_fields.extend(["ip"])
    # Add other type-specific validations as needed

    for field in required_fields:
        if field not in interface_config:
            msg = f"Missing required field '{field}' for interface type '{interface_config.get('type')}' (name: '{interface_name_for_log}')."
            logger.error(msg)
            return {"error": msg}

    try:
        api_response = fgt_client.cmdb.system.interface.create(data=interface_config)
        
        status_code = getattr(api_response, 'status_code', None)
        response_data = api_response
        if hasattr(api_response, 'json'):
            try:
                response_data = api_response.json()
            except ValueError:
                response_data = getattr(api_response, 'text', str(api_response))
        
        logger.debug(f"API response for interface '{interface_name_for_log}': HTTP {status_code if status_code else 'N/A'}, Data: {response_data}")

        if status_code and 200 <= status_code < 300:
            if isinstance(response_data, dict) and response_data.get("status") == "error": # FortiOS specific error in payload
                error_detail = _parse_api_error_details(response_data)
                logger.error(f"FortiGate API error for interface '{interface_name_for_log}' (HTTP {status_code}): {error_detail}")
                return {"error": f"FortiGate API error for '{interface_name_for_log}'", "details": response_data}
            
            logger.info(f"Successfully created interface '{interface_name_for_log}' (HTTP {status_code}).")
            return {"status": "success", "message": f"Interface '{interface_name_for_log}' created successfully.", "details": response_data}
        elif status_code: # Error HTTP status code
            error_detail = _parse_api_error_details(response_data)
            logger.error(f"FortiGate API error (HTTP {status_code}) for interface '{interface_name_for_log}': {error_detail}")
            return {"error": f"FortiGate API error (HTTP {status_code}) for '{interface_name_for_log}'", "details": response_data}
        elif isinstance(api_response, dict): # Fallback for direct dict responses
            if api_response.get("status") == "success":
                 logger.info(f"Interface '{interface_name_for_log}' creation successful (dict response).")
                 return {"status": "success", "message": f"Interface '{interface_name_for_log}' created successfully.", "details": api_response}
            else:
                 error_detail = _parse_api_error_details(api_response)
                 logger.error(f"Interface '{interface_name_for_log}' creation failed (dict response): {error_detail}")
                 return {"error": f"Interface creation failed for '{interface_name_for_log}' (dict response)", "details": api_response}
        else:
            logger.error(f"Interface creation for '{interface_name_for_log}' returned an unexpected response type: {type(api_response)}, {api_response}")
            return {"error": "Unexpected response type from API library.", "details": str(api_response)}

    except Exception as e:
        logger.error(f"API exception creating interface '{interface_name_for_log}': {e}", exc_info=True)
        error_details = str(e)
        if hasattr(e, 'response'):
            error_details = _parse_api_error_details(e.response)
        return {"error": f"API exception during interface '{interface_name_for_log}' creation.", "details": error_details}

if __name__ == '__main__':
    from fortigate_client import get_fortigate_client, FortiGateClientError
    logging.basicConfig(level=logging.DEBUG)
    logger.info("Testing interfaces module...")
    client = None
    try:
        client = get_fortigate_client()
        if client:
            logger.info("Attempting explicit login for interfaces test...")
            client.login()
            logger.info("Login successful for interfaces test.")

            print("\n--- Testing Get All Interfaces ---")
            all_interfaces = get_interfaces_details(client)
            if isinstance(all_interfaces, dict) and "error" in all_interfaces:
                logger.error(f"Error getting all interfaces: {all_interfaces['error']}")
            else:
                logger.info(f"Fetched {len(all_interfaces) if isinstance(all_interfaces, list) else 'N/A'} interfaces. First few names: {[iface.get('name') for iface in (all_interfaces[:3] if isinstance(all_interfaces, list) else [])]}")

            test_interface_name = "port1" # Replace with a known interface on your FortiGate
            print(f"\n--- Testing Get Interface '{test_interface_name}' ---")
            specific_interface = get_interfaces_details(client, interface_name=test_interface_name)
            if isinstance(specific_interface, dict) and "error" in specific_interface:
                logger.error(f"Error getting interface '{test_interface_name}': {specific_interface['error']}")
            else:
                logger.info(f"Details for interface '{test_interface_name}': {specific_interface}")

            print("\n--- Testing Create VLAN Interface (Example) ---")
            # Ensure 'port2' (or your chosen physical_if_for_vlan) exists on your FortiGate
            physical_if_for_vlan = "port2"
            vlan_name_to_create = "mcp_vlan_test999"
            vlan_config = {
                "name": vlan_name_to_create,
                "type": "vlan",
                # "vdom": FORTIGATE_VDOM, # Usually handled by client if vdom-specific
                "ip": "192.168.99.1 255.255.255.0",
                "allowaccess": "ping https", # Adjust as needed: e.g. ping https ssh
                "vlanid": 999,
                "interface": physical_if_for_vlan,
                "description": "VLAN created by MCP tool Python test"
            }
            logger.info(f"Create VLAN interface test for '{vlan_name_to_create}' is normally commented out. Uncomment to run.")
            # create_vlan_response = create_interface(client, vlan_config)
            # if isinstance(create_vlan_response, dict) and "error" in create_vlan_response:
            #     logger.error(f"Error creating VLAN interface '{vlan_name_to_create}': {create_vlan_response.get('error')}, Details: {create_vlan_response.get('details')}")
            # else:
            #     logger.info(f"VLAN interface '{vlan_name_to_create}' creation response: {create_vlan_response}")
            #     if create_vlan_response and create_vlan_response.get("status") == "success":
            #         logger.info(f"--- Test: Attempting to delete created VLAN interface '{vlan_name_to_create}' (Illustrative) ---")
            #         # try:
            #         #     # client.cmdb.system.interface.delete(mkey=vlan_name_to_create) # Actual delete call
            #         #     logger.info(f"Deletion request for interface '{vlan_name_to_create}' submitted (if uncommented).")
            #         # except Exception as del_e:
            #         #     logger.error(f"Error deleting interface '{vlan_name_to_create}': {del_e}")
            #         pass
        else:
            logger.error("Could not get FortiGate client for testing interfaces.")
    except FortiGateClientError as e:
        logger.error(f"Client setup error during interfaces test: {e}")
    except Exception as e:
        logger.error(f"General error in interfaces test (e.g. login failed): {e}", exc_info=True)

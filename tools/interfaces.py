# mcp_fortigate_server/tools/interfaces.py

import logging
from .fortigate_client import FortiGateClientError, FORTIGATE_VDOM
from .utils import _parse_api_error_details, handle_api_response

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
        return handle_api_response(api_response, f"interface creation for '{interface_name_for_log}'", FORTIGATE_VDOM, logger)
    except Exception as e:
        logger.error(f"API exception creating interface '{interface_name_for_log}': {e}", exc_info=True)
        error_details_str = _parse_api_error_details(e.response) if hasattr(e, 'response') else str(e)
        return {"error": f"API exception during interface '{interface_name_for_log}' creation.", "details": error_details_str}

def update_interface(fgt_client, interface_name: str, interface_config: dict):
    """
    Updates an existing network interface.
    """
    logger.info(f"Attempting to update interface '{interface_name}' in VDOM: {FORTIGATE_VDOM}")
    logger.debug(f"Update payload for interface '{interface_name}': {interface_config}")

    if not interface_name:
        msg = "Interface name not provided for update."
        logger.error(msg)
        return {"error": msg}

    try:
        # Note: FortiOS API uses 'set' for updates, but the python SDK might use 'update' or 'set'
        # Assuming 'set' is the correct method based on common FortiOS API patterns for CMDB.
        # If 'update' is the method, fgt_client.cmdb.system.interface.update(mkey=interface_name, data=interface_config)
        api_response = fgt_client.cmdb.system.interface.set(mkey=interface_name, data=interface_config)
        return handle_api_response(api_response, f"interface update for '{interface_name}'", FORTIGATE_VDOM, logger)
    except Exception as e:
        logger.error(f"API exception updating interface '{interface_name}': {e}", exc_info=True)
        error_details_str = _parse_api_error_details(e.response) if hasattr(e, 'response') else str(e)
        # Specific check for "entry not found" or similar for updates on non-existent items
        if "entry not found" in error_details_str.lower() or "404" in error_details_str: # Check the parsed/stringified error
             logger.warning(f"Attempted to update non-existent interface '{interface_name}'. Error: {error_details_str}")
             return {"error": f"Interface '{interface_name}' not found for update.", "details": error_details_str}
        return {"error": f"API exception during interface '{interface_name}' update.", "details": error_details_str}

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

            print(f"\n--- Testing Update Interface '{test_interface_name}' ---")
            logger.warning(f"The update interface test will use '{test_interface_name}'. Ensure this interface exists and is suitable for non-disruptive testing (e.g., changing description).")

            logger.info(f"Fetching initial details for interface '{test_interface_name}' before update...")
            initial_interface_details = get_interfaces_details(client, interface_name=test_interface_name)

            if isinstance(initial_interface_details, dict) and "error" in initial_interface_details:
                logger.error(f"Cannot proceed with update test for '{test_interface_name}': Error fetching initial details: {initial_interface_details['error']}")
            # get_interfaces_details for a specific interface should return the interface dict directly or an error dict
            elif not isinstance(initial_interface_details, dict) or initial_interface_details.get('name') != test_interface_name : # Or some other key that must be present
                logger.error(f"Cannot proceed with update test for '{test_interface_name}': Expected a dict with interface details but got: {initial_interface_details}")
            else:
                original_description = initial_interface_details.get("description", "")
                logger.info(f"Original description for '{test_interface_name}': '{original_description}'")

                update_config = {
                    "description": "Updated by MCP tool Python test - Integration Test"
                }
                logger.info(f"Attempting to update '{test_interface_name}' with new description: '{update_config['description']}'")
                update_response = update_interface(client, test_interface_name, update_config)

                if isinstance(update_response, dict) and "error" in update_response:
                    logger.error(f"Error updating interface '{test_interface_name}': {update_response.get('error')}, Details: {update_response.get('details')}")
                else:
                    logger.info(f"Interface '{test_interface_name}' update API call response: {update_response}")
                    logger.info(f"Verifying update for interface '{test_interface_name}'...")
                    updated_details = get_interfaces_details(client, interface_name=test_interface_name)
                    if isinstance(updated_details, dict) and updated_details.get('name') == test_interface_name:
                        current_description = updated_details.get("description", "")
                        if current_description == update_config["description"]:
                            logger.info(f"SUCCESS: Interface '{test_interface_name}' description updated successfully to '{current_description}'.")
                        else:
                            logger.error(f"FAILURE: Interface '{test_interface_name}' description verification failed. Expected: '{update_config['description']}', Got: '{current_description}'.")
                    elif isinstance(updated_details, dict) and "error" in updated_details:
                        logger.error(f"Could not verify update for '{test_interface_name}'. Error fetching details post-update: {updated_details['error']}")
                    else:
                        logger.error(f"Could not verify update for '{test_interface_name}'. Unexpected response: {updated_details}")

                    # Revert Change
                    revert_config = {"description": original_description}
                    logger.info(f"Attempting to revert description for '{test_interface_name}' to: '{original_description}'")
                    revert_response = update_interface(client, test_interface_name, revert_config)

                    if isinstance(revert_response, dict) and "error" in revert_response:
                        logger.error(f"Error reverting interface '{test_interface_name}' description: {revert_response.get('error')}, Details: {revert_response.get('details')}")
                    else:
                        logger.info(f"Interface '{test_interface_name}' revert API call response: {revert_response}")
                        logger.info(f"Verifying revert for interface '{test_interface_name}'...")
                        reverted_details = get_interfaces_details(client, interface_name=test_interface_name)
                    if isinstance(reverted_details, dict) and reverted_details.get('name') == test_interface_name:
                        final_description = reverted_details.get("description", "")
                            if final_description == original_description:
                                logger.info(f"SUCCESS: Interface '{test_interface_name}' description successfully reverted to '{final_description}'.")
                            else:
                                logger.error(f"FAILURE: Interface '{test_interface_name}' description revert verification failed. Expected: '{original_description}', Got: '{final_description}'.")
                    elif isinstance(reverted_details, dict) and "error" in reverted_details:
                        logger.error(f"Could not verify revert for '{test_interface_name}'. Error fetching details post-revert: {reverted_details['error']}")
                        else:
                        logger.error(f"Could not verify revert for '{test_interface_name}'. Unexpected response: {reverted_details}")
        else:
            logger.error("Could not get FortiGate client for testing interfaces.")
    except FortiGateClientError as e:
        logger.error(f"Client setup error during interfaces test: {e}")
    except Exception as e:
        logger.error(f"General error in interfaces test (e.g. login failed): {e}", exc_info=True)

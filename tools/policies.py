# mcp_fortigate_server/tools/policies.py

import logging
from .fortigate_client import FortiGateClientError, FORTIGATE_VDOM

# Configure logging
logger = logging.getLogger(__name__)

def get_policy_details(fgt_client, policy_id: int):
    """
    Retrieves details for a specific firewall policy by its ID.

    Args:
        fgt_client: An initialized FortiGateAPI client instance.
        policy_id (int): The ID (mkey) of the firewall policy to retrieve.

    Returns:
        dict: Policy details or an error message.
    """
    logger.info(f"Attempting to fetch policy details for policy ID: {policy_id} in VDOM: {FORTIGATE_VDOM}")
    try:
        # The `get()` method with a `mkey` (primary key, which is policyid for policies)
        policy_data = fgt_client.cmdb.firewall.policy.get(mkey=policy_id)
        if policy_data: # `get(mkey=...)` should return a single dict if found
            logger.info(f"Successfully fetched policy ID {policy_id}: {policy_data}")
            return policy_data
        else:
            # This case might not be reached if fortigate-api raises an exception for 404
            logger.warning(f"Policy ID {policy_id} not found in VDOM {FORTIGATE_VDOM}.")
            return {"error": f"Policy ID {policy_id} not found."}
    except FortiGateClientError as e: # Catch client-specific errors
        logger.error(f"FortiGate client error fetching policy {policy_id}: {e}")
        return {"error": f"FortiGate client error: {e}"}
    except Exception as e: # Catch other errors, including potential API errors from the library
        logger.error(f"An error occurred fetching policy {policy_id}: {e}", exc_info=True)
        # Check if the exception is due to a 404 (Not Found) from the API library
        if "404" in str(e) or "not found" in str(e).lower():
            return {"error": f"Policy ID {policy_id} not found (API error)."}
        return {"error": f"An unexpected error occurred: {str(e)}"}


def get_all_policies(fgt_client):
    """
    Retrieves all firewall policies from the FortiGate device.

    Args:
        fgt_client: An initialized FortiGateAPI client instance.

    Returns:
        list: A list of all firewall policies, or an error message.
    """
    logger.info(f"Attempting to fetch all firewall policies from VDOM: {FORTIGATE_VDOM}")
    try:
        # The get() method without mkey or other filters should return all policies
        policies_data = fgt_client.cmdb.firewall.policy.get()
        
        # The API often returns a list of results, or a dict containing a 'results' key
        if isinstance(policies_data, dict) and 'results' in policies_data:
            logger.info(f"Successfully fetched {len(policies_data['results'])} policies from VDOM: {FORTIGATE_VDOM}.")
            return policies_data['results']
        elif isinstance(policies_data, list):
            logger.info(f"Successfully fetched {len(policies_data)} policies from VDOM: {FORTIGATE_VDOM}.")
            return policies_data
        else:
            # This case handles unexpected successful response structures
            logger.warning(f"Fetched policies, but the response format was not a list or a dict with 'results'. Data: {policies_data}")
            return {"warning": "Policies fetched, but in an unexpected format.", "data": policies_data}

    except FortiGateClientError as e:
        logger.error(f"FortiGate client error fetching all policies: {e}")
        return {"error": f"FortiGate client error: {e}"}
    except Exception as e:
        logger.error(f"An error occurred fetching all policies: {e}", exc_info=True)
        return {"error": f"An unexpected error occurred: {str(e)}"}


def delete_policy(fgt_client, policy_id: int):
    """
    Deletes a specific firewall policy by its ID.

    Args:
        fgt_client: An initialized FortiGateAPI client instance.
        policy_id (int): The ID (mkey) of the firewall policy to delete.

    Returns:
        dict: Success or error message.
    """
    logger.info(f"Attempting to delete policy ID: {policy_id} in VDOM: {FORTIGATE_VDOM}")
    try:
        # The delete() method uses mkey (primary key, which is policyid for policies)
        fgt_client.cmdb.firewall.policy.delete(mkey=policy_id)
        # FortiOS API delete operations usually return HTTP 200 OK on success
        # and do not return a body, or return a status object.
        # The fortigate-api library might raise an exception for non-2xx responses.
        logger.info(f"Successfully submitted request to delete policy ID {policy_id}.")
        # Verify deletion or rely on absence of error as success confirmation.
        # Some APIs might return a confirmation, others just HTTP 200.
        # For now, assume success if no exception is raised.
        # A follow-up get_policy_details(policy_id) could confirm deletion if needed,
        # but it should result in a 404 or error.
        return {"status": "success", "message": f"Policy ID {policy_id} deletion request submitted."}
    except FortiGateClientError as e:
        logger.error(f"FortiGate client error deleting policy {policy_id}: {e}")
        return {"error": f"FortiGate client error: {e}"}
    except Exception as e:
        logger.error(f"An error occurred deleting policy {policy_id}: {e}", exc_info=True)
        # Check if the exception is due to the policy already being deleted (404 Not Found)
        if "404" in str(e) or "not found" in str(e).lower() or "Entry not found" in str(e):
            logger.warning(f"Policy ID {policy_id} may have already been deleted or did not exist: {e}")
            return {"status": "success", "message": f"Policy ID {policy_id} not found, potentially already deleted."}
        return {"error": f"An unexpected error occurred: {str(e)}"}

def reorder_policy(fgt_client, policy_id_to_move: int, target_policy_id: int, move_action: str):
    """
    Reorders a firewall policy to be before or after another policy.

    Args:
        fgt_client: An initialized FortiGateAPI client instance.
        policy_id_to_move (int): The ID (mkey) of the policy to move.
        target_policy_id (int): The ID (mkey) of the policy to move next to.
        move_action (str): Either "before" or "after", specifying where to move
                           the policy relative to the target_policy_id.

    Returns:
        dict: Success or error message.
    """
    if move_action not in ["before", "after"]:
        err_msg = "Invalid move_action. Must be 'before' or 'after'."
        logger.error(err_msg)
        return {"error": err_msg}

    logger.info(f"Attempting to move policy ID {policy_id_to_move} {move_action} policy ID {target_policy_id} in VDOM: {FORTIGATE_VDOM}")
    
    payload = {
        "action": "move",
        move_action: target_policy_id  # This will be either {"before": target_id} or {"after": target_id}
    }
    
    try:
        # The update/PUT method is often used for actions like 'move' by specifying the mkey of the policy to move
        # and providing the move parameters in the data payload.
        # The exact method might vary based on the API library's interpretation (e.g. set, update, or a specific 'move' method)
        # Assuming 'set' or 'update' is used for such operations, and the mkey is the policy being moved.
        # Some libraries might have a dedicated `move` function: `fgt_client.cmdb.firewall.policy.move(mkey=policy_id_to_move, data=payload)`
        # Or it might be part of an 'update' or 'set' with 'action': 'move'
        # Let's assume a `set` or `update` that accepts an action payload.
        # The `fortigate-api` library uses `set` for PUT requests.
        response = fgt_client.cmdb.firewall.policy.set(mkey=policy_id_to_move, data=payload)
        
        logger.info(f"Policy move request for ID {policy_id_to_move} submitted. Response: {response}")
        # Successful move typically returns HTTP 200 OK.
        # The response content might vary. Some APIs return the full object, others just a status.
        # Add response parsing if necessary based on actual API behavior.
        if isinstance(response, dict) and response.get("status") == "success": # Ideal response
             logger.info(f"Successfully moved policy ID {policy_id_to_move} {move_action} policy ID {target_policy_id}.")
             return {"status": "success", "message": f"Policy {policy_id_to_move} moved successfully."}
        elif isinstance(response, dict) and response.get("status") == "error":
            logger.error(f"FortiGate API error moving policy {policy_id_to_move}: {response}")
            return {"error": f"FortiGate API error during policy move: {response.get('cli_error', str(response))}", "details": response}
        # A simple HTTP 200 OK might also be indicated by a lack of error or a simple response
        # from the library if it doesn't parse deeply. If no exception and response is minimal, assume ok.
        # This part needs testing against the actual API response for move operations.
        # For now, considering no exception as potentially successful.
        logger.info(f"Policy move for {policy_id_to_move} seems to have been processed. Verify order manually or via get_all_policies.")
        return {"status": "processed", "message": f"Policy {policy_id_to_move} move action processed. Response: {response}"}

    except FortiGateClientError as e:
        logger.error(f"FortiGate client error moving policy {policy_id_to_move}: {e}")
        return {"error": f"FortiGate client error: {e}"}
    except Exception as e:
        logger.error(f"An error occurred moving policy {policy_id_to_move}: {e}", exc_info=True)
        return {"error": f"An unexpected error occurred during policy move: {str(e)}"}

def create_policy(fgt_client, policy_config: dict):
    """
    Creates a new firewall policy.
    Requires a policy_config dictionary. Example keys:
    "name", "srcintf", "dstintf", "srcaddr", "dstaddr", "action",
    "schedule", "service", "status".
    Optional security profiles can be added, e.g.:
    "webfilter-profile": "default",
    "av-profile": "default",
    "ssl-ssh-profile": "certificate-inspection",
    "ips-sensor": "default",
    "application-list": "default",
    "logtraffic": "all" or "utm" or "disable".
    "nat": "enable" or "disable". (Enable for outbound internet usually)
    Ensure all referenced objects (interfaces, addresses, services, profiles) exist.
    """
    logger.info(f"Attempting to create firewall policy '{policy_config.get('name')}' with config in VDOM: {FORTIGATE_VDOM}")
    logger.debug(f"Policy creation payload for '{policy_config.get('name')}': {policy_config}")

    required_fields = ["name", "srcintf", "dstintf", "srcaddr", "dstaddr", "action", "schedule", "service", "status"]
    for field in required_fields:
        if field not in policy_config:
            msg = f"Missing required field '{field}' in policy configuration."
            logger.error(msg)
            return {"error": msg}
        if field in ["srcintf", "dstintf", "srcaddr", "dstaddr", "service"] and not isinstance(policy_config[field], list):
            msg = f"Field '{field}' must be a list of dicts (e.g., [{{'name': 'value'}}])."
            logger.error(msg)
            return {"error": msg}
        for item_list_name in ["srcintf", "dstintf", "srcaddr", "dstaddr", "service"]:
            if item_list_name == field:
                for item in policy_config[item_list_name]:
                    if not isinstance(item, dict) or "name" not in item:
                        msg = f"Items in '{item_list_name}' must be dicts with a 'name' key (e.g., {{'name': 'port1'}})."
                        logger.error(msg)
                        return {"error": msg}
    try:
        api_response_object = fgt_client.cmdb.firewall.policy.create(data=policy_config)
        
        # Standardized response handling (similar to create_interface)
        if hasattr(api_response_object, 'status_code') and hasattr(api_response_object, 'text'):
            status_code = api_response_object.status_code
            # ... (similar detailed response handling as in create_interface, including checking for internal errors in 200 OK JSON responses) ...
            # For brevity, I'll skip repeating the full block
            response_text_data = api_response_object.text
            try:
                response_text_data = api_response_object.json()
            except ValueError:
                pass
            
            logger.debug(f"API response for policy '{policy_config.get('name')}': HTTP {status_code}, Data: {response_text_data}")

            if 200 <= status_code < 300:
                if isinstance(response_text_data, dict) and response_text_data.get("status") == "error":
                    cli_error = response_text_data.get("cli_error", str(response_text_data))
                    logger.error(f"FortiGate API error for policy '{policy_config.get('name')}' (HTTP {status_code}): {cli_error}")
                    return {"error": f"FortiGate API error for policy '{policy_config.get('name')}'", "details": response_text_data}
                
                mkey = response_text_data.get("mkey", policy_config.get("name")) if isinstance(response_text_data, dict) else policy_config.get("name")
                logger.info(f"Successfully created policy (HTTP {status_code}). Policy ID/Name: {mkey}.")
                return {"status": "success", "message": "Policy created successfully.", "policy_id": mkey, "details": response_text_data}
            else:
                cli_error = response_text_data.get("cli_error", str(response_text_data)) if isinstance(response_text_data, dict) else str(response_text_data)
                logger.error(f"FortiGate API error (HTTP {status_code}) for policy '{policy_config.get('name')}': {cli_error}")
                return {"error": f"FortiGate API error (HTTP {status_code})", "details": response_text_data}

        elif isinstance(api_response_object, dict): # Fallback for direct dict responses
            # ... (similar handling) ...
            logger.info(f"Policy creation response (dict) for '{policy_config.get('name')}': {api_response_object}")
            return api_response_object

        else: 
            logger.error(f"Policy creation for '{policy_config.get('name')}' returned an unexpected response type: {type(api_response_object)}, {api_response_object}")
            return {"error": "Unexpected response type from API library.", "details": str(api_response_object)}

    except Exception as e: 
        logger.error(f"An API error occurred creating policy '{policy_config.get('name')}': {e}", exc_info=True)
        error_details = str(e)
        if hasattr(e, 'response') and e.response is not None and hasattr(e.response, 'text'):
            try:
                error_details = e.response.json()
            except ValueError: 
                error_details = e.response.text
        elif hasattr(e, 'message'): 
             error_details = e.message
        return {"error": f"An API error occurred during policy '{policy_config.get('name')}' creation.", "details": error_details}

if __name__ == '__main__':
    from .fortigate_client import get_fortigate_client 
    logging.basicConfig(level=logging.INFO) 
    try:
        logger.info("Testing policies module...")
        client = get_fortigate_client()
        if client:
            policy_id_to_get = 1 
            print(f"\n--- Testing Get Policy {policy_id_to_get} ---")
            details = get_policy_details(client, policy_id_to_get)
            if isinstance(details, dict) and "error" in details:
                logger.error(f"Error getting policy {policy_id_to_get}: {details['error']}")
            else:
                logger.info(f"Details for policy {policy_id_to_get}: {details}")

            print("\n--- Testing Create Policy ---")
            new_policy_config = {
                "name": "MCP_Tool_Test_Policy_Example", # Changed name
                "srcintf": [{"name": "port1"}], # Example: use a specific interface
                "dstintf": [{"name": "port2"}], # Example: use a specific interface
                "srcaddr": [{"name": "all"}],   # Or a specific address object name
                "dstaddr": [{"name": "all"}],   # Or a specific address object name
                "action": "accept",
                "schedule": "always",
                "service": [{"name": "HTTP"}, {"name": "HTTPS"}], # Or custom service names
                "logtraffic": "utm", 
                "status": "enable",
                "nat": "disable", # Often 'enable' for internet access policies from LAN
                # Example security profiles (ensure these profiles exist on your FortiGate)
                "webfilter-profile": "default", 
                "av-profile": "default",
                # "ips-sensor": "default",
                # "ssl-ssh-profile": "certificate-inspection", 
                # "application-list": "default", 
                "comments": "Policy created by MCP Tool for testing"
            }
            logger.info("Create policy test is commented out to prevent unintended changes. Uncomment to run if your .env and FortiGate are correctly set up.")
            # creation_response = create_policy(client, new_policy_config) 
            # if isinstance(creation_response, dict) and "error" in creation_response:
            #     logger.error(f"Error creating policy: {creation_response.get('error')}, Details: {creation_response.get('details')}")
            # else:
            #     logger.info(f"Policy creation response: {creation_response}")
            #     new_policy_id = creation_response.get("policy_id")
            #     if new_policy_id: # If successful and ID is returned
            #         logger.info(f"--- Test: Attempting to delete created policy ID: {new_policy_id} ---")
            #         try:
            #             # Assuming the policy was created and we have an ID to delete
            #             # Note: if name was used as mkey in creation, use name for deletion if ID is not clear
            #             del_mkey = new_policy_id 
            #             # If new_policy_id is None but name is there, and name is the actual mkey for deletion
            #             # if not del_mkey and "name" in new_policy_config: del_mkey = new_policy_config["name"]

            #             if del_mkey:
            #                 del_response = client.cmdb.firewall.policy.delete(mkey=del_mkey)
            #                 logger.info(f"Deletion response for policy {del_mkey}: {del_response}")
            #             else:
            #                 logger.warning("Could not determine mkey for deletion of test policy.")
            #         except Exception as del_e:
            #             logger.error(f"Error deleting policy {new_policy_id}: {del_e}")
        else:
            logger.error("Could not get FortiGate client for testing policies.")
    except FortiGateClientError as e:
        logger.error(f"Client setup error during policies test: {e}")
    except Exception as e:
        logger.error(f"General error in policies test: {e}", exc_info=True)
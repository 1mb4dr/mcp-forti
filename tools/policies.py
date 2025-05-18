# mcp_fortigate_server/tools/policies.py

import logging
from .fortigate_client import FortiGateClientError, FORTIGATE_VDOM

# Configure logging
logger = logging.getLogger(__name__)

def _parse_api_error_details(response_obj_or_text):
    """Helper to extract error details from various response types."""
    if hasattr(response_obj_or_text, 'text'): # requests.Response like
        try:
            data = response_obj_or_text.json()
            return data.get("cli_error", data.get("error_message", str(data)))
        except ValueError:
            return response_obj_or_text.text
    elif isinstance(response_obj_or_text, dict):
        return response_obj_or_text.get("cli_error", response_obj_or_text.get("error_message", str(response_obj_or_text)))
    return str(response_obj_or_text)

def get_policy_details(fgt_client, policy_id: int):
    """
    Retrieves details for a specific firewall policy by its ID.
    """
    logger.info(f"Attempting to fetch policy details for specific policy ID: {policy_id} in VDOM: {FORTIGATE_VDOM}")
    try:
        policy_data = fgt_client.cmdb.firewall.policy.get(mkey=policy_id)
        if policy_data:
            logger.info(f"Successfully fetched policy ID {policy_id}.")
            logger.debug(f"Policy ID {policy_id} data: {policy_data}")
            return policy_data
        else:
            # This case may not be reached if fortigate-api raises an exception for 404
            logger.warning(f"Policy ID {policy_id} not found in VDOM {FORTIGATE_VDOM} (empty response).")
            return {"error": f"Policy ID {policy_id} not found (empty response from API)."}
    except Exception as e:
        logger.error(f"Error fetching policy {policy_id}: {e}", exc_info=True)
        if "404" in str(e) or "not found" in str(e).lower() or "entry not found" in str(e).lower():
            return {"error": f"Policy ID {policy_id} not found (API error)."}
        return {"error": f"An unexpected error occurred while fetching policy {policy_id}: {str(e)}"}

def get_all_policies(fgt_client):
    """
    Retrieves all firewall policies from the FortiGate device.
    """
    logger.info(f"Attempting to fetch all firewall policies from VDOM: {FORTIGATE_VDOM}")
    try:
        policies_data = fgt_client.cmdb.firewall.policy.get()
        
        results = []
        if isinstance(policies_data, dict) and 'results' in policies_data:
            results = policies_data['results']
        elif isinstance(policies_data, list):
            results = policies_data
        else:
            logger.warning(f"Fetched policies, but the response format was unexpected. Data: {policies_data}")
            return {"warning": "Policies fetched, but in an unexpected format.", "data": policies_data}
        
        logger.info(f"Successfully fetched {len(results)} policies from VDOM: {FORTIGATE_VDOM}.")
        return results
    except Exception as e:
        logger.error(f"An error occurred fetching all policies: {e}", exc_info=True)
        return {"error": f"An unexpected error occurred while fetching all policies: {str(e)}"}

def delete_policy(fgt_client, policy_id: int):
    """
    Deletes a specific firewall policy by its ID.
    """
    logger.info(f"Attempting to delete policy ID: {policy_id} in VDOM: {FORTIGATE_VDOM}")
    try:
        fgt_client.cmdb.firewall.policy.delete(uid=policy_id)
        logger.info(f"Successfully submitted request to delete policy ID {policy_id}.")
        return {"status": "success", "message": f"Policy ID {policy_id} deletion request submitted."}
    except Exception as e:
        logger.error(f"Error deleting policy {policy_id}: {e}", exc_info=True)
        if "404" in str(e) or "not found" in str(e).lower() or "Entry not found" in str(e):
            logger.warning(f"Policy ID {policy_id} may have already been deleted or did not exist: {e}")
            return {"status": "success", "message": f"Policy ID {policy_id} not found or already deleted."}
        return {"error": f"An unexpected error occurred while deleting policy {policy_id}: {str(e)}"}

def reorder_policy(fgt_client, policy_id_to_move: int, target_policy_id: int, move_action: str):
    """
    Reorders a firewall policy to be before or after another policy.
    move_action: "before" or "after".
    """
    if move_action not in ["before", "after"]:
        err_msg = "Invalid move_action. Must be 'before' or 'after'."
        logger.error(err_msg)
        return {"error": err_msg}

    logger.info(f"Attempting to move policy ID {policy_id_to_move} {move_action} policy ID {target_policy_id} in VDOM: {FORTIGATE_VDOM}")
    payload = {"action": "move", move_action: target_policy_id}
    
    try:
        response = fgt_client.cmdb.firewall.policy.set(mkey=policy_id_to_move, data=payload) # 'set' is typically used for PUT
        logger.info(f"Policy move request for ID {policy_id_to_move} submitted. Response: {response}")

        # Fortigate-api often returns the response directly or raises an exception.
        # If no exception, assume processed. Response content varies.
        if isinstance(response, dict):
            if response.get("status") == "success":
                 logger.info(f"Successfully moved policy ID {policy_id_to_move} {move_action} policy ID {target_policy_id}.")
                 return {"status": "success", "message": f"Policy {policy_id_to_move} moved successfully.", "details": response}
            elif response.get("status") == "error":
                error_detail = _parse_api_error_details(response)
                logger.error(f"FortiGate API error moving policy {policy_id_to_move}: {error_detail}")
                return {"error": f"FortiGate API error during policy move: {error_detail}", "details": response}
        
        # If no detailed success/error in dict, or not a dict, assume processed if no exception.
        return {"status": "processed", "message": f"Policy {policy_id_to_move} move action processed. Verify order. Response: {response}"}
    except Exception as e:
        logger.error(f"Error moving policy {policy_id_to_move}: {e}", exc_info=True)
        return {"error": f"An unexpected error occurred during policy move for {policy_id_to_move}: {str(e)}"}

def create_policy(fgt_client, policy_config: dict):
    """
    Creates a new firewall policy.
    """
    policy_name = policy_config.get('name', 'UnnamedPolicy')
    logger.info(f"Attempting to create firewall policy '{policy_name}' in VDOM: {FORTIGATE_VDOM}")
    logger.debug(f"Policy creation payload for '{policy_name}': {policy_config}")

    required_fields = ["name", "srcintf", "dstintf", "srcaddr", "dstaddr", "action", "schedule", "service", "status"]
    for field in required_fields:
        if field not in policy_config:
            msg = f"Missing required field '{field}' in policy configuration for '{policy_name}'."
            logger.error(msg)
            return {"error": msg}
        if field in ["srcintf", "dstintf", "srcaddr", "dstaddr", "service"]:
            if not isinstance(policy_config[field], list):
                msg = f"Field '{field}' must be a list for '{policy_name}' (e.g., [{{\"name\": \"value\"}}])."
                logger.error(msg)
                return {"error": msg}
            for item in policy_config[field]:
                if not isinstance(item, dict) or "name" not in item:
                    msg = f"Items in '{field}' must be dicts with a 'name' key for '{policy_name}' (e.g., {{\"name\": \"port1\"}})."
                    logger.error(msg)
                    return {"error": msg}
    try:
        api_response = fgt_client.cmdb.firewall.policy.create(data=policy_config)
        
        status_code = getattr(api_response, 'status_code', None)
        response_data = api_response
        if hasattr(api_response, 'json'):
            try:
                response_data = api_response.json()
            except ValueError: # Not JSON
                response_data = getattr(api_response, 'text', str(api_response))
        
        logger.debug(f"API response for policy '{policy_name}': HTTP {status_code if status_code else 'N/A'}, Data: {response_data}")

        if status_code and 200 <= status_code < 300:
            if isinstance(response_data, dict) and response_data.get("status") == "error":
                error_detail = _parse_api_error_details(response_data)
                logger.error(f"FortiGate API error for policy '{policy_name}' (HTTP {status_code}): {error_detail}")
                return {"error": f"FortiGate API error for policy '{policy_name}'", "details": response_data}
            
            mkey = response_data.get("mkey", policy_name) if isinstance(response_data, dict) else policy_name
            logger.info(f"Successfully created policy (HTTP {status_code}). Policy ID/Name: {mkey}.")
            return {"status": "success", "message": "Policy created successfully.", "policy_id": mkey, "details": response_data}
        elif status_code: # Error HTTP status code
            error_detail = _parse_api_error_details(response_data)
            logger.error(f"FortiGate API error (HTTP {status_code}) for policy '{policy_name}': {error_detail}")
            return {"error": f"FortiGate API error (HTTP {status_code})", "details": response_data}
        elif isinstance(api_response, dict): # Fallback for direct dict responses if no status_code
            if api_response.get("status") == "success": # Check for fortigate-api's own success markers
                 mkey = api_response.get("mkey", policy_name)
                 logger.info(f"Policy '{policy_name}' creation successful (dict response). Policy ID/Name: {mkey}")
                 return {"status": "success", "message": "Policy created successfully.", "policy_id": mkey, "details": api_response}
            else:
                 error_detail = _parse_api_error_details(api_response)
                 logger.error(f"Policy '{policy_name}' creation failed (dict response): {error_detail}")
                 return {"error": f"Policy creation failed for '{policy_name}' (dict response)", "details": api_response}
        else:
            logger.error(f"Policy creation for '{policy_name}' returned an unexpected response type: {type(api_response)}, {api_response}")
            return {"error": "Unexpected response type from API library.", "details": str(api_response)}

    except Exception as e:
        logger.error(f"API exception creating policy '{policy_name}': {e}", exc_info=True)
        error_details = str(e)
        if hasattr(e, 'response'): # requests.exceptions.HTTPError often has a response attribute
            error_details = _parse_api_error_details(e.response)
        return {"error": f"API exception during policy '{policy_name}' creation.", "details": error_details}

if __name__ == '__main__':
    # Import get_fortigate_client locally for testing this module
    from fortigate_client import get_fortigate_client, FortiGateClientError
    logging.basicConfig(level=logging.DEBUG)
    logger.info("Testing policies module...")
    client = None
    try:
        client = get_fortigate_client()
        if client:
            logger.info("Attempting explicit login for policies test...")
            client.login() # For username/password auth
            logger.info("Login successful for policies test.")

            policy_id_to_get = 1
            print(f"\n--- Testing Get Policy {policy_id_to_get} ---")
            details = get_policy_details(client, policy_id_to_get)
            if isinstance(details, dict) and "error" in details:
                logger.error(f"Error getting policy {policy_id_to_get}: {details['error']}")
            else:
                logger.info(f"Details for policy {policy_id_to_get}: {details}")

            print("\n--- Testing Get All Policies ---")
            all_pols = get_all_policies(client)
            if isinstance(all_pols, dict) and "error" in all_pols:
                logger.error(f"Error getting all policies: {all_pols['error']}")
            else:
                logger.info(f"Fetched {len(all_pols)} policies. First few (if any): {all_pols[:2]}")


            print("\n--- Testing Create Policy (Example) ---")
            new_policy_config = {
                "name": "MCP_Tool_Test_Policy_Py",
                "srcintf": [{"name": "port1"}], # Replace with valid interface names
                "dstintf": [{"name": "port2"}], # Replace with valid interface names
                "srcaddr": [{"name": "all"}],
                "dstaddr": [{"name": "all"}],
                "action": "accept", # or "deny"
                "schedule": "always",
                "service": [{"name": "HTTPS"}], # Replace with valid service names
                "logtraffic": "utm",
                "status": "enable",
                "nat": "disable",
                "comments": "Policy created by MCP Tool for Python testing"
            }
            logger.info("Create policy test is normally commented out. Ensure your .env and FortiGate are correctly set up if you uncomment.")
            # creation_response = create_policy(client, new_policy_config)
            # if isinstance(creation_response, dict) and "error" in creation_response:
            #     logger.error(f"Error creating policy: {creation_response.get('error')}, Details: {creation_response.get('details')}")
            # else:
            #     logger.info(f"Policy creation response: {creation_response}")
            #     new_policy_id = creation_response.get("policy_id") # This might be the name or actual ID
            #     if new_policy_id:
            #         logger.info(f"--- Test: Attempting to delete created policy with ID/mkey: {new_policy_id} ---")
            #         # Ensure new_policy_id is the correct mkey (usually numeric ID for existing, or name if just created and ID is name)
            #         # For safety, you might want to fetch the policy by name to get its actual numeric ID before deleting.
            #         # del_response = delete_policy(client, new_policy_id) # Be careful with this!
            #         # logger.info(f"Deletion response for policy {new_policy_id}: {del_response}")
            #         pass # Placeholder for delete call

        else:
            logger.error("Could not get FortiGate client for testing policies.")
    except FortiGateClientError as e:
        logger.error(f"Client setup error during policies test: {e}")
    except Exception as e: # Catches login errors too
        logger.error(f"General error in policies test (e.g. login failed): {e}", exc_info=True)

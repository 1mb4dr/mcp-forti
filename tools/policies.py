# mcp_fortigate_server/tools/policies.py

import logging
from .fortigate_client import FortiGateClientError, FORTIGATE_VDOM
from .utils import _parse_api_error_details, handle_api_response

# Configure logging
logger = logging.getLogger(__name__)

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
        api_response = fgt_client.cmdb.firewall.policy.set(mkey=policy_id_to_move, data=payload)
        action_desc = f"policy reorder for ID {policy_id_to_move} to be {move_action} policy ID {target_policy_id}"
        return handle_api_response(api_response, action_desc, FORTIGATE_VDOM, logger)
    except Exception as e:
        logger.error(f"Error moving policy {policy_id_to_move}: {e}", exc_info=True)
        error_details_str = _parse_api_error_details(e.response) if hasattr(e, 'response') else str(e)
        return {"error": f"An unexpected error occurred during policy move for {policy_id_to_move}: {error_details_str}"}

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
        # Special handling for mkey in policy creation success
        response_dict = handle_api_response(api_response, f"policy creation for '{policy_name}'", FORTIGATE_VDOM, logger)
        if response_dict.get("status") == "success":
            # Attempt to extract mkey (policy ID) from details if present
            details = response_dict.get("details", {})
            mkey = details.get("mkey") if isinstance(details, dict) else None
            if mkey:
                response_dict["policy_id"] = mkey
            else: # If mkey not directly in details, it might be under results (less common for create)
                results = details.get("results") if isinstance(details, dict) else None
                if isinstance(results, list) and results:
                    mkey = results[0].get("mkey")
                elif isinstance(results, dict): # If results is a single dict
                    mkey = results.get("mkey")

                if mkey:
                     response_dict["policy_id"] = mkey
                else: # Fallback if mkey is not found, use the provided name as a potential identifier
                    response_dict["policy_id"] = policy_name
                    logger.warning(f"Could not determine 'mkey' (policy ID) from API response for policy '{policy_name}'. Using provided name as fallback ID.")
            
            # Ensure 'message' reflects policy creation specifically
            response_dict["message"] = f"Policy '{response_dict.get('policy_id', policy_name)}' created successfully."

        return response_dict
    except Exception as e:
        logger.error(f"API exception creating policy '{policy_name}': {e}", exc_info=True)
        error_details_str = _parse_api_error_details(e.response) if hasattr(e, 'response') else str(e)
        return {"error": f"API exception during policy '{policy_name}' creation.", "details": error_details_str}

def update_policy(fgt_client, policy_id: int, policy_config: dict):
    """
    Updates an existing firewall policy by its ID.
    """
    logger.info(f"Attempting to update policy ID: {policy_id} in VDOM: {FORTIGATE_VDOM}")
    logger.debug(f"Update payload for policy ID {policy_id}: {policy_config}")

    if not policy_id: # policy_id is int, so check for 0 or None if that's possible. Assuming 0 is invalid.
        msg = "Policy ID not provided for update."
        logger.error(msg)
        return {"error": msg}

    try:
        # The fortigate-api library uses 'set' for updates (HTTP PUT) on CMDB items.
        api_response = fgt_client.cmdb.firewall.policy.set(mkey=policy_id, data=policy_config)
        return handle_api_response(api_response, f"policy update for ID {policy_id}", FORTIGATE_VDOM, logger)
    except Exception as e:
        logger.error(f"API exception updating policy ID {policy_id}: {e}", exc_info=True)
        error_details_str = _parse_api_error_details(e.response) if hasattr(e, 'response') else str(e)
        
        # Specific check for "entry not found" or similar for updates on non-existent items
        if "entry not found" in error_details_str.lower() or "404" in error_details_str or "not found" in error_details_str.lower():
             logger.warning(f"Attempted to update non-existent policy ID {policy_id}. Error: {error_details_str}")
             return {"error": f"Policy ID {policy_id} not found for update.", "details": error_details_str}
        return {"error": f"API exception during policy ID {policy_id} update.", "details": error_details_str}

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
            
            print(f"\n--- Testing Update Policy ID {policy_id_to_get} ---")
            logger.warning(f"The update policy test will use policy ID '{policy_id_to_get}'. Ensure this policy ID exists and is suitable for non-disruptive testing (e.g., changing comments and status).")

            logger.info(f"Fetching initial details for policy ID {policy_id_to_get} before update...")
            initial_policy_details_response = get_policy_details(client, policy_id=policy_id_to_get)

            if isinstance(initial_policy_details_response, dict) and "error" in initial_policy_details_response:
                logger.error(f"Cannot proceed with update test for policy ID {policy_id_to_get}: Error fetching initial details: {initial_policy_details_response['error']}")
            # get_policy_details for a specific policy should return the policy dict directly or an error dict
            elif not isinstance(initial_policy_details_response, dict) or initial_policy_details_response.get('policyid') != policy_id_to_get: # Check for policyid
                logger.error(f"Cannot proceed with update test for policy ID {policy_id_to_get}: Expected a dict with policy details but got: {initial_policy_details_response}")
                initial_policy_details = None # Add this line
            else:
                initial_policy_details = initial_policy_details_response # Assign directly
            
            if initial_policy_details: # Check if initial_policy_details is not None
                original_comments = initial_policy_details.get("comments", "")
                original_status = initial_policy_details.get("status")
                logger.info(f"Original comments for policy ID {policy_id_to_get}: '{original_comments}'")
                logger.info(f"Original status for policy ID {policy_id_to_get}: '{original_status}'")

                if original_status is None: # Status is a mandatory field usually, but good to check
                    logger.error(f"Original status for policy ID {policy_id_to_get} could not be determined. Skipping update test.")
                else:
                    update_policy_config = {
                        "comments": "Updated by MCP Tool Python test - Integration Test",
                        "status": "disable"
                    }
                    logger.info(f"Attempting to update policy ID {policy_id_to_get} with: Comments='{update_policy_config['comments']}', Status='{update_policy_config['status']}'")
                    update_response = update_policy(client, policy_id_to_get, update_policy_config)

                    if isinstance(update_response, dict) and "error" in update_response:
                        logger.error(f"Error updating policy ID {policy_id_to_get}: {update_response.get('error')}, Details: {update_response.get('details')}")
                    else:
                        logger.info(f"Policy ID {policy_id_to_get} update API call response: {update_response}")
                        logger.info(f"Verifying update for policy ID {policy_id_to_get}...")
                        updated_details = get_policy_details(client, policy_id=policy_id_to_get)
                        if isinstance(updated_details, dict) and updated_details.get('policyid') == policy_id_to_get:
                            current_comments = updated_details.get("comments", "")
                            current_status = updated_details.get("status")
                            if current_comments == update_policy_config["comments"] and current_status == update_policy_config["status"]:
                                logger.info(f"SUCCESS: Policy ID {policy_id_to_get} updated successfully. Comments: '{current_comments}', Status: '{current_status}'.")
                            else:
                                logger.error(f"FAILURE: Policy ID {policy_id_to_get} verification failed. Expected: Comments='{update_policy_config['comments']}', Status='{update_policy_config['status']}'. Got: Comments='{current_comments}', Status='{current_status}'.")
                        else:
                            logger.error(f"Could not verify update for policy ID {policy_id_to_get}'. Error fetching details post-update: {updated_details}")

                        # Revert Change
                        revert_policy_config = {"comments": original_comments, "status": original_status}
                        logger.info(f"Attempting to revert policy ID {policy_id_to_get} to: Comments='{original_comments}', Status='{original_status}'")
                        revert_response = update_policy(client, policy_id_to_get, revert_policy_config)

                        if isinstance(revert_response, dict) and "error" in revert_response:
                            logger.error(f"Error reverting policy ID {policy_id_to_get}: {revert_response.get('error')}, Details: {revert_response.get('details')}")
                        else:
                            logger.info(f"Policy ID {policy_id_to_get} revert API call response: {revert_response}")
                            logger.info(f"Verifying revert for policy ID {policy_id_to_get}'...")
                            reverted_details = get_policy_details(client, policy_id=policy_id_to_get)
                            if isinstance(reverted_details, dict) and reverted_details.get('policyid') == policy_id_to_get:
                                final_comments = reverted_details.get("comments", "")
                                final_status = reverted_details.get("status")
                                if final_comments == original_comments and final_status == original_status:
                                    logger.info(f"SUCCESS: Policy ID {policy_id_to_get} successfully reverted. Comments: '{final_comments}', Status: '{final_status}'.")
                                else:
                                    logger.error(f"FAILURE: Policy ID {policy_id_to_get} revert verification failed. Expected: Comments='{original_comments}', Status='{original_status}'. Got: Comments='{final_comments}', Status='{final_status}'.")
                            else:
                                logger.error(f"Could not verify revert for policy ID {policy_id_to_get}'. Error fetching details post-revert: {reverted_details}")
        else:
            logger.error("Could not get FortiGate client for testing policies.")
    except FortiGateClientError as e:
        logger.error(f"Client setup error during policies test: {e}")
    except Exception as e: # Catches login errors too
        logger.error(f"General error in policies test (e.g. login failed): {e}", exc_info=True)

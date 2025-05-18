# mcp_fortigate_server/tools/service_objects.py

import logging
from .fortigate_client import FortiGateClientError, FORTIGATE_VDOM

def _parse_api_error_details(response_obj_or_text):
    """Helper to extract error details from various response types."""
    if hasattr(response_obj_or_text, 'text'): # requests.Response like
        try:
            data = response_obj_or_text.json()
            return data.get("cli_error", data.get("message", str(data)))
        except ValueError:
            return response_obj_or_text.text
    elif isinstance(response_obj_or_text, dict):
        return response_obj_or_text.get("cli_error", response_obj_or_text.get("message", str(response_obj_or_text)))
    return str(response_obj_or_text)

logger = logging.getLogger(__name__)

def _resolve_fgt_api_path(fgt_client, path_parts: list, operation_desc: str):
    """Helper to resolve the API path on the fgt_client object."""
    current_path_obj = fgt_client
    path_so_far = "fgt_client"
    for part in path_parts:
        if not hasattr(current_path_obj, part):
            error_msg = f"FortiGate API client path error for {operation_desc}: '{path_so_far}' has no attribute '{part}'. Review library docs. Path parts: {path_parts}"
            logger.error(error_msg)
            raise AttributeError(error_msg) # Raise to be caught by calling function
        current_path_obj = getattr(current_path_obj, part)
        path_so_far += f".{part}"
        logger.debug(f"Resolved path part for {operation_desc}: {path_so_far}")
    return current_path_obj

def create_service_object(fgt_client, service_config: dict):
    """
    Creates a new custom firewall service object.
    """
    service_name = service_config.get('name', 'UnnamedServiceObject')
    if "name" not in service_config: # Name is mkey, absolutely required
        logger.error(f"Missing 'name' in service object configuration.")
        return {"error": "Missing 'name' in service object configuration."}

    logger.info(f"Attempting to create service object '{service_name}' in VDOM: {FORTIGATE_VDOM}")
    logger.debug(f"Service object creation payload for '{service_name}': {service_config}")

    protocol = service_config.get("protocol", "").upper()
    validation_error = None
    if protocol == "TCP/UDP/SCTP":
        if not any(k in service_config for k in ["tcp-portrange", "udp-portrange", "sctp-portrange"]):
            validation_error = f"For protocol TCP/UDP/SCTP, at least one of 'tcp-portrange', 'udp-portrange', or 'sctp-portrange' must be set for service '{service_name}'."
    elif protocol == "IP" and "protocol-number" not in service_config:
        validation_error = f"For protocol IP, 'protocol-number' must be set for service '{service_name}'."
    
    if validation_error:
        logger.error(validation_error)
        return {"error": validation_error}

    try:
        # Path for custom service creation: cmdb.firewall_service.custom
        api_collection_obj = _resolve_fgt_api_path(fgt_client, ["cmdb", "firewall_service", "custom"], f"CREATE service object '{service_name}'")
        api_response = api_collection_obj.create(data=service_config)
        
        status_code = getattr(api_response, 'status_code', None)
        response_data = api_response
        text_content_for_check = ""

        if hasattr(api_response, 'text'):
            text_content_for_check = api_response.text
        if hasattr(api_response, 'json'):
            try:
                response_data = api_response.json()
                if isinstance(response_data, dict):
                    text_content_for_check = str(response_data)
            except ValueError:
                response_data = text_content_for_check if text_content_for_check else str(api_response)

        logger.debug(f"API response for service '{service_name}': HTTP {status_code if status_code else 'N/A'}, Data: {response_data}")

        if status_code and 200 <= status_code < 300:
            if isinstance(response_data, dict) and response_data.get("status") == "error":
                error_detail = _parse_api_error_details(response_data)
                logger.error(f"FortiGate API error for service '{service_name}' (HTTP {status_code}): {error_detail}")
                return {"error": f"FortiGate API error for service '{service_name}'", "details": response_data}
            logger.info(f"Successfully sent create request for service object '{service_name}'. HTTP Status: {status_code}.")
            return {"status": "success", "message": f"Service object '{service_name}' creation request sent.", "details": response_data}
        
        elif status_code == 500 and ("already exist" in text_content_for_check.lower() or "duplicate entry" in text_content_for_check.lower() or "-5: Object already_exists" in text_content_for_check.lower()):
            logger.warning(f"Service object '{service_name}' might already exist. FortiGate returned HTTP 500. Details: {response_data}")
            return {"status": "warning", "message": f"Service object '{service_name}' may already exist (HTTP 500).", "details": response_data}
        
        elif status_code:
            error_detail = _parse_api_error_details(response_data)
            logger.error(f"FortiGate API error (HTTP {status_code}) for service '{service_name}': {error_detail}")
            return {"error": f"FortiGate API error (HTTP {status_code}) for '{service_name}'", "details": response_data}
        
        elif isinstance(api_response, dict): # Fallback for direct dict responses
            if api_response.get("status") == "success":
                 logger.info(f"Service object '{service_name}' creation successful (dict response).")
                 return {"status": "success", "message": f"Service object '{service_name}' created successfully.", "details": api_response}
            else: # Includes cases like "status": "error" or http_status being non-200 in the dict
                 error_detail = _parse_api_error_details(api_response)
                 if "already exist" in error_detail.lower() or "duplicate entry" in error_detail.lower() or "-5: Object already_exists" in error_detail:
                     logger.warning(f"Service object '{service_name}' might already exist (parsed dict). Details: {api_response}")
                     return {"status": "warning", "message": f"Service object '{service_name}' might already exist (parsed dict).", "details": api_response}
                 logger.error(f"Service object '{service_name}' creation failed (dict response): {error_detail}")
                 return {"error": f"Service object creation failed for '{service_name}' (dict response)", "details": api_response}
        else:
            logger.error(f"Service object creation for '{service_name}' returned an unexpected response type: {type(api_response)}, {api_response}")
            return {"error": "Unexpected response type from API library for service creation.", "details": str(api_response)}

    except AttributeError as ae: # From _resolve_fgt_api_path
        return {"error": str(ae)}
    except Exception as e:
        logger.error(f"API exception creating service object '{service_name}': {e}", exc_info=True)
        return {"error": f"An API exception occurred for service '{service_name}'.", "details": str(e)}


def get_service_object(fgt_client, service_name: str = None, service_type: str = "custom"):
    """
    Retrieves details for custom or predefined service objects.
    """
    action_desc = f"{service_type} service object '{service_name}'" if service_name else f"all {service_type} service objects"
    logger.info(f"Attempting to fetch details for {action_desc} in VDOM: {FORTIGATE_VDOM}")

    # For custom services: cmdb.firewall_service.custom
    # For predefined, there isn't a direct standard "list all predefined" via one specific path in the same way.
    # Often, predefined services are just used by name.
    # If listing is needed, it's usually the 'custom' path that might show some, or one might check 'all' services.
    path_parts = ["cmdb", "firewall_service", "custom"] # Default to custom path
    
    if service_type == "predefined":
        # This is tricky. FortiGate doesn't typically have a dedicated "list all predefined services" endpoint
        # in the same way it has for custom objects. Predefined services are usually just known.
        # For getting a specific predefined service by name, using the 'custom' path can sometimes work if the
        # library or FortiOS checks both custom and predefined tables when a name is given.
        # If `service_name` is provided, we'll try the 'custom' path. If not, listing "predefined" is problematic.
        if not service_name:
            logger.warning("Listing all 'predefined' services directly is not a standard FortiGate API operation. Returning empty list for this case.")
            return [] # Or an appropriate error/warning
        logger.info(f"Attempting to fetch predefined service '{service_name}' by querying the typical service object path.")
        # The 'custom' path might resolve predefined names if the API/library is smart.

    try:
        api_collection_object = _resolve_fgt_api_path(fgt_client, path_parts, f"GET {action_desc}")

        if service_name:
            service_data = api_collection_object.get(mkey=service_name)
            if service_data:
                logger.info(f"Successfully fetched {action_desc}.")
                logger.debug(f"Data for {action_desc}: {service_data}")
                return service_data
            else:
                logger.warning(f"{action_desc} not found via path fgt_client.{'.'.join(path_parts)} (empty response).")
                return {"error": f"Service object '{service_name}' of type '{service_type}' not found (empty API response)."}
        else: # Get all (primarily for 'custom' type)
            services_data = api_collection_object.get()
            logger.info(f"Successfully fetched {len(services_data) if isinstance(services_data, list) else 'unknown number of'} objects from path fgt_client.{'.'.join(path_parts)} (intended for {service_type}).")
            return services_data

    except AttributeError as ae: # From _resolve_fgt_api_path
        return {"error": str(ae)}
    except Exception as e:
        logger.error(f"Error fetching {action_desc}: {e}", exc_info=True)
        if service_name and ("404" in str(e) or "not found" in str(e).lower() or "entry not found" in str(e).lower()):
             return {"error": f"Service object '{service_name}' (type {service_type}) not found (API error)."}
        return {"error": f"An unexpected error occurred while fetching {action_desc}: {str(e)}"}


def create_service_group(fgt_client, group_config: dict):
    """
    Creates a new firewall service group.
    """
    group_name = group_config.get('name', 'UnnamedServiceGroup')
    if "name" not in group_config:
        logger.error(f"Missing 'name' in service group configuration.")
        return {"error": "Missing 'name' in service group configuration."}
    if "member" not in group_config or not isinstance(group_config["member"], list):
        logger.error(f"Missing or invalid 'member' list in service group '{group_name}'. Must be a list of dicts e.g., [{{\"name\": \"SERVICE_NAME\"}}].")
        return {"error": "Missing or invalid 'member' list. It should be a list of service name dicts."}

    logger.info(f"Attempting to create service group '{group_name}' in VDOM: {FORTIGATE_VDOM}")
    logger.debug(f"Service group creation payload for '{group_name}': {group_config}")

    try:
        # Path for service group creation: cmdb.firewall_service.group
        api_collection_obj = _resolve_fgt_api_path(fgt_client, ["cmdb", "firewall_service", "group"], f"CREATE service group '{group_name}'")
        api_response = api_collection_obj.create(data=group_config)

        status_code = getattr(api_response, 'status_code', None)
        response_data = api_response
        text_content_for_check = ""

        if hasattr(api_response, 'text'):
            text_content_for_check = api_response.text
        if hasattr(api_response, 'json'):
            try:
                response_data = api_response.json()
                if isinstance(response_data, dict):
                    text_content_for_check = str(response_data)
            except ValueError:
                response_data = text_content_for_check if text_content_for_check else str(api_response)

        logger.debug(f"API response for service group '{group_name}': HTTP {status_code if status_code else 'N/A'}, Data: {response_data}")

        if status_code and 200 <= status_code < 300:
            if isinstance(response_data, dict) and response_data.get("status") == "error":
                error_detail = _parse_api_error_details(response_data)
                logger.error(f"FortiGate API error for service group '{group_name}' (HTTP {status_code}): {error_detail}")
                return {"error": f"FortiGate API error for service group '{group_name}'", "details": response_data}
            logger.info(f"Successfully sent create request for service group '{group_name}'. HTTP Status: {status_code}.")
            return {"status": "success", "message": f"Service group '{group_name}' creation request sent.", "details": response_data}

        elif status_code == 500 and ("already exist" in text_content_for_check.lower() or "duplicate entry" in text_content_for_check.lower() or "-5: Object already_exists" in text_content_for_check.lower()):
            logger.warning(f"Service group '{group_name}' might already exist. FortiGate returned HTTP 500. Details: {response_data}")
            return {"status": "warning", "message": f"Service group '{group_name}' may already exist (HTTP 500).", "details": response_data}

        elif status_code:
            error_detail = _parse_api_error_details(response_data)
            logger.error(f"FortiGate API error (HTTP {status_code}) for service group '{group_name}': {error_detail}")
            return {"error": f"FortiGate API error (HTTP {status_code}) for '{group_name}'", "details": response_data}

        elif isinstance(api_response, dict): # Fallback for direct dict responses
            if api_response.get("status") == "success":
                 logger.info(f"Service group '{group_name}' creation successful (dict response).")
                 return {"status": "success", "message": f"Service group '{group_name}' created successfully.", "details": api_response}
            else:
                 error_detail = _parse_api_error_details(api_response)
                 if "already exist" in error_detail.lower() or "duplicate entry" in error_detail.lower() or "-5: Object already_exists" in error_detail:
                     logger.warning(f"Service group '{group_name}' might already exist (parsed dict). Details: {api_response}")
                     return {"status": "warning", "message": f"Service group '{group_name}' might already exist (parsed dict).", "details": api_response}
                 logger.error(f"Service group '{group_name}' creation failed (dict response): {error_detail}")
                 return {"error": f"Service group creation failed for '{group_name}' (dict response)", "details": api_response}
        else:
            logger.error(f"Service group creation for '{group_name}' returned an unexpected response type: {type(api_response)}, {api_response}")
            return {"error": "Unexpected response type from API library for service group creation.", "details": str(api_response)}

    except AttributeError as ae: # From _resolve_fgt_api_path
        return {"error": str(ae)}
    except Exception as e:
        logger.error(f"API exception creating service group '{group_name}': {e}", exc_info=True)
        return {"error": f"An API exception occurred for service group '{group_name}'.", "details": str(e)}

def get_service_group(fgt_client, group_name: str = None):
    """
    Retrieves details for all service groups or a specific one.
    """
    action_desc = f"service group '{group_name}'" if group_name else "all service groups"
    logger.info(f"Attempting to fetch details for {action_desc} in VDOM: {FORTIGATE_VDOM}")
    
    try:
        # Path for service groups: cmdb.firewall_service.group
        api_collection_object = _resolve_fgt_api_path(fgt_client, ["cmdb", "firewall_service", "group"], f"GET {action_desc}")

        if group_name:
            group_data = api_collection_object.get(mkey=group_name)
            if group_data:
                logger.info(f"Successfully fetched {action_desc}.")
                logger.debug(f"Data for {action_desc}: {group_data}")
                return group_data
            else:
                logger.warning(f"{action_desc} not found in VDOM {FORTIGATE_VDOM} (empty response).")
                return {"error": f"Service group '{group_name}' not found (empty API response)."}
        else: 
            groups_data = api_collection_object.get()
            logger.info(f"Successfully fetched {len(groups_data) if isinstance(groups_data, list) else 'unknown number of'} service groups.")
            return groups_data
            
    except AttributeError as ae: # From _resolve_fgt_api_path
        return {"error": str(ae)}
    except Exception as e:
        logger.error(f"Error fetching {action_desc}: {e}", exc_info=True)
        if group_name and ("404" in str(e) or "not found" in str(e).lower() or "entry not found" in str(e).lower()):
             return {"error": f"Service group '{group_name}' not found (API error)."}
        return {"error": f"An unexpected error occurred while fetching {action_desc}: {str(e)}"}


if __name__ == '__main__':
    from fortigate_client import get_fortigate_client, FortiGateClientError
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger.info("Testing service_objects module...")
    
    client = None
    try:
        client = get_fortigate_client()
        if client:
            logger.info("Attempting explicit login for service_objects test...")
            client.login()
            logger.info("Login successful for service_objects test.")

            # Test Custom TCP Service
            tcp_service_name = "MCP-TestTCP-Py9003"
            tcp_service_config = {
                "name": tcp_service_name, "protocol": "TCP/UDP/SCTP", 
                "tcp-portrange": "9003", "comment": "Custom TCP service for MCP Python autotest"
            }
            print(f"\n--- Test: Creating TCP Service Object '{tcp_service_name}' ---")
            # create_tcp_response = create_service_object(client, tcp_service_config)
            # logger.info(f"Create TCP service response: {create_tcp_response}")

            # print(f"\n--- Test: Getting Custom TCP Service Object '{tcp_service_name}' ---")
            # get_tcp_response = get_service_object(client, service_name=tcp_service_name, service_type="custom")
            # logger.info(f"Get Custom TCP service response: {get_tcp_response}")

            # Test Get All Custom Services
            print("\n--- Test: Getting All Custom Service Objects ---")
            get_all_custom_response = get_service_object(client, service_type="custom")
            if isinstance(get_all_custom_response, dict) and "error" in get_all_custom_response:
                 logger.error(f"Error fetching all custom services: {get_all_custom_response['error']}")
            elif isinstance(get_all_custom_response, list):
                logger.info(f"Fetched {len(get_all_custom_response)} custom services. First few: {get_all_custom_response[:2]}")
            else:
                logger.info(f"Response for all custom services (unexpected type): {get_all_custom_response}")
            
            # Test Get Predefined Service
            predefined_service_to_get = "HTTPS" # A common predefined service
            print(f"\n--- Test: Getting Predefined Service Object '{predefined_service_to_get}' ---")
            get_predefined_response = get_service_object(client, service_name=predefined_service_to_get, service_type="predefined")
            logger.info(f"Get predefined '{predefined_service_to_get}' response: {get_predefined_response}")

            # Test Service Group
            group_name = "MCP-TestGroup-Py"
            # Ensure member services (like tcp_service_name or "HTTPS") exist or test will be less meaningful
            group_members = [{"name": "HTTP"}, {"name": "HTTPS"}] # Example members
            # if get_tcp_response and get_tcp_response.get("name") == tcp_service_name: # If TCP service was created/fetched
            #    group_members.append({"name": tcp_service_name})
            
            service_group_config = {
                "name": group_name, "member": group_members,
                "comment": "Custom service group for MCP Python autotest"
            }
            print(f"\n--- Test: Creating Service Group '{group_name}' ---")
            # create_group_response = create_service_group(client, service_group_config)
            # logger.info(f"Create service group response: {create_group_response}")

            # print(f"\n--- Test: Getting Service Group '{group_name}' ---")
            # get_group_response = get_service_group(client, group_name=group_name)
            # logger.info(f"Get service group response: {get_group_response}")

            # Illustrative Deletes (use with caution)
            # print(f"\n--- Test: Deleting Custom TCP Service Object '{tcp_service_name}' (Illustrative) ---")
            # # custom_collection_obj = _resolve_fgt_api_path(client, ["cmdb", "firewall_service", "custom"], "DELETE")
            # # custom_collection_obj.delete(mkey=tcp_service_name)

            # print(f"\n--- Test: Deleting Service Group '{group_name}' (Illustrative) ---")
            # # group_collection_obj = _resolve_fgt_api_path(client, ["cmdb", "firewall_service", "group"], "DELETE")
            # # group_collection_obj.delete(mkey=group_name)
        else:
            logger.error("Could not get FortiGate client.")
    except FortiGateClientError as e:
        logger.error(f"Client setup error during service_objects test: {e}")
    except Exception as e:
        logger.error(f"General error in service_objects test (e.g. login failed): {e}", exc_info=True)

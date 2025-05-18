# mcp_fortigate_server/tools/service_objects.py

import logging
from .fortigate_client import FortiGateClientError, FORTIGATE_VDOM

# Configure logging
logger = logging.getLogger(__name__)

def create_service_object(fgt_client, service_config: dict):
    """
    Creates a new custom firewall service object.

    Args:
        fgt_client: An initialized FortiGateAPI client instance.
        service_config (dict): Configuration for the service object.
                               Required: 'name'.
                               Protocol specific: 'protocol' (TCP/UDP/SCTP), 'tcp-portrange', 'udp-portrange'.
                               Example TCP: {'name': 'MyCustomTCP', 'protocol': 'TCP/UDP/SCTP', 'tcp-portrange': '1000-1005:5000'}
                               Example UDP: {'name': 'MyCustomUDP', 'protocol': 'TCP/UDP/SCTP', 'udp-portrange': '2000'}
                               For ICMP: {'name': 'MyCustomICMP', 'protocol': 'ICMP', 'icmptype': 8} (type is optional)
                               For IP: {'name': 'MyCustomIP', 'protocol': 'IP', 'protocol-number': 50}

    Returns:
        dict: A success or error message dict.
    """
    if "name" not in service_config:
        logger.error("Missing 'name' in service object configuration.")
        return {"error": "Missing 'name' in service object configuration."}
    # Protocol is generally needed for custom services
    # if "protocol" not in service_config:
    #     logger.warning("Missing 'protocol' in service object configuration. Assuming 'TCP/UDP/SCTP' and portranges are set.")
    #     service_config.setdefault("protocol", "TCP/UDP/SCTP")


    service_name = service_config['name']
    logger.info(f"Attempting to create service object '{service_name}' in VDOM: {FORTIGATE_VDOM} with config: {service_config}")
    logger.debug(f"Service object creation payload for '{service_name}': {service_config}")

    # Validate required fields based on protocol
    protocol = service_config.get("protocol", "").upper()
    if protocol == "TCP/UDP/SCTP":
        if not service_config.get("tcp-portrange") and not service_config.get("udp-portrange") and not service_config.get("sctp-portrange"):
            msg = f"For protocol TCP/UDP/SCTP, at least one of 'tcp-portrange', 'udp-portrange', or 'sctp-portrange' must be set for service '{service_name}'."
            logger.error(msg)
            return {"error": msg}
    elif protocol == "ICMP" or protocol == "ICMP6":
        pass # icmptype/icmpcode are optional
    elif protocol == "IP":
        if "protocol-number" not in service_config:
            msg = f"For protocol IP, 'protocol-number' must be set for service '{service_name}'."
            logger.error(msg)
            return {"error": msg}

    try:
        # Path confirmed from user-provided documentation
        path_parts_for_create = ["cmdb", "firewall_service", "custom", "create"]

        logger.debug(f"Attempting to resolve API path for CREATE: fgt_client.{'.'.join(path_parts_for_create)}")
        
        current_path_obj = fgt_client
        path_so_far = "fgt_client"
        
        for part in path_parts_for_create:
            if not hasattr(current_path_obj, part):
                logger.error(f"Object at path '{path_so_far}' does not have attribute '{part}'. This is where the API path resolution fails for service object creation.")
                logger.error(f"Please check your FortiGate API library documentation for the correct CMDB path. Current path parts: {path_parts_for_create}")
                return {"error": f"FortiGate API client path error for CREATE: '{path_so_far}' has no attribute '{part}'. Review library docs."}
            current_path_obj = getattr(current_path_obj, part)
            path_so_far += f".{part}"
            logger.debug(f"Resolved path part for CREATE: {path_so_far}")

        api_create_method = current_path_obj # This should be the 'create' method
        api_response = api_create_method(data=service_config)
        
        if hasattr(api_response, 'status_code') and hasattr(api_response, 'text'): # Assuming requests-like response
            status_code = api_response.status_code
            response_text = api_response.text
            response_json = {}
            try:
                response_json = api_response.json()
            except ValueError:
                pass # Not JSON

            if 200 <= status_code < 300:
                if isinstance(response_json, dict) and response_json.get("status") == "error":
                     logger.error(f"FortiGate API error for service '{service_name}' (HTTP {status_code}): {response_json}")
                     return {"error": f"FortiGate API error for service '{service_name}'", "details": response_json}
                logger.info(f"Successfully sent create request for service object '{service_name}'. HTTP Status: {status_code}.")
                return {"status": "success", "message": f"Service object '{service_name}' creation request sent.", "details": response_json or response_text}
            else:
                if status_code == 500 and "already exist" in response_text.lower():
                    logger.warning(f"Service object '{service_name}' might already exist. FortiGate returned HTTP 500: {response_text}")
                    return {"status": "error", "message": f"Service object '{service_name}' may already exist.", "details": response_json or response_text, "error_code": status_code}
                logger.error(f"FortiGate API error (HTTP {status_code}) for service '{service_name}': {response_text}")
                return {"error": f"FortiGate API error (HTTP {status_code}) for '{service_name}'", "details": response_json or response_text}
        elif isinstance(api_response, dict): # Fallback for direct dict responses from library
            logger.info(f"Service object '{service_name}' creation response (dict): {api_response}")
            return api_response
        else: 
            logger.error(f"Service object creation for '{service_name}' returned an unexpected response type: {type(api_response)}, {api_response}")
            return {"error": "Unexpected response type from API library for service creation.", "details": str(api_response)}

    except FortiGateClientError as e:
        logger.error(f"FortiGate client error creating service object '{service_name}': {e}", exc_info=True)
        return {"error": f"FortiGate client error: {e}"}
    except AttributeError as e:
        logger.error(f"AttributeError during service object creation for '{service_name}': {e}", exc_info=True)
        logger.error("This likely means the API path in `path_parts_for_create` is incorrect for your library version, or an issue with the library.")
        return {"error": f"AttributeError accessing API client for service creation: {e}. Check library documentation for correct CMDB path."}
    except Exception as e:
        logger.error(f"An API error occurred creating service object '{service_name}': {e}", exc_info=True)
        return {"error": f"An API error occurred for '{service_name}'.", "details": str(e)}


def get_service_object(fgt_client, service_name: str = None, service_type: str = "custom"):
    """
    Retrieves details for all custom service objects or a specific one.
    Can also list predefined services if service_type is 'predefined'.

    Args:
        fgt_client: An initialized FortiGateAPI client instance.
        service_name (str, optional): The name of the service object to retrieve.
                                      If None, retrieves all services of the specified type.
        service_type (str, optional): 'custom' or 'predefined'. Defaults to 'custom'.

    Returns:
        list or dict: A list of service objects or a single object's details, or an error dict.
    """
    action_desc = f"all {service_type} service objects"
    if service_name:
        action_desc = f"{service_type} service object '{service_name}'"
    logger.info(f"Attempting to fetch details for {action_desc} in VDOM: {FORTIGATE_VDOM}")

    # Path confirmed from user-provided documentation for custom services
    path_parts_for_get = ["cmdb", "firewall_service", "custom"] 
    
    if service_type == "predefined":
        # For predefined services, the exact path might be different.
        # The documentation provided was for '.../firewall.service/custom' and '.../firewall.service/group'.
        # We need to infer or find the path for general predefined services.
        # A common pattern might be just 'firewall_service' itself or a specific 'predefined' sub-object.
        # For now, let's try a plausible guess, but this might need adjustment based on library behavior or further docs.
        path_parts_for_get = ["cmdb", "firewall_service", "custom"] # Fallback to custom if no specific predefined path is known/set
        # A more direct path for predefined might be just ["cmdb", "firewall_service"] then filter by type,
        # or a specific endpoint like ["cmdb", "firewall_service", "predefined_list"] if it exists.
        logger.warning(f"Path for 'predefined' services is assumed to be same as 'custom' for now ([cmdb, firewall_service, custom]) and then filtered. This might be incorrect or inefficient. Consult library docs for optimal predefined service listing.")
        # The FortiGate API often lists predefined services implicitly when you query policies or a general service list.
        # A direct query for *all* predefined services might require a different approach or might not be standard.
    
    api_collection_object = None

    try:
        logger.debug(f"Attempting to resolve API path for GET ({service_type}): fgt_client.{'.'.join(path_parts_for_get)}")
        current_path_obj = fgt_client
        path_so_far = "fgt_client"

        for part in path_parts_for_get:
            if not hasattr(current_path_obj, part):
                logger.error(f"Object at path '{path_so_far}' does not have attribute '{part}'. This is where the API path resolution fails for service object retrieval ({service_type}).")
                logger.error(f"Please check your FortiGate API library documentation. Current path parts: {path_parts_for_get}")
                return {"error": f"FortiGate API client path error for GET ({service_type}): '{path_so_far}' has no attribute '{part}'. Review library docs."}
            current_path_obj = getattr(current_path_obj, part)
            path_so_far += f".{part}"
            logger.debug(f"Resolved path part for GET ({service_type}): {path_so_far}")
        
        api_collection_object = current_path_obj

        if service_name:
            service_data = api_collection_object.get(mkey=service_name)
            if service_data: 
                logger.info(f"Successfully fetched {action_desc}: {service_data}")
                return service_data
            else: 
                # If type is predefined and direct get failed, try listing all (from custom path) and filtering
                if service_type == "predefined":
                    logger.warning(f"Direct get for predefined service '{service_name}' via custom path failed. Attempting to list all custom services and filter by name.")
                    all_custom_services = api_collection_object.get() # Gets all from the 'custom' path
                    if isinstance(all_custom_services, list):
                        # This filtering assumes predefined might appear in custom list or share naming
                        found_service = next((s for s in all_custom_services if isinstance(s, dict) and s.get('name') == service_name), None)
                        if found_service:
                            logger.info(f"Found '{service_name}' by filtering the list from '{'.'.join(path_parts_for_get)}'. It might be a custom object with that name or a predefined one listed there.")
                            return found_service
                    logger.warning(f"Service '{service_name}' (intended as predefined) not found by direct get or by filtering the list from '{'.'.join(path_parts_for_get)}'.")
                
                logger.warning(f"{action_desc} not found in VDOM {FORTIGATE_VDOM} using path fgt_client.{'.'.join(path_parts_for_get)}.")
                return {"error": f"Service object '{service_name}' of type '{service_type}' not found via path fgt_client.{'.'.join(path_parts_for_get)}."}
        else: 
            services_data = api_collection_object.get()
            count = len(services_data) if isinstance(services_data, list) else "an unknown number of"
            logger.info(f"Successfully fetched {count} objects from path fgt_client.{'.'.join(path_parts_for_get)} (intended for {service_type}).")
            logger.debug(f"Fetched data (first 5 if list): {services_data[:5] if isinstance(services_data, list) else services_data}")
            return services_data

    except FortiGateClientError as e:
        logger.error(f"FortiGate client error fetching {action_desc}: {e}", exc_info=True)
        return {"error": f"FortiGate client error: {e}"}
    except AttributeError as e:
        logger.error(f"AttributeError during service object retrieval for '{action_desc}': {e}", exc_info=True)
        logger.error("This likely means the API path in `path_parts_for_get` is incorrect for your library version, or an issue with the resolved API object (e.g., no 'get' method).")
        return {"error": f"AttributeError accessing API client for service retrieval: {e}. Check `path_parts_for_get` and library docs."}
    except Exception as e:
        logger.error(f"An error occurred fetching {action_desc}: {e}", exc_info=True)
        if "404" in str(e).lower() or "not found" in str(e).lower():
             return {"error": f"Service object '{service_name}' not found (API error)."}
        return {"error": f"An unexpected error occurred: {str(e)}"}


# <<< START OF NEW CODE FOR SERVICE GROUPS >>>

def create_service_group(fgt_client, group_config: dict):
    """
    Creates a new firewall service group.

    Args:
        fgt_client: An initialized FortiGateAPI client instance.
        group_config (dict): Configuration for the service group.
                               Required: 'name', 'member' (list of service names).
                               Example: {'name': 'MyWebServices', 'member': [{'name': 'HTTP'}, {'name': 'HTTPS'}]}

    Returns:
        dict: A success or error message dict.
    """
    if "name" not in group_config:
        logger.error("Missing 'name' in service group configuration.")
        return {"error": "Missing 'name' in service group configuration."}
    if "member" not in group_config or not isinstance(group_config["member"], list):
        logger.error("Missing or invalid 'member' list in service group configuration.")
        return {"error": "Missing or invalid 'member' list. It should be a list of service name dicts, e.g., [{'name': 'SERVICE_NAME'}]."}

    group_name = group_config['name']
    logger.info(f"Attempting to create service group '{group_name}' in VDOM: {FORTIGATE_VDOM} with config: {group_config}")
    logger.debug(f"Service group creation payload for '{group_name}': {group_config}")

    try:
        # Based on provided documentation: FortiGateAPI.cmdb.firewall_service.group
        path_parts_for_group_create = ["cmdb", "firewall_service", "group", "create"]

        logger.debug(f"Attempting to resolve API path for CREATE GROUP: fgt_client.{'.'.join(path_parts_for_group_create)}")
        
        current_path_obj = fgt_client
        path_so_far = "fgt_client"
        
        for part in path_parts_for_group_create:
            if not hasattr(current_path_obj, part):
                error_msg = f"FortiGate API client path error for CREATE GROUP: '{path_so_far}' has no attribute '{part}'. Review library docs. Path parts: {path_parts_for_group_create}"
                logger.error(error_msg)
                return {"error": error_msg}
            current_path_obj = getattr(current_path_obj, part)
            path_so_far += f".{part}"
            logger.debug(f"Resolved path part for CREATE GROUP: {path_so_far}")

        api_create_method = current_path_obj # This should be the 'create' method for groups
        api_response = api_create_method(data=group_config)
        
        # Standardized response handling
        if hasattr(api_response, 'status_code') and hasattr(api_response, 'text'):
            status_code = api_response.status_code
            response_text = api_response.text
            response_json = {}
            try:
                response_json = api_response.json()
            except ValueError:
                pass

            if 200 <= status_code < 300:
                if isinstance(response_json, dict) and response_json.get("status") == "error":
                     logger.error(f"FortiGate API error for service group '{group_name}' (HTTP {status_code}): {response_json}")
                     return {"error": f"FortiGate API error for service group '{group_name}'", "details": response_json}
                logger.info(f"Successfully sent create request for service group '{group_name}'. HTTP Status: {status_code}.")
                return {"status": "success", "message": f"Service group '{group_name}' creation request sent.", "details": response_json or response_text}
            else: # Error status code
                if status_code == 500 and "already exist" in response_text.lower():
                    logger.warning(f"Service group '{group_name}' might already exist. FortiGate returned HTTP 500: {response_text}")
                    return {"status": "error", "message": f"Service group '{group_name}' may already exist.", "details": response_json or response_text, "error_code": status_code}
                logger.error(f"FortiGate API error (HTTP {status_code}) for service group '{group_name}': {response_text}")
                return {"error": f"FortiGate API error (HTTP {status_code}) for '{group_name}'", "details": response_json or response_text}
        elif isinstance(api_response, dict):
            logger.info(f"Service group '{group_name}' creation response (dict): {api_response}")
            return api_response
        else: 
            logger.error(f"Service group creation for '{group_name}' returned an unexpected response type: {type(api_response)}, {api_response}")
            return {"error": "Unexpected response type from API library for service group creation.", "details": str(api_response)}

    except FortiGateClientError as e:
        logger.error(f"FortiGate client error creating service group '{group_name}': {e}", exc_info=True)
        return {"error": f"FortiGate client error: {e}"}
    except AttributeError as e:
        logger.error(f"AttributeError during service group creation for '{group_name}': {e}", exc_info=True)
        logger.error("This likely means the API path in `path_parts_for_group_create` is incorrect for your library version.")
        return {"error": f"AttributeError accessing API client for service group creation: {e}. Check `path_parts_for_group_create`."}
    except Exception as e:
        logger.error(f"An API error occurred creating service group '{group_name}': {e}", exc_info=True)
        return {"error": f"An API error occurred for service group '{group_name}'.", "details": str(e)}


def get_service_group(fgt_client, group_name: str = None):
    """
    Retrieves details for all service groups or a specific one.

    Args:
        fgt_client: An initialized FortiGateAPI client instance.
        group_name (str, optional): The name of the service group to retrieve.
                                      If None, retrieves all service groups.
    Returns:
        list or dict: A list of service groups or a single group's details, or an error dict.
    """
    action_desc = "all service groups"
    if group_name:
        action_desc = f"service group '{group_name}'"
    logger.info(f"Attempting to fetch details for {action_desc} in VDOM: {FORTIGATE_VDOM}")

    # Based on provided documentation: FortiGateAPI.cmdb.firewall_service.group
    path_parts_for_group_get = ["cmdb", "firewall_service", "group"]
    
    api_collection_object = None

    try:
        logger.debug(f"Attempting to resolve API path for GET GROUP: fgt_client.{'.'.join(path_parts_for_group_get)}")
        current_path_obj = fgt_client
        path_so_far = "fgt_client"

        for part in path_parts_for_group_get:
            if not hasattr(current_path_obj, part):
                error_msg = f"FortiGate API client path error for GET GROUP: '{path_so_far}' has no attribute '{part}'. Review library docs. Path parts: {path_parts_for_group_get}"
                logger.error(error_msg)
                return {"error": error_msg}
            current_path_obj = getattr(current_path_obj, part)
            path_so_far += f".{part}"
            logger.debug(f"Resolved path part for GET GROUP: {path_so_far}")
        
        api_collection_object = current_path_obj # This should now point to the 'group' collection

        if group_name:
            group_data = api_collection_object.get(mkey=group_name)
            if group_data:
                logger.info(f"Successfully fetched {action_desc}: {group_data}")
                return group_data
            else:
                logger.warning(f"{action_desc} not found in VDOM {FORTIGATE_VDOM}.")
                return {"error": f"Service group '{group_name}' not found."}
        else: # Get all service groups
            groups_data = api_collection_object.get()
            count = len(groups_data) if isinstance(groups_data, list) else "an unknown number of"
            logger.info(f"Successfully fetched {count} service groups.")
            logger.debug(f"Fetched service groups data (first 5 if list): {groups_data[:5] if isinstance(groups_data, list) else groups_data}")
            return groups_data

    except FortiGateClientError as e:
        logger.error(f"FortiGate client error fetching {action_desc}: {e}", exc_info=True)
        return {"error": f"FortiGate client error: {e}"}
    except AttributeError as e:
        logger.error(f"AttributeError during service group retrieval for '{action_desc}': {e}", exc_info=True)
        logger.error("This likely means the API path in `path_parts_for_group_get` is incorrect, or resolved object has no 'get' method.")
        return {"error": f"AttributeError accessing API client for service group retrieval: {e}. Check `path_parts_for_group_get`."}
    except Exception as e:
        logger.error(f"An error occurred fetching {action_desc}: {e}", exc_info=True)
        if "404" in str(e).lower() or "not found" in str(e).lower():
             return {"error": f"Service group '{group_name}' not found (API error)."}
        return {"error": f"An unexpected error occurred: {str(e)}"}

# <<< END OF NEW CODE FOR SERVICE GROUPS >>>


if __name__ == '__main__':
    from .fortigate_client import get_fortigate_client
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger.info("Testing service_objects module...")
    
    client = None
    try:
        client = get_fortigate_client()
        logger.info("Successfully connected to FortiGate.")
    except Exception as e:
        logger.error(f"Failed to get FortiGate client: {e}", exc_info=True)
        exit(1)

    if client:
        # Test 1: Create a custom TCP service object
        tcp_service_config = {
            "name": "MCP-TestTCP-9001",
            "protocol": "TCP/UDP/SCTP", 
            "tcp-portrange": "9001",   
            "comment": "Custom TCP service for MCP autotest"
        }
        logger.info(f"\n--- Test: Creating TCP Service Object '{tcp_service_config['name']}' ---")
        create_tcp_response = create_service_object(client, tcp_service_config)
        logger.info(f"Create TCP service response: {create_tcp_response}")

        created_successfully = isinstance(create_tcp_response, dict) and create_tcp_response.get("status") == "success"
        get_tcp_response = None # Initialize for later checks
        
        # Test 2: Get the created custom TCP service object
        if created_successfully or (isinstance(create_tcp_response, dict) and "already exist" in str(create_tcp_response.get("message","")).lower()):
            logger.info(f"\n--- Test: Getting Custom TCP Service Object '{tcp_service_config['name']}' ---")
            get_tcp_response = get_service_object(client, service_name=tcp_service_config['name'], service_type="custom")
            logger.info(f"Get Custom TCP service response: {get_tcp_response}")
        else:
            logger.warning(f"Skipping get of '{tcp_service_config['name']}' as creation may have failed.")

        # Test 3: Get all custom service objects
        logger.info("\n--- Test: Getting All Custom Service Objects ---")
        get_all_custom_response = get_service_object(client, service_type="custom")
        if isinstance(get_all_custom_response, list):
            logger.info(f"Fetched {len(get_all_custom_response)} custom services. First few: {get_all_custom_response[:3]}")
        elif isinstance(get_all_custom_response, dict) and "error" in get_all_custom_response:
             logger.error(f"Error fetching all custom services: {get_all_custom_response}")
        else:
            logger.info(f"Response for all custom services: {get_all_custom_response}")
        
        # Test 4: Attempt to get a common predefined service (e.g., HTTPS)
        predefined_service_to_get = "HTTPS"
        logger.info(f"\n--- Test: Getting Predefined Service Object '{predefined_service_to_get}' ---")
        # Note: get_service_object with service_type="predefined" might need path adjustment
        get_predefined_response = get_service_object(client, service_name=predefined_service_to_get, service_type="predefined")
        logger.info(f"Get predefined '{predefined_service_to_get}' response: {get_predefined_response}")

        # Test 5: Delete the created custom TCP service object (if created or existed)
        if created_successfully or (get_tcp_response and isinstance(get_tcp_response, dict) and not get_tcp_response.get("error")):
            logger.info(f"\n--- Test: Deleting Custom TCP Service Object '{tcp_service_config['name']}' (Illustrative) ---")
            try:
                path_to_custom_collection_parts = ["cmdb", "firewall_service", "custom"] 
                custom_collection_obj = client
                for part in path_to_custom_collection_parts:
                    if hasattr(custom_collection_obj, part):
                        custom_collection_obj = getattr(custom_collection_obj, part)
                    else:
                        # This should not happen if create/get worked with these parts
                        raise AttributeError(f"Path to custom collection for delete failed at '{part}'")
                # delete_resp = custom_collection_obj.delete(mkey=tcp_service_config['name']) # Actual delete call
                # logger.info(f"Delete TCP service response: {delete_resp}")
                logger.warning(f"Delete for '{tcp_service_config['name']}' is illustrative. Actual delete call is commented out.")
            except Exception as e:
                logger.error(f"Error attempting to delete service '{tcp_service_config['name']}': {e}", exc_info=True)
        else:
            logger.warning(f"Skipping delete of '{tcp_service_config['name']}' as it was not successfully created or fetched.")


        # <<< START OF NEW TESTS FOR SERVICE GROUPS >>>
        logger.info("\n--- Test: Creating Service Group 'MCP-TestGroup' ---")
        group_members = []
        
        # Check if the custom service (MCP-TestTCP-9001) exists to add to group
        # Prefer using the result from get_tcp_response if it was successful
        tcp_service_for_group = None
        if get_tcp_response and isinstance(get_tcp_response, dict) and get_tcp_response.get('name') == tcp_service_config['name']:
            tcp_service_for_group = get_tcp_response
        elif created_successfully: # If created but get_tcp_response is not definitive, assume it might be there
            tcp_service_for_group = {"name": tcp_service_config['name']} # Minimal dict for member list

        if tcp_service_for_group:
             group_members.append({"name": tcp_service_for_group['name']})
        
        # Check if the predefined service (HTTPS) exists to add to group
        predefined_service_for_group = None
        if get_predefined_response and isinstance(get_predefined_response, dict) and get_predefined_response.get('name') == predefined_service_to_get:
            predefined_service_for_group = get_predefined_response
        
        if predefined_service_for_group:
            group_members.append({"name": predefined_service_for_group['name']})
        else: # Add HTTPS as a fallback if not found by get, assuming it typically exists
            if not any(member.get("name") == "HTTPS" for member in group_members): # Avoid duplicates
                logger.info(f"Predefined service '{predefined_service_to_get}' not confirmed, adding 'HTTPS' to group as a fallback.")
                group_members.append({"name": "HTTPS"})

        if not group_members: # Should not happen if HTTPS is added as fallback
            logger.warning("Cannot test group creation meaningfully as no member services are available. Defaulting to [{\"name\": \"ALL\"}].")
            group_members = [{"name": "ALL"}] # A very broad default if others fail

        service_group_config = {
            "name": "MCP-TestGroup",
            "member": group_members,
            "comment": "Custom service group for MCP autotest"
        }
        logger.info(f"Attempting to create group with members: {group_members}")
        create_group_response = create_service_group(client, service_group_config)
        logger.info(f"Create service group response: {create_group_response}")

        group_created_successfully = isinstance(create_group_response, dict) and create_group_response.get("status") == "success"
        get_group_response = None # Initialize for later check

        if group_created_successfully or (isinstance(create_group_response, dict) and "already exist" in str(create_group_response.get("message","")).lower()):
            logger.info(f"\n--- Test: Getting Service Group '{service_group_config['name']}' ---")
            get_group_response = get_service_group(client, group_name=service_group_config['name'])
            logger.info(f"Get service group response: {get_group_response}")

            if get_group_response and isinstance(get_group_response, dict) and not get_group_response.get("error"):
                logger.info(f"\n--- Test: Deleting Service Group '{service_group_config['name']}' (Illustrative) ---")
                try:
                    path_to_group_collection_parts = ["cmdb", "firewall_service", "group"]
                    group_collection_obj = client
                    for part in path_to_group_collection_parts:
                        if hasattr(group_collection_obj, part):
                            group_collection_obj = getattr(group_collection_obj, part)
                        else:
                            raise AttributeError(f"Path to group collection for delete failed at '{part}'")
                    # delete_group_resp = group_collection_obj.delete(mkey=service_group_config['name']) # Actual delete
                    # logger.info(f"Delete service group response: {delete_group_resp}")
                    logger.warning(f"Delete for service group '{service_group_config['name']}' is illustrative. Actual delete call is commented out.")
                except Exception as e:
                    logger.error(f"Error attempting to delete service group '{service_group_config['name']}': {e}", exc_info=True)

        logger.info("\n--- Test: Getting All Service Groups ---")
        get_all_groups_response = get_service_group(client)
        if isinstance(get_all_groups_response, list):
            logger.info(f"Fetched {len(get_all_groups_response)} service groups. First few: {get_all_groups_response[:3]}")
        elif isinstance(get_all_groups_response, dict) and "error" in get_all_groups_response:
            logger.error(f"Error fetching all service groups: {get_all_groups_response}")
        else:
            logger.info(f"Response for all service groups: {get_all_groups_response}")
        # <<< END OF NEW TESTS FOR SERVICE GROUPS >>>

        logger.info("\n--- Service Objects Module Testing Complete ---")

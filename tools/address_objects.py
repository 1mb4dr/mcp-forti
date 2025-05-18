# mcp_fortigate_server/tools/address_objects.py

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

def create_address_object(fgt_client, object_config: dict):
    """
    Creates a new firewall address object (e.g., FQDN, IP range, subnet).
    """
    obj_name = object_config.get('name', 'UnnamedAddressObject')
    obj_type = object_config.get('type', 'UnknownType')

    if "name" not in object_config or "type" not in object_config:
        msg = f"Missing 'name' or 'type' in address object configuration ('{obj_name}')."
        logger.error(msg)
        return {"error": msg}

    validation_error = None
    if obj_type == "fqdn" and "fqdn" not in object_config:
        validation_error = f"Missing 'fqdn' for FQDN address object '{obj_name}'."
    elif obj_type == "iprange" and ("start-ip" not in object_config or "end-ip" not in object_config):
        validation_error = f"Missing 'start-ip' or 'end-ip' for IP range object '{obj_name}'."
    elif obj_type == "ipmask" and "subnet" not in object_config:
         validation_error = f"Missing 'subnet' (e.g., '192.168.1.0 255.255.255.0' or '192.168.1.0/24') for ipmask object '{obj_name}'."
    
    if validation_error:
        logger.error(validation_error)
        return {"error": validation_error}

    logger.info(f"Attempting to create address object '{obj_name}' of type '{obj_type}' in VDOM: {FORTIGATE_VDOM}")
    logger.debug(f"Address object creation payload for '{obj_name}': {object_config}")

    try:
        api_response = fgt_client.cmdb.firewall.address.create(data=object_config)
        
        status_code = getattr(api_response, 'status_code', None)
        response_data = api_response
        text_content_for_check = ""

        if hasattr(api_response, 'text'):
            text_content_for_check = api_response.text
        if hasattr(api_response, 'json'):
            try:
                response_data = api_response.json()
                # If json parsing works, use it also for string checks if it's a dict
                if isinstance(response_data, dict):
                    text_content_for_check = str(response_data)
            except ValueError:
                # response_data remains api_response.text or str(api_response)
                response_data = text_content_for_check if text_content_for_check else str(api_response)
        
        logger.debug(f"API response for '{obj_name}': HTTP {status_code if status_code else 'N/A'}, Data: {response_data}")

        if status_code and 200 <= status_code < 300:
            if isinstance(response_data, dict) and response_data.get("status") == "error":
                error_detail = _parse_api_error_details(response_data)
                logger.error(f"FortiGate API error for '{obj_name}' (HTTP {status_code}): {error_detail}")
                return {"error": f"FortiGate API error for '{obj_name}'", "details": response_data}
            
            logger.info(f"Successfully sent create request for address object '{obj_name}'. HTTP Status: {status_code}.")
            return {"status": "success", "message": f"Address object '{obj_name}' creation request sent.", "details": response_data}
        
        elif status_code == 500: # Specific handling for HTTP 500
            str_response_lower = text_content_for_check.lower()
            if "already exist" in str_response_lower or "duplicate entry" in str_response_lower or "-5: Object already_exists" in str_response_lower : # -5 is common for already exists
                logger.warning(f"Address object '{obj_name}' might already exist. FortiGate returned HTTP 500. Details: {response_data}")
                return {"status": "warning", "message": f"Address object '{obj_name}' might already exist (HTTP 500).", "details": response_data}
            error_detail = _parse_api_error_details(response_data)
            logger.error(f"FortiGate API error HTTP 500 during address object '{obj_name}' creation: {error_detail}")
            return {"error": f"FortiGate API error (HTTP 500) for '{obj_name}'", "details": response_data}

        elif status_code: # Other non-2xx, non-500 errors
            error_detail = _parse_api_error_details(response_data)
            logger.error(f"FortiGate API error (HTTP {status_code}) for address object '{obj_name}': {error_detail}")
            return {"error": f"FortiGate API error (HTTP {status_code}) for '{obj_name}'", "details": response_data}
        
        elif isinstance(api_response, dict): # Fallback for direct dict responses
            if api_response.get("status") == "success":
                 logger.info(f"Address object '{obj_name}' creation successful (dict response).")
                 return {"status": "success", "message": f"Address object '{obj_name}' created successfully.", "details": api_response}
            else: # Includes cases like "status": "error" or http_status being non-200 in the dict
                 error_detail = _parse_api_error_details(api_response)
                 if "already exist" in error_detail.lower() or "duplicate entry" in error_detail.lower() or "-5: Object already_exists" in error_detail:
                     logger.warning(f"Address object '{obj_name}' might already exist (parsed dict). Details: {api_response}")
                     return {"status": "warning", "message": f"Address object '{obj_name}' might already exist (parsed dict).", "details": api_response}
                 logger.error(f"Address object '{obj_name}' creation failed (dict response): {error_detail}")
                 return {"error": f"Address object creation failed for '{obj_name}' (dict response)", "details": api_response}
        else:
            logger.error(f"Address object creation for '{obj_name}' returned an unexpected response type: {type(api_response)}, {api_response}")
            return {"error": "Unexpected response type from API library.", "details": str(api_response)}

    except Exception as e:
        logger.error(f"API exception creating address object '{obj_name}': {e}", exc_info=True)
        error_details_str = str(e)
        if hasattr(e, 'response'):
            error_details_str = _parse_api_error_details(e.response)
        
        # Check for common CLI errors if available in the response text
        if "Command fail" in error_details_str or "entry not found" in error_details_str.lower(): # "entry not found" might imply a referenced object is missing
             return {"error": f"FortiGate CLI error for '{obj_name}'. Check config or if it already exists.", "details": error_details_str}
        return {"error": f"An API exception occurred for '{obj_name}'.", "details": error_details_str}


def get_address_object(fgt_client, object_name: str = None):
    """
    Retrieves details for all address objects or a specific address object.
    """
    action_desc = f"address object '{object_name}'" if object_name else "all address objects"
    logger.info(f"Attempting to fetch details for {action_desc} in VDOM: {FORTIGATE_VDOM}")

    try:
        if object_name:
            addr_object_data = fgt_client.cmdb.firewall.address.get(mkey=object_name)
            if addr_object_data:
                logger.info(f"Successfully fetched {action_desc}.")
                logger.debug(f"Address object '{object_name}' data: {addr_object_data}")
                return addr_object_data
            else:
                logger.warning(f"{action_desc} not found in VDOM {FORTIGATE_VDOM} (empty response).")
                return {"error": f"Address object '{object_name}' not found (empty API response)."}
        else:
            addr_objects_data = fgt_client.cmdb.firewall.address.get()
            logger.info(f"Successfully fetched {len(addr_objects_data) if isinstance(addr_objects_data, list) else 'unknown number of'} address objects.")
            return addr_objects_data
    except Exception as e:
        logger.error(f"Error fetching {action_desc}: {e}", exc_info=True)
        if object_name and ("404" in str(e) or "not found" in str(e).lower() or "entry not found" in str(e).lower()):
             return {"error": f"Address object '{object_name}' not found (API error)."}
        return {"error": f"An unexpected error occurred while fetching {action_desc}: {str(e)}"}

if __name__ == '__main__':
    from fortigate_client import get_fortigate_client, FortiGateClientError
    logging.basicConfig(level=logging.DEBUG)
    logger.info("Testing address_objects module...")

    client = None
    try:
        client = get_fortigate_client()
        if client:
            logger.info("Attempting explicit login for address_objects test...")
            client.login()
            logger.info("Login successful for address_objects test.")

            # Test FQDN
            fqdn_name = "test-fqdn-mcp-py"
            fqdn_config = {
                "name": fqdn_name,
                "type": "fqdn",
                "fqdn": "docs.fortinet.com",
                "comment": "Created by MCP tool Python test"
            }
            print(f"\n--- Test: Creating FQDN Address Object '{fqdn_name}' ---")
            # create_response = create_address_object(client, fqdn_config)
            # logger.info(f"Create FQDN response: {create_response}")
            # if create_response and create_response.get("status") in ["success", "warning"]: # warning if already exists
            #     print(f"\n--- Test: Getting FQDN Address Object '{fqdn_name}' ---")
            #     get_one_response = get_address_object(client, object_name=fqdn_name)
            #     logger.info(f"Get FQDN response: {get_one_response}")
            #     # print(f"\n--- Test: Deleting FQDN Address Object '{fqdn_name}' (Illustrative) ---")
            #     # try:
            #     #     # client.cmdb.firewall.address.delete(mkey=fqdn_name)
            #     #     logger.info(f"Deletion request for '{fqdn_name}' submitted (if uncommented).")
            #     # except Exception as e:
            #     #     logger.error(f"Error deleting address object '{fqdn_name}': {e}")
            #     pass # Placeholder
            # else:
            #     logger.warning(f"Skipping get/delete for FQDN '{fqdn_name}' as creation might have failed or was commented out.")
            
            print("\n--- Test: Getting All Address Objects ---")
            get_all_response = get_address_object(client)
            if isinstance(get_all_response, dict) and "error" in get_all_response:
                 logger.error(f"Error fetching all address objects: {get_all_response['error']}")
            elif isinstance(get_all_response, list):
                logger.info(f"Fetched {len(get_all_response)} address objects. First few: {get_all_response[:2]}")
            else:
                logger.info(f"Response for all address objects (unexpected type): {get_all_response}")

            # Example for IP Range (Illustrative - uncomment and adjust to test)
            iprange_name = "test-mcp-iprange-py"
            iprange_config = { "name": iprange_name, "type": "iprange", "start-ip": "172.16.200.1", "end-ip": "172.16.200.10", "comment": "MCP test"}
            print(f"\n--- Test: Creating IP Range Object '{iprange_name}' (Illustrative) ---")
            # create_iprange_response = create_address_object(client, iprange_config)
            # logger.info(f"Create IP range response: {create_iprange_response}")
            # if create_iprange_response and create_iprange_response.get("status") in ["success", "warning"]:
            #    logger.info(f"--- Test: Deleting IP Range Object '{iprange_name}' (Illustrative) ---")
            #    # client.cmdb.firewall.address.delete(mkey=iprange_name)
            #    pass

            # Example for Subnet/IPMask (Illustrative - uncomment and adjust to test)
            subnet_name = "test-mcp-subnet-py"
            subnet_config = { "name": subnet_name, "type": "ipmask", "subnet": "192.168.177.0 255.255.255.0", "comment": "MCP test"}
            print(f"\n--- Test: Creating Subnet Object '{subnet_name}' (Illustrative) ---")
            # create_subnet_response = create_address_object(client, subnet_config)
            # logger.info(f"Create subnet response: {create_subnet_response}")
            # if create_subnet_response and create_subnet_response.get("status") in ["success", "warning"]:
            #    logger.info(f"--- Test: Deleting Subnet Object '{subnet_name}' (Illustrative) ---")
            #    # client.cmdb.firewall.address.delete(mkey=subnet_name)
            #    pass
        else:
            logger.error("Could not get FortiGate client.")
    except FortiGateClientError as e:
        logger.error(f"Client setup error during address_objects test: {e}")
    except Exception as e:
        logger.error(f"General error in address_objects test (e.g. login failed): {e}", exc_info=True)

# mcp_fortigate_server/tools/address_objects.py

import logging
from .fortigate_client import FortiGateClientError, FORTIGATE_VDOM

# Configure logging
logger = logging.getLogger(__name__)

def create_address_object(fgt_client, object_config: dict):
    """
    Creates a new firewall address object (e.g., FQDN, IP range, subnet).

    Args:
        fgt_client: An initialized FortiGateAPI client instance.
        object_config (dict): Configuration for the address object.
                              Required fields: 'name' (a unique identifier), 'type'.
                              For FQDN: {'name': 'example-fqdn-site', 'type': 'fqdn', 'fqdn': 'example.com', 'comment': 'Optional'}
                              For IP Range: {'name': 'example-iprange', 'type': 'iprange', 'start-ip': '1.1.1.1', 'end-ip': '1.1.1.10'}
                              For Subnet: {'name': 'Prod_Network_1', 'type': 'ipmask', 'subnet': '192.168.1.0 255.255.255.0'}
                                          OR {'name': 'Prod_Network_1_CIDR', 'type': 'ipmask', 'subnet': '192.168.1.0/24'}
                                          (Note: FortiOS API usually prefers space-separated mask, but some library versions might handle CIDR)
    Returns:
        dict: A success or error message dict.
    """
    if "name" not in object_config:
        logger.error("Missing 'name' (unique identifier) in address object configuration.")
        return {"error": "Missing 'name' (unique identifier) in address object configuration."}
    if "type" not in object_config:
        logger.error(f"Missing 'type' in address object configuration for '{object_config.get('name')}'.")
        return {"error": f"Missing 'type' in address object configuration for '{object_config.get('name')}'."}

    obj_name = object_config['name']
    obj_type = object_config['type']
    
    # Validate specific fields for common types
    if obj_type == "fqdn" and "fqdn" not in object_config:
        return {"error": f"Missing 'fqdn' for FQDN address object '{obj_name}'."}
    if obj_type == "iprange" and ("start-ip" not in object_config or "end-ip" not in object_config):
        return {"error": f"Missing 'start-ip' or 'end-ip' for IP range object '{obj_name}'."}
    if obj_type == "ipmask" and "subnet" not in object_config:
         return {"error": f"Missing 'subnet' (e.g., '192.168.1.0 255.255.255.0' or '192.168.1.0/24') for ipmask object '{obj_name}'."}

    logger.info(f"Attempting to create address object '{obj_name}' of type '{obj_type}' in VDOM: {FORTIGATE_VDOM}")
    logger.debug(f"Address object creation payload for '{obj_name}': {object_config}")

    try:
        api_response = fgt_client.cmdb.firewall.address.create(data=object_config)

        # It seems the API returns <Response [500]> even on "attempted" or already exists cases sometimes.
        # Proper check would be a GET before CREATE or more specific error parsing if library allows.
        if hasattr(api_response, 'status_code'): # requests.Response like object
            status_code = api_response.status_code
            response_text = api_response.text
            try:
                parsed_json = api_response.json() # Try to parse as JSON
                response_text = parsed_json # Use parsed JSON if successful
            except ValueError:
                pass # Keep as text if not JSON

            logger.debug(f"API response for '{obj_name}': HTTP {status_code}, Data: {response_text}")

            if 200 <= status_code < 300:
                 #FortiOS sometimes returns 200 OK even if there's a CLI error message within JSON
                if isinstance(response_text, dict) and response_text.get("status") == "error":
                    logger.error(f"FortiGate API indicated an error for '{obj_name}' despite HTTP {status_code}: {response_text}")
                    return {"error": f"FortiGate API error for '{obj_name}'", "details": response_text}
                
                logger.info(f"Successfully sent create request for address object '{obj_name}'. HTTP Status: {status_code}. Details: {response_text}")
                return {
                    "status": "success", # Or "attempted" if 500 errors persist for existing objects
                    "message": f"Address object '{obj_name}' creation request sent. Review FortiGate. HTTP Status: {status_code}",
                    "details": response_text
                }
            # Handling the 500 errors we've seen:
            elif status_code == 500:
                # Check for common "already exists" or "entry not found" patterns if possible
                # This part is highly dependent on the actual text response from FortiOS for these cases
                str_response = str(response_text).lower()
                if "already exist" in str_response or "duplicate entry" in str_response:
                    logger.warning(f"Address object '{obj_name}' might already exist. FortiGate returned HTTP 500. Details: {response_text}")
                    return {"status": "warning", "message": f"Address object '{obj_name}' might already exist (HTTP 500).", "details": response_text}
                logger.error(f"FortiGate API error HTTP {status_code} during address object '{obj_name}' creation: {response_text}")
                return {"error": f"FortiGate API error (HTTP {status_code}) for '{obj_name}'", "details": response_text}
            else: # Other non-2xx errors
                logger.error(f"FortiGate API error HTTP {status_code} during address object '{obj_name}' creation: {response_text}")
                return {"error": f"FortiGate API error (HTTP {status_code}) for '{obj_name}'", "details": response_text}

        # Fallback for older fortigate-api-py versions or unexpected non-Response objects
        elif isinstance(api_response, dict): # If it's already a dict (some library versions might do this)
            logger.debug(f"API response (dict) for '{obj_name}': {api_response}")
            if api_response.get("status") == "success" and api_response.get("http_status") == 200:
                logger.info(f"Successfully created address object '{obj_name}'. Response: {api_response}")
                return {"status": "success", "message": f"Address object '{obj_name}' created successfully.", "details": api_response}
            else:
                logger.error(f"FortiGate API error (parsed dict) during address object '{obj_name}' creation: {api_response}")
                return {"error": f"FortiGate API error creating '{obj_name}' (parsed dict)", "details": api_response}
        else:
            logger.warning(f"Address object creation for '{obj_name}' returned an unexpected response type: {type(api_response)}. Raw: {api_response}")
            return {
                "status": "unknown",
                "message": f"Address object '{obj_name}' creation attempted. Review FortiGate. Unexpected response type. Raw: {str(api_response)}",
                "details": str(api_response)
            }

    except FortiGateClientError as e:
        logger.error(f"FortiGate client error creating address object '{obj_name}': {e}")
        return {"error": f"FortiGate client error: {e}"}
    except Exception as e:
        logger.error(f"An API error occurred creating address object '{obj_name}': {e}", exc_info=True)
        error_details = str(e)
        if hasattr(e, 'response') and e.response is not None and hasattr(e.response, 'text'):
            try:
                error_details = e.response.json()
            except ValueError:
                error_details = e.response.text
        elif hasattr(e, 'message'): # some libs use 'message'
             error_details = e.message

        # Check for common CLI errors if available in the response
        if "Command fail" in str(error_details) or "entry not found" in str(error_details).lower() :
             return {"error": f"FortiGate CLI error for '{obj_name}'. Check if the object already exists or config is invalid.", "details": error_details}

        return {"error": f"An API error occurred for '{obj_name}'.", "details": error_details}


def get_address_object(fgt_client, object_name: str = None):
    """
    Retrieves details for all address objects or a specific address object.

    Args:
        fgt_client: An initialized FortiGateAPI client instance.
        object_name (str, optional): The name of the address object to retrieve.
                                     If None, retrieves all address objects.

    Returns:
        list or dict: A list of address objects if no name is specified,
                      or a dict with a single object's details if a name is provided.
                      Returns an error message dict on failure.
    """
    action_desc = "all address objects"
    if object_name:
        action_desc = f"address object '{object_name}'"
    logger.info(f"Attempting to fetch details for {action_desc} in VDOM: {FORTIGATE_VDOM}")

    try:
        if object_name:
            addr_object_data = fgt_client.cmdb.firewall.address.get(mkey=object_name)
            if addr_object_data:
                logger.info(f"Successfully fetched {action_desc}: {addr_object_data}")
                return addr_object_data
            else:
                logger.warning(f"{action_desc} not found in VDOM {FORTIGATE_VDOM}.")
                return {"error": f"Address object '{object_name}' not found."}
        else:
            addr_objects_data = fgt_client.cmdb.firewall.address.get()
            logger.info(f"Successfully fetched {len(addr_objects_data)} address objects.")
            return addr_objects_data
    except FortiGateClientError as e:
        logger.error(f"FortiGate client error fetching {action_desc}: {e}")
        return {"error": f"FortiGate client error: {e}"}
    except Exception as e:
        logger.error(f"An error occurred fetching {action_desc}: {e}", exc_info=True)
        if "404" in str(e) or "not found" in str(e).lower():
             return {"error": f"Address object '{object_name}' not found (API error)."}
        return {"error": f"An unexpected error occurred: {str(e)}"}

if __name__ == '__main__':
    # Example Usage (requires fortigate_client.py and .env setup)
    from .fortigate_client import get_fortigate_client
    logging.basicConfig(level=logging.DEBUG)
    logger.info("Testing address_objects module...")

    client = None
    try:
        client = get_fortigate_client()
    except FortiGateClientError as e:
        logger.error(f"Failed to get FortiGate client: {e}")
        exit()
    except Exception as e:
        logger.error(f"Unexpected error getting client: {e}")
        exit()

    if client:
        # Test creating an FQDN address object
        fqdn_config = {
            "name": "test-fqdn-fortinet-docs", # Descriptive name
            "type": "fqdn",
            "fqdn": "docs.fortinet.com",
            "comment": "Created by MCP tool test"
        }
        logger.info(f"--- Test: Creating FQDN Address Object '{fqdn_config['name']}' ---")
        # create_response = create_address_object(client, fqdn_config) # Uncomment to test creation
        # logger.info(f"Create response: {create_response}")

        # Test retrieving the created object (if creation was successful)
        # if create_response and create_response.get("status") == "success":
        #     logger.info(f"--- Test: Getting FQDN Address Object '{fqdn_config['name']}' ---")
        #     get_one_response = get_address_object(client, object_name=fqdn_config['name'])
        #     logger.info(f"Get one response: {get_one_response}")

            # Test deleting the created object
            # logger.info(f"--- Test: Deleting FQDN Address Object '{fqdn_config['name']}' ---")
            # try:
            #     delete_response = client.cmdb.firewall.address.delete(mkey=fqdn_config['name'])
            #     logger.info(f"Delete response: {delete_response}")
            # except Exception as e:
            #     logger.error(f"Error deleting address object '{fqdn_config['name']}': {e}")
        # else:
        #     logger.warning("Skipping get/delete tests as creation might have failed or was commented out.")
        
        logger.info("--- Test: Getting All Address Objects ---")
        get_all_response = get_address_object(client)
        if isinstance(get_all_response, list):
            logger.info(f"Fetched {len(get_all_response)} address objects. First few: {get_all_response[:2]}")
        else:
            logger.error(f"Error fetching all address objects: {get_all_response}")

        # Example for IP Range (uncomment to test)
        iprange_config = {
            "name": "test-mcp-iprange", # Descriptive name
            "type": "iprange",
            "start-ip": "172.16.100.1",
            "end-ip": "172.16.100.10",
            "comment": "Created by MCP tool test for iprange"
        }
        logger.info(f"--- Test: Creating IP Range Address Object '{iprange_config['name']}' ---")
        create_iprange_response = create_address_object(client, iprange_config)
        logger.info(f"Create IP range response: {create_iprange_response}")
        if create_iprange_response and create_iprange_response.get("status") == "success":
           logger.info(f"--- Test: Deleting IP Range Address Object '{iprange_config['name']}' ---")
           client.cmdb.firewall.address.delete(mkey=iprange_config['name'])


        # Example for Subnet/IPMask (uncomment to test)
        subnet_config = {
            "name": "test-mcp-subnet", # Descriptive name
            "type": "ipmask",
            "subnet": "192.168.77.0 255.255.255.0", 
            "comment": "Created by MCP tool test for subnet"
        }
        logger.info(f"--- Test: Creating Subnet Address Object '{subnet_config['name']}' ---")
        create_subnet_response = create_address_object(client, subnet_config)
        logger.info(f"Create subnet response: {create_subnet_response}")
        if create_subnet_response and create_subnet_response.get("status") == "success":
           logger.info(f"--- Test: Deleting Subnet Address Object '{subnet_config['name']}' ---")
           client.cmdb.firewall.address.delete(mkey=subnet_config['name'])
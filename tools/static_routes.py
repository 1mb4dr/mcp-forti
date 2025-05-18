# mcp_fortigate_server/tools/static_routes.py

import logging
from .fortigate_client import FortiGateClientError, FORTIGATE_VDOM

# Configure logging
logger = logging.getLogger(__name__)

def get_static_routes(fgt_client, route_seq_num: int = None):
    """
    Retrieves all static routes or a specific static route by its sequence number.
    The primary key (mkey) for static routes is 'seq-num'.

    Args:
        fgt_client: An initialized FortiGateAPI client instance.
        route_seq_num (int, optional): The sequence number ('seq-num') of the static route.
                                     If None, retrieves all static routes.

    Returns:
        list or dict: A list of static routes or details of a specific route.
                      Returns an error message dict on failure.
    """
    action_desc = "all static routes"
    if route_seq_num is not None: 
        action_desc = f"static route with seq-num '{route_seq_num}'"
    logger.info(f"Attempting to fetch {action_desc} in VDOM: {FORTIGATE_VDOM}")

    try:
        if route_seq_num is not None:
            route_data = fgt_client.cmdb.router.static.get(mkey=route_seq_num)
            if route_data: 
                logger.info(f"Successfully fetched static route seq-num {route_seq_num}: {route_data}")
                return route_data
            else:
                logger.warning(f"Static route with seq-num '{route_seq_num}' not found in VDOM {FORTIGATE_VDOM}.")
                return {"error": f"Static route with seq-num '{route_seq_num}' not found."}
        else:
            routes_data = fgt_client.cmdb.router.static.get()
            logger.info(f"Successfully fetched {len(routes_data)} static routes.")
            return routes_data
    except FortiGateClientError as e:
        logger.error(f"FortiGate client error fetching {action_desc}: {e}")
        return {"error": f"FortiGate client error: {e}"}
    except Exception as e:
        logger.error(f"An error occurred fetching {action_desc}: {e}", exc_info=True)
        if route_seq_num is not None and ("404" in str(e) or "not found" in str(e).lower()):
             return {"error": f"Static route with seq-num '{route_seq_num}' not found (API error)."}
        return {"error": f"An unexpected error occurred: {str(e)}"}


def create_static_route(fgt_client, route_config: dict):
    """
    Creates a new static route.
    """
    route_dst_for_log = route_config.get('dst', 'N/A')
    logger.info(f"Attempting to create static route for dst '{route_dst_for_log}' with config: {route_config} in VDOM: {FORTIGATE_VDOM}")

    required_fields = ["dst", "gateway", "device"] 
    for field in required_fields:
        if field not in route_config:
            msg = f"Missing required field '{field}' in static route configuration."
            logger.error(msg)
            return {"error": msg}
    
    route_config.setdefault("status", "enable") 

    try:
        api_response_object = fgt_client.cmdb.router.static.create(data=route_config)
        
        if hasattr(api_response_object, 'status_code') and hasattr(api_response_object, 'text'):
            if 200 <= api_response_object.status_code < 300: 
                try:
                    parsed_response = api_response_object.json()
                    mkey = parsed_response.get("mkey", parsed_response.get("seq-num")) 
                    logger.info(f"Successfully created static route (HTTP {api_response_object.status_code}). Seq-num: {mkey}. Dst: {route_dst_for_log}")
                    return {"status": "success", "message": "Static route created successfully.", "seq-num": mkey, "details": parsed_response}
                except ValueError: 
                    logger.info(f"Successfully created static route (HTTP {api_response_object.status_code}), but response was not JSON. Dst: {route_dst_for_log}")
                    return {"status": "success", "message": "Static route created successfully (non-JSON response).", "details": api_response_object.text}
            else: 
                logger.error(f"FortiGate API error during static route creation for dst '{route_dst_for_log}'. HTTP Status: {api_response_object.status_code}. Response: {api_response_object.text}")
                return {"error": f"FortiGate API error (HTTP {api_response_object.status_code}) for dst '{route_dst_for_log}'", "details": api_response_object.text}

        elif isinstance(api_response_object, dict):
            if api_response_object.get("http_status") == 200 and api_response_object.get("status") == "success":
                new_route_seq_num = api_response_object.get("mkey") 
                logger.info(f"Successfully created static route. New seq-num: {new_route_seq_num}. Dst: {route_dst_for_log}")
                return {"status": "success", "message": "Static route created successfully.", "seq-num": new_route_seq_num, "details": api_response_object}
            elif api_response_object.get("status") == "error" or api_response_object.get("http_status", 0) >= 400 : 
                logger.error(f"FortiGate API error (parsed dict) during static route creation for dst '{route_dst_for_log}': {api_response_object}")
                return {"error": f"FortiGate API error (parsed dict) for dst '{route_dst_for_log}'", "details": api_response_object}
            else: 
                logger.warning(f"Static route creation for dst '{route_dst_for_log}' returned an ambiguous dictionary response: {api_response_object}.")
                return {"status": "unknown", "message": f"Static route creation for dst '{route_dst_for_log}' returned an ambiguous response. Review FortiGate.", "details": api_response_object}
        
        else: 
            logger.error(f"Static route creation for dst '{route_dst_for_log}' returned an unexpected response type: {type(api_response_object)}, {api_response_object}")
            return {"error": "Unexpected response type from API library.", "details": str(api_response_object)}

    except Exception as e: 
        logger.error(f"An API exception occurred creating static route for dst '{route_dst_for_log}': {e}", exc_info=True)
        error_details = str(e)
        if hasattr(e, 'response') and e.response is not None and hasattr(e.response, 'text'):
            try:
                error_details = e.response.json()
            except ValueError: 
                error_details = e.response.text
        elif hasattr(e, 'message'): 
             error_details = e.message
        return {"error": f"An API exception occurred during static route for dst '{route_dst_for_log}' creation.", "details": error_details}

if __name__ == '__main__':
    from .fortigate_client import get_fortigate_client 
    logging.basicConfig(level=logging.INFO) 
    try:
        logger.info("Testing static_routes module...")
        client = get_fortigate_client()
        if client:
            print("\n--- Testing Get All Static Routes ---")
            all_routes = get_static_routes(client)
            if isinstance(all_routes, dict) and "error" in all_routes:
                logger.error(f"Error getting all static routes: {all_routes['error']}")
            else:
                logger.info(f"Fetched {len(all_routes)} static routes. First few: {all_routes[:2]}")

            test_route_seq_num = 1 
            print(f"\n--- Testing Get Static Route (seq-num {test_route_seq_num}) ---")
            specific_route = get_static_routes(client, route_seq_num=test_route_seq_num)
            if isinstance(specific_route, dict) and "error" in specific_route:
                logger.error(f"Error getting static route {test_route_seq_num}: {specific_route['error']}")
            else:
                logger.info(f"Details for static route {test_route_seq_num}: {specific_route}")

            print("\n--- Testing Create Static Route ---")
            egress_device_for_route = "port3" 
            gateway_ip_for_route = "192.168.3.254" 
            
            new_route_config = {
                "dst": "10.201.0.0 255.255.0.0", 
                "gateway": gateway_ip_for_route,
                "device": egress_device_for_route,
                "status": "enable",
                "comment": "Static route created by MCP tool test"
            }
            logger.info(f"Create static route test for dst '{new_route_config['dst']}' is commented out. Uncomment to run.")
        else:
            logger.error("Could not get FortiGate client for testing static_routes.")
    except FortiGateClientError as e:
        logger.error(f"Client setup error during static_routes test: {e}")
    except Exception as e:
        logger.error(f"General error in static_routes test: {e}", exc_info=True)
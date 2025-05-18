# mcp_fortigate_server/tools/static_routes.py

import logging
from .fortigate_client import FortiGateClientError, FORTIGATE_VDOM
# Re-using the helper from policies or define locally if preferred
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

def get_static_routes(fgt_client, route_seq_num: int = None):
    """
    Retrieves all static routes or a specific static route by its sequence number.
    """
    action_desc = f"static route with seq-num '{route_seq_num}'" if route_seq_num is not None else "all static routes"
    logger.info(f"Attempting to fetch {action_desc} in VDOM: {FORTIGATE_VDOM}")

    try:
        if route_seq_num is not None:
            route_data = fgt_client.cmdb.router.static.get(mkey=route_seq_num)
            if route_data:
                logger.info(f"Successfully fetched {action_desc}.")
                logger.debug(f"Static route seq-num {route_seq_num} data: {route_data}")
                return route_data
            else:
                logger.warning(f"Static route with seq-num '{route_seq_num}' not found in VDOM {FORTIGATE_VDOM} (empty response).")
                return {"error": f"Static route with seq-num '{route_seq_num}' not found (empty API response)."}
        else:
            routes_data = fgt_client.cmdb.router.static.get()
            logger.info(f"Successfully fetched {len(routes_data) if isinstance(routes_data, list) else 'unknown number of'} static routes.")
            return routes_data
    except Exception as e:
        logger.error(f"Error fetching {action_desc}: {e}", exc_info=True)
        if route_seq_num is not None and ("404" in str(e) or "not found" in str(e).lower() or "entry not found" in str(e).lower()):
             return {"error": f"Static route with seq-num '{route_seq_num}' not found (API error)."}
        return {"error": f"An unexpected error occurred while fetching {action_desc}: {str(e)}"}


def create_static_route(fgt_client, route_config: dict):
    """
    Creates a new static route.
    """
    route_dst_for_log = route_config.get('dst', 'N/A')
    logger.info(f"Attempting to create static route for dst '{route_dst_for_log}' in VDOM: {FORTIGATE_VDOM}")
    logger.debug(f"Static route creation payload for dst '{route_dst_for_log}': {route_config}")

    required_fields = ["dst", "gateway", "device"]
    for field in required_fields:
        if field not in route_config:
            msg = f"Missing required field '{field}' in static route configuration for dst '{route_dst_for_log}'."
            logger.error(msg)
            return {"error": msg}
    
    route_config.setdefault("status", "enable")

    try:
        api_response = fgt_client.cmdb.router.static.create(data=route_config)
        
        status_code = getattr(api_response, 'status_code', None)
        response_data = api_response
        if hasattr(api_response, 'json'):
            try:
                response_data = api_response.json()
            except ValueError:
                response_data = getattr(api_response, 'text', str(api_response))
        
        logger.debug(f"API response for static route dst '{route_dst_for_log}': HTTP {status_code if status_code else 'N/A'}, Data: {response_data}")

        if status_code and 200 <= status_code < 300:
            if isinstance(response_data, dict) and response_data.get("status") == "error":
                error_detail = _parse_api_error_details(response_data)
                logger.error(f"FortiGate API error for static route dst '{route_dst_for_log}' (HTTP {status_code}): {error_detail}")
                return {"error": f"FortiGate API error for dst '{route_dst_for_log}'", "details": response_data}

            mkey = response_data.get("mkey", response_data.get("seq-num")) if isinstance(response_data, dict) else None
            logger.info(f"Successfully created static route (HTTP {status_code}). Seq-num: {mkey if mkey else 'N/A'}. Dst: {route_dst_for_log}")
            return {"status": "success", "message": "Static route created successfully.", "seq-num": mkey, "details": response_data}
        elif status_code: # Error HTTP status code
            error_detail = _parse_api_error_details(response_data)
            logger.error(f"FortiGate API error (HTTP {status_code}) for static route dst '{route_dst_for_log}': {error_detail}")
            return {"error": f"FortiGate API error (HTTP {status_code}) for dst '{route_dst_for_log}'", "details": response_data}
        elif isinstance(api_response, dict): # Fallback for direct dict responses
            if api_response.get("status") == "success":
                 mkey = api_response.get("mkey", api_response.get("seq-num"))
                 logger.info(f"Static route for dst '{route_dst_for_log}' creation successful (dict response). Seq-num: {mkey if mkey else 'N/A'}")
                 return {"status": "success", "message": "Static route created successfully.", "seq-num": mkey, "details": api_response}
            else:
                 error_detail = _parse_api_error_details(api_response)
                 logger.error(f"Static route for dst '{route_dst_for_log}' creation failed (dict response): {error_detail}")
                 return {"error": f"Static route creation for dst '{route_dst_for_log}' failed (dict response)", "details": api_response}
        else:
            logger.error(f"Static route creation for dst '{route_dst_for_log}' returned an unexpected response type: {type(api_response)}, {api_response}")
            return {"error": "Unexpected response type from API library.", "details": str(api_response)}

    except Exception as e:
        logger.error(f"API exception creating static route for dst '{route_dst_for_log}': {e}", exc_info=True)
        error_details = str(e)
        if hasattr(e, 'response'):
            error_details = _parse_api_error_details(e.response)
        return {"error": f"API exception during static route creation for dst '{route_dst_for_log}'.", "details": error_details}

if __name__ == '__main__':
    from fortigate_client import get_fortigate_client, FortiGateClientError
    logging.basicConfig(level=logging.DEBUG)
    logger.info("Testing static_routes module...")
    client = None
    try:
        client = get_fortigate_client()
        if client:
            logger.info("Attempting explicit login for static_routes test...")
            client.login()
            logger.info("Login successful for static_routes test.")

            print("\n--- Testing Get All Static Routes ---")
            all_routes = get_static_routes(client)
            if isinstance(all_routes, dict) and "error" in all_routes:
                logger.error(f"Error getting all static routes: {all_routes['error']}")
            else:
                logger.info(f"Fetched {len(all_routes) if isinstance(all_routes, list) else 'N/A'} static routes. First few: {all_routes[:2] if isinstance(all_routes, list) else 'N/A'}")

            # Replace with a seq-num that might exist, or expect an error if it doesn't
            test_route_seq_num = 1
            print(f"\n--- Testing Get Static Route (seq-num {test_route_seq_num}) ---")
            specific_route = get_static_routes(client, route_seq_num=test_route_seq_num)
            if isinstance(specific_route, dict) and "error" in specific_route:
                logger.error(f"Error getting static route {test_route_seq_num}: {specific_route['error']}")
            else:
                logger.info(f"Details for static route {test_route_seq_num}: {specific_route}")

            print("\n--- Testing Create Static Route (Example) ---")
            # Ensure 'port3' (or your chosen egress_device_for_route) exists and gateway is valid
            egress_device_for_route = "port1" # Example, change to a valid interface
            gateway_ip_for_route = "192.168.1.254"  # Example, change to a valid gateway
            
            new_route_config = {
                "dst": "10.250.0.0 255.255.0.0", # Example destination
                "gateway": gateway_ip_for_route,
                "device": egress_device_for_route,
                "status": "enable", # 'enable' or 'disable'
                "comment": "Static route created by MCP tool Python test"
            }
            logger.info(f"Create static route test for dst '{new_route_config['dst']}' is normally commented out. Uncomment to run.")
            # create_route_response = create_static_route(client, new_route_config)
            # if isinstance(create_route_response, dict) and "error" in create_route_response:
            #     logger.error(f"Error creating static route: {create_route_response.get('error')}, Details: {create_route_response.get('details')}")
            # else:
            #     logger.info(f"Static route creation response: {create_route_response}")
            #     created_seq_num = create_route_response.get("seq-num")
            #     if created_seq_num: # If successful and seq-num is returned
            #         logger.info(f"--- Test: Attempting to delete created static route seq-num: {created_seq_num} (Illustrative) ---")
            #         # try:
            #         #     # client.cmdb.router.static.delete(mkey=created_seq_num) # Actual delete call
            #         #     logger.info(f"Deletion request for static route {created_seq_num} submitted (if uncommented).")
            #         # except Exception as del_e:
            #         #     logger.error(f"Error deleting static route {created_seq_num}: {del_e}")
            #         pass
        else:
            logger.error("Could not get FortiGate client for testing static_routes.")
    except FortiGateClientError as e:
        logger.error(f"Client setup error during static_routes test: {e}")
    except Exception as e:
        logger.error(f"General error in static_routes test (e.g. login failed): {e}", exc_info=True)
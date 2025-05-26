# tools/utils.py
import logging

logger = logging.getLogger(__name__)

def _parse_api_error_details(response_obj_or_text):
    """Helper to extract error details from various response types."""
    if hasattr(response_obj_or_text, 'text'): # requests.Response like
        try:
            data = response_obj_or_text.json()
            # FortiOS often has 'cli_error' or 'error' (numeric code) or 'message'
            return data.get("cli_error", data.get("message", str(data)))
        except ValueError:
            return response_obj_or_text.text
    elif isinstance(response_obj_or_text, dict):
        return response_obj_or_text.get("cli_error", response_obj_or_text.get("message", str(response_obj_or_text)))
    return str(response_obj_or_text)

def handle_api_response(api_response, action_name_for_log: str, vdom_name: str, logger_instance=None):
    """
    Handles the response from FortiGate API calls consistently.
    
    Args:
        api_response: The response object from the FortiGate API client.
        action_name_for_log: A string describing the action being performed (e.g., "interface creation").
        vdom_name: The name of the VDOM for logging purposes.
        logger_instance: The logger to use. If None, uses the module's logger.

    Returns:
        A dictionary with either a "status": "success" or "error": "message".
    """
    if logger_instance is None:
        current_logger = logger # Use the utils module's logger by default
    else:
        current_logger = logger_instance

    status_code = getattr(api_response, 'status_code', None)
    response_data = api_response
    if hasattr(api_response, 'json'):
        try:
            response_data = api_response.json()
        except ValueError: # If response is not JSON
            response_data = getattr(api_response, 'text', str(api_response))
    
    current_logger.debug(f"API response for {action_name_for_log} in VDOM {vdom_name}: HTTP {status_code if status_code else 'N/A'}, Data: {response_data}")

    if status_code and 200 <= status_code < 300:
        if isinstance(response_data, dict) and response_data.get("status") == "error": # FortiOS specific error in payload
            error_detail = _parse_api_error_details(response_data)
            current_logger.error(f"FortiGate API error on {action_name_for_log} in VDOM {vdom_name} (HTTP {status_code}): {error_detail}")
            return {"error": f"FortiGate API error for {action_name_for_log}", "details": response_data}
        
        current_logger.info(f"Successfully completed {action_name_for_log} in VDOM {vdom_name} (HTTP {status_code}).")
        return {"status": "success", "message": f"{action_name_for_log.capitalize()} completed successfully.", "details": response_data}
    elif status_code: # Error HTTP status code
        error_detail = _parse_api_error_details(response_data)
        # Specific check for "not found" type errors from HTTP status
        if status_code == 404 or "not found" in error_detail.lower() or "entry not found" in error_detail.lower():
            current_logger.warning(f"{action_name_for_log.capitalize()} target not found in VDOM {vdom_name} (HTTP {status_code}). Error: {error_detail}")
            return {"error": f"{action_name_for_log.capitalize()} target not found (API error).", "details": error_detail, "http_status": status_code}
        current_logger.error(f"FortiGate API error (HTTP {status_code}) during {action_name_for_log} in VDOM {vdom_name}: {error_detail}")
        return {"error": f"FortiGate API error (HTTP {status_code}) for {action_name_for_log}", "details": response_data, "http_status": status_code}
    elif isinstance(api_response, dict): # Fallback for direct dict responses
        if api_response.get("status") == "success":
             current_logger.info(f"{action_name_for_log.capitalize()} successful (dict response) in VDOM {vdom_name}.")
             return {"status": "success", "message": f"{action_name_for_log.capitalize()} completed successfully.", "details": api_response}
        else: # Assume error if not explicitly success
             error_detail = _parse_api_error_details(api_response)
             if "entry not found" in error_detail.lower() or ("results" in api_response and not api_response["results"]): # Check for error codes if present
                current_logger.warning(f"{action_name_for_log.capitalize()} target not found in VDOM {vdom_name} (dict response). Error: {error_detail}")
                # For dict responses, we don't have a direct HTTP status, so pass a common non-HTTP error or specific code if available
                return {"error": f"{action_name_for_log.capitalize()} target not found (API error).", "details": error_detail, "http_status": api_response.get("error", -1)} # Use -1 or other non-HTTP code
             current_logger.error(f"{action_name_for_log.capitalize()} failed (dict response) in VDOM {vdom_name}: {error_detail}")
             return {"error": f"{action_name_for_log.capitalize()} failed (dict response)", "details": api_response, "http_status": api_response.get("error", -1)}  # Use -1 or other non-HTTP code
    else: # Unexpected response type
        current_logger.error(f"{action_name_for_log.capitalize()} in VDOM {vdom_name} returned an unexpected response type: {type(api_response)}, {api_response}")
        return {"error": "Unexpected response type from API library.", "details": str(api_response), "http_status": None}

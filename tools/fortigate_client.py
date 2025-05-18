# mcp-forti/tools/fortigate_client.py
import os
import logging
from fortigate_api import FortiGateAPI # Ensure this is the correct import
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

FORTIGATE_HOST = os.getenv("FORTIGATE_HOST")
FORTIGATE_API_TOKEN = os.getenv("FORTIGATE_API_TOKEN") # Use API Token
FORTIGATE_VDOM = os.getenv("FORTIGATE_VDOM", "root") # Default to 'root' VDOM
FORTIGATE_SSL_VERIFY_STR = os.getenv("FORTIGATE_SSL_VERIFY", "False").lower()
FORTIGATE_SSL_VERIFY = FORTIGATE_SSL_VERIFY_STR == "true"
# Default to HTTP, port 80 unless explicitly changed
FORTIGATE_SCHEME = os.getenv("FORTIGATE_SCHEME", "http").lower()
FORTIGATE_PORT_STR = os.getenv("FORTIGATE_PORT", "80" if FORTIGATE_SCHEME == "http" else "443")
try:
    FORTIGATE_PORT = int(FORTIGATE_PORT_STR)
except ValueError:
    logger.warning(f"Invalid FORTIGATE_PORT value: '{FORTIGATE_PORT_STR}'. Defaulting to 80 for http, 443 for https.")
    FORTIGATE_PORT = 80 if FORTIGATE_SCHEME == "http" else 443


class FortiGateClientError(Exception):
    """Custom exception for FortiGate client errors."""
    pass


def get_fortigate_client():
    """
    Initializes and returns a FortiGateAPI client.
    Reads configuration from environment variables, using API Token.
    """
    if not FORTIGATE_HOST or not FORTIGATE_API_TOKEN:
        logger.error("FORTIGATE_HOST and FORTIGATE_API_TOKEN must be set in .env file.")
        raise FortiGateClientError("Missing FortiGate connection details (host or API token) in environment variables.")

    try:
        # Initialize the FortiGateAPI client with API Token
        fgt = FortiGateAPI(
            host=FORTIGATE_HOST,
            api_token=FORTIGATE_API_TOKEN, # Use api_token parameter
            vdom=FORTIGATE_VDOM,
            verify=FORTIGATE_SSL_VERIFY,
            scheme=FORTIGATE_SCHEME,
            port=FORTIGATE_PORT,
            timeout=20 # Increased timeout slightly
        )
        logger.info(f"FortiGateAPI client tentatively initialized for host: {FORTIGATE_HOST} using {FORTIGATE_SCHEME.upper()} on port {FORTIGATE_PORT}. VDOM: {FORTIGATE_VDOM}. SSL Verify: {FORTIGATE_SSL_VERIFY}.")
        # It's good practice to test the connection if the library doesn't do it on init
        # For example, by trying to get a simple, non-sensitive piece of information.
        # However, this is often done by the calling code (e.g., main.py's global client init).
        return fgt
    except Exception as e:
        logger.error(f"Failed to initialize FortiGateAPI client: {e}", exc_info=True)
        raise FortiGateClientError(f"Failed to initialize FortiGateAPI client: {e}")

# Example usage (optional, for testing this module directly)
if __name__ == "__main__":
    logger.info("Attempting to initialize FortiGate client for module testing...")
    try:
        client = get_fortigate_client()
        if client:
            logger.info("Successfully created FortiGate client instance using API Token.")
            # Test with a simple read operation
            # Ensure this test doesn't expose sensitive data and is a lightweight call.
            # Example: Get system status or a list of interfaces (limit 1)
            try:
                logger.info("Attempting a test API call (e.g., get system status or first interface)...")
                # Option 1: System Status (often a good simple test)
                # status = client.get_system_status() # This method name is hypothetical
                # logger.info(f"FortiGate System Status: {status}")

                # Option 2: Get a list of interfaces (usually exists and is read-only)
                interfaces = client.cmdb.system.interface.get(limit=1) # limit to 1 for a quick check
                if interfaces and isinstance(interfaces, list) and len(interfaces) > 0:
                    logger.info(f"Successfully connected to FortiGate and fetched an interface: {interfaces[0].get('name')}")
                elif isinstance(interfaces, dict) and interfaces.get('name'): # If single object returned
                     logger.info(f"Successfully connected to FortiGate and fetched an interface: {interfaces.get('name')}")
                else:
                    logger.info(f"Connected to FortiGate, but no interfaces found or response was empty/unexpected: {interfaces}")

            except Exception as api_call_e:
                logger.error(f"FortiGate client initialized, but test API call failed: {api_call_e}", exc_info=True)
        else:
            logger.error("Failed to create FortiGate client (returned None).") # Should not happen if exceptions are raised
    except FortiGateClientError as e:
        logger.error(f"Client Error during module test: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred during module test: {e}", exc_info=True)

import os
import logging
from fortigate_api import FortiGateAPI
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load environment variables from.env file
load_dotenv()

FORTIGATE_HOST = os.getenv("FORTIGATE_HOST")
FORTIGATE_USERNAME = os.getenv("FORTIGATE_USERNAME")
FORTIGATE_PASSWORD = os.getenv("FORTIGATE_PASSWORD")
FORTIGATE_VDOM = os.getenv("FORTIGATE_VDOM", "root") # Default to 'root' VDOM
FORTIGATE_SSL_VERIFY_STR = os.getenv("FORTIGATE_SSL_VERIFY", "False").lower()
FORTIGATE_SSL_VERIFY = FORTIGATE_SSL_VERIFY_STR == "true"


class FortiGateClientError(Exception):
    """Custom exception for FortiGate client errors."""
    pass


def get_fortigate_client():
    """
    Initializes and returns a FortiGateAPI client using HTTP.
    Reads configuration from environment variables.
    """
    if not FORTIGATE_HOST or not FORTIGATE_USERNAME or not FORTIGATE_PASSWORD:
        logger.error("FORTIGATE_HOST, FORTIGATE_USERNAME, and FORTIGATE_PASSWORD must be set in.env file for HTTP.")
        raise FortiGateClientError("Missing FortiGate connection details in environment variables for HTTP.")

    try:
        # Initialize the FortiGateAPI client with HTTP
        fgt = FortiGateAPI(
            host=FORTIGATE_HOST,
            username=FORTIGATE_USERNAME,
            password=FORTIGATE_PASSWORD,
            vdom=FORTIGATE_VDOM,
            verify=FORTIGATE_SSL_VERIFY,
            scheme="http",  # Explicitly set the scheme to HTTP
            port=80,        # Explicitly set the port to 80 for HTTP
            timeout=20 # Increased timeout slightly
        )
        logger.info(f"FortiGateAPI client tentatively initialized for host: {FORTIGATE_HOST}, VDOM: {FORTIGATE_VDOM}. SSL Verify: {FORTIGATE_SSL_VERIFY} using HTTP on port 80.")
        return fgt
    except Exception as e:
        logger.error(f"Failed to initialize FortiGateAPI client: {e}", exc_info=True)
        raise FortiGateClientError(f"Failed to initialize FortiGateAPI client: {e}")

# Example usage (optional, for testing this module directly)
if __name__ == "__main__":
    try:
        client = get_fortigate_client()
        if client:
            logger.info("Successfully created FortiGate client instance.")
            # Test with a simple read operation
            try:
                # Attempt to get a list of interfaces (usually exists and is read-only)
                interfaces = client.cmdb.system.interface.get(limit=1) # limit to 1 for a quick check
                if interfaces:
                    logger.info(f"Successfully connected to FortiGate via HTTP on port 80 and fetched an interface: {interfaces.get('name')}")
                else:
                    logger.info("Connected to FortiGate, but no interfaces found (or empty response).")
            except Exception as api_call_e:
                logger.error(f"FortiGate client initialized, but API call failed: {api_call_e}", exc_info=True)
        else:
            logger.error("Failed to create FortiGate client.")
    except FortiGateClientError as e:
        logger.error(f"Client Error: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
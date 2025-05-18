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
FORTIGATE_USERNAME = os.getenv("FORTIGATE_USERNAME") # Use Username
FORTIGATE_PASSWORD = os.getenv("FORTIGATE_PASSWORD") # Use Password
FORTIGATE_VDOM = os.getenv("FORTIGATE_VDOM", "root") # Default to 'root' VDOM
FORTIGATE_SSL_VERIFY_STR = os.getenv("FORTIGATE_SSL_VERIFY", "False").lower()
FORTIGATE_SSL_VERIFY = FORTIGATE_SSL_VERIFY_STR == "true"

# Default to HTTP, port 80 unless explicitly changed by FORTIGATE_SCHEME and FORTIGATE_PORT
FORTIGATE_SCHEME = os.getenv("FORTIGATE_SCHEME", "http").lower()
default_port = 80 if FORTIGATE_SCHEME == "http" else 443
FORTIGATE_PORT_STR = os.getenv("FORTIGATE_PORT", str(default_port))

try:
    FORTIGATE_PORT = int(FORTIGATE_PORT_STR)
except ValueError:
    logger.warning(f"Invalid FORTIGATE_PORT value: '{FORTIGATE_PORT_STR}'. Defaulting to {default_port} for {FORTIGATE_SCHEME}.")
    FORTIGATE_PORT = default_port


class FortiGateClientError(Exception):
    """Custom exception for FortiGate client errors."""
    pass


def get_fortigate_client():
    """
    Initializes and returns a FortiGateAPI client using Username and Password.
    Reads configuration from environment variables.
    """
    if not FORTIGATE_HOST or not FORTIGATE_USERNAME or not FORTIGATE_PASSWORD:
        logger.error("FORTIGATE_HOST, FORTIGATE_USERNAME, and FORTIGATE_PASSWORD must be set in .env file.")
        raise FortiGateClientError("Missing FortiGate connection details (host, username, or password) in environment variables.")

    try:
        fgt = FortiGateAPI(
            host=FORTIGATE_HOST,
            username=FORTIGATE_USERNAME,
            password=FORTIGATE_PASSWORD,
            vdom=FORTIGATE_VDOM,
            verify=FORTIGATE_SSL_VERIFY,
            scheme=FORTIGATE_SCHEME,
            port=FORTIGATE_PORT,
            timeout=20
        )
        logger.info(f"FortiGateAPI client tentatively initialized for host: {FORTIGATE_HOST} with user {FORTIGATE_USERNAME} using {FORTIGATE_SCHEME.upper()} on port {FORTIGATE_PORT}. VDOM: {FORTIGATE_VDOM}. SSL Verify: {FORTIGATE_SSL_VERIFY}.")
        return fgt
    except Exception as e:
        logger.error(f"Failed to initialize FortiGateAPI client with username/password: {e}", exc_info=True)
        raise FortiGateClientError(f"Failed to initialize FortiGateAPI client: {e}")

# Example usage (optional, for testing this module directly)
if __name__ == "__main__":
    logger.info("Attempting to initialize FortiGate client for module testing (using Username/Password)...")
    try:
        client = get_fortigate_client()
        if client:
            logger.info(f"Successfully created FortiGate client instance for user {FORTIGATE_USERNAME}.")
            try:
                # Attempt to login explicitly (good for testing the credentials)
                logger.info("Attempting explicit client.login()...")
                client.login()
                logger.info("Explicit client.login() successful.")

                logger.info("Attempting a test API call (get first interface)...")
                interfaces = client.cmdb.system.interface.get(limit=1)
                if interfaces and isinstance(interfaces, list) and len(interfaces) > 0:
                    logger.info(f"Successfully connected to FortiGate and fetched an interface: {interfaces[0].get('name')}")
                elif isinstance(interfaces, dict) and interfaces.get('name'):
                     logger.info(f"Successfully connected to FortiGate and fetched an interface: {interfaces.get('name')}")
                else:
                    logger.info(f"Connected to FortiGate, but no interfaces found or response was empty/unexpected: {interfaces}")

            except Exception as api_call_e:
                logger.error(f"Error during or after explicit login / test API call: {api_call_e}", exc_info=True)
        else:
            logger.error("Failed to create FortiGate client (returned None).")
    except FortiGateClientError as e:
        logger.error(f"Client Error during module test: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred during module test: {e}", exc_info=True)
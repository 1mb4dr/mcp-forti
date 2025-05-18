# mcp-forti: FortiGate Management Server for Model Context Protocol (MCP)

`mcp-forti` is a server application that integrates with FortiGate firewall devices, exposing various management and monitoring functionalities through the Model Context Protocol (MCP). It allows for programmatic interaction with your FortiGate for automation and orchestration tasks.

This server is built using Python, the `fortigate-api` library for FortiGate communication, and `FastMCP` for the MCP server implementation.

## Features

The server provides MCP tools to perform the following actions on a connected FortiGate device:

*   **Firewall Policies:**
    *   Get details of a specific policy.
    *   Create a new firewall policy.
    *   Retrieve all firewall policies.
    *   Delete a firewall policy.
    *   Reorder firewall policies.
*   **Network Interfaces:**
    *   Get details of all or a specific network interface.
    *   Create new network interfaces (e.g., VLANs, loopback).
*   **Static Routes:**
    *   Get details of all or a specific static route.
    *   Create new static routes.
*   **Address Objects:**
    *   Get details of all or a specific firewall address object.
    *   Create new address objects (types: FQDN, IP Range, Subnet).
*   **Service Objects:**
    *   Get details of all or a specific custom/predefined firewall service object.
    *   Create new custom service objects (types: TCP/UDP/SCTP, ICMP, IP).
*   **Service Groups:**
    *   Get details of all or a specific firewall service group.
    *   Create new service groups.
*   **Traffic Logs:**
    *   Retrieve traffic logs.
    *   **IMPORTANT CAVEAT:** The traffic log retrieval functionality is currently **MOCKED** and returns sample data. It does not fetch live logs from the FortiGate.

## Prerequisites

*   Python 3.11 (as specified in `.python-version`)
*   Access to a FortiGate device.
*   The FortiGate device must be configured to allow API access for the admin user you will use.
*   Required Python packages (see `requirements.txt`).

## Setup and Installation

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd mcp-forti
    ```

2.  **Create and activate a Python virtual environment:**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Environment Variables:**
    Create a `.env` file in the root of the project (`mcp-forti/.env`). This file will store your FortiGate connection details.

    Copy the example below into your `.env` file and replace the placeholder values with your actual FortiGate information:

    ```dotenv
    # .env file for mcp-forti

    FORTIGATE_HOST=your_fortigate_ip_or_hostname
    FORTIGATE_USERNAME=your_fortigate_admin_username
    FORTIGATE_PASSWORD=your_fortigate_admin_password

    # Optional: Specify VDOM (defaults to 'root' if not set)
    # FORTIGATE_VDOM=your_target_vdom

    # Optional: Specify connection scheme (http or https, defaults to 'http')
    # FORTIGATE_SCHEME=https

    # Optional: Specify port (defaults to 80 for http, 443 for https)
    # FORTIGATE_PORT=10443

    # Optional: SSL certificate verification for HTTPS (defaults to 'False')
    # Set to 'True' if using HTTPS with a valid certificate and you want to verify it.
    # FORTIGATE_SSL_VERIFY=True
    ```

    **Note on Admin User:** Ensure the administrator account (`FORTIGATE_USERNAME`) has the necessary permissions on the FortiGate/VDOM to perform the actions exposed by this server (e.g., read/write for policies, system, router, etc.). Also, ensure the IP address of the machine running `mcp-forti` is listed in the "Trusted Hosts" for this admin user on the FortiGate if that security feature is enabled.

## Running the Server

To run the MCP server, execute the following command from the project's root directory:

```bash
mcp dev main.py
```

This will start the server, and it should register the tools defined in `main.py`, making them available to an MCP client.

## Available MCP Tools

The server exposes the following tools. Refer to the docstrings within `main.py` for detailed information on parameters and expected input/output formats for each tool.

*   `get_fortigate_traffic_logs`: Retrieves traffic logs (currently mocked).
*   `get_fortigate_policy_details`: Retrieves details for a specific firewall policy ID.
*   `create_fortigate_firewall_policy`: Creates a new firewall policy.
*   `get_fortigate_interface_details`: Retrieves details for network interfaces.
*   `create_fortigate_network_interface`: Creates a new network interface.
*   `get_fortigate_static_routes`: Retrieves static routes.
*   `create_fortigate_static_route`: Creates a new static route.
*   `create_fortigate_address_object`: Creates a new firewall address object.
*   `get_fortigate_address_object`: Retrieves firewall address objects.
*   `create_fortigate_service_object`: Creates a new custom firewall service object.
*   `get_fortigate_service_object`: Retrieves custom or predefined service objects.
*   `create_fortigate_service_group`: Creates a new firewall service group.
*   `get_fortigate_service_group`: Retrieves firewall service groups.

## Important Considerations

*   **Traffic Log Mocking:** As stated, `get_fortigate_traffic_logs` returns sample data. For live log retrieval, the `tools/traffic_logs.py` module will need to be updated with actual FortiGate API calls for log fetching.
*   **Communication Protocol:** The FortiGate client is configured by default to use HTTP (via `FORTIGATE_SCHEME` defaulting to `http`). If you switch to HTTPS, ensure your FortiGate is configured for HTTPS API access and consider setting `FORTIGATE_SSL_VERIFY=True` if you have a trusted certificate.
*   **Error Handling:** The tools generally return a JSON response. On error, this JSON typically includes an `"error"` key with a descriptive message and sometimes a `"details"` key with more specific information from the API.
*   **Security:** Credentials (`FORTIGATE_USERNAME`, `FORTIGATE_PASSWORD`) stored in the `.env` file are sensitive. Ensure this file is **not** committed to your Git repository (it should be in your `.gitignore` file).

## Development Notes (for `tools/` modules)

The modules within `tools/` (especially `service_objects.py`) sometimes use dynamic path resolution (e.g., `_resolve_fgt_api_path` helper) to interact with the `fortigate-api` client library. This approach can be sensitive to changes in the underlying `fortigate-api` library structure across different versions. If issues arise after updating `fortigate-api`, these paths might need to be re-verified against the library's documentation.


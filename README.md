# Guide to Running FetchTamper.py

## Overview
This script is designed to generate a report of tamper protection passwords for all devices in Sophos Central. It uses the Sophos Central API to fetch data about sub-estates (tenants) and devices, retrieves tamper passwords where enabled, and outputs the results to a CSV file.

**Important Notes:**
- This is not supported by Sophos Support.
- This was written by Matt Feates
- It requires API credentials (Client ID and Client Secret) from Sophos Central.
- The script handles partners, organizations, and tenants.
- It supports pagination, rate limiting retries, and token refresh.
- Date in script: July 17, 2025 (future-dated for reference).
- Version: 1.00

## Prerequisites
1. **Python Environment:**
   - Python 3.6+ (tested up to 3.12).
   - Required libraries: requests, csv, configparser, os, getpass, datetime, time, json.
     - Install via pip if needed: `pip install requests`

2. **Sophos Central API Credentials:**
   - Create an API client in Sophos Central (Admin > API Credentials).
   - Note down the Client ID and Client Secret.
   - Ensure the API client has appropriate permissions (read access to endpoints and tamper protection).

3. **Config File:**
   - Create a file named `config.ini` in the same directory as the script.
   - Example content (as provided):
     ```
     [DEFAULT]
     ClientID = your_client_id_here
     ClientSecret = your_client_secret_here  # Optional: Leave empty to prompt for it during runtime

     [REPORT]
     ReportFilePath = /path/to/save/reports/  # Ensure this ends with a slash if needed, or the script will append one based on OS
     ```
   - Replace placeholders:
     - `ClientID`: Your Sophos API Client ID.
     - `ClientSecret`: Your Sophos API Client Secret (or leave blank to be prompted securely at runtime).
     - `ReportFilePath`: Directory where CSV reports will be saved (e.g., `C:\Reports\` on Windows or `/home/user/reports/` on Linux). The script auto-appends a slash if missing.

4. **Operating System:**
   - Works on Windows, Linux, macOS.
   - Color output (ANSI) is enabled for PowerShell/terminals that support it.

## Setup Steps
1. **Download the Script:**
   - Save the provided Python script as `Sophos_Central_Get_Tamper_Passwords.py`.

2. **Create config.ini:**
   - Use a text editor to create the file with the structure above.
   - If ClientSecret is left blank, you'll be prompted to enter it securely when running the script.

3. **Ensure Directory Permissions:**
   - Make sure the `ReportFilePath` directory exists and is writable.

## Running the Script
1. **Open a Terminal/Command Prompt:**
   - Navigate to the directory containing the script and config.ini.

2. **Execute the Script:**
   - Run: `python FetchTamper.py` (or `python3` on some systems).
   - If ClientSecret is blank in config.ini, enter it when prompted.

3. **Script Prompts:**
   - It will ask: "Enter the tamper report name:" 
     - Provide a name (e.g., "MyTamperReport"). This becomes part of the CSV filename, e.g., "MyTamperReport17072025_14-30-00.csv".

4. **What Happens During Execution:**
   - Authenticates with Sophos API using credentials.
   - Determines if your account is a partner, organization, or tenant.
   - Fetches sub-estates (tenants) if applicable.
   - Iterates through each sub-estate, fetching devices (up to 500 per page).
   - For each device, retrieves tamper password (if enabled).
   - Handles errors like no access (403), rate limits (429 with retries), empty estates.
   - Outputs progress to console (e.g., device names and passwords in color).
   - Saves a CSV report with columns: Sub Estate, Sub EstateID, Hostname, Type, OS, id, Region, Tamper Password.
   - Displays total devices, script runtime, and report path.

5. **Example Output:**
   - Console: Lists sub-estates, devices, passwords, totals.
   - CSV File: Timestamped file in the specified path.

## Troubleshooting
- **API Errors:**
  - 401/403: Check credentials/permissions in Sophos Central.
  - 429: Rate limit hit; script retries automatically (up to 10 times, 5s delay).
  - Other: Check console for status codes.

- **No Devices Found:**
  - Empty sub-estate: Added as "Empty sub estate" in report.
  - No access: Added as "No access" in report.

- **Token Expiration:**
  - Script auto-refreshes every 3600 seconds.

- **Color Issues:**
  - If colors don't display, it's terminal-dependent; functionality unaffected.

- **Config Issues:**
  - Ensure config.ini is in the same folder.
  - Path issues: Use absolute paths in ReportFilePath.

- **Large Environments:**
  - For many devices, it may take time due to API pagination and rate limits.

## Security Considerations
- Store config.ini securely; avoid committing to version control if ClientSecret is included.
- Script uses getpass for secret input if blank.
- API calls are over HTTPS.

## Customization
- Page Size: Adjustable in code (pagesize=500 for devices).
- Report Columns: Defined in report_field_names(); modify if needed.
- Add more retries/delays in get_all_devices() if rate limits are frequent.

## License
- GNU GPL v3.0 (see script header).

For support, contact Sophos Professional Services (unsupported script). If issues persist, provide console output and error codes.

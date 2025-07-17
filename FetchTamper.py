# Licensed under the GNU General Public License v3.0(the "License"); you may
# not use this file except in compliance with the License.
#
# You may obtain a copy of the License at:
# https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.
#
#
# Sophos_Central_Get_Tamper_Passwords.py
#
# This script generates a report of tamper protection passwords for all devices in Sophos Central.
#
# Created by Matt Feates (Senior Global Escalations Engineer 3 - ESG GES @ SOPHOS)
# Date: July 17, 2025
# Version: 1.00
# README: This script is an unsupported solution provided by Sophos Support

import requests
import csv
import configparser
import os
import getpass
from datetime import datetime, timedelta
import time
import json

# Allows colour to work in Microsoft PowerShell
os.system("")

today = datetime.today()
now = datetime.now()
time_stamp = str(now.strftime("%d%m%Y_%H-%M-%S"))

# This list will hold all the sub estates
sub_estate_list = []

# This list will hold all the devices with their tamper passwords
device_list = []

# Count the number of total devices across all sub estates
total_devices = 0

# Page size for API calls
page_size = 100

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Get Access Token - JWT in the documentation
def get_bearer_token(client, secret, url):
    global headers
    d = {
        'grant_type': 'client_credentials',
        'client_id': client,
        'client_secret': secret,
        'scope': 'token'
    }
    request_token = requests.post(url, auth=(client, secret), data=d)
    json_token = request_token.json()
    headers = {'Authorization': f"Bearer {json_token['access_token']}"}
    return headers

def get_whoami():
    global organization_id
    global organization_header
    global organization_type
    global region_url
    whoami_url = 'https://api.central.sophos.com/whoami/v1'
    request_whoami = requests.get(whoami_url, headers=headers)
    whoami = request_whoami.json()
    organization_type = whoami["idType"]
    if whoami["idType"] == "partner":
        organization_header = "X-Partner-ID"
    elif whoami["idType"] == "organization":
        organization_header = "X-Organization-ID"
    else:
        organization_header = "X-Tenant-ID"
    organization_id = whoami["id"]
    region_url = whoami.get('apiHosts', {}).get("dataRegion", None)
    return organization_id, organization_header, organization_type, region_url

def get_all_sub_estates():
    global organization_header
    headers[organization_header] = organization_id
    request_sub_estates = requests.get(
        f"https://api.central.sophos.com/{organization_type}/v1/tenants?pageTotal=True", headers=headers)
    sub_estate_json = request_sub_estates.json()
    total_pages = sub_estate_json["pages"]["total"]
    sub_estate_keys = ('id', 'name', 'dataRegion', 'showAs')
    while total_pages != 0:
        request_sub_estates = requests.get(
            f"https://api.central.sophos.com/{organization_type}/v1/tenants?page={total_pages}",
            headers=headers)
        sub_estate_json = request_sub_estates.json()
        for all_sub_estates in sub_estate_json["items"]:
            sub_estate_dictionary = {key: value for key, value in all_sub_estates.items() if key in sub_estate_keys}
            sub_estate_list.append(sub_estate_dictionary)
            print(f"Sub Estate - {sub_estate_dictionary['showAs']}. Sub Estate ID - {sub_estate_dictionary['id']}")
        total_pages -= 1
    del headers[organization_header]
    print(f"Sub Estates Found: {len(sub_estate_list)}")

def get_all_devices(sub_estate_token, data_region, url, sub_estate_name):
    global headers
    global start_time
    pagesize = 500
    devices_url = f"{url}/endpoints?pageSize={pagesize}&view=full&sort=hostname"
    page_count = 1
    devices_in_sub_estate = 0
    while page_count != 0:
        time_since_start = time.time()
        token_time = (time_since_start - start_time)
        headers['X-Tenant-ID'] = sub_estate_token
        if token_time >= 3600:
            headers = get_bearer_token(client_id, client_secret, token_url)
            headers['X-Tenant-ID'] = sub_estate_token
            start_time = time.time()
        retry_counter = 0
        retry_delay = 5
        retry_max = 10
        request_devices = requests.get(devices_url, headers=headers)
        while request_devices.status_code == 429:
            request_devices = requests.get(devices_url, headers=headers)
            if request_devices.status_code == 200:
                break
            if request_devices.status_code != 429:
                print(f"ERROR {request_devices.status_code} {request_devices.reason} -> ABORT")
                return 0
            retry_counter += 1
            if retry_counter > retry_max:
                print(f"Maximum retries ({retry_max}) reached. -> ABORT")
                return 0
            print(f"Wait {retry_delay} seconds and do {retry_counter}. retry")
            time.sleep(retry_delay)
        if request_devices.status_code == 403:
            print(f"{bcolors.FAIL}No access to sub estate - {sub_estate_name}. Status Code - {request_devices.status_code}{bcolors.ENDC}")
            device_dictionary = {'hostname': 'No access', 'Sub Estate': sub_estate_name, 'Tamper Password': 'N/A'}
            device_list.append(device_dictionary)
            break
        devices_json = request_devices.json()
        device_keys = ('id', 'hostname', 'os', 'type', 'Sub Estate')
        for all_devices in devices_json["items"]:
            device_dictionary = {key: value for key, value in all_devices.items() if key in device_keys}
            if 'hostname' not in device_dictionary:
                device_dictionary['hostname'] = 'Unknown'
            try:
                device_dictionary['os'] = all_devices['os']['name']
            except:
                device_dictionary['os'] = 'Unknown'
            if organization_type != "tenant":
                device_dictionary['Sub Estate'] = sub_estate_name
                device_dictionary['Sub EstateID'] = sub_estate_token
            else:
                device_dictionary['Sub Estate'] = 'Tenant'
                device_dictionary['Sub EstateID'] = organization_id
            device_dictionary['Region'] = data_region
            # Get tamper password
            tamper_password = get_tamper_password(data_region, device_dictionary['id'])
            device_dictionary['Tamper Password'] = tamper_password
            print(f"Device {bcolors.OKGREEN}{device_dictionary['hostname']}{bcolors.ENDC} - Tamper Password: {bcolors.OKBLUE}{tamper_password}{bcolors.ENDC}")
            device_list.append(device_dictionary)
        if 'nextKey' in devices_json['pages']:
            next_page = devices_json['pages']['nextKey']
            devices_url = f"{url}/endpoints?pageFromKey={next_page}&pageSize={pagesize}&view=full&sort=hostname"
            devices_in_sub_estate += len(devices_json['items'])
        else:
            devices_in_sub_estate += len(devices_json['items'])
            page_count = 0
    if devices_in_sub_estate == 0:
        device_dictionary = {'hostname': 'Empty sub estate', 'Sub Estate': sub_estate_name, 'Tamper Password': 'N/A'}
        device_list.append(device_dictionary)
    print(f'Checked sub estate - {sub_estate_name}. Devices in sub estate: {devices_in_sub_estate}')
    return devices_in_sub_estate

def get_tamper_password(region, device_id):
    tamper_url = f"https://api-{region}.central.sophos.com/endpoint/v1/endpoints/{device_id}/tamper-protection"
    request_tamper = requests.get(tamper_url, headers=headers)
    if request_tamper.status_code == 200:
        tamper_json = request_tamper.json()
        if 'password' in tamper_json:
            return tamper_json['password']
        else:
            return 'Not Enabled'
    elif request_tamper.status_code == 429:
        time.sleep(5)  # Simple backoff for rate limit
        return get_tamper_password(region, device_id)  # Retry once
    else:
        return f'Error: {request_tamper.status_code}'

def report_field_names():
    report_column_names = [
        'Sub Estate',
        'Sub EstateID',
        'Hostname',
        'Type',
        'OS',
        'id',
        'Region',
        'Tamper Password'
    ]
    report_column_order = [
        'Sub Estate',
        'Sub EstateID',
        'hostname',
        'type',
        'os',
        'id',
        'Region',
        'Tamper Password'
    ]
    return report_column_names, report_column_order

def print_tamper_report(devices_in_report, report_name):
    report_column_names, report_column_order = report_field_names()
    full_report_path = f"{report_file_path}{report_name}{time_stamp}{'.csv'}"
    with open(full_report_path, 'w', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(report_column_names)
    with open(full_report_path, 'a+', encoding='utf-8', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, report_column_order)
        dict_writer.writerows(devices_in_report)
    print(f"Report saved to: {full_report_path}")

def read_config():
    config = configparser.ConfigParser()
    config.read('config.ini')
    config.sections()
    client_id = config['DEFAULT']['ClientID']
    client_secret = config['DEFAULT']['ClientSecret']
    if client_secret == '':
        client_secret = getpass.getpass(prompt='Enter Client Secret: ', stream=None)
    report_file_path = config['REPORT']['ReportFilePath']
    if report_file_path[-1].isalpha():
        if os.name != "posix":
            report_file_path += "\\"
        else:
            report_file_path += "/"
    return client_id, client_secret, report_file_path

def generate_tamper_report():
    global start_time
    start_time = time.time()
    script_start_time = time.time()
    global token_url
    token_url = 'https://id.sophos.com/api/v2/oauth2/token'
    headers = get_bearer_token(client_id, client_secret, token_url)
    organization_id, organization_header, organization_type, region_url = get_whoami()
    report_name = input("Enter the tamper report name: ")
    all_devices_count = 0
    if organization_type != "tenant":
        print(f"Sophos Central is a {organization_type}")
        get_all_sub_estates()
        for sub_estate in sub_estate_list:
            devices_count = get_all_devices(
                sub_estate['id'],
                sub_estate['dataRegion'],
                f"https://api-{sub_estate['dataRegion']}.central.sophos.com/endpoint/v1",
                sub_estate['showAs']
            )
            all_devices_count += devices_count
        print(f"Total Number Of Devices: {all_devices_count}")
        print_tamper_report(device_list, report_name)
    else:
        print(f"Sophos Central is a {organization_type}")
        tenant_region = region_url[12:16]
        devices_count = get_all_devices(
            organization_id,
            tenant_region,
            f"{region_url}/endpoint/v1",
            organization_type
        )
        all_devices_count += devices_count
        print(f"Total Number Of Devices: {all_devices_count}")
        print_tamper_report(device_list, report_name)
    end_time = time.time()
    print(f"Script run time - {timedelta(seconds=end_time - script_start_time)}")

# Main execution
client_id, client_secret, report_file_path = read_config()
generate_tamper_report()
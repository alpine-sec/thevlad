#!/usr/bin/env python3
#
# vlad.py
#
# (c) Authors: Juan Carlos Sanchez & Miguel Quero
# e-mail: jc.sanchez@alpinesec.io
# company: Alpine Security
#
# ***************************************************************
#
# The license below covers all files distributed with infofile unless 
# otherwise noted in the file itself.
#
# This program is free software: you can redistribute it and/or 
# modify it under the terms of the GNU General Public License as 
# published by the Free Software Foundation, version 3.
# 
# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License 
# along with this program. If not, see <https://www.gnu.org/licenses/>. 
#
#


#Libraries
import argparse
import gzip
import os
import pathlib
import re
import shutil
import yaml
import urllib.request
import urllib.parse
import json
import sys
import requests
import base64
import time
from munch import munchify

#Global Variables
VERSION = '0.1'

def parse_config(file_path):

    confdata = []

    with open(file_path, "r") as f:
        config = yaml.safe_load(f)

    for c in config:
        confdata.append(c)

    return confdata, munchify(config)

def mdatp_auth(client, apicred):

    if hasattr(getattr(apicred, client), "MDATP"):
        tenantId = getattr(getattr(getattr(apicred, client), "MDATP"), "TENANTID")
        appId = getattr(getattr(getattr(apicred, client), "MDATP"), "APPID")
        appSecret = getattr(getattr(getattr(apicred, client), "MDATP"), "APPSECRET")

        url = "https://login.microsoftonline.com/{}/oauth2/token".format(tenantId)

        resourceAppIdUri = 'https://api-eu.securitycenter.microsoft.com'

        body = {
            'resource' : resourceAppIdUri,
            'client_id' : appId,
            'client_secret' : appSecret,
            'grant_type' : 'client_credentials'
        }

        data = urllib.parse.urlencode(body).encode("utf-8")

        req = urllib.request.Request(url, data)
        try:
            response = urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
            print("    - API error: {}".format(e))
            return False
        jsonResponse = json.loads(response.read())
        aadToken = jsonResponse["access_token"]

        return aadToken

def print_headers_list_endpoints():
    print("    {:<30} {:<45} {:<15} {:<20} {:<30} {:<10} {:<20}".format("Computer Name", "ID", "OS", "IP", "Last Seen", "Status", "Onboarding Status"))
    print("    {:<30} {:<45} {:<15} {:<20} {:<30} {:<10} {:<20}".format("-------------", "--", "--", "--", "---------", "------", "----------"))

def list_endpoints(token, vendor, search=None):
    if vendor == "MDATP":   
        url = "https://api-eu.securitycenter.microsoft.com/api/machines"
        first_time_headers = True
        while True:   
            headers = { 
                'Authorization' : "Bearer " + token,
            }
            try:
                response = requests.get(url, headers=headers)
            except requests.exceptions.RequestException as e:
                print("    - MDATP API ERROR: Error {}".format(e))
                return None
            
            if response.status_code == 200:               
                host_found = False
                host_info = None
                machines = response.json()['value']
                if not machines:
                    break
                for machine in response.json()['value']:
                    if search and machine['healthStatus'] == 'Active' and machine['onboardingStatus'] == 'Onboarded':
                        if search in machine['computerDnsName']:   
                            host_found = True
                            if first_time_headers == True:
                                print_headers_list_endpoints()
                                first_time_headers = False
                            print_formatted_machine(machine)
                    elif machine['healthStatus'] == 'Active' and machine['onboardingStatus'] == 'Onboarded':
                        if first_time_headers == True:
                            print_headers_list_endpoints()
                            first_time_headers = False
                        host_found = True
                        print_formatted_machine(machine)
                        print()           
                    
            if "@odata.nextLink" in response.json().keys():
                url = response.json()['@odata.nextLink']
            else:
                break        
        if host_found == False:
                print("    Endpoint not found!")
                print()
        else:
            if host_info != None:
                print(host_info)
                print()    
                    
def print_formatted_machine(machine):
    computerDnsName = machine['computerDnsName'] if machine['computerDnsName'] is not None else 'N/A'
    id = machine['id'] if machine['id'] is not None else 'N/A'
    osPlatform = machine['osPlatform'] if machine['osPlatform'] is not None else 'N/A'
    lastIpAddress = machine['lastIpAddress'] if machine['lastIpAddress'] is not None else 'N/A'
    lastSeen = machine['lastSeen'] if machine['lastSeen'] is not None else 'N/A'
    healthStatus = machine['healthStatus'] if machine['healthStatus'] is not None else 'N/A'
    onboardingStatus = machine['onboardingStatus'] if machine['onboardingStatus'] is not None else 'N/A'
    print("    {:<30} {:<45} {:<15} {:<20} {:<30} {:<10} {:<20}".format(computerDnsName, id, osPlatform, lastIpAddress, lastSeen, healthStatus, onboardingStatus))

def generate_command_script(command, output_file):
    try:
        decoded_command = base64.b64decode(command).decode('utf-8')
    except (TypeError, ValueError) as e:
        print(f"    - Error decoding command: {e}")
        return

    try:
        with open(output_file, 'w') as f:
            f.write(decoded_command)
    except IOError as e:
        print(f"    - Error writing to file {output_file}: {e}")

def upload_file(token, vendor, file_path):
    if vendor == "MDATP":
        url = "https://api-eu.securitycenter.microsoft.com/api/libraryfiles"
        headers = { 
            'Authorization' : "Bearer " + token,
        }

        filename = os.path.basename(file_path)
        # Check if file extesion is .ps1
        if filename.endswith('.ps1'):
            print("- UPLOADING EXECUTION SCRIPT {} TO MDATP LIVE RESPONSE LIBRARY".format(filename))
            description = "Vlad Remote Execution Script"
        else:
            print("- UPLOADING BINARY {} TO MDATP LIVE RESPONSE LIBRARY".format(filename))
            description = "Vlad Uploaded Binary"

        with open(file_path, "rb") as f:
            file = f.read()

        files = {'file': (filename, file)}

        data = {
            'OverrideIfExists': 'true',
            'Description': description
        }
        response = requests.post(url, headers=headers, data=data, files=files)
        return response, filename

def put_file(token, vendor, machineid, binary):
    actionid = None
    if vendor == "MDATP":
        url = "https://api-eu.securitycenter.microsoft.com/api/machines/{}/runliveresponse".format(machineid)
        headers = { 
            'Authorization' : "Bearer " + token,
            'Content-Type': 'application/json'
        }

        data = {
            "Commands":[
                {
                    "type":"PutFile",
                    "params":[
                        {
                            "key":"FileName",
                            "value": binary
                        }
                    ]
                },
            ],
            "Comment":"Vlad Live Response Automations"
        }

        response = requests.post(url, headers=headers, json=data)
        if response.status_code != 200 and response.status_code != 201:
            print("  + ERROR: Execution failed: {}".format(response.text))
            return None
        print("  + PUT FILE DONE WITH STATUS CODE: {}".format(response.status_code))
        statusdata = json.loads(response.text)
        # DEBUG PRINT
        #print("    + DEBUG: {}".format(statusdata))
        actionid = statusdata['id']
        return actionid

def execute_command(token, vendor, machineid, script):
    actionid = None
    if vendor == "MDATP":
        url = "https://api-eu.securitycenter.microsoft.com/api/machines/{}/runliveresponse".format(machineid)
        headers = { 
            'Authorization' : "Bearer " + token,
            'Content-Type': 'application/json'
        }
        data = {
            "Commands":[
                {
                    "type":"RunScript",
                    "params":[
                        {
                            "key":"ScriptName",
                            "value": script
                        }
                    ]
                }
            ],
            "Comment":"Vlad Live Response Automations"
        }
        response = requests.post(url, headers=headers, json=data)
        if response.status_code != 200 and response.status_code != 201:
            print("    + ERROR: Execution failed: {}".format(response.text))
            return None
        print("    + EXECUTION DONE WITH STATUS CODE: {}".format(response.status_code))
        statusdata = json.loads(response.text)
        actionid = statusdata['id']

        return actionid

def get_pending_actions(token, vendor, machineid):
    if vendor == "MDATP":
        url = "https://api.securitycenter.microsoft.com/api/machineactions?$filter=machineId eq '{}' and status eq 'Pending'".format(machineid)
        headers = { 
            'Authorization' : "Bearer " + token,
        }
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            print("  + ERROR: Execution failed: {}".format(response.text))
            return None
        if response.text == '{"@odata.context":"https://api.securitycenter.microsoft.com/api/$metadata#MachineActions","value":[]}':
            print("  + NO PENDING ACTIONS FOUND")
            return None
        else:
            id = parse_json_actionsid(response.text)
            print("  + PENDING ACTIONS: {}".format(id))
            delete_action(token, vendor, id)

def waiting_download_execution(token, vendor, machineid):
    if vendor == "MDATP":
        url = "https://api.securitycenter.microsoft.com/api/machineactions?$filter=machineId eq '{}'".format(machineid)
        headers = { 
            'Authorization' : "Bearer " + token,
        }
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            print("  + ERROR: Execution failed: {}".format(response.text))
            return None
        resdata = json.loads(response.text)
        print("    + STATUS: {}".format(resdata['value'][0]['status']))
        print("    + TASK ID: {}".format(resdata['value'][0]['id'])) 
        #DEBUG PRINT
        #print("    + INDEX: {}".format(resdata['value'][0]['commands'][0]['index'])) 
        index_task = resdata['value'][0]['commands'][0]['index']  
        task_id = resdata['value'][0]['id']     

        print("    + WAITING FOR THE TASK TO BE COMPLETED: [", end="")
        count = 0
        while resdata['value'][0]['status'] != 'Succeeded':
            response = requests.get(url, headers=headers)
            resdata = json.loads(response.text)
            # Print point without space to avoid new line, in realtime in console witouh buffering
            print("·", end="", flush=True)
            time.sleep(5)
            count += 1
            if count == 120:
                print("]")
                print("  - ERROR TIMEOUT")
                return None
            elif resdata['value'][0]['status'] == 'Failed':
                print("] - ERROR EXECUTION FAILED. BINARY ALREADY RUNNING?")
                sys.exit(1)
        print("]") 
        print("    + DONE")
        #DEBUG PRINT
        #print("    + Index_task: {}".format(index_task))
        print("    + Task_id: {}".format(task_id))

        url = "https://api.securitycenter.microsoft.com/api/machineactions/{}/GetLiveResponseResultDownloadLink(index={})".format(task_id,index_task)
        headers = { 
            'Authorization' : "Bearer " + token,
        }
        response = requests.get(url, headers=headers)
        data = response.json()
        return data['value'], task_id
        
                

def get_execution_output(token, vendor, actionid):
    
    if vendor == "MDATP":
        index = 0 # Default index. The script executed is always the first one
        url = "https://api-eu.securitycenter.microsoft.com/api/machineactions/{}".format(actionid)
        headers = { 
            'Authorization' : "Bearer " + token,
        }
        # Monitorize execution status
        response = requests.get(url, headers=headers)
    
        if response.status_code != 200:
            print("  + ERROR: Execution failed: {}".format(response.text))
            return None

        resdata = json.loads(response.text)

        print("    + EXECUTING COMMAND: [", end="")
        count = 0
        while resdata['status'] != 'Succeeded':
            response = requests.get(url, headers=headers)
            if response.text:
                resdata = json.loads(response.text)
                # Print point without space to avoid new line, in realtime in console witouh buffering
                print("·", end="", flush=True)
                time.sleep(5)
                count += 1
                if count == 120:
                    print("]")
                    print("  - ERROR TIMEOUT")
                    return None
                elif resdata['status'] == 'Failed':
                    print("] - ERROR EXECUTION FAILED. BINARY ALREADY RUNNING?")
                    return resdata['status']
            else:
                resdata = None
                print('Warning: Response text is empty')    
        print("]") 
        print("    + DONE")

        # Get output
        url = "https://api.securitycenter.microsoft.com/api/machineactions/{}/GetLiveResponseResultDownloadLink(index={})".format(actionid, index)
        response = requests.get(url, headers=headers)
        return response.text
    
def decode_command_script(command):
    decoded_command = base64.b64decode(command).decode('utf-8')
    return decoded_command

def parse_json_actionsid(json_string):
    data = json.loads(json_string)
    id = data['value'][0]['id']
    return id

def parse_json(json_string,command):
    # Load the JSON string into a Python dictionary
    json_dict = json.loads(json_string)
    
    # Access the values in the dictionary
    exit_code = json_dict["exit_code"]
    script_errors = json_dict["script_errors"]
    script_name = json_dict["script_name"]
    script_output = json_dict["script_output"]
    
    if exit_code != 0:
        print("    + ERROR: Script execution failed: {}".format(script_errors))
    else:
        print("    + SCRIPT EXECUTION DONE WITH EXIT CODE: {}".format(exit_code))
        decoded_command = decode_command_script(command)
        print("    + SCRIPT COMMAND EXECUTION: {}".format(decoded_command))
        print("    + SCRIPT OUTPUT: {}".format(script_output))
        
def delete_action(token, vendor, delete_actionid):
    if vendor == "MDATP":
        url = "https://api.securitycenter.microsoft.com/api/machineactions/{}/cancel".format(delete_actionid)
        headers = { 
            'Authorization' : "Bearer " + token,
            'Content-Type': 'application/json'
        }
        data = {
            "Comment":"Vlad Live Response Automations cancelled id {}".format(delete_actionid)
        }

        response = requests.post(url, headers=headers, json=data)

        if response.status_code == 200: 
            print("  + PENDING TASK DELETED: {}".format(delete_actionid))
        else:
            print("    - API error: {}".format(response.status_code))
            print("    - API error: {}".format(response))
        time.sleep(10)

def download_file(token, vendor, path, machineid, downod):
    actionid = None
    if vendor == "MDATP":
        url = "https://api.securitycenter.microsoft.com/api/machines/{}/runliveresponse".format(machineid)
        headers = { 
            'Authorization' : "Bearer " + token,
            'Content-Type': 'application/json'
        }
        data = {
            "Commands":[
                {
                    "type":"GetFile",
                    "params":[
                        {
                            "key":"Path",
                            "value": path
                        }
                    ]
                }
            ],
            "Comment":"Vlad Live Response Automations"
        }
        response = requests.post(url, headers=headers, json=data)
        if response.status_code != 200 and response.status_code != 201:
            print("    + ERROR: Execution failed: {}".format(response.text))
            return None
        print("    + EXECUTION DONE WITH STATUS CODE: {}".format(response.status_code))
        url_to_download, task_id = waiting_download_execution(token, vendor, machineid)
        #DEBUG PRINT
        #print("    + DOWNLOADING FILE FROM : {}".format(url_to_download))
        path = path.replace("\\", "/")
        path_object = pathlib.Path(path)
        filename = path_object.name
        filename_path = "{}/{}_{}.gz".format(downod,task_id,filename)
        filename_output = "{}/{}_{}".format(downod,task_id,filename)
        print("    + SAVING FILE TO : {}".format(filename_path))
        urllib.request.urlretrieve(url_to_download, filename_path)
        print("    + DECOMPRESSING FILE TO : {}".format(filename_output))
        decompress_gz_file(filename_path,filename_output)

def decompress_gz_file(input_path, output_path):
    try:
        with gzip.open(input_path, 'rb') as f_in:
            with open(output_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)      
    except IOError as e:  
        print("    - DECOMPRESS ERROR: Error {}".format(e))

def cleanup_files(token, vendor, filename):
    print ("    + CLEANING UP FILE: {}".format(filename))
    if vendor == "MDATP":
        url = "https://api.securitycenter.microsoft.com/api/libraryfiles/{}".format(filename)
        headers = { 
            'Authorization' : "Bearer " + token,
        }
        response = requests.delete(url, headers=headers)
        return response    
    
def list_library(token, vendor,print_output=True):
    if vendor == "MDATP":
        url = "https://api.securitycenter.microsoft.com/api/libraryfiles"
        headers = { 
            'Authorization' : "Bearer " + token,
        }
        response = requests.get(url, headers=headers)
        formatted_json = response.json()
        files_info = []  
        if print_output:
            print("    + OUTPUT:")
        for file in formatted_json['value']:
            file_info = {
                'fileName': file.get('fileName', 'N/A'),
                'description': file.get('description', 'N/A'),
                'sha256': file.get('sha256', 'N/A'),
                'createdBy': file.get('createdBy', 'N/A')
        }
            files_info.append(file_info) 
            if print_output:
                formatted_output = "        - fileName: {fileName}, description: {description}, sha256: {sha256}, createdBy: {createdBy}".format(**file_info)
                print(formatted_output)  
        return files_info

def cleanup_all_files(token, vendor):
    files_info = list_library(token, vendor,print_output=False)
    files_to_delete = [file for file in files_info if "Vlad" in file['description']]
    if not files_to_delete: 
        print("  + NO FILES FOUND WITH 'Vlad' IN THEIR DESCRIPTION.")
        return
    for file in files_to_delete:
        print("    + Deleting file: {}".format(file['fileName']))
        cleanup_files(token, vendor,file['fileName'])  
        time.sleep(1)

def get_args():
    argparser = argparse.ArgumentParser(
        description='Alpine The Vlad Tool - Version {}'.format(VERSION))

    argparser.add_argument('-V', '--version',
                            action='version', 
                            version='%(prog)s {}'.format(VERSION))

    argparser.add_argument('-c', '--client',
                           required=True,
                           action='store',
                           help='Client target')

    argparser.add_argument('-v', '--vendor',
                           required=True,
                           action='store',
                           help='Vendor target')
    
    argparser.add_argument('-l', '--list_endpoints',
                           required=False,
                           action='store_true', 
                           help='List every endpoint in the client with theese vendor.')

    argparser.add_argument('-s', '--search_endpoints',
                           required=False,
                           action='store',
                           help='Search partial/literal endpoints by name')

    argparser.add_argument('-x', '--command',
                           required=False,
                           action='store',
                           help='Command to execute in base64 format')

    argparser.add_argument('-m', '--machineid',
                           required=False,
                           action='store',
                           help='Machine ID to execute command.')

    argparser.add_argument('-b', '--binary',
                           required=False,
                           action='store',
                           help='Binary to upload and execute. -x required')
    
    argparser.add_argument('-d', '--download_file',
                           required=False,
                           action='store',
                           help='Download the file indicated in the path. -c required')
    
    argparser.add_argument('-f', '--force_action',
                           required=False,
                           action='store_true',
                           help='Force the execution of the action.')
    
    argparser.add_argument('-k', '--clear_file',
                           required=False,
                           action='store',
                           help='Clear files from live response library.')
    
    argparser.add_argument('-e', '--list_library_uploads',
                           required=False,
                           action='store_true',
                           help='List files uploaded from live response library.')
    
    argparser.add_argument('-a', '--clear_all_files',
                           required=False,
                           action='store_true',
                           help='Clear all files from live response library.')

    args = argparser.parse_args()

    return args

def main():

    args = get_args()
    client = args.client
    vendor = args.vendor
    command = args.command
    binary = args.binary
    endlist = args.list_endpoints
    machineid = args.machineid
    searchstr = args.search_endpoints
    downloadfile = args.download_file
    force_action = args.force_action
    clearfile = args.clear_file
    listlibrary = args.list_library_uploads
    clearallfiles = args.clear_all_files


# Parse config file
    
    config_name = 'vlad.yaml'

    # determine if application is a script file or frozen exe
    if getattr(sys, 'frozen', False):
        INSTALL_PATH = os.path.dirname(sys.executable)
    elif __file__:
        INSTALL_PATH = os.path.dirname(__file__)

    configapifile = os.path.join(INSTALL_PATH, config_name)

    #Check if config file exists
    if not os.path.exists(configapifile):
        print("    - ERROR: Config file not found")
        sys.exit(1)

    api_clients, apicred = parse_config(configapifile)

# Create tmp folder
    tmpod = os.path.join(INSTALL_PATH, 'tmp')
    if not os.path.exists(tmpod):
        os.makedirs(tmpod)

# Create Dowload folder
    downod = os.path.join(INSTALL_PATH, 'downloads')
    if not os.path.exists(downod):
        os.makedirs(downod)    

# Authenticate
    if client not in api_clients:
        print("Client not found in config file")
        sys.exit(1)
    if vendor != "MDATP":
        print("Vendor not supported")
        sys.exit(1)
    else:
        token = mdatp_auth(client, apicred)

    if not token:
        print("    - ERROR: No token received")
        sys.exit(1)

    if endlist:
        print()
        print("  - LIST {} {} ENDPOINTS".format(vendor, client))
        print()
        list_endpoints(token, vendor)
        sys.exit(0)

    if searchstr:
        print("  - SEARCH {} {} ENDPOINTS".format(vendor, client))
        print()
        list_endpoints(token, vendor, searchstr)
        sys.exit(0)  

    if force_action:
        force_action = True
        print("- LOOKING FOR PENDING TASKS TO BE CANCELLED")
        get_pending_actions(token, vendor, machineid)
      
    if downloadfile:
        print("- DOWNLOAD FILE {} FROM MACHINE ID {}".format(downloadfile, machineid))
        download_file(token, vendor, downloadfile, machineid, downod)
        sys.exit(0) 

    if clearfile:
        print("- DELETE FILE {} FROM LIVE RESPONSE LIBRARY".format(clearfile))
        cleanup_files(token, vendor, clearfile)
        sys.exit(0) 

    if listlibrary:
        print("- SHOW FILES FROM LIVE RESPONSE LIBRARY")
        list_library(token,vendor, print_output=True)
        sys.exit(0) 
        
    if clearallfiles:
        print("- DELETE ALL FILES FROM LIVE RESPONSE LIBRARY")
        cleanup_all_files(token, vendor)
        sys.exit(0)
    

    if not command:
        print("  - ERROR: No command received")
        sys.exit(1)

    if not client:
        print("  - ERROR: No client received")
        sys.exit(1)
    
    if not vendor:
        print("  - ERROR: No vendor received")
        sys.exit(1)

    if not machineid:
        print("  - ERROR: No machineid received")
        sys.exit(1)

    if not token:
        print("  - ERROR: No token received")
        sys.exit(1)

    

    # Create tmp output file with random beauty name
    ps1of = os.path.join(tmpod, 'vlad-{}.ps1'.format(os.urandom(4).hex()))   

    # Generate script
    script = generate_command_script(command, ps1of) 

    # Upload file
    response, uscript = upload_file(token, vendor, ps1of)

    ubinary = None
    if binary:
        response, ubinary = upload_file(token, vendor, binary)
        putactid = put_file(token, vendor, machineid, ubinary)
        print("    + PUT FILE ACTION ID: {}".format(putactid))
        time.sleep(5)
        if putactid:
            output = get_execution_output(token, vendor, putactid)
            if output == 'Failed':
                cleanup_files(token, vendor, uscript)
                print("    + ERROR: PutFile failed")
                sys.exit(1)
        else:
            print("    + ERROR: No PutFile actionid received")
            cleanup_files(token, vendor, uscript)
            sys.exit(1)
            

    # Execute command
    print("- EXECUTING SCRIPT: {}".format(ps1of))
    exeactid = execute_command(token, vendor, machineid, uscript)
    print("    + SCRIPT ACTION ID: {}".format(exeactid))

    # Wait until actionid appear on systems
    time.sleep(5)

    if exeactid:
        output = get_execution_output(token, vendor, exeactid)
    else:
        print("  + ERROR: No RunScript actionid received")
        cleanup_files(token, vendor, uscript)
        sys.exit(1)
    
    if not output:
        print("  + ERROR: No RunScript output received")
        cleanup_files(token, vendor, uscript)
        sys.exit(1)

    resdata = json.loads(output)

    if 'error' in resdata:
        print("  + ERROR {}: {}".format(resdata['error']['code'], resdata['error']['message']))
        # Cleanup files
        cleanup_files(token, vendor, uscript)
        print("  + SCRIPT {} CLEANED: {}".format(uscript, response))
        if binary:
            cleanup_files(token, vendor, ubinary)
            print("  + BINARY {} CLEANED: {}".format(ubinary, response))

    # Download output
    #DEBUG PRINT
    #print("    + DOWNLOADING OUTPUT: {}".format(resdata['value']))
    url = resdata['value']
    response = requests.get(url)
    data = response.json()
    

    # Print json beauty in console
    print("    + PRINTING JSON OUTPUT: ")
     #print(json.dumps(data, indent=4, sort_keys=True))
    json_string=(json.dumps(data, indent=4, sort_keys=True))
    parse_json(json_string,command)
    
    

    # Cleanup files
    cleanup_files(token, vendor, uscript)
    print("    + SCRIPT {} CLEANED: {}".format(uscript, response))
    if binary:
        cleanup_files(token, vendor, ubinary)
        print("  + BINARY {} CLEANED: {}".format(ubinary, response))

# *** MAIN LOOP ***
if __name__ == '__main__':
    main()
#!/usr/bin/env python3

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
INSTALL_PATH = os.path.dirname(os.path.abspath(__file__)) # represents the path where the script is located


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
        headers = { 
            'Authorization' : "Bearer " + token,
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200: 
            #Create a header for the output with this fields:
            #Computer Name, ID, OS, IP, Last Seen, Health Status, Onboarding Status
            first_time_headers = True
            host_found = False
            host_info = None
            for machine in response.json()['value']:
                if search and machine['healthStatus'] == 'Active' and machine['onboardingStatus'] == 'Onboarded':
                    if search in machine['computerDnsName']:   
                        host_found = True
                        if first_time_headers == True:
                            print_headers_list_endpoints()
                            first_time_headers = False
                        host_info = "    {:<30} {:<45} {:<15} {:<20} {:<30} {:<10} {:<20}".format(machine['computerDnsName'], machine['id'], machine['osPlatform'], machine['lastIpAddress'], machine['lastSeen'], machine['healthStatus'], machine['onboardingStatus'])
                    
                elif machine['healthStatus'] == 'Active' and machine['onboardingStatus'] == 'Onboarded':
                    if first_time_headers == True:
                        print_headers_list_endpoints()
                        first_time_headers = False
                    host_found = True
                    print("    {:<30} {:<45} {:<15} {:<20} {:<30} {:<10} {:<20}".format(machine['computerDnsName'], machine['id'], machine['osPlatform'], machine['lastIpAddress'], machine['lastSeen'], machine['healthStatus'], machine['onboardingStatus']))
                    print()
            if host_found == False:
                print("    Endpoint not found!")
                print()
            else:
                if host_info != None:
                    print(host_info)
                    print()  
        else:
            print("    - API error: {}".format(response.status_code))     

def generate_command_script(command, output_file):
    decoded_command = base64.b64decode(command).decode('utf-8')
    with open(output_file, 'w') as f:
        f.write(decoded_command)

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
            description = "Jungl3 Remote Execution Script"
        else:
            print("- UPLOADING BINARY {} TO MDATP LIVE RESPONSE LIBRARY".format(filename))
            description = "Jungl3 Uploaded Binary"

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
            "Comment":"Jungl3 Live Response Automations"
        }

        response = requests.post(url, headers=headers, json=data)
        if response.status_code != 200 and response.status_code != 201:
            print("  + ERROR: Execution failed: {}".format(response.text))
            return None
        print("  + PUT FILE DONE WITH STATUS CODE: {}".format(response.status_code))
        statusdata = json.loads(response.text)
        print("    + DEBUG: {}".format(statusdata))
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
            "Comment":"Jungl3 Live Response Automations"
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

        #with open("/tmp/testing.txt", 'w') as f:
        # Convierte 'resdata' a una cadena de texto y escribe el contenido en 'f'
         #   f.write(json.dumps(resdata))
        
        print("    + STATUS: {}".format(resdata['value'][0]['status']))
        print("    + TASK ID: {}".format(resdata['value'][0]['id'])) 
        print("    + INDEX: {}".format(resdata['value'][0]['commands'][0]['index'])) 
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

        print("    + Index_task: {}".format(index_task))
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
            "Comment":"Jungl3 Live Response Automations cancelled id {}".format(delete_actionid)
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
            "Comment":"Jungl3 Live Response Automations"
        }
        response = requests.post(url, headers=headers, json=data)
        if response.status_code != 200 and response.status_code != 201:
            print("    + ERROR: Execution failed: {}".format(response.text))
            return None
        print("    + EXECUTION DONE WITH STATUS CODE: {}".format(response.status_code))
        url_to_download, task_id = waiting_download_execution(token, vendor, machineid)
        print("    + DOWNLOADING FILE FROM : {}".format(url_to_download))
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
    with gzip.open(input_path, 'rb') as f_in:
        with open(output_path, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)        
    
def cleanup_files(token, vendor, filename):
    if vendor == "MDATP":
        url = "https://api.securitycenter.microsoft.com/api/libraryfiles/{}".format(filename)
        headers = { 
            'Authorization' : "Bearer " + token,
        }
        response = requests.delete(url, headers=headers)
        return response    
        

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
                           action='store_true', # store_true means that if the argument is present, it will be set to True	
                           help='Command to execute in base64 format')

    argparser.add_argument('-s', '--search_endpoints',
                           required=False,
                           action='store',
                           help='Search endpoints by name')

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
                           help='Download the file indicated in the path. -c required and must be MDATP')
    
    argparser.add_argument('-f', '--force_action',
                           required=False,
                           action='store_true',
                           help='Force the execution of the action. . -x required')

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

# Parse config file
    configapifile = "{}/vlad.yaml".format(INSTALL_PATH)
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
    ps1of = os.path.join(tmpod, 'j3-{}.ps1'.format(os.urandom(4).hex()))   

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
                print("    + ERROR: PutFile failed")
                sys.exit(1)
        else:
            print("    + ERROR: No PutFile actionid received")
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
        sys.exit(1)
    
    if not output:
        print("  + ERROR: No RunScript output received")
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
    
    print("    + DOWNLOADING OUTPUT: {}".format(resdata['value']))
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
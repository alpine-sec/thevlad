import os
import json
import time
import pathlib
import requests

from libs.utils import parse_json_actionsid, decompress_gz_file, print_headers_list_endpoints
from libs.utils import print_formatted_machine

BASEURL = "https://api-eu.securitycenter.microsoft.com"

def mdatp_auth(client, apicred):

    tenantId = getattr(getattr(getattr(apicred, client), "MDATP"), "TENANTID")
    appId = getattr(getattr(getattr(apicred, client), "MDATP"), "APPID")
    appSecret = getattr(getattr(getattr(apicred, client), "MDATP"), "APPSECRET")

    url = "https://login.microsoftonline.com/{}/oauth2/token".format(tenantId)

    body = {
        'resource' : BASEURL,
        'client_id' : appId,
        'client_secret' : appSecret,
        'grant_type' : 'client_credentials'
    }

    try:
        response = requests.post(url, data=body)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print("    - MDATP AUTH API ERROR: {}".format(e))
        return False
    jsonResponse = response.json()
    aadToken = jsonResponse["access_token"]

    return aadToken

def mdatp_list_endpoints(token, search=None): 
    url = "{}/api/machines".format(BASEURL)
    first_time_headers = True
    while True:   
        headers = { 
            'Authorization' : "Bearer " + token,
        }
        try:
            response = requests.get(url, headers=headers)
        except requests.exceptions.RequestException as e:
            print("    - MDATP LIST ENDPOINT API ERROR: Error {}".format(e))
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
                        print_formatted_machine(machine, "MDATP")
                elif machine['healthStatus'] == 'Active' and machine['onboardingStatus'] == 'Onboarded':
                    if first_time_headers == True:
                        print_headers_list_endpoints()
                        first_time_headers = False
                    host_found = True
                    print_formatted_machine(machine, "MDATP")
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

def mdatp_upload_file(token, file_path):
    url = "{}/api/libraryfiles".format(BASEURL)
    headers = { 
        'Authorization' : "Bearer " + token,
    }

    filename = os.path.basename(file_path)
    # Check if file extesion is .ps1
    if filename.endswith('.ps1') or filename.endswith('.sh'):
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
    try:
        response = requests.post(url, headers=headers, data=data, files=files)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("    - MDATP UPLOAD FILE API ERROR: Error {}".format(e))
        return None

    return response, filename


def mdatp_put_file(token, machineid, binary):
    actionid = None
    url = "{}/api/machines/{}/runliveresponse".format(BASEURL, machineid)
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
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("    - MDATP PUT FILE API ERROR: Error {}".format(e))
        return None

    if response.status_code != 200 and response.status_code != 201:
        print("  + MDATP ERROR: Put file failed: {}".format(response.text))
        return None

    print("  + MDATP PUT FILE DONE WITH STATUS CODE: {}".format(response.status_code))
    statusdata = json.loads(response.text)
    actionid = statusdata['id']
    return actionid

def mdatp_execute_command(token, machineid, script):
    actionid = None
    url = "{}/api/machines/{}/runliveresponse".format(BASEURL, machineid)
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
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("    - MDATP EXECUTE COMMAND API ERROR: Error {}".format(e))
        return None

    if response.status_code != 200 and response.status_code != 201:
        print("    + MDATP ERROR: Execution failed: {}".format(response.text))
        return None
    print("    + EXECUTION TASK GENERATED WITH STATUS CODE: {}".format(response.status_code))
    statusdata = json.loads(response.text)
    actionid = statusdata['id']

    return actionid

def mdatp_delete_action(token, delete_actionid):

    url = "{}/api/machineactions/{}/cancel".format(BASEURL, delete_actionid)
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

def mdatp_delete_pending_actions(token, machineid):

    url = "{}/api/machineactions?$filter=machineId eq '{}' and status eq 'Pending'".format(BASEURL, machineid)
    headers = { 
        'Authorization' : "Bearer " + token,
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("    - MDATP PENDING ACTIONS API ERROR: Error {}".format(e))
        return None

    if response.status_code != 200:
        print("  + MDATP ERROR: Execution failed: {}".format(response.text))
        return None
    respdata = response.json()
    if not respdata['value']:
        print("  + NO PENDING ACTIONS FOUND")
        return None
    else:
        id = parse_json_actionsid(response.text)
        print("  + MDATP PENDING ACTIONS: {}".format(id))
        mdatp_delete_action(token, id)

def mdatp_waiting_download_execution(token, machineid):
    url = "{}/api/machineactions?$filter=machineId eq '{}'".format(BASEURL, machineid)
    headers = { 
        'Authorization' : "Bearer " + token,
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("    - MDATP DOWNLOAD MACHINE ACTIONS I API ERROR: Error {}".format(e))
        return None, None
    
    if response.status_code != 200:
        print("  + ERROR: Execution failed: {}".format(response.text))
        return None, None
    resdata = json.loads(response.text)
    print("    + STATUS: {}".format(resdata['value'][0]['status']))
    print("    + TASK ID: {}".format(resdata['value'][0]['id'])) 
    #DEBUG PRINT
    #print("    + INDEX: {}".format(resdata['value'][0]['commands'][0]['index'])) 
    index_task = resdata['value'][0]['commands'][0]['index']  
    task_id = resdata['value'][0]['id']     

    print("    + WAITING FOR THE MDATP TASK TO BE COMPLETED: [", end="")
    count = 0
    while resdata['value'][0]['status'] != 'Succeeded':
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print("] - MDATP DOWNLOAD MACHINE ACTIONS II API ERROR: Error {} - Try again in 5 seconds".format(e))
            count += 1
            if count >= 120:
                print("] - ERROR DOWNLOAD EXECUTION TIMEOUT")
                return None, None
            time.sleep(5)
            continue

        resdata = json.loads(response.text)
        # Print point without space to avoid new line, in realtime in console witouh buffering
        print("·", end="", flush=True)
        time.sleep(5)
        count += 1
        if count >= 120:
            print("]")
            print("  - ERROR DOWNLOAD EXECUTION TIMEOUT")
            return None, None
        elif resdata['value'][0]['status'] == 'Failed':
            print("] - ERROR DOWNLOAD EXECUTION FAILED. BINARY ALREADY RUNNING?")
            return None, None

    print("] - DONE") 
    #DEBUG PRINT
    #print("    + Index_task: {}".format(index_task))
    print("    + Task_id: {}".format(task_id))

    url = "{}/api/machineactions/{}/GetLiveResponseResultDownloadLink(index={})".format(BASEURL, task_id, index_task)
    headers = { 
        'Authorization' : "Bearer " + token,
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("    - MDATP DOWNLOAD EXECUTION API ERROR: Error {}".format(e))
        return None, None

    data = response.json()
    return data['value'], task_id

def mdatp_get_execution_output(token, actionid, action=None):

    index = 0 # Default index. The script executed is always the first one
    url = "{}/api/machineactions/{}".format(BASEURL, actionid)
    headers = { 
        'Authorization' : "Bearer " + token,
    }
    # Monitorize execution status
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("    - MDATP GET MACHINE EXECUTION ACTIONS I API ERROR: Error {}".format(e))
        return None

    if response.status_code != 200:
        print("  + ERROR: Execution failed: {}".format(response.text))
        return None

    resdata = json.loads(response.text)

    print("    + WAITING FOR EXECUTION OUTPUT: [", end="")
    count = 0
    while resdata['status'] != 'Succeeded':
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print("] - MDATP GET MACHINE EXECUTION ACTIONS II API ERROR: Error {} - Try again in 5 seconds".format(e))
            count += 1
            time.sleep(5)
            if count >= 120:
                print("] - MDATP ERROR TIMEOUT")
                return
            continue
        if response.text:
            resdata = json.loads(response.text)
            # Print point without space to avoid new line, in realtime in console witouh buffering
            print("·", end="", flush=True)
            time.sleep(5)
            count += 1
            if count == 120:
                print("]")
                print("  - MDATP ERROR TIMEOUT")
                return None
            elif resdata['status'] == 'Failed':
                print("] - MDATP ERROR EXECUTION FAILED. BINARY ALREADY RUNNING?")
                return resdata['status']
        else:
            resdata = None
            print('  - MDATP WARNING: Response text is empty')    
    print("] - DONE")

    #print ("    + DEBUG: {} - {} - {}".format(resdata, actionid, index))
    if resdata:
        if resdata['commands'][0]['command']['type'] == "PutFile":
            return resdata['commands'][0]['commandStatus']

    time.sleep(5)

    # Get output
    url = "{}/api/machineactions/{}/GetLiveResponseResultDownloadLink(index={})".format(BASEURL, actionid, index)
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("    - MDATP GET EXECUTION OUTPUT API ERROR: Error {}".format(e))
        return None
    return response.text

def mdatp_download_file(token, path, machineid, downod):
    actionid = None

    url = "{}/api/machines/{}/runliveresponse".format(BASEURL, machineid)
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
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("    - MDATP DOWNLOAD FILE API ERROR: Error {}".format(e))
        return None

    if response.status_code != 200 and response.status_code != 201:
        print("    + ERROR: Execution failed: {}".format(response.text))
        return None

    print("    + TASK DONE WITH STATUS CODE: {}".format(response.status_code))
    url_to_download, task_id = mdatp_waiting_download_execution(token, machineid)
    if url_to_download == None:
        return None
    #DEBUG PRINT
    #print("    + DOWNLOADING FILE FROM : {}".format(url_to_download))
    path = path.replace("\\", "/")
    path_object = pathlib.Path(path)
    filename = path_object.name
    filename_path = "{}/{}_{}.gz".format(downod,task_id,filename)
    filename_output = "{}/{}_{}".format(downod,task_id,filename)
    print("    + SAVING FILE TO : {}".format(filename_path))

    try:
        with requests.get(url_to_download, stream=True) as response:
            response.raise_for_status()
            with open(filename_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
    except requests.exceptions.RequestException as e:
        print("    - DOWNLOAD FILE ERROR: {}".format(e))
        return None
        
    print("    + DECOMPRESSING FILE TO : {}".format(filename_output))
    decompress_gz_file(filename_path, filename_output)

def mdatp_cleanup_file(token, filename):
    print ("    + CLEANING UP FILE: {}".format(filename))
    url = "{}/api/libraryfiles/{}".format(BASEURL, filename)
    headers = { 
        'Authorization' : "Bearer " + token,
    }
    try:
        response = requests.delete(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("    - MDATP CLEAN UP FILE API ERROR: Error {}".format(e))
        return False
    return response
    
def mdatp_list_library(token,print_output=True):
    url = "{}/api/libraryfiles".format(BASEURL)
    headers = { 
        'Authorization' : "Bearer " + token,
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("    - MDATP LIST LIBRARY API ERROR: Error {}".format(e))
        return None

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

def mdatp_cleanup_all_files(token):
    files_info = mdatp_list_library(token,print_output=False)
    files_to_delete = [file for file in files_info if file['description'] is not None and "Vlad" in file['description']]
    if not files_to_delete: 
        print("  + NO FILES FOUND WITH 'Vlad' IN THEIR DESCRIPTION.")
        return
    for file in files_to_delete:
        count = 0
        while count < 5:
            check = mdatp_cleanup_file(token, file['fileName'])
            if check:
                time.sleep(5)
                break
            else:
                count += 1
                print ("    - ERROR DELETING FILE: {} - Try again in 10 seconds {}/5".format(file['fileName'],count))
                time.sleep(10)
        if count == 5:
            print ("    - ERROR DELETING FILE: {} - MAX RETRIES REACHED".format(file['fileName']))

def mdatp_get_machine_info(token, machineid):
    url = "{}/api/machines/{}".format(BASEURL, machineid)
    headers = {
        'Authorization' : "Bearer " + token,
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print("  + MDATP GET MACHINE INFO API ERROR: Error {}".format(e))
        return None

    if response.status_code != 200:
        print("  + ERROR: Execution failed: {}".format(response.text))
        return None

    return response.json()
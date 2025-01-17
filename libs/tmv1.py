import os
import time
import json
import requests

from datetime import datetime, timedelta

from libs.utils import print_formatted_machine, print_headers_list_endpoints, decompress_zip_file


def tmv1_auth(client, apicred):

    aatmv1 = {}
    aatmv1["baseurl"] = getattr(getattr(getattr(apicred, client), "TMV1"), "BASEURL")
    aatmv1["token"] = getattr(getattr(getattr(apicred, client), "TMV1"), "TOKEN")

    return aatmv1

def tmv1_list_endpoints(aatmv1, search=None):
    count = 0
    first_time_headers = True

    token = aatmv1["token"]
    baseurl = aatmv1["baseurl"]

    url = "{}/v3.0/eiqs/endpoints".format(baseurl)

    query_params = {'top': 50}

    query = "(osName eq 'Windows') or (osName eq 'Linux') or (osName eq 'macOS') or (osName eq 'macOSX')"

    headers = {'TMV1-Query': query.encode('utf-8'),
               'Authorization': 'Bearer ' + token,
               'Content-Type': 'application/json;charset=utf-8'}

    try:
        response = requests.get(url, params=query_params, headers=headers)
    except requests.exceptions.RequestException as e:
        print("    - TMV1 LIST ENDPOINTS API ERROR: Error {}".format(e))
        return None
    
    if response.status_code == 200:
        host_found = False
        host_info = None
        jsonResponse = response.json()
        rawmachines = jsonResponse["items"]

        

        nexlink = jsonResponse["nextLink"]

        while nexlink:
            for m in rawmachines:
                machine = {}
                if not m['protectionManager']: # Skip machines without protection manager. Fix duplicates ids bug in TMV1 API
                    continue

                ip_data = m.get('ip', {})
                if not ip_data:
                    ip_data = 'N/A'
                ipaddress = ip_data.get('value', [])
                if not ipaddress:
                    ipaddress = 'N/A'
                else:
                    ipaddress = ipaddress[0]

                # Not show IPv6 addresses
                if ':' in ipaddress:
                    ipaddress = 'N/A'

                machine['ip'] = ipaddress

                platform = m['osName']
                machine['id'] = m['agentGuid']
                machine['name'] = m['endpointName']['value']
                machine['os'] = platform.title()
                machine['firstseen'] = ""
                machine['lastseen'] = m['loginAccount']['updatedDateTime']

                if '.' in machine['lastseen']:
                    dlastseen = datetime.strptime(machine['lastseen'], "%Y-%m-%dT%H:%M:%S.%fZ")
                else:
                    try:
                        dlastseen = datetime.strptime(machine['lastseen'], "%Y-%m-%dT%H:%M:%SZ")
                    except ValueError:
                        dlastseen = datetime.strptime(machine['lastseen'], "%Y-%m-%dT%H:%MZ")

                #if dlastseen is older than 1 month, set machine['sysstatus'] to "Inactive" and machine['edrstatus'] to "Inactive"
                if dlastseen < datetime.now() - timedelta(days=30):
                    machine['sysstatus'] = "Inactive"
                    machine['edrstatus'] = "Inactive"
                else:
                    machine['sysstatus'] = "Active"
                    machine['edrstatus'] = "Onboarded"

                #print("    - DEBUG: Machine: {}".format(machine))

                if search and machine['sysstatus'] == "Active":
                    if search in machine['name']:
                        host_found = True
                        if first_time_headers == True:
                            print_headers_list_endpoints()
                            first_time_headers = False
                        print_formatted_machine(machine, "TMV1")
                elif machine['sysstatus'] == "Active":
                    if first_time_headers == True:
                        print_headers_list_endpoints()
                        first_time_headers = False
                    host_found = True
                    print_formatted_machine(machine, "TMV1")
                    print()
                
            if "nextLink" in jsonResponse:
                nexlink = jsonResponse["nextLink"]
                #print("    - TMV1 API: Next link: {}".format(nexlink))
                try:
                    response = requests.get(nexlink, headers=headers)
                except requests.exceptions.RequestException as e:
                    print("    - TMV1 LIST ENDPOINTS NEXT API ERROR: Error {}".format(e))
                    nexlink = None
                if response.status_code == 200:
                    jsonResponse = response.json()
                    #print(jsonResponse)
                    rawmachines = jsonResponse["items"]
            else:
                nexlink = None


def tmv1_list_library(aatmv1, print_output=True):
    token = aatmv1["token"]
    baseurl = aatmv1["baseurl"]

    url = "{}/v3.0/response/customScripts".format(baseurl)

    headers = {'Authorization': 'Bearer ' + token,
               'Content-Type': 'application/json;charset=utf-8'}

    try:
        response = requests.get(url, headers=headers)
    except requests.exceptions.RequestException as e:
        print("    - TMV1 LIST LIBRARY API ERROR: Error {}".format(e))
        return None

    #print ("DEBUG: Response: {}".format(response))

    if response.status_code == 200:
        jsonResponse = response.json()
        rawscripts = jsonResponse["items"]

        if print_output:
            print("TREND VISION ONE Custom Scripts Library:\n")
            # Column widths based on typical content
            fmt = "{:<50} | {:<36} | {:<35} | {:<10}"
            
            # Headers
            print(fmt.format("Script Filename", "Script ID", "Script Description", "Script Type"))
            print("-" * 51 + "+" + "-" * 38 + "+"+ "-" * 37 + "+"+ "-" * 12)
            
            # Data rows
            for s in rawscripts:
                print(fmt.format(
                    s['fileName'][:49],
                    s['id'][:35], 
                    s['description'][:34],
                    s['fileType'][:9]
                ))
    if response.status_code == 403:
        print("    - TMV1 LIST LIBRARY ERROR: Access Denied. Please check your api permissions.")
        return None

def tmv1_upload_file(aatmv1, file_path):
    token = aatmv1["token"]
    baseurl = aatmv1["baseurl"]

    url = "{}/v3.0/response/customScripts".format(baseurl)
    filename = os.path.basename(file_path)

    # Determine file type
    if filename.endswith('.ps1'):
        file_type = 'powershell'
    elif filename.endswith('.sh'):
        file_type = 'bash'
    else:
        print("    - TMV1 UPLOAD FILE ERROR: Unsupported file type")
        return None, None

    headers = {
        'Authorization': 'Bearer ' + token
    }

    # Separate data dictionary as per documentation
    data = {
        'fileType': file_type,
        'description': "Vlad Remote Execution Script"
    }

    # Files with MIME type
    files = {
        'file': (filename, open(file_path, 'rb'), 'text/plain')
    }

    try:
        response = requests.post(
            url, 
            headers=headers,
            data=data,
            files=files
        )
        
        #print("DEBUG: Response: {}".format(response.text))
        
        if response.status_code == 201:
            print("    - TMV1 UPLOAD FILE: File uploaded successfully")
            return response, filename
        else:
            print("    - TMV1 UPLOAD FILE ERROR: Error {}".format(response.text))
            return None, None
            
    except requests.exceptions.RequestException as e:
        print("    - TMV1 UPLOAD FILE API ERROR: Error {}".format(e))
        return None, None
    finally:
        # Ensure file is closed
        if 'file' in files:
            files['file'][1].close()


def tmv1_execute_command(aatmv1, machineid, scriptof):
    token = aatmv1["token"]
    baseurl = aatmv1["baseurl"]

    filename = os.path.basename(scriptof)

    url = "{}/v3.0/response/endpoints/runScript".format(baseurl)

    headers = {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json;charset=utf-8'
    }

    query_params = {}

    # Body must be a list of dictionaries
    body = [{
        'agentGuid': machineid,
        'fileName': filename
    }]

    try:
        response = requests.post(url, headers=headers, json=body, params=query_params)
        response_json = response.json()
        #print("DEBUG: Response: {}".format(response_json))
        
        # Check individual response statuses
        if response.status_code == 207:
            for result in response_json:
                if result.get('status') == 403:
                    print("    - TMV1 EXECUTE COMMAND ERROR: Access Denied. Please check your api permissions.")
                    return None
                elif result.get('status') not in [200, 201, 202]:
                    print("    - TMV1 EXECUTE COMMAND ERROR: {}".format(result))
                    return None
            
            print("    + TMV1 EXECUTE COMMAND: Command sent successfully")
            statusdata = response.json()
            taskid = statusdata[0].get('headers', [{}])[0].get('value', '').split('/')[-1]
            return taskid

        else:
            print("    - TMV1 EXECUTE COMMAND ERROR: {}".format(response_json))
            return None
            
    except requests.exceptions.RequestException as e:
        print("    - TMV1 EXECUTE COMMAND API ERROR: Error {}".format(e))
        return None

def tmv1_cleanup_file(aatmv1, uscript):
    token = aatmv1["token"]
    baseurl = aatmv1["baseurl"]

    url = "{}/v3.0/response/customScripts".format(baseurl)

    headers = {
        'Authorization': 'Bearer ' + token
    }

    # Correct filter syntax without 'filter=' prefix in the value
    query_params = {
        'filter': "fileName eq '{}'".format(uscript)
    }

    try:
        response = requests.get(url, headers=headers, params=query_params)
        #print("DEBUG: Response: {}".format(response.text))

        if response.status_code == 200:
            scripts = response.json().get('items', [])
            if not scripts:
                print("    - TMV1 CLEANUP: Script not found")
                return None
                
            script_id = scripts[0].get('id')
            if script_id:
                # Delete the script using the ID
                delete_url = f"{baseurl}/v3.0/response/customScripts/{script_id}"
                delete_response = requests.delete(delete_url, headers=headers)
                
                if delete_response.status_code == 204:
                    print("    - TMV1 CLEANUP: Script deleted successfully")
                    return delete_response
                else:
                    print("    - TMV1 CLEANUP ERROR: Failed to delete script")
                    return None
        else:
            print("    - TMV1 CLEANUP ERROR: {}".format(response.text))
            return None
            
    except requests.exceptions.RequestException as e:
        print("    - TMV1 CLEANUP API ERROR: Error {}".format(e))
        return None

def tmv1_cleanup_all_files(aatmv1):
    token = aatmv1["token"]
    baseurl = aatmv1["baseurl"]

    url = "{}/v3.0/response/customScripts".format(baseurl)

    headers = {
        'Authorization': 'Bearer ' + token
    }


    try:
        response = requests.get(url, headers=headers)
        #print("DEBUG: Response: {}".format(response.text))

        if response.status_code == 200:
            scripts = response.json().get('items', [])
            if not scripts:
                print("    - TMV1 CLEANUP ALL: No scripts found")
                return None
                
            for script in scripts:
                script_id = script.get('id')
                description = script.get('description')
                if "Vlad" in description:
                    script_id = script.get('id')
                    script_name = script.get('fileName')
                    #print("DEBUG: Script ID: {}".format(script_id))
                    # Delete the script using the ID
                    delete_url = f"{baseurl}/v3.0/response/customScripts/{script_id}"
                    delete_response = requests.delete(delete_url, headers=headers)

                    if delete_response.status_code == 204:
                        print("    - TMV1 CLEANUP ALL: {} Script deleted successfully".format(script_name))
                    else:
                        print("    - TMV1 CLEANUP ALL ERROR: {} Failed to delete script".format(script_name))
                        return False
            return True
        else:
            print("    - TMV1 CLEANUP ALL ERROR: {}".format(response.text))
            return False

    except requests.exceptions.RequestException as e:
        print("    - TMV1 CLEANUP API ERROR: Error {}".format(e))
        return None

def tmv1_get_machine_info(aatmv1, machineid):
    token = aatmv1["token"]
    baseurl = aatmv1["baseurl"]

    url = "{}/v3.0/endpointSecurity/endpoints/{}".format(baseurl, machineid)

    headers = {
        'Authorization': 'Bearer ' + token
    }

    try:
        response = requests.get(url, headers=headers)
        #print("DEBUG: Response: {}".format(response.text))

        if response.status_code == 200:
            machine = response.json()
            endpointname = machine.get('endpointName', {})
            print("  + TMV1 CHECK ENDPOINT: Machine {} found".format(endpointname))
            return machine
        else:
            print("  + TMV1 CHECK ENDPOINT ERROR: {}".format(response.text))
            return None

    except requests.exceptions.RequestException as e:
        print("  + TMV1 CHECK ENDPOINT API ERROR: Error {}".format(e))
        return None


def tmv1_download_file(aatmv1, path, machineid, downod):
    token = aatmv1["token"]
    baseurl = aatmv1["baseurl"]

    url = "{}/v3.0/response/endpoints/collectFile".format(baseurl)

    headers = {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json;charset=utf-8'
    }

    # Body must be a list of dictionaries
    body = [{
        'agentGuid': machineid,
        'filePath': path,
        'description': 'Vlad Remote Download of {}'.format(path)
    }]
    #print("DEBUG: Body: {}".format(body))

    try:
        response = requests.post(url, headers=headers, json=body)
        response_json = response.json()
        #print("DEBUG: Response: {}".format(response_json))
        
        # Check individual response statuses
        if response.status_code == 207:
            for result in response_json:
                if result.get('status') == 403:
                    print("    - TMV1 DOWNLOAD FILE ERROR: Access Denied. Please check your api permissions.")
                    return None
                elif result.get('status') not in [200, 201, 202]:
                    print("    - TMV1 DOWNLOAD FILE ERROR: {}".format(result))
                    return None
            
            print("    - TMV1 DOWNLOAD FILE: File download request sent successfully")
            return response
        else:
            print("    - TMV1 DOWNLOAD FILE ERROR: {}".format(response_json))
            return None

    except requests.exceptions.RequestException as e:
        print("    - TMV1 DOWNLOAD FILE API ERROR: Error {}".format(e))
        return None


def tmv1_get_execution_output(aatmv1, taskid, timeout_minutes=10):
    valid_statuses = {
        'queued', 'running', 'succeeded', 'failed',
        'canceled', 'pendingApproval', 'rejected'
    }
    terminal_statuses = {'succeeded', 'failed', 'canceled', 'rejected'}
    
    start_time = time.time()
    timeout_seconds = timeout_minutes * 60

    print("    + WAITING FOR THE TMV1 TASK TO BE COMPLETED: [", end="")
    while (time.time() - start_time) < timeout_seconds:
        result = tmv1_get_execution_status(aatmv1, taskid)
        
        if not result or 'items' not in result or not result['items']:
            print("] - TMV1 WAIT EXECUTION: No valid response received")
            time.sleep(20)
            continue

        task = result['items'][0]
        status = task.get('status', '')
        print("·", end="", flush=True)

        if status not in valid_statuses:
            print(f"] - TMV1 WAIT EXECUTION: Unknown status: {status}")
            return None
            
        if status in terminal_statuses:
            print(f"] - DONE with Task status: {status}")
            return result
            
        time.sleep(30)
    
    print("] - TMV1 WAIT EXECUTION: Timeout after {} minutes".format(timeout_minutes))
    return None


def tmv1_get_execution_status(aatmv1, taskid):
    token = aatmv1["token"]
    baseurl = aatmv1["baseurl"]

    url = "{}/v3.0/response/tasks".format(baseurl)

    query_params = {
        'filter': "id eq '{}'".format(taskid)
    }

    headers = {
        'Authorization': 'Bearer ' + token
    }

    try:
        response = requests.get(url, headers=headers, params=query_params)
        response_json = response.json()
        #print("DEBUG: Response: {}".format(response_json))
        
        if response.status_code == 200:
            return response_json
        else:
            print("] - TMV1 GET EXECUTION OUTPUT ERROR: {}".format(response_json))
            return None

    except requests.exceptions.RequestException as e:
        print("] - TMV1 GET EXECUTION OUTPUT API ERROR: Error {}".format(e))
        return None

    return response_json

def tmv1_download_output(aatmv1, execdata):
    token = aatmv1["token"]
    baseurl = aatmv1["baseurl"]

    taskid = execdata.get('items', [{}])[0].get('id', '')
    
    url = "{}/v3.0/response/tasks/{}".format(baseurl, taskid)

    #print("DEBUG: Download URL: {}".format(url))
    
    headers = {
        'Authorization': 'Bearer ' + token
    }
    
    try:
        response = requests.get(url, headers=headers)
        response_json = response.json()
        #print("DEBUG: Download Response: {}".format(response_json))
        
        if response.status_code == 200:
            return response_json
        else:
            print(f"    - TMV1 DOWNLOAD OUTPUT ERROR: {response_json}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"    - TMV1 DOWNLOAD OUTPUT API ERROR: Error {e}")
        return None


def tmv1_extract_data(execdata, tmpod):
    if not execdata or 'resourceLocation' not in execdata:
        print("    - TMV1 EXTRACT: No valid resource location")
        return None
        
    url = execdata['resourceLocation']
    password = execdata.get('password', '')
    taskid = execdata['id']

    filename = "{}.7z".format(taskid)
    filename_path = "{}/{}".format(tmpod, filename)
    print("    + SAVING FILE TO : {}".format(filename_path))

    try:
        with requests.get(url, stream=True) as response:
            response.raise_for_status()
            with open(filename_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
    except requests.exceptions.RequestException as e:
        print("    - DOWNLOAD FILE ERROR: {}".format(e))
        return None

    output_path = "{}/{}".format(tmpod, taskid)
    print("    + EXTRACTING FILE TO : {}".format(output_path))
    decompress_zip_file(filename_path, output_path, password)

    return output_path


def tmv1_download_file(aatmv1, downloadfile, machineid):
    token = aatmv1["token"]
    baseurl = aatmv1["baseurl"]

    url = "{}/v3.0/response/endpoints/collectFile".format(baseurl)

    headers = {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json;charset=utf-8'
    }

    # Body must be a list of dictionaries
    body = [{
        'agentGuid': machineid,
        'filePath': downloadfile
    }]

    try:
        response = requests.post(url, headers=headers, json=body)
        response_json = response.json()
        #print("DEBUG: Response: {}".format(response_json))
        
        # Check individual response statuses
        if response.status_code == 207:
            for result in response_json:
                if result.get('status') == 403:
                    print("    - TMV1 DOWNLOAD FILE ERROR: Access Denied. Please check your api permissions.")
                    return None
                elif result.get('status') not in [200, 201, 202]:
                    print("    - TMV1 DOWNLOAD FILE ERROR: {}".format(result))
                    return None
            
            print("    - TMV1 DOWNLOAD FILE: File download request sent successfully")
            statusdata = response.json()
            taskid = statusdata[0].get('headers', [{}])[0].get('value', '').split('/')[-1]
            return taskid
        else:
            print("    - TMV1 DOWNLOAD FILE ERROR: {}".format(response_json))
            return None

    except requests.exceptions.RequestException as e:
        print("    - TMV1 DOWNLOAD FILE API ERROR: Error {}".format(e))
        return None

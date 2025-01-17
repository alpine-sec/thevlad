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
import os
import json
import sys
import requests
import time

from libs.utils import parse_config, generate_command_script, print_output_json
from libs.utils import print_output_txt

from libs.mdatp import mdatp_auth, mdatp_list_endpoints, mdatp_upload_file
from libs.mdatp import mdatp_put_file, mdatp_execute_command, mdatp_delete_pending_actions
from libs.mdatp import mdatp_get_execution_output, mdatp_download_file, mdatp_cleanup_file
from libs.mdatp import mdatp_list_library, mdatp_cleanup_all_files, mdatp_get_machine_info

from libs.tmv1 import tmv1_auth, tmv1_list_endpoints, tmv1_list_library, tmv1_upload_file
from libs.tmv1 import tmv1_execute_command, tmv1_cleanup_file, tmv1_cleanup_all_files
from libs.tmv1 import tmv1_get_machine_info, tmv1_get_execution_output, tmv1_download_output
from libs.tmv1 import tmv1_extract_data, tmv1_download_file

# GLOBAL VARIABLES
VERSION = '0.4'
INSTALL_PATH = os.path.dirname(os.path.abspath(__file__))

SUPPORTED_VENDORS= ["MDATP", "TMV1"]

def vlad_auth(client, vendor, apicred):
    if vendor == 'MDATP':
        token = mdatp_auth(client, apicred)
    elif vendor == 'TMV1':
        token = tmv1_auth(client, apicred)

    return token

def vlad_list_endpoints(token, vendor, searchstr=None):
    if vendor == 'MDATP':
        mdatp_list_endpoints(token, searchstr)
    elif vendor == 'TMV1':
        tmv1_list_endpoints(token, searchstr)

def vlad_delete_pending_actions(token, vendor, machineid):
    if vendor == 'MDATP':
        mdatp_delete_pending_actions(token, machineid)
    elif vendor == 'TMV1':
        print("    - ERROR: TMV1 does not support force action")

def vlad_download_file(token, vendor, downloadfile, machineid):
    # Create Download folder
    downod = os.path.join(INSTALL_PATH, 'downloads')
    if not os.path.exists(downod):
        os.makedirs(downod)

    if vendor == 'MDATP':
        mdatp_download_file(token, downloadfile, machineid, downod)
    elif vendor == 'TMV1':
        taskid = tmv1_download_file(token, downloadfile, machineid)
        if not taskid:
            print("    - ERROR: No TaskID received")
            return None
        print("    + SCRIPT TASK ID: {}".format(taskid))
        execdata = tmv1_get_execution_output(token, taskid)
        if not execdata:
            print("    - ERROR: No output received")
            return None
        output = tmv1_download_output(token, execdata)
        if not output:
            print("    - ERROR: No output received")
            return None
        output_path = tmv1_extract_data(output, downod)
        if not output_path:
            print("    - ERROR: No output path received. Extraction failed")
            return None

        print("    + FILE DOWNLOADED TO: {}".format(output_path))


def vlad_cleanup_file(token, vendor, clearfile):
    if vendor == 'MDATP':
        mdatp_cleanup_file(token, clearfile)
    elif vendor == 'TMV1':
        print("    - ERROR: TMV1 does not support clear file")

def vlad_list_library(token, vendor, print_output=False):
    if vendor == 'MDATP':
        print("- MDATP FILES FROM LIVE RESPONSE LIBRARY")
        mdatp_list_library(token, print_output)
    elif vendor == 'TMV1':
        tmv1_list_library(token, print_output)

def vlad_cleanup_all_files(token, vendor):
    if vendor == 'MDATP':
        mdatp_cleanup_all_files(token)
    elif vendor == 'TMV1':
        tmv1_cleanup_all_files(token)

def vlad_upload_file(token, vendor, file):
    if vendor == 'MDATP':
        return mdatp_upload_file(token, file)
    elif vendor == 'TMV1':
        return tmv1_upload_file(token, file)

def vlad_upload_binary(token, vendor, machineid, binary):
    if vendor == 'MDATP':
        response, ubinary = mdatp_upload_file(token, binary)
        putactid = mdatp_put_file(token, machineid, ubinary)
        print("    + PUT FILE ACTION ID: {}".format(putactid))
        time.sleep(5)
        if putactid:
            output = mdatp_get_execution_output(token, putactid)
            if output != 'Completed':
                mdatp_cleanup_file(token, uscript)
                print("    + ERROR: PutFile failed")
                return None, None
        else:
            print("    + ERROR: No PutFile actionid received")
            mdatp_cleanup_file(token, uscript)
            return None, None
    elif vendor == 'TMV1':
        print("    - ERROR: TMV1 does not support binary upload")
        return None, None

    return response, ubinary

def vlad_execute_command(token, vendor, machineid, scriptof, uscript):
    if vendor == 'MDATP':
        # Execute command
        print("- EXECUTING SCRIPT: {}".format(scriptof))
        exeactid = mdatp_execute_command(token, machineid, uscript)
        print("    + SCRIPT ACTION ID: {}".format(exeactid))

        # Wait until actionid appear on systems
        time.sleep(5)

        if exeactid:
            output = mdatp_get_execution_output(token, exeactid)
        else:
            print("  + ERROR: No RunScript actionid received")
            mdatp_cleanup_file(token, uscript)
            return None
        
        if not output:
            print("  + ERROR: No RunScript output received")
            mdatp_cleanup_file(token, uscript)
            return None

    elif vendor == 'TMV1':
        print("- EXECUTING SCRIPT: {}".format(scriptof))
        taskid = tmv1_execute_command(token, machineid, uscript)
        if not taskid:
            print("    - ERROR: No TaskID received")
            return None
        print("    + SCRIPT TASK ID: {}".format(taskid))
        output = tmv1_get_execution_output(token, taskid)

    return output

def vlad_get_execution_output(token, vendor, execdata):
    if vendor == 'MDATP':
        url = execdata['value']
        try:
            response = requests.get(url)
        except requests.exceptions.RequestException as e:
            print("    - MDATP GET EXECUTION OUTPUT API ERROR: Error {}".format(e))
            return None
        if response.status_code == 200:
            output = response.json()
        else:
            print("    - MDATP GET EXECUTION OUTPUT API ERROR: Error {}".format(response.status_code))
            return None
    elif vendor == 'TMV1':
        output = tmv1_download_output(token, execdata)
        #print ("    + SCRIPT GET EXECUTION OUTPUT: {}".format(output))

    return output

def vlad_print_output(output, vendor, command, tmpod=None):
    if vendor == 'MDATP':
        print_output_json(vendor, output, command)
    elif vendor == 'TMV1':
        report_path = tmv1_extract_data(output, tmpod)
        print_output_txt(vendor, report_path, command)

def vlad_cleanup_files(token, vendor, uscript, ubinary=None):
    if vendor == 'MDATP':
        check = mdatp_cleanup_file(token, uscript)
        if check:
            print("    + SCRIPT {} CLEANED".format(uscript))
        else:
            return False
        if ubinary:
            check = mdatp_cleanup_file(token, ubinary)
            if check:
                print("    + BINARY {} CLEANED".format(ubinary))
            else:
                return False
    elif vendor == 'TMV1':
        check = tmv1_cleanup_file(token, uscript)
        if check:
            print("    + SCRIPT {} CLEANED".format(uscript))
        else:
            return False

    return True

def vlad_get_machine_info(token, vendor, machineid):
    if vendor == 'MDATP':
        endpoint = mdatp_get_machine_info(token, machineid)
    elif vendor == 'TMV1':
        endpoint = tmv1_get_machine_info(token, machineid)

    return endpoint

def vlad_generate_output_file(tmpod, vendor, endpoint):
    if vendor == 'MDATP':
        osname = endpoint['osPlatform']
        if "windows" in osname.lower():
            ps1of = os.path.join(tmpod, 'vlad-{}.ps1'.format(os.urandom(4).hex()))
        else:
            ps1of = os.path.join(tmpod, 'vlad-{}.sh'.format(os.urandom(4).hex()))

    elif vendor == 'TMV1':
        osname = endpoint['os']['platform']
        if "windows" in osname.lower():
            ps1of = os.path.join(tmpod, 'vlad-{}.ps1'.format(os.urandom(4).hex()))
        else:
            ps1of = os.path.join(tmpod, 'vlad-{}.sh'.format(os.urandom(4).hex()))

    return ps1of


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
    
    argparser.add_argument('-d', '--collect_file',
                           required=False,
                           action='store',
                           help='Collect the machine file indicated in the path. -m required')
    
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
    downloadfile = args.collect_file
    force_action = args.force_action
    clearfile = args.clear_file
    listlibrary = args.list_library_uploads
    clearallfiles = args.clear_all_files


    # Get config file
    configapifile = "{}/vlad.yaml".format(INSTALL_PATH)

    #Check if config file exists
    if not os.path.exists(configapifile):
        print("    - ERROR: Config file not found")
        sys.exit(1)

    api_clients, apicred = parse_config(configapifile)

    # Create tmp folder
    tmpod = os.path.join(INSTALL_PATH, 'tmp')
    if not os.path.exists(tmpod):
        os.makedirs(tmpod)

    if client not in api_clients:
        print("Client not found in config file")
        sys.exit(1)
    if vendor not in SUPPORTED_VENDORS:
        print("Vendor {} not supported".format(vendor))
        sys.exit(1)
    
    token = vlad_auth(client, vendor, apicred)

    if not token:
        print("    - ERROR: No token received")
        sys.exit(1)

    if endlist:
        print()
        print("  - LIST {} {} ENDPOINTS".format(vendor, client))
        print()
        vlad_list_endpoints(token, vendor)
        sys.exit(0)

    if searchstr:
        print("  - SEARCH {} {} ENDPOINTS".format(vendor, client))
        print()
        vlad_list_endpoints(token, vendor, searchstr)
        sys.exit(0)  

    if force_action:
        force_action = True
        print("- LOOKING FOR PENDING TASKS TO BE CANCELLED")
        vlad_delete_pending_actions(token, vendor, machineid)
      
    if downloadfile:
        if not machineid:
            print("  - ERROR: machineid required to download file")
            sys.exit(1)
        print("- DOWNLOAD FILE {} FROM MACHINE ID {}".format(downloadfile, machineid))
        vlad_download_file(token, vendor, downloadfile, machineid)
        sys.exit(0) 

    if clearfile:
        print("- DELETE FILE {} FROM LIVE RESPONSE LIBRARY".format(clearfile))
        vlad_cleanup_file(token, vendor, clearfile)
        sys.exit(0) 

    if listlibrary:
        vlad_list_library(token, vendor, print_output=True)
        sys.exit(0) 
        
    if clearallfiles:
        print("- DELETE ALL VLAD FILES FROM LIVE RESPONSE LIBRARY")
        vlad_cleanup_all_files(token, vendor)
        sys.exit(0)

    if not command:
        print("  - ERROR: No command received")
        sys.exit(1)

    if not machineid:
        print("  - ERROR: No machineid received")
        sys.exit(1)

    print("- CHECKING MACHINE ID {}".format(machineid))
    endpoint =  vlad_get_machine_info(token, vendor, machineid)
    if not endpoint:
        print("  + ERROR: Endpoint {} not found".format(machineid))
        sys.exit(1)

    #print("DEBUGING: {}".format(endpoint))

    # Create tmp output file
    scriptof = vlad_generate_output_file(tmpod, vendor, endpoint)

    # Generate script
    script = generate_command_script(command, scriptof)

    # Upload file
    response, uscript = vlad_upload_file(token, vendor, scriptof)

    if binary:
        response, ubinary = vlad_upload_binary(token, vendor, machineid, binary)

    # Execute command

    execdata = vlad_execute_command(token, vendor, machineid, scriptof, uscript)

    if execdata:
        output = vlad_get_execution_output(token, vendor, execdata)
        if not output:
            print("    - ERROR: No output received")
    else:
        output = None
        print("    - ERROR: No execution data received")

    # Print Output
    if output:
        vlad_print_output(output, vendor, command, tmpod)

    # Cleanup files
    print ("- CLEANING UP FILES")
    if binary:
        check = vlad_cleanup_files(token, vendor, uscript, ubinary)
    else:
        check = vlad_cleanup_files(token, vendor, uscript)
    if not check:
        print("    - ERROR: Cleanup failed")
        sys.exit(1)
    else:
        print("    + CLEANUP SUCCESSFUL")

    print ("- END OF VLAD EXECUTION. Enjoy!")

    sys.exit(0)

# *** MAIN LOOP ***
if __name__ == '__main__':
    main()
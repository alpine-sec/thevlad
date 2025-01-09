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

from libs.utils import parse_config, generate_command_script, parse_json

from libs.mdatp import mdatp_auth, mdatp_list_endpoints, mdatp_upload_file
from libs.mdatp import mdatp_put_file, mdatp_execute_command, mdatp_get_pending_actions
from libs.mdatp import mdatp_get_execution_output, mdatp_download_file, mdatp_cleanup_file
from libs.mdatp import mdatp_list_library, mdatp_cleanup_all_files

# GLOBAL VARIABLES
VERSION = '0.2'
INSTALL_PATH = os.path.dirname(os.path.abspath(__file__))


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
                           help='Download the machine file indicated in the path. -m required')
    
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
        mdatp_list_endpoints(token)
        sys.exit(0)

    if searchstr:
        print("  - SEARCH {} {} ENDPOINTS".format(vendor, client))
        print()
        mdatp_list_endpoints(token, searchstr)
        sys.exit(0)  

    if force_action:
        force_action = True
        print("- LOOKING FOR PENDING TASKS TO BE CANCELLED")
        mdatp_get_pending_actions(token, machineid)
      
    if downloadfile:
        if not machineid:
            print("  - ERROR: machineid required to download file")
            sys.exit(1)
        print("- DOWNLOAD FILE {} FROM MACHINE ID {}".format(downloadfile, machineid))
        mdatp_download_file(token, downloadfile, machineid, downod)
        sys.exit(0) 

    if clearfile:
        print("- DELETE FILE {} FROM LIVE RESPONSE LIBRARY".format(clearfile))
        mdatp_cleanup_file(token, clearfile)
        sys.exit(0) 

    if listlibrary:
        print("- SHOW FILES FROM LIVE RESPONSE LIBRARY")
        mdatp_list_library(token, print_output=True)
        sys.exit(0) 
        
    if clearallfiles:
        print("- DELETE ALL VLAD FILES FROM LIVE RESPONSE LIBRARY")
        mdatp_cleanup_all_files(token)
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
    response, uscript = mdatp_upload_file(token, ps1of)

    ubinary = None
    if binary:
        response, ubinary = mdatp_upload_file(token, binary)
        putactid = mdatp_put_file(token, machineid, ubinary)
        print("    + PUT FILE ACTION ID: {}".format(putactid))
        time.sleep(5)
        if putactid:
            output = mdatp_get_execution_output(token, putactid)
            if output != 'Completed':
                mdatp_cleanup_file(token, uscript)
                print("    + ERROR: PutFile failed")
                sys.exit(1)
        else:
            print("    + ERROR: No PutFile actionid received")
            mdatp_cleanup_file(token, uscript)
            sys.exit(1)
            

    # Execute command
    print("- EXECUTING SCRIPT: {}".format(ps1of))
    exeactid = mdatp_execute_command(token, machineid, uscript)
    print("    + SCRIPT ACTION ID: {}".format(exeactid))

    # Wait until actionid appear on systems
    time.sleep(5)

    if exeactid:
        output = mdatp_get_execution_output(token, exeactid)
    else:
        print("  + ERROR: No RunScript actionid received")
        mdatp_cleanup_file(token, uscript)
        sys.exit(1)
    
    if not output:
        print("  + ERROR: No RunScript output received")
        mdatp_cleanup_file(token, uscript)
        sys.exit(1)

    resdata = json.loads(output)

    if 'error' in resdata:
        print("  + ERROR {}: {}".format(resdata['error']['code'], resdata['error']['message']))
        # Cleanup files
        mdatp_cleanup_file(token, uscript)
        print("  + SCRIPT {} CLEANED: {}".format(uscript, response))
        if binary:
            mdatp_cleanup_file(token, ubinary)
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
    mdatp_cleanup_file(token, uscript)
    print("    + SCRIPT {} CLEANED: {}".format(uscript, response))
    if binary:
        mdatp_cleanup_file(token, ubinary)
        print("  + BINARY {} CLEANED: {}".format(ubinary, response))

# *** MAIN LOOP ***
if __name__ == '__main__':
    main()
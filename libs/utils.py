import yaml
import json
import gzip
import shutil
import base64

from munch import munchify


def parse_config(file_path):

    confdata = []

    with open(file_path, "r") as f:
        config = yaml.safe_load(f)

    for c in config:
        confdata.append(c)

    return confdata, munchify(config)

def print_headers_list_endpoints():
    print("    {:<30} {:<45} {:<15} {:<20} {:<30} {:<10} {:<20}".format("Computer Name", "ID", "OS", "IP", "Last Seen", "Health", "Status"))
    print("    {:<30} {:<45} {:<15} {:<20} {:<30} {:<10} {:<20}".format("-------------", "--", "--", "--", "---------", "------", "------"))

def print_formatted_machine(machine, vendor):
    if vendor == "MDATP":
        computerDnsName = machine['computerDnsName'] if machine['computerDnsName'] is not None else 'N/A'
        id = machine['id'] if machine['id'] is not None else 'N/A'
        osPlatform = machine['osPlatform'] if machine['osPlatform'] is not None else 'N/A'
        lastIpAddress = machine['lastIpAddress'] if machine['lastIpAddress'] is not None else 'N/A'
        lastSeen = machine['lastSeen'] if machine['lastSeen'] is not None else 'N/A'
        healthStatus = machine['healthStatus'] if machine['healthStatus'] is not None else 'N/A'
        onboardingStatus = machine['onboardingStatus'] if machine['onboardingStatus'] is not None else 'N/A'
        print("    {:<30} {:<45} {:<15} {:<20} {:<30} {:<10} {:<20}".format(computerDnsName, id, osPlatform, lastIpAddress, lastSeen, healthStatus, onboardingStatus))

    if vendor == "TMV1":
        print ("    {:<30} {:<45} {:<15} {:<20} {:<30} {:<10} {:<20}".format(machine['name'], machine['id'], machine['os'], machine['ip'], machine['lastseen'], machine['sysstatus'], machine['edrstatus']))

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

def decode_command_script(command):
    decoded_command = base64.b64decode(command).decode('utf-8')
    return decoded_command

def parse_json_actionsid(json_string):
    data = json.loads(json_string)
    id = data['value'][0]['id']
    return id

def print_output_json(vendor, output, command):

    if vendor == "MDATP":
        # Access the values in the dictionary
        exit_code = output["exit_code"]
        script_errors = output["script_errors"]
        script_name = output["script_name"]
        script_output = output["script_output"]
        
        if exit_code != 0:
            print("    + ERROR: Script execution failed: {}".format(script_errors))
        else:
            print("    + SCRIPT EXECUTION DONE WITH EXIT CODE: {}".format(exit_code))
            decoded_command = decode_command_script(command)
            print("    + SCRIPT COMMAND EXECUTION: {}".format(decoded_command))
            print("    + SCRIPT OUTPUT:\n")
            print("---------------------------------------------")
            print()
            print(script_output)
            print("---------------------------------------------")
            print()

def decompress_gz_file(input_path, output_path):
    try:
        with gzip.open(input_path, 'rb') as f_in:
            with open(output_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)      
    except IOError as e:  
        print("    - DECOMPRESS ERROR: Error {}".format(e))
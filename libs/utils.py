import os
import yaml
import json
import gzip
import pyzipper
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

def print_output_txt(vendor, output, command):
    if vendor == "TMV1":
        report = "{}/executed_result.txt".format(output)
        try:
            if os.path.exists(report):
                with open(report, 'r', encoding='utf-8') as f:
                    content = f.read()
                    decoded_command = decode_command_script(command)
                    print("    + READING EXECUTION REPORT FROM: {}".format(report))
                    print("    + SCRIPT COMMAND EXECUTION: {}".format(decoded_command))
                    print("    + SCRIPT OUTPUT:\n")
                    print("---------------------------------------------")
                    print(content.strip())
                    print("---------------------------------------------")
                    print()
            else:
                print(f"    - ERROR: Report file not found: {report}")
                
        except Exception as e:
            print(f"    - ERROR: Failed to read report: {str(e)}")
            print("---------------------------------------------")

def decompress_gz_file(input_path, output_path):
    try:
        with gzip.open(input_path, 'rb') as f_in:
            with open(output_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)      
    except IOError as e:  
        print("    - DECOMPRESS ERROR: Error {}".format(e))

def decompress_zip_file(input_path, output_path, password=None):
    try:
        # Check if input exists
        if not os.path.exists(input_path):
            print(f"    - DECOMPRESS ZIP: Input file not found: {input_path}")
            return False

        # Create output dir
        os.makedirs(output_path, exist_ok=True)

        # Open and extract zip file with pyzipper
        with pyzipper.AESZipFile(input_path) as zf:
            if password:
                zf.pwd = password.encode()
            zf.extractall(output_path)

        print(f"    + DECOMPRESS ZIP: Successfully extracted to {output_path}")
        return True

    except Exception as e:
        print(f"    - DECOMPRESS ZIP ERROR: {str(e)}")
        return False

def detect_compression(filepath):
    """
    Detects compression type of a file
    Returns: str - compression type ('7z', 'zip', 'gz', 'unknown')
    """
    if not os.path.exists(filepath):
        print(f"    - DETECT: File not found: {filepath}")
        return "unknown"

    # Check file signatures
    try:
        with open(filepath, 'rb') as f:
            magic_bytes = f.read(8)  # Read first 8 bytes
            
            # 7z signature: '7z¼¯'[AF 27 1C]
            if magic_bytes.startswith(b'7z\xbc\xaf'):
                return "7z"
                
            # ZIP signature: 'PK\x03\x04'
            if magic_bytes.startswith(b'PK\x03\x04'):
                return "zip"
                
            # GZIP signature: '\x1f\x8b'
            if magic_bytes.startswith(b'\x1f\x8b'):
                return "gz"

        # Fallback to extension check
        ext = os.path.splitext(filepath)[1].lower()
        if ext in ['.7z', '.zip', '.gz']:
            return ext[1:]  # Remove dot
            
        return "unknown"
        
    except Exception as e:
        print(f"    - DETECT ERROR: {str(e)}")
        return "unknown"
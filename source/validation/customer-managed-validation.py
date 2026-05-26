# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## + -----------------------------------+ ##
## | AWS Managed Policies Validation    | ##
## + -----------------------------------+ ##

import boto3
import json
import argparse
import sys
import os
import logging

"""
Arguments used by the script:
--policies-folder: Folder where the customer-managed policy files are stored. Default: '../templates/customer-managed-policies/'
--assignments-folder: Folder where the customer-managed assignment files are stored. Default: '../templates/assignments/'
"""

# Setting arguments
parser = argparse.ArgumentParser(description='Customer Managed Policies Validation')
parser.add_argument('--policies-folder', action="store", dest='pFolder')
parser.add_argument('--assignments-folder', action="store", dest='asFolder')
args = parser.parse_args()

# Logging configuration
logging.basicConfig(format='%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.DEBUG)
log = logging.getLogger()
log.setLevel(logging.INFO)

def list_policy_folder():
    policy_dict = {}
    
    # Check if the folder exists before attempting to list files
    if os.path.exists(args.pFolder):
        for eachFile in os.listdir(args.pFolder):
            if eachFile.endswith('.json'):  # Verifica se o arquivo é .json
                try:
                    with open(os.path.join(args.pFolder, eachFile), 'r', encoding='utf-8') as file:
                        policy_dict[eachFile] = json.load(file)
                    log.info(f"Policy '{eachFile}' loaded successfully.")
                except json.JSONDecodeError as e:
                    log.error(f"Error decoding JSON in file '{eachFile}': {e}")
                except Exception as e:
                    log.error(f"Error loading file '{eachFile}': {e}")
        log.info('Customer managed policies successfully loaded from repository files.')
    else:
        log.warning(f"The specified folder '{args.pFolder}' does not exist. Skipping policy loading.")
    
    return policy_dict
    
def validate_unique_policy_name():
    # Verifica se o dicionário de políticas está vazio
    if not policies:
        log.error(f"No policies loaded from folder '{args.pFolder}'. Exiting.")
        raise Exception("No policies found to validate.")
    
    list_of_policy_names = [policy.get('PolicyName') for policy in policies.values() if 'PolicyName' in policy]
    
    if len(list_of_policy_names) > len(set(list_of_policy_names)):
        log.error("There are customer-managed policies with the same name. Please check your templates.")
        raise Exception("Duplicate policy names found.")
    
    log.info("No customer-managed policies with the same name were detected.")
    return True

def main():
    # Check if policy folder argument exists
    if args.pFolder is None:
        print("Usage: python " + str(sys.argv[0]) + " --policies-folder <POLICIES_FOLDER> --assignments-folder <ASSIGNMENTS_FOLDER>")
        print("Example: python " + str(sys.argv[0]) + " --policies-folder '../../templates/customer-managed-policies/' --assignments-folder '../../templates/assignments/'")
        exit(1)

    # Load policy files from folder to global variable
    global policies
    policies = list_policy_folder()

    # Verificação se as políticas foram carregadas corretamente
    if not policies:
        log.error(f"No policies found in folder '{args.pFolder}'. Exiting.")
        exit(1)

    # List of controls that will be validated
    validate_unique_policy_name()
    
    log.info('Congrats! All customer managed policies were evaluated without errors! :)')

if __name__ == "__main__":
    main()

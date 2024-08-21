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

## + ----------------------------------
## | AWS Managed Policies Validation
## + -----------------------------------

import boto3
import json
import argparse
import sys
import os
import logging

"""
Arguments used by the script:
--policies-folder: Folder where the customer-managed policy files are stored. Default: '../templates/policies/'
"""

# Setting arguments
parser = argparse.ArgumentParser(description='AWS Managed Policies Validation')
parser.add_argument('--policies-folder', action="store", dest='policiesFolder', default='../templates/policies/')
args = parser.parse_args()

# Logging configuration
logging.basicConfig(format='%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.DEBUG)
log = logging.getLogger()
log.setLevel(logging.INFO)

def list_policy_folder():
    policy_dict = {
        eachFile: json.loads(open(os.path.join(args.policiesFolder, eachFile)).read())
        for eachFile in os.listdir(args.policiesFolder)
    }
    log.info('Customer-managed policies successfully loaded from repository files')
    return policy_dict

def validate_unique_policy_name():
    list_of_policy_names = [policy['PolicyName'] for policy in policies.values()]
    
    if len(list_of_policy_names) > len(set(list_of_policy_names)):
        log.error("There are customer-managed policies with the same name. Please check your templates.")
        exit(1)
    
    log.info("No customer-managed policies with the same name were detected.")
    return True

def validate_json_policy_format():
    log.info("Analyzing each customer-managed policy.") 
    client = boto3.client('accessanalyzer')
    
    for policy_name, policy in policies.items():
        log.info(f"[{policy_name}] Analyzing policy document")
        policy_document = json.dumps(policy['PolicyDocument'])
        response = client.validate_policy(
            locale='EN', 
            policyDocument=policy_document, 
            policyType='IDENTITY_POLICY'
        )
        results = response["findings"]
        
        while "NextToken" in response:
            response = client.validate_policy(
                locale='EN', 
                policyDocument=policy_document, 
                policyType='IDENTITY_POLICY', 
                NextToken=response["NextToken"]
            )
            results.extend(response["findings"])

        for eachFinding in results:
            if eachFinding['findingType'] == 'ERROR':
                log.error(f"[{policy_name}] An error was found in the policy: " + str(eachFinding['findingDetails']))
                exit(1)
            if eachFinding['findingType'] == 'WARNING':
                log.warning(f"[{policy_name}] An issue was found in the policy: " + str(eachFinding['findingDetails']))
    
def validate_managed_policies_arn():
    log.info("Analyzing attached managed policies in each customer-managed policy.") 
    client = boto3.client('iam')

    for policy_name, policy in policies.items():
        if 'AttachedPolicies' in policy:
            for managed_policy_arn in policy['AttachedPolicies']:
                try:
                    client.get_policy(PolicyArn=managed_policy_arn)
                except Exception as error:
                    log.error(f"[{policy_name}] An issue was found with the managed policy ARN: " + str(error))
                    exit(1)

def main():
    print("########################################")
    print("# Starting AWS Managed Policies Validation #")
    print("########################################\n")
    
    # Check if policy folder argument exists
    if args.policiesFolder is None:
        print ("Usage: python " + str(sys.argv[0]) +  " --policies-folder <POLICIES_FOLDER>")
        print ("Example: python " + str(sys.argv[0]) +  " --policies-folder '../templates/policies/'")
        exit()

    # Load policy files from folder to global variable
    global policies
    policies = list_policy_folder()

    # List of controls that will be validated
    validate_unique_policy_name()
    validate_json_policy_format()
    validate_managed_policies_arn()
    
    log.info('Congrats! All policies were evaluated without errors! :)')

main()

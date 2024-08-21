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

import boto3
import json
import os
import logging
from botocore.config import Config

# Logging configuration
logging.basicConfig(format='%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                    datefmt='%Y-%m-%d:%H:%M:%S',
                    level=logging.DEBUG)
log = logging.getLogger()
log.setLevel(logging.INFO)

# Config to handle throttling
config = Config(
    retries={
        'max_attempts': 1000,
        'mode': 'adaptive'
    }
)

# This method will return all customer managed policies in AWS IAM
def get_current_customer_managed_policies():
    client = boto3.client('iam', config=config)
    policies_dict = {}

    response = client.list_policies(Scope='Local', OnlyAttached=False)

    policies = response["Policies"]
    while "Marker" in response:
        response = client.list_policies(Scope='Local', OnlyAttached=False, Marker=response["Marker"])
        policies.extend(response["Policies"])

    for policy in policies:
        policies_dict[policy["PolicyName"]] = policy["Arn"]

    return policies_dict

# This method will return all customer managed policies in the specified folder
def get_repository_customer_managed_policies():
    policy_files = os.listdir('../../templates/policies/')
    policies_dict = {}

    for policy_file in policy_files:
        path = '../../templates/policies/' + policy_file
        with open(path) as f:
            data = json.load(f)
            policies_dict[data['PolicyName']] = data
    return policies_dict

# Create or update a customer managed policy
def create_or_update_policy(policy_name, policy_document):
    client = boto3.client('iam', config=config)
    
    current_policies = get_current_customer_managed_policies()

    if policy_name in current_policies:
        # Update existing policy
        log.info(f"[Policy: {policy_name}] Updating existing policy...")
        try:
            response = client.create_policy_version(
                PolicyArn=current_policies[policy_name],
                PolicyDocument=json.dumps(policy_document),
                SetAsDefault=True
            )
            log.info(f"[Policy: {policy_name}] Successfully updated policy.")
        except Exception as e:
            log.error(f"[Policy: {policy_name}] Could not update policy. Reason: {str(e)}")
            exit(1)
    else:
        # Create new policy
        log.info(f"[Policy: {policy_name}] Creating new policy...")
        try:
            response = client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=json.dumps(policy_document),
            )
            log.info(f"[Policy: {policy_name}] Successfully created policy.")
        except Exception as e:
            log.error(f"[Policy: {policy_name}] Could not create policy. Reason: {str(e)}")
            exit(1)

# Delete a customer managed policy
def delete_policy(policy_arn):
    client = boto3.client('iam', config=config)
    
    try:
        response = client.delete_policy(
            PolicyArn=policy_arn
        )
        log.info(f"Successfully deleted policy: {policy_arn}")
    except Exception as e:
        log.error(f"Could not delete policy: {policy_arn}. Reason: {str(e)}")
        exit(1)

# Compare repository policies with existing policies in IAM and take appropriate actions
def define_policy_changes(current_policies, repository_policies):
    # Create or update policies
    for policy_name, policy_data in repository_policies.items():
        log.info(f"Processing policy: {policy_name}")
        create_or_update_policy(policy_name, policy_data['PolicyDocument'])

    # Delete policies not in repository
    for policy_name, policy_arn in current_policies.items():
        if policy_name not in repository_policies:
            log.info(f"Policy not found in repository, deleting: {policy_name}")
            delete_policy(policy_arn)

def main():
    print("######################################")
    print("# Starting AWS IAM Policy Script #")
    print("######################################\n")

    current_policies = get_current_customer_managed_policies()
    repository_policies = get_repository_customer_managed_policies()

    define_policy_changes(current_policies, repository_policies)
    log.info('Congrats! Policy script finished without errors! :)')

main()

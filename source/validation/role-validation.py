import boto3
import json
import argparse
import os
import sys
import logging

logging.basicConfig(
    format='%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.INFO
)
log = logging.getLogger()

ROLE_NAME = "deploy-customer-managed-policy"

parser = argparse.ArgumentParser(description='Role Validation for Customer Managed Policies')
parser.add_argument('--assignments-folder', action="store", dest='asFolder', required=True)
args = parser.parse_args()


def get_target_accounts():
    accounts = set()
    folder = args.asFolder

    if not os.path.exists(folder):
        log.error(f"Pasta de assignments '{folder}' não encontrada.")
        sys.exit(1)

    for f in os.listdir(folder):
        if not f.endswith('.json'):
            continue
        with open(os.path.join(folder, f), 'r', encoding='utf-8-sig') as fh:
            data = json.load(fh)
        for assignment in data.get("Assignments", []):
            for account_id in assignment.get("Target", []):
                accounts.add(account_id)

    log.info(f"Contas de destino encontradas: {accounts}")
    return accounts


def check_role_exists(account_id):
    sts = boto3.client('sts')
    try:
        assumed = sts.assume_role(
            RoleArn=f'arn:aws:iam::{account_id}:role/{ROLE_NAME}',
            RoleSessionName="RoleValidationSession"
        )
        creds = assumed['Credentials']
        iam = boto3.client(
            'iam',
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken']
        )
        iam.get_role(RoleName=ROLE_NAME)
        log.info(f"[{account_id}] Role '{ROLE_NAME}' validada com sucesso.")
        return True
    except Exception as e:
        log.error(f"[{account_id}] Role '{ROLE_NAME}' não acessível: {e}")
        return False


def main():
    accounts = get_target_accounts()
    if not accounts:
        log.error("Nenhuma conta de destino encontrada nos assignments.")
        sys.exit(1)

    errors = []
    for account_id in accounts:
        if not check_role_exists(account_id):
            errors.append(account_id)

    if errors:
        log.error(f"Role '{ROLE_NAME}' não encontrada ou inacessível nas contas: {errors}")
        log.error("Verifique se o StackSet criou a role nessas contas.")
        sys.exit(1)

    log.info("Validação de roles concluída com sucesso em todas as contas!")


if __name__ == "__main__":
    main()

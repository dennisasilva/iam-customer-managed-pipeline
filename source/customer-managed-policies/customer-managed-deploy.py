import json
import boto3
import os
import sys
import argparse
import hashlib
import logging
from datetime import datetime, timezone

logging.basicConfig(
    format='%(asctime)s %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.INFO
)
log = logging.getLogger()

parser = argparse.ArgumentParser(description='Customer Managed Policies Deploy')
parser.add_argument('--dry-run', action='store_true', dest='dry_run')
parser.add_argument('--state-bucket', action='store', dest='state_bucket', default=None)
args = parser.parse_args()

ASSIGNMENTS_DIR = '../../templates/assignments'
POLICIES_DIR = '../../templates/customer-managed-policies'
ROLE_NAME = 'deploy-customer-managed-policy'


def policy_hash(doc):
    return hashlib.sha256(json.dumps(doc, sort_keys=True).encode()).hexdigest()


def filter_tags(tags):
    return [t for t in tags if t.get('Key') and t.get('Value')]


def load_state(s3, account_id):
    if not args.state_bucket:
        return {}
    try:
        obj = s3.get_object(Bucket=args.state_bucket, Key=f'state/{account_id}.json')
        return json.loads(obj['Body'].read())
    except s3.exceptions.NoSuchKey:
        return {}
    except Exception as e:
        log.warning(f"[{account_id}] Erro ao ler state: {e}")
        return {}


def save_state(s3, account_id, state):
    if not args.state_bucket:
        return
    try:
        state['last_execution'] = datetime.now(timezone.utc).isoformat()
        s3.put_object(
            Bucket=args.state_bucket,
            Key=f'state/{account_id}.json',
            Body=json.dumps(state, indent=2),
            ContentType='application/json'
        )
        log.info(f"[{account_id}] State salvo em s3://{args.state_bucket}/state/{account_id}.json")
    except Exception as e:
        log.error(f"[{account_id}] Erro ao salvar state: {e}")


def diff_policy(account_id, policy_name, old_doc, new_doc):
    if old_doc == new_doc:
        return
    log.info(f"[{account_id}] DIFF '{policy_name}':")
    old_stmts = {s.get('Sid', f'stmt-{i}'): s for i, s in enumerate(old_doc.get('Statement', []))}
    new_stmts = {s.get('Sid', f'stmt-{i}'): s for i, s in enumerate(new_doc.get('Statement', []))}

    for sid in set(list(old_stmts.keys()) + list(new_stmts.keys())):
        if sid not in old_stmts:
            log.info(f"  + Statement '{sid}' ADICIONADO")
        elif sid not in new_stmts:
            log.info(f"  - Statement '{sid}' REMOVIDO")
        else:
            old_actions = set(old_stmts[sid].get('Action', []))
            new_actions = set(new_stmts[sid].get('Action', []))
            added = new_actions - old_actions
            removed = old_actions - new_actions
            if added:
                log.info(f"  Statement '{sid}' Actions adicionadas: {added}")
            if removed:
                log.info(f"  Statement '{sid}' Actions removidas: {removed}")
            old_res = set(old_stmts[sid].get('Resource', []) if isinstance(old_stmts[sid].get('Resource'), list) else [old_stmts[sid].get('Resource', '')])
            new_res = set(new_stmts[sid].get('Resource', []) if isinstance(new_stmts[sid].get('Resource'), list) else [new_stmts[sid].get('Resource', '')])
            res_added = new_res - old_res
            res_removed = old_res - new_res
            if res_added:
                log.info(f"  Statement '{sid}' Resources adicionados: {res_added}")
            if res_removed:
                log.info(f"  Statement '{sid}' Resources removidos: {res_removed}")


def get_current_policy_doc(iam, policy_arn):
    try:
        pol = iam.get_policy(PolicyArn=policy_arn)
        version_id = pol['Policy']['DefaultVersionId']
        ver = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        return ver['PolicyVersion']['Document']
    except Exception:
        return None


def get_iam_client(account_id):
    sts = boto3.client('sts')
    assumed = sts.assume_role(
        RoleArn=f'arn:aws:iam::{account_id}:role/{ROLE_NAME}',
        RoleSessionName="CustomerManagedPolicySession"
    )
    creds = assumed['Credentials']
    return boto3.client('iam',
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken']
    )


def create_update_customer_managed_policy():
    s3 = boto3.client('s3') if args.state_bucket else None
    prefix = "[DRY-RUN] " if args.dry_run else ""

    for assignment_file in os.listdir(ASSIGNMENTS_DIR):
        if not assignment_file.endswith('.json'):
            continue
        with open(os.path.join(ASSIGNMENTS_DIR, assignment_file), 'r', encoding='utf-8-sig') as f:
            assignments_data = json.load(f)

        for assignment in assignments_data.get("Assignments", []):
            policy_name_list = assignment.get("CustomerManagedPolicyName", [])
            target_accounts = assignment.get("Target", [])

            for account_id in target_accounts:
                log.info(f"{prefix}Processando conta: {account_id}")
                iam = get_iam_client(account_id)
                state = load_state(s3, account_id) if s3 else {}
                policies_state = state.get('policies', {})

                for policy_file in os.listdir(POLICIES_DIR):
                    if not policy_file.endswith('.json'):
                        continue
                    with open(os.path.join(POLICIES_DIR, policy_file), 'r', encoding='utf-8-sig') as pf:
                        policy_data = json.load(pf)

                    policy_name = policy_data.get("PolicyName")
                    if policy_name not in policy_name_list:
                        continue

                    policy_document = policy_data['PolicyDocument']
                    repo_hash = policy_hash(policy_document)
                    policy_tags = filter_tags(policy_data.get("Tags", []))
                    path = policy_data.get("Path", "/")
                    description = policy_data.get("Description", "Custom managed policy")

                    # Check state - skip if unchanged
                    saved = policies_state.get(policy_name, {})
                    if saved.get('policy_hash') == repo_hash:
                        log.info(f"{prefix}[{account_id}] '{policy_name}' sem alteração (hash match). Pulando.")
                        # Drift detection
                        current_doc = get_current_policy_doc(iam, f'arn:aws:iam::{account_id}:policy{path}{policy_name}')
                        if current_doc and policy_hash(current_doc) != repo_hash:
                            log.warning(f"{prefix}[{account_id}] DRIFT detectado em '{policy_name}'!")
                        continue

                    policy_arn = f'arn:aws:iam::{account_id}:policy{path}{policy_name}'
                    try:
                        response = iam.get_policy(PolicyArn=policy_arn)
                        tags_response = iam.list_policy_tags(PolicyArn=policy_arn)
                        existing_tags = {tag['Key']: tag['Value'] for tag in tags_response['Tags']}

                        if existing_tags.get('cx-mng') != 'true':
                            log.info(f"{prefix}[{account_id}] '{policy_name}' sem tag cx-mng:true. Pulando.")
                            continue

                        # Diff
                        current_doc = get_current_policy_doc(iam, policy_arn)
                        if current_doc:
                            diff_policy(account_id, policy_name, current_doc, policy_document)

                        log.info(f"{prefix}[{account_id}] ATUALIZAR '{policy_name}'")
                        if not args.dry_run:
                            versions = iam.list_policy_versions(PolicyArn=policy_arn)['Versions']
                            if len(versions) >= 5:
                                oldest = sorted(versions, key=lambda v: v['CreateDate'])[0]
                                iam.delete_policy_version(PolicyArn=policy_arn, VersionId=oldest['VersionId'])

                            resp = iam.create_policy_version(PolicyArn=policy_arn, PolicyDocument=json.dumps(policy_document), SetAsDefault=True)
                            if policy_tags:
                                iam.tag_policy(PolicyArn=policy_arn, Tags=policy_tags)

                            policies_state[policy_name] = {
                                'arn': policy_arn,
                                'version_id': resp['PolicyVersion']['VersionId'],
                                'policy_hash': repo_hash,
                                'last_deployed': datetime.now(timezone.utc).isoformat()
                            }
                            log.info(f"[{account_id}] '{policy_name}' atualizada.")

                    except iam.exceptions.NoSuchEntityException:
                        log.info(f"{prefix}[{account_id}] CRIAR '{policy_name}'")
                        if not args.dry_run:
                            resp = iam.create_policy(PolicyName=policy_name, Path=path, PolicyDocument=json.dumps(policy_document), Description=description)
                            policy_arn = resp['Policy']['Arn']
                            tags_to_apply = [{'Key': 'cx-mng', 'Value': 'true'}] + policy_tags
                            iam.tag_policy(PolicyArn=policy_arn, Tags=tags_to_apply)

                            policies_state[policy_name] = {
                                'arn': policy_arn,
                                'version_id': 'v1',
                                'policy_hash': repo_hash,
                                'last_deployed': datetime.now(timezone.utc).isoformat()
                            }
                            log.info(f"[{account_id}] '{policy_name}' criada.")

                    except Exception as e:
                        log.error(f"[{account_id}] Erro em '{policy_name}': {e}")

                if not args.dry_run and s3:
                    state['account_id'] = account_id
                    state['policies'] = policies_state
                    save_state(s3, account_id, state)


def get_previously_managed_accounts(s3):
    """Lê do S3 as contas que foram gerenciadas anteriormente."""
    if not s3 or not args.state_bucket:
        return set()
    try:
        resp = s3.list_objects_v2(Bucket=args.state_bucket, Prefix='state/')
        accounts = set()
        for obj in resp.get('Contents', []):
            key = obj['Key']
            if key.endswith('.json'):
                account_id = key.replace('state/', '').replace('.json', '')
                if account_id.isdigit():
                    accounts.add(account_id)
        return accounts
    except Exception as e:
        log.warning(f"Erro ao listar states no S3: {e}")
        return set()


def delete_customer_managed_policy():
    s3 = boto3.client('s3') if args.state_bucket else None
    prefix = "[DRY-RUN] " if args.dry_run else ""

    # Mapeia quais policies cada conta deve ter
    policies_per_account = {}
    all_target_accounts = set()

    for assignment_file in os.listdir(ASSIGNMENTS_DIR):
        if not assignment_file.endswith('.json'):
            continue
        with open(os.path.join(ASSIGNMENTS_DIR, assignment_file), 'r', encoding='utf-8-sig') as f:
            assignments_data = json.load(f)
        for assignment in assignments_data.get("Assignments", []):
            policies = assignment.get("CustomerManagedPolicyName", [])
            for account_id in assignment.get("Target", []):
                all_target_accounts.add(account_id)
                if account_id not in policies_per_account:
                    policies_per_account[account_id] = set()
                policies_per_account[account_id].update(policies)

    # Incluir contas que foram gerenciadas antes mas foram removidas dos assignments
    previous_accounts = get_previously_managed_accounts(s3)
    removed_accounts = previous_accounts - all_target_accounts
    if removed_accounts:
        log.info(f"Contas removidas dos assignments detectadas via state: {removed_accounts}")
    all_accounts_to_check = all_target_accounts | removed_accounts

    for account_id in all_accounts_to_check:
        # Para contas removidas, nenhuma policy deve ser mantida
        keep_for_account = policies_per_account.get(account_id, set())
        iam = get_iam_client(account_id)
        state = load_state(s3, account_id) if s3 else {}
        policies_state = state.get('policies', {})

        response = iam.list_policies(Scope='Local')
        for policy in response['Policies']:
            p_name = policy['PolicyName']
            p_arn = policy['Arn']

            if p_name in keep_for_account:
                continue
            try:
                tags_response = iam.list_policy_tags(PolicyArn=p_arn)
                tags = {t['Key']: t['Value'] for t in tags_response['Tags']}
                if tags.get('cx-mng') != 'true':
                    continue

                log.info(f"{prefix}[{account_id}] DELETAR '{p_name}'")
                if not args.dry_run:
                    versions = iam.list_policy_versions(PolicyArn=p_arn)['Versions']
                    for v in versions:
                        if not v['IsDefaultVersion']:
                            iam.delete_policy_version(PolicyArn=p_arn, VersionId=v['VersionId'])
                    iam.delete_policy(PolicyArn=p_arn)
                    policies_state.pop(p_name, None)
                    log.info(f"[{account_id}] '{p_name}' deletada.")
            except Exception as e:
                log.error(f"[{account_id}] Erro ao deletar '{p_name}': {e}")

        if not args.dry_run and s3:
            state['account_id'] = account_id
            state['policies'] = policies_state
            if policies_state:
                save_state(s3, account_id, state)
            elif account_id in removed_accounts:
                # Conta removida e sem policies — limpar state
                try:
                    s3.delete_object(Bucket=args.state_bucket, Key=f'state/{account_id}.json')
                    log.info(f"[{account_id}] State removido do S3.")
                except Exception as e:
                    log.warning(f"[{account_id}] Erro ao remover state: {e}")


if __name__ == "__main__":
    create_update_customer_managed_policy()
    delete_customer_managed_policy()

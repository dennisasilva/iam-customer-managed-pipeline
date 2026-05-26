# IAM Customer Managed Policies Pipeline

Pipeline CI/CD para gerenciamento automatizado de IAM Customer Managed Policies em múltiplas contas AWS via CodePipeline.

## Diagrama de Arquitetura

![Architecture Diagram](images/architecture-diagram.drawio)

```
GitHub → CodeStar Connection → Pipeline (6 stages) → Target AWS Accounts
                                    │
                                    ├── Source
                                    ├── TemplateValidation
                                    ├── RoleValidation
                                    ├── DryRun
                                    ├── Approval (manual, opcional)
                                    └── CustomerManagedPolicies
```

## Pré-requisitos

### 1. GitHub Fine-Grained Personal Access Token

Crie um token no GitHub com as seguintes permissões:

- **Account permissions:** `Administration` → Read and write
- **Repository permissions:**
  - `Contents` → Read and write
  - `Metadata` → Read-only
  - `Issues` → Read and write

Acesse: GitHub → Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token

### 2. AWS Secrets Manager

Armazene o token do GitHub no Secrets Manager:

```bash
aws secretsmanager create-secret \
  --name dev/cx-mgn-pipe/github \
  --secret-string "<GITHUB_TOKEN>" \
  --region us-east-1
```

### 3. S3 Bucket com código inicial

Crie um bucket S3 e faça upload do arquivo .zip com o código inicial do repositório:

```bash
# Criar o bucket
aws s3 mb s3://iam-cx-mng-pipeline-initialcode --region us-east-1

# Criar o zip com o código do repositório
cd iam-cx-mng-pipeline-main
zip -r iam-cx-mng-pipeline.zip . -x ".git/*" "cfn/*" "images/*" "README.md"

# Upload do zip
aws s3 cp iam-cx-mng-pipeline.zip s3://iam-cx-mng-pipeline-initialcode/
```

O arquivo .zip deve conter a seguinte estrutura:

```
iam-cx-mng-pipeline.zip
├── source/
│   ├── validation/
│   │   ├── customer-managed-validation.py
│   │   └── role-validation.py
│   └── customer-managed-policies/
│       └── customer-managed-deploy.py
└── templates/
    ├── assignments/
    │   └── example.json
    └── customer-managed-policies/
        ├── MyCustomerPolicy.json
        ├── My2CustomerPolicy.json
        └── ...
```

### 4. StackSet para IAM Role nas contas de destino

Deploy do StackSet com o template `cfn/cx-mng-stackset-deploy-role.yaml` na OU raiz com auto-deploy habilitado:

```bash
aws cloudformation create-stack-set \
  --stack-set-name cx-mng-deploy-role \
  --template-body file://cfn/cx-mng-stackset-deploy-role.yaml \
  --parameters ParameterKey=PipelineAccountId,ParameterValue=<PIPELINE_ACCOUNT_ID> \
               ParameterKey=NamingConvention,ParameterValue=cx-mng-pipeline \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1
```

Isso cria a role `deploy-customer-managed-policy` em todas as contas da OU automaticamente.

### 5. GitHub Default Branch

Configure o Git para usar `main` como branch padrão:

```bash
git config --global init.defaultBranch main
```

## Deploy da Pipeline

### Parâmetros do CloudFormation (`cx-mng-policies-2.yaml`)

| Parâmetro | Descrição | Default | Obrigatório |
|-----------|-----------|---------|-------------|
| `RepositoryType` | Tipo do repositório (GitHub ou GitLab) | `GitHub` | Sim |
| `S3BucketCodeBucket` | Bucket S3 com o código inicial (.zip) | `iam-cx-mng-pipeline-initialcode` | Sim |
| `S3BucketCodeKey` | Nome do arquivo .zip no bucket S3 | `iam-cx-mng-pipeline.zip` | Sim |
| `RepositoryName` | Nome do repositório GitHub | `iam-cx-mng-pipeline` | Sim |
| `RepositoryOwner` | Username do owner do repositório GitHub | `dennisasilva` | Sim |
| `SecretId` | Nome do secret no Secrets Manager com o token GitHub | `dev/cx-mgn-pipe/github` | Sim |
| `NamingConvention` | Prefixo para nomes dos recursos | `cx-mng-pipeline` | Sim |
| `ManualApproval` | Habilitar stage de aprovação manual | `true` | Sim |

### Comando de deploy

```bash
aws cloudformation deploy \
  --template-file cfn/cx-mng-policies-2.yaml \
  --stack-name cx-mng-policies-pipeline \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    RepositoryType=GitHub \
    S3BucketCodeBucket=iam-cx-mng-pipeline-initialcode \
    S3BucketCodeKey=iam-cx-mng-pipeline.zip \
    RepositoryName=iam-cx-mng-pipeline \
    RepositoryOwner=dennisasilva \
    SecretId=dev/cx-mgn-pipe/github \
    NamingConvention=cx-mng-pipeline \
    ManualApproval=true \
  --region us-east-1
```

> **Importante:** Após o deploy, acesse o console do CodeStar Connections e complete a conexão com o GitHub (status deve mudar de `PENDING` para `AVAILABLE`).

## Estrutura do Projeto

```
├── cfn/
│   ├── cx-mng-policies-2.yaml           # Template principal da pipeline
│   └── cx-mng-stackset-deploy-role.yaml  # StackSet para role nas contas de destino
├── source/
│   ├── validation/
│   │   ├── customer-managed-validation.py  # Validação de templates (nomes únicos, JSON)
│   │   └── role-validation.py              # Validação de roles nas contas de destino
│   └── customer-managed-policies/
│       └── customer-managed-deploy.py      # Deploy das customer managed policies
├── templates/
│   ├── assignments/
│   │   └── example.json                    # Associação de policies → contas
│   └── customer-managed-policies/
│       ├── MyCustomerPolicy.json           # Definição de cada policy
│       └── ...
├── images/
│   └── architecture-diagram.drawio         # Diagrama de arquitetura
└── README.md
```

## Pipeline Stages

### 1. Source
Puxa o código do GitHub via CodeStar Connection. Trigger automático em push na branch `main`.

### 2. TemplateValidation
Valida os JSONs de policies: nomes únicos, sintaxe JSON válida.

### 3. RoleValidation
Verifica se a role `deploy-customer-managed-policy` está acessível em todas as contas listadas nos assignments. Falha antes de qualquer alteração se alguma conta não tiver a role.

### 4. DryRun
Executa o script de deploy em modo dry-run:
- Compara o state salvo no S3 com o estado atual das policies nas contas
- Mostra diff detalhado do que vai mudar (ações adicionadas/removidas)
- Detecta drift (alterações manuais nas policies)
- Não faz nenhuma alteração

### 5. Approval (opcional)
Stage de aprovação manual. O operador revisa os logs do DryRun no CodeBuild e aprova ou rejeita. Controlado pelo parâmetro `ManualApproval`.

### 6. CustomerManagedPolicies
Executa o deploy real:
- Cria policies novas com tag `cx-mng: true`
- Atualiza policies existentes (com tag `cx-mng: true`)
- Deleta policies removidas dos assignments (com tag `cx-mng: true`)
- Salva o state no S3 após cada operação

## Gestão de Estado (S3)

O state é armazenado no bucket de artefatos da pipeline em `state/<account-id>.json`:

```json
{
  "account_id": "111111111111",
  "last_execution": "2026-04-12T16:00:00+00:00",
  "policies": {
    "MyFirstCustomerPolicy": {
      "arn": "arn:aws:iam::111111111111:policy/MyFirstCustomerPolicy",
      "version_id": "v4",
      "policy_hash": "sha256:abc123...",
      "last_deployed": "2026-04-12T16:00:00+00:00"
    }
  }
}
```

O state permite:
- Pular policies que não mudaram (evita versions desnecessárias)
- Detectar drift (alterações manuais)
- Histórico de deploys

## Assignments

Arquivo JSON em `templates/assignments/` que associa policies a contas:

```json
{
  "Assignments": [
    {
      "SID": "MyFirstPolicy",
      "Target": ["111111111111", "222222222222"],
      "CustomerManagedPolicyName": ["MyFirstCustomerPolicy", "My2CustomerPolicy"]
    }
  ]
}
```

## Customer Managed Policies

Arquivo JSON em `templates/customer-managed-policies/` com a definição da policy:

```json
{
  "PolicyName": "MyFirstCustomerPolicy",
  "Description": "Description of the policy",
  "Path": "/",
  "PolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "CustomPolicy",
        "Action": ["ec2:Describe*"],
        "Effect": "Allow",
        "Resource": "*"
      }
    ]
  },
  "Tags": []
}
```

## Ordem de Deploy (primeira vez)

1. Criar secret no Secrets Manager com o token GitHub
2. Criar bucket S3 e fazer upload do .zip com código inicial
3. Deploy do StackSet `cx-mng-stackset-deploy-role.yaml` na OU raiz
4. Deploy do stack `cx-mng-policies-2.yaml` na conta da pipeline
5. Completar a conexão CodeStar no console AWS
6. Renomear branch `master` para `main` no repositório GitHub (se necessário)

## Ordem de Update

- **Adicionar permissões na role de destino:** atualizar StackSet primeiro, depois pipeline
- **Mudar nomes de roles na pipeline:** atualizar pipeline primeiro, depois StackSet
- **Adicionar nova conta:** StackSet com auto-deploy já cuida automaticamente

# Test Suite — `iam-cx-mng-pipeline`

Este documento descreve o que a suite de testes valida hoje, **classifica cada teste por tipo (unit / integration / E2E)**, e — mais importante — **lista honestamente o que ainda não é coberto**, para guiar onde aumentar a confiança no futuro.

## TL;DR

| Camada | Quantidade | O que cobrem | Limitações |
|---|---|---|---|
| Pure unit | 73 | Lógica isolada (regex, hash, diff, validações, config, ExternalId via mock) | Não pegam erros de I/O, AWS API ou orquestração |
| Filesystem integration | 18 | Leitura real de JSONs em pasta (incluindo os templates de produção) | Não mockam — usam `tmp_path` ou os templates reais |
| AWS-mocked integration (moto) | 22 | S3, IAM, STS — incluindo orquestração end-to-end de `create_update`, `delete` e tratamento do cap de 5 versões IAM | Mocks da `moto` ≠ comportamento real da AWS (veja "Limitações" abaixo) |
| CFN template structural | 7 | Parse de `cx-mng-stackset-deploy-role.yaml` (tag condition em ações destrutivas) e de `cx-mng-pipeline.yaml` (Deny de writes no prefixo `state/`) | Valida a *estrutura* do template; a aplicação real só ocorre no IAM/S3 em runtime |
| E2E manual | 2 | Pipeline `customer-managed-validation.py` rodada com sucesso e com Target inválido | Apenas o validador; deploy/role-validation **não** têm E2E |
| **Total** | **120** | — | — |

A preocupação "fazer testes isolados e não detectar erros" é legítima — listo abaixo o que a suite atual cobre, o que ainda não cobre, e o que fazer sobre cada caso.

---

## Taxonomia usada

### Pure unit test
- **Definição:** chama uma função pura com input em memória, valida output em memória.
- **Sem:** filesystem, sem rede, sem AWS, sem subprocess.
- **Ex:** `test_policy_hash_is_deterministic` — passa um dict, verifica a string SHA-256 retornada.
- **Vantagem:** rápido (microssegundos), determinístico, não-flaky.
- **Limitação:** não pega bug de integração entre componentes.

### Filesystem integration
- **Definição:** envolve leitura/escrita real em filesystem (via `tmp_path` do pytest ou pasta real do projeto).
- **Sem:** rede, sem AWS.
- **Ex:** `test_load_policy_files_loads_valid_jsons` — escreve `.json` em `tmp_path`, chama `load_policy_files`, verifica o dict retornado.
- **Vantagem:** valida que o código lida com FS de verdade (encoding, permissões, listdir).
- **Limitação:** não pega problemas de chamada AWS.

### AWS-mocked integration (moto)
- **Definição:** usa `@mock_aws` da biblioteca `moto` para intercept boto3 calls e simular respostas de IAM/S3/STS.
- **Ex:** `test_check_role_exists_returns_true_when_role_present` — cria role no IAM mockado, chama `check_role_exists`, verifica que retorna `True`.
- **Vantagem:** valida fluxo de chamada boto3 (parâmetros corretos, parsing da response, tratamento de exceção).
- **⚠️ Limitação importante:** `moto` simula a API mas **não** simula:
  - **IAM policy evaluation:** se a role real não tiver `iam:CreatePolicy`, a chamada AWS falha. moto aceita.
  - **Quotas/rate limits:** AWS IAM tem 5 versions/policy. moto não enforça.
  - **Eventual consistency:** AWS é eventualmente consistente; moto é instantâneo.
  - **Service-specific quirks:** ex: o `aws/s3` KMS key tem comportamento próprio.

### E2E (end-to-end) manual
- **Definição:** roda o script Python real, com argumentos reais, contra dados reais.
- **Ex:** os comandos `cd source/validation && python customer-managed-validation.py --policies-folder ../../templates/...` que rodei durante o desenvolvimento.
- **Vantagem:** prova que o sistema completo funciona, da CLI ao output final.
- **Limitação:** não está automatizado em pytest — precisa ser executado manualmente.

---

## Catálogo de testes por arquivo

### `tests/test_customer_managed_validation.py` — 46 testes

| # | Teste | Tipo | Componente / fluxo | O que valida |
|---|---|---|---|---|
| 1 | `test_load_policy_files_loads_valid_jsons` | Filesystem | `load_policy_files()` | JSONs válidos em `tmp_path` são carregados num dict |
| 2 | `test_load_policy_files_skips_non_json` | Filesystem | `load_policy_files()` | `.txt`, `.md` etc são ignorados |
| 3 | `test_load_policy_files_returns_empty_for_missing_folder` | Filesystem | `load_policy_files()` | Pasta inexistente retorna `{}` sem raise |
| 4 | `test_load_policy_files_raises_on_invalid_json` | Filesystem | `load_policy_files()` | `JSONDecodeError` propaga para chamador |
| 5 | `test_validate_unique_policy_name_passes_when_unique` | Pure unit | `validate_unique_policy_name()` | Sem duplicatas → não levanta |
| 6 | `test_validate_unique_policy_name_raises_on_duplicates` | Pure unit | idem | Duplicatas → ValueError |
| 7 | `test_validate_unique_policy_name_raises_on_empty` | Pure unit | idem | Dict vazio → ValueError |
| 8 | `test_validate_unique_policy_name_ignores_entries_without_policy_name` | Pure unit | idem | Entries sem `PolicyName` são puladas |
| 9-13 | `test_validate_policy_paths_accepts_valid_paths[...]` (5 paramétricos) | Pure unit | `validate_policy_paths()` | `/`, `/admin/`, `/customer1/`, `/foo/bar/`, `/a/b/c/` passam |
| 14 | `test_validate_policy_paths_defaults_to_slash_when_missing` | Pure unit | idem | Path ausente → assume `/` |
| 15-21 | `test_validate_policy_paths_rejects_invalid_paths[...]` (7 paramétricos) | Pure unit | idem | `admin/`, `/admin`, `//`, `/foo//bar/`, `/foo bar/`, `/foo<>/`, vazio rejeitados |
| 22 | `test_validate_policy_paths_rejects_non_string_path` | Pure unit | idem | Path como list/dict → ValueError |
| 23 | `test_validate_policy_paths_rejects_path_over_max_length` | Pure unit | idem | > 512 chars → ValueError |
| 24 | `test_validate_policy_paths_aggregates_multiple_errors` | Pure unit | idem | Múltiplos erros logados antes do raise |
| 25 | `test_real_templates_have_valid_paths` | **Filesystem (real)** | idem | Smoke test contra `templates/customer-managed-policies/` |
| 26 | `test_load_assignment_files_loads_valid_jsons` | Filesystem | `load_assignment_files()` | JSONs em `tmp_path` carregados |
| 27 | `test_load_assignment_files_skips_non_json` | Filesystem | idem | Não-JSON ignorados |
| 28 | `test_load_assignment_files_returns_empty_for_missing_folder` | Filesystem | idem | Pasta inexistente → `{}` |
| 29 | `test_load_assignment_files_raises_on_invalid_json` | Filesystem | idem | `JSONDecodeError` propaga |
| 30 | `test_validate_target_account_ids_accepts_valid` | Pure unit | `validate_target_account_ids()` | IDs 12-dígitos passam |
| 31 | `test_validate_target_account_ids_handles_missing_assignments_key` | Pure unit | idem | Sem `Assignments` → no-op |
| 32 | `test_validate_target_account_ids_handles_empty_target_list` | Pure unit | idem | `Target: []` → no-op |
| 33-41 | `test_validate_target_account_ids_rejects_invalid[...]` (9 paramétricos) | Pure unit | idem | "123", "99999999999", "1234567890123", letras, whitespace, dashes, vírgulas, vazio |
| 42 | `test_validate_target_account_ids_rejects_non_string` | Pure unit | idem | int em vez de str → ValueError |
| 43 | `test_validate_target_account_ids_rejects_target_not_a_list` | Pure unit | idem | `Target: "..."` (sem []) → ValueError |
| 44 | `test_validate_target_account_ids_aggregates_errors` | Pure unit | idem | Múltiplos errors logados antes do raise |
| 45 | `test_real_assignments_have_valid_target_ids` | **Filesystem (real)** | idem | Smoke test contra `templates/assignments/` |
| 46 | `test_real_templates_have_unique_policy_names` | **Filesystem (real)** | `validate_unique_policy_name()` | Smoke test contra `templates/customer-managed-policies/` |

### `tests/test_role_validation.py` — 11 testes

| # | Teste | Tipo | Componente / fluxo | O que valida |
|---|---|---|---|---|
| 1 | `test_get_target_accounts_aggregates_from_all_files` | Filesystem | `get_target_accounts()` | Agrega Targets de múltiplos `*.json`, deduplica |
| 2 | `test_get_target_accounts_skips_non_json` | Filesystem | idem | `.txt` ignorado |
| 3 | `test_get_target_accounts_handles_missing_assignments_key` | Filesystem | idem | JSON sem `Assignments` → 0 accounts |
| 4 | `test_get_target_accounts_exits_when_folder_missing` | Filesystem | idem | Pasta inexistente → `sys.exit(1)` |
| 5 | `test_get_target_accounts_exits_on_invalid_account_id` | Filesystem | idem | Defesa em profundidade: ID inválido → exit 1 |
| 6 | `test_get_target_accounts_exits_on_account_id_with_whitespace` | Filesystem | idem | Whitespace → exit 1 |
| 7 | `test_check_role_exists_returns_true_when_role_present` | **AWS-mocked (moto)** | `check_role_exists()` | Role existente → True |
| 8 | `test_check_role_exists_returns_false_when_role_missing` | **AWS-mocked (moto)** | idem | Role ausente → False (não levanta) |
| 9 | `test_build_session_name_default_prefix_is_validate` | Pure unit | `_build_session_name()` | Default prefix do role-validation é `CxMngValidate` |
| 10 | `test_build_session_name_uses_codebuild_id` | Pure unit | idem | `CODEBUILD_BUILD_ID` aparece no nome, sanitizado |
| 11 | `test_role_validation_boto3_config_has_expected_settings` | Pure unit | `BOTO3_CONFIG` | Mesma config de retry/timeout do deploy script |

### `tests/test_customer_managed_deploy.py` — 51 testes

| # | Teste | Tipo | Componente / fluxo | O que valida |
|---|---|---|---|---|
| 1 | `test_policy_hash_is_deterministic` | Pure unit | `policy_hash()` | Mesmo doc → mesmo hash |
| 2 | `test_policy_hash_is_key_order_independent` | Pure unit | idem | Reordenar keys → mesmo hash (`sort_keys=True`) |
| 3 | `test_policy_hash_changes_when_document_changes` | Pure unit | idem | Doc diferente → hash diferente |
| 4 | `test_filter_tags_keeps_complete_entries` | Pure unit | `filter_tags()` | Tags `{Key, Value}` preservadas |
| 5 | `test_filter_tags_drops_entries_without_value` | Pure unit | idem | Value vazio → dropado |
| 6 | `test_filter_tags_drops_entries_without_key` | Pure unit | idem | Key vazia → dropado |
| 7 | `test_filter_tags_handles_empty_input` | Pure unit | idem | Lista vazia → lista vazia |
| 8 | `test_diff_policy_handles_identical_documents` | Pure unit | `diff_policy()` | Docs iguais → não loga DIFF |
| 9 | `test_diff_policy_handles_string_resource` | Pure unit | idem | `Resource: "string"` (não lista) → não crasha |
| 10 | `test_diff_policy_reports_added_and_removed_actions` | Pure unit | idem | Actions added/removed aparecem no log |
| 11 | `test_load_state_returns_empty_when_no_object` | **AWS-mocked (moto S3)** | `load_state()` | Bucket vazio → `{}` |
| 12 | `test_load_state_returns_dict_when_object_exists` | **AWS-mocked (moto S3)** | idem | Object existe → dict parseado |
| 13 | `test_load_state_returns_empty_when_bucket_unset` | Pure unit | idem | `state_bucket=None` → `{}` sem chamada S3 |
| 14 | `test_save_state_writes_and_stamps_timestamp` | **AWS-mocked (moto S3)** | `save_state()` | PutObject feito + `last_execution` adicionado |
| 15 | `test_previously_managed_accounts_lists_existing_state_files` | **AWS-mocked (moto S3)** | `get_previously_managed_accounts()` | Lista keys sob `state/`, filtra por all-digits |
| 16 | `test_previously_managed_accounts_empty_when_no_bucket` | Pure unit | idem | `s3_client=None` → set vazio |
| 17 | `test_default_assignments_and_policies_folders_match_constants` | Pure unit | `parse_args()` | Defaults batem com `DEFAULT_*_DIR` |
| 18 | `test_assignments_and_policies_folders_can_be_overridden` | Pure unit | idem | CLI args sobrepõem defaults |
| 19 | `test_validate_account_id_accepts_12_digits` | Pure unit | `_validate_account_id()` | ID válido passa |
| 20-26 | `test_validate_account_id_rejects_invalid[...]` (7 paramétricos) | Pure unit | idem | Inválidos → ValueError |
| 27 | `test_validate_account_id_rejects_non_string` | Pure unit | idem | int → ValueError |
| 28 | `test_validate_account_id_includes_context_in_error` | Pure unit | idem | `context` aparece na msg |
| 29-35 | `test_build_session_name_*` (7 testes) | Pure unit | `_build_session_name()` | Env var, fallback, sanitização, truncação, regex IAM, sem `--` |
| 36 | `test_get_iam_client_returns_working_iam_client` | **AWS-mocked (moto)** | `get_iam_client()` | Assume role → retorna IAM client funcional |
| 37 | `test_get_current_policy_doc_returns_document_when_policy_exists` | **AWS-mocked (moto)** | `get_current_policy_doc()` | Policy existe → retorna documento |
| 38 | `test_get_current_policy_doc_returns_none_when_policy_missing` | **AWS-mocked (moto)** | idem | Policy inexistente → None (sem raise) |
| 39 | `test_create_update_creates_new_policy_with_cxmng_tag` | **AWS-mocked (moto)** | `create_update_*` | First-time create + tag `cx-mng:true` automática |
| 40 | `test_create_update_applies_user_tags_alongside_cxmng_tag` | **AWS-mocked (moto)** | idem | Tags do JSON + tag `cx-mng:true` aplicadas juntas |
| 41 | `test_create_update_creates_new_version_for_existing_managed_policy` | **AWS-mocked (moto)** | idem | Policy `cx-mng:true` com doc diferente → nova IAM policy version |
| 42 | `test_create_update_skips_when_hash_in_state_matches_repo` | **AWS-mocked (moto)** | idem | State S3 com hash igual → nenhum API call |
| 43 | `test_create_update_skips_existing_policy_without_cxmng_tag` | **AWS-mocked (moto)** | idem | **Safety**: policy sem tag `cx-mng:true` não é tocada |
| 44 | `test_create_update_dry_run_makes_no_api_mutations` | **AWS-mocked (moto)** | idem | `--dry-run` → nenhuma policy criada |
| 45 | `test_delete_removes_managed_policy_no_longer_in_assignments` | **AWS-mocked (moto)** | `delete_*` | Policy `cx-mng:true` fora de assignments → deletada |
| 46 | `test_delete_preserves_policy_without_cxmng_tag` | **AWS-mocked (moto)** | idem | **Safety**: policy sem tag `cx-mng:true` jamais é deletada |
| 47 | `test_delete_preserves_policy_currently_in_assignment` | **AWS-mocked (moto)** | idem | Policy ainda em assignment → preservada |
| 48 | `test_delete_dry_run_makes_no_api_mutations` | **AWS-mocked (moto)** | idem | `--dry-run` → nenhuma deleção |
| 49 | `test_boto3_config_has_expected_timeouts_and_retries` | Pure unit | `BOTO3_CONFIG` | Connect/read timeouts e retries config corretos |
| 50 | `test_get_iam_client_applies_boto3_config` | **AWS-mocked (moto)** | `get_iam_client()` | Config é realmente aplicada ao client retornado |
| 51 | `test_create_update_handles_five_version_cap` | **AWS-mocked (moto)** | `create_update_*` | Cap de 5 versions IAM: oldest deletada antes de criar nova |

---

## Cobertura por arquivo de produção

| Script de produção | Funções tocadas pelos testes | Funções **NÃO** tocadas |
|---|---|---|
| `customer-managed-validation.py` | `load_policy_files`, `validate_unique_policy_name`, `validate_policy_paths`, `load_assignment_files`, `validate_target_account_ids` | `parse_args` (CLI parsing), `main` (orquestração CLI) |
| `role-validation.py` | `get_target_accounts`, `check_role_exists`, `_build_session_name` | `parse_args`, `main` |
| `customer-managed-deploy.py` | `policy_hash`, `filter_tags`, `_validate_account_id`, `_build_session_name`, `parse_args`, `load_state`, `save_state`, `diff_policy`, `get_previously_managed_accounts`, `get_iam_client`, `get_current_policy_doc`, `create_update_customer_managed_policy`, `delete_customer_managed_policy` | `main` (orquestração CLI) |

Todas as funções públicas dos 3 scripts estão cobertas, exceto a orquestração CLI (`main()`) que é trivial — apenas chama as funções já testadas.

### `tests/test_stackset_role_template.py` — 4 testes

Parseiam `cfn/cx-mng-stackset-deploy-role.yaml` (com loader que ignora `!Sub`/`!Ref`) e validam o invariante de segurança do least-privilege split (MEDIUM-4):

| # | Teste | O que valida |
|---|---|---|
| 1 | `test_destructive_actions_require_cxmng_tag_condition` | Toda ação destrutiva (`iam:DeletePolicy`, `iam:DeletePolicyVersion`, `iam:CreatePolicyVersion`, `iam:TagPolicy`, `iam:UntagPolicy`) está num statement com `Condition: aws:ResourceTag/cx-mng=true` |
| 2 | `test_no_destructive_action_in_unconditioned_statement` | Nenhum statement **sem** a tag condition contém ações destrutivas (pega regressão de alguém mover uma ação destrutiva para o statement de read/create) |
| 3 | `test_create_policy_is_allowed_without_tag_condition` | `iam:CreatePolicy` **não** está sob a tag condition (senão a criação nunca funcionaria — a policy não tem tag no momento de criar) |
| 4 | `test_no_wildcard_resource_on_destructive_statements` | Statements destrutivos usam `Resource` escopado à conta, não `*` |

### `tests/test_pipeline_bucket_policy.py` — 3 testes

Parseiam `cfn/cx-mng-pipeline.yaml` e validam o controle de integridade do state (HIGH-2, variante leve via bucket policy):

| # | Teste | O que valida |
|---|---|---|
| 1 | `test_state_prefix_write_protection_exists` | Existe um `Deny` para `s3:PutObject`/`s3:DeleteObject` no prefixo `state/*` |
| 2 | `test_state_protection_excepts_only_via_principal_arn` | O Deny usa `StringNotEquals` em `aws:PrincipalArn` (padrão seguro, não `NotPrincipal`) |
| 3 | `test_state_protection_applies_to_all_principals` | `Principal` é `*` (o Deny + condição cobre todos os callers) |

---

## Limitações de cobertura — o que a suite atual NÃO pega

Esta seção é a parte mais importante para responder à preocupação "testes isolados não detectam erros". As 3 categorias abaixo descrevem bugs que **passariam** pela suite atual:

### Categoria 1 — `moto` ≠ AWS real

**O que `moto` NÃO simula:**

| Aspecto | Comportamento AWS real | Comportamento moto |
|---|---|---|
| **IAM policy evaluation** | Se o role não tem `iam:CreatePolicy`, falha com AccessDenied | Aceita (não checa permissões) |
| **STS ExternalId** | Se a role exige ExternalId e não passamos, falha | Aceita |
| **Quotas (à exceção das que testamos)** | 1500 policies/conta, etc. | Sem limite |
| **Rate limits / Throttling em runtime** | TooManyRequestsException sob carga | Nunca acontece |
| **Eventual consistency** | `create_policy` → `get_policy` pode retornar 404 por alguns ms | Sempre síncrono |
| **KMS via S3** | Precisa de `kms:Decrypt` no role para Get/PutObject em bucket KMS-encrypted | moto não enforça |

**Bugs que passariam pela suite atual:**
- IAM permission missing — pegamos só quando deploy falha em produção
- Eventual consistency bugs (race entre create e read)
- Falta de retry em quota/throttling errors em runtime real

**Por que o teste de retry com `botocore.stub` não funciona:** `Stubber` intercepta DEPOIS do retry handler — quando ele retorna erro, o boto3 já passou pelo loop de retry e considera "resposta da API". Não há como exercitar o caminho de retry sem mockar HTTP-level (mais frágil que o valor que adiciona).

**O que dá pra fazer:** Após qualquer mudança de IAM no template, rodar uma execução **real** em conta de DEV/teste (não há substituto para isso). Isso é parte da próxima categoria de testes pendente.

### Categoria 2 — CloudFormation deployment

**O que `cfn-lint` NÃO pega:**

| Tipo de erro | Pega? |
|---|---|
| Sintaxe YAML inválida | ✅ Sim |
| Schema CloudFormation (props erradas) | ✅ Sim |
| Tipo errado (ex: passar dict onde espera string) | ✅ Sim |
| Referência circular | ⚠️ Parcial |
| Permissões IAM faltando para CFN deploy | ❌ Não |
| Resource conflict (nome de role já existe) | ❌ Não |
| Quota da conta (ex: 200 stacks) | ❌ Não |
| Race condition entre dependências | ❌ Não |
| **Behavior em runtime** (ex: lifecycle apagando state real) | ❌ Não |

**Bugs que passariam:**
- Lifecycle config apagando `state/` em produção (pegado por revisão humana, não por teste)
- Replacement não-óbvio de recurso (mudar `Name` da pipeline força recriação, perde execuções históricas)
- Bucket policy bloqueando algo que CodePipeline precisa

**O que dá pra fazer:**
- **Change-set obrigatório antes de deploy:** `aws cloudformation create-change-set` e revisar manualmente antes de `execute-change-set`.
- **Smoke test após deploy:** `scripts/post_deploy_smoke_test.py` que verifica que o stack está em `CREATE_COMPLETE`/`UPDATE_COMPLETE` e os recursos críticos existem.
- **Deploy de teste em conta isolada** com pipeline real disparado, antes de aplicar em conta de produção.

### Categoria 3 — Pipeline E2E em conta real

Nenhum mock simula:
- A cadeia completa: GitHub push → CodePipeline trigger → CodeBuild stage → IAM cross-account
- Latência real entre stages
- CodeBuild logs em CloudWatch
- Falhas de network reais entre regions/services

**O que dá pra fazer:** disparar a pipeline real contra contas de teste com policies reais. **Não é teste automatizado** — é parte do processo de release.

---

## Recomendações por nível de risco da mudança

### Mudança de baixo risco (script Python, lógica isolada)
- **Mínimo aceitável:** os testes existentes passando + um E2E manual contra os templates reais
- Exemplo de mudança nesse perfil: validações novas, helpers

### Mudança de risco médio (template CFN, sem efeito cross-account novo)
- **Mínimo:** `cfn-lint` exit 0 + pytest passando + revisão humana do diff do template
- **Recomendável:** rodar `aws cloudformation create-change-set` antes do `execute-change-set`
- **Após o deploy:** rodar `scripts/post_deploy_smoke_test.py` para validar o stack
- Exemplo: mudanças de IAM scoping, encryption, retention

### Mudança de risco alto (cross-account, ExternalId, ou que afeta produção direto)
- **Mínimo:** tudo do médio + deploy em **conta de dev isolada** com pipeline real disparada antes de aplicar em produção
- **Recomendável:** plan de rollback escrito, janela de manutenção combinada
- Exemplo: state integrity, tag conditions cross-account, ExternalId

---

## Próximas adições recomendadas

Em ordem de prioridade:

1. **Pipeline E2E em conta de dev:** disparar a pipeline real contra contas de teste com policies reais. **Não é teste automatizado** — é parte do processo de release. Esforço: depende da infraestrutura disponível.

2. **Verificação cross-account em produção:** após deploy do StackSet, executar uma rotina manual ou script que faça `assume_role` em cada conta-alvo com a role real, confirmando que a role existe e tem as permissões esperadas.

---

## Como rodar os testes

```bash
# Setup (uma vez)
cd cloudformation/iam-cx-mng-pipeline-main
python3 -m venv .venv
source .venv/bin/activate

# Reproducible / hash-pinned install (preferred, especially on any host that
# holds AWS credentials). requirements-dev.lock is generated by
# pip-compile --generate-hashes and must be committed; see the "Reproducible
# / hash-pinned installs" section of the top-level README.md.
pip install --require-hashes -r requirements-dev.lock

# Abstract/unpinned install (local experimentation only):
#   pip install -r requirements-dev.txt

# Suite completa
pytest

# Versão silenciosa (apenas dots)
pytest -q

# Com nomes detalhados
pytest -v

# Apenas um arquivo
pytest tests/test_customer_managed_validation.py

# Apenas testes que casam um padrão
pytest -k policy_hash
pytest -k "validate_account_id and rejects"

# Testes que tocam AWS (via moto)
pytest -k "load_state or save_state or check_role_exists or previously_managed"

# Apenas testes pure unit (mais rápidos, menos completos)
pytest -k "policy_hash or filter_tags or validate_unique or build_session_name or validate_account_id"

# Smoke tests contra templates reais
pytest -k real_
```

## Como interpretar quando um teste falha

| Categoria do teste falhando | Provável causa | Impacto |
|---|---|---|
| Pure unit | Bug na função pura ou regressão acidental | Pequeno se isolado, mas vale investigar |
| Filesystem integration | Mudança em formato de JSON ou path inesperado | Médio — pode afetar o real run |
| AWS-mocked (moto) | Mudança no fluxo de chamadas boto3 | Médio — pode mascarar bug real |
| Smoke (`test_real_*`) | **Templates reais inconsistentes** | **Crítico** — pipeline vai falhar em produção |

Os 3 smoke tests (`test_real_templates_have_unique_policy_names`, `test_real_templates_have_valid_paths`, `test_real_assignments_have_valid_target_ids`) são a "primeira linha de defesa": se um deles falha, **não faça merge** até o template ser corrigido.

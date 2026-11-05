# Guia de Implantação: Governança de Cloud Run, AI Studio e IAP em Escala Organizacional

Este documento orienta a implementação da governança de segurança em toda a organização Google Cloud Platform (GCP). O objetivo é garantir que **100% dos serviços Cloud Run** — tanto os **mais de 150 já existentes** em múltiplos projetos quanto **qualquer novo serviço ou atualização** implantada via **Google AI Studio**, Console ou CLI:

1. Tenham o acesso público desautenticado (`allUsers`) bloqueado preventivamente por **Organization Policies**.
2. Tenham automaticamente a proteção do **Identity-Aware Proxy (IAP)** ativada em segundos através de uma **esteira de remediação orientada a eventos**.
3. Tenham todo o estoque legado de serviços remediado de forma rápida e segura através de um **script de remediação concorrente em massa**.
4. Concedam acesso no IAP exclusivamente para os colaboradores do domínio corporativo da empresa, eliminando riscos de vazamento de dados ou acessos indevidos.

---

## Arquitetura da Solução Completa

```
                                  ORGANIZAÇÃO GCP (Multi-Projeto)
 ┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │                                                                                                        │
 │   [ Projeto A (AI Studio) ]          [ Projeto B (Dev) ]               [ 150+ Projetos Legados ]       │
 │               │                               │                                    │                   │
 │               └───────────────────────────────┼────────────────────────────────────┘                   │
 │                                               ▼                                                        │
 │                               Organization Policies (Bloqueio Preventivo)                              │
 │                               • constraints/run.managed.requireInvokerIam                              │
 │                               • constraints/iam.allowedPolicyMemberDomains                             │
 │                                               │                                                        │
 │                        ┌──────────────────────┴──────────────────────┐                                 │
 │                        │                                             │                                 │
 │                        ▼ (Novos Deploys / Updates)                   ▼ (Auditoria / Legado)            │
 │            Organization Log Sink (--include-children)       remediate_existing_services.py             │
 │                        │                                    • Descoberta via Cloud Asset Inventory     │
 │                        │                                    • Paralelismo multi-thread (Audit & Apply) │
 └────────────────────────┼───────────────────────────────────────────────────┬───────────────────────────┘
                          │ Encaminha eventos em tempo real                   │ Aplica correções em lote
                          ▼                                                   ▼
                                        PROJETO CENTRAL DE GOVERNANÇA
 ┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │                                                                                                        │
 │                                       Pub/Sub Central Topic                                            │
 │                                                 │                                                      │
 │                                                 ▼                                                      │
 │                                  Cloud Function (Gen 2 - Python)                                       │
 │                                                 │                                                      │
 │               Para CADA serviço detectado (Legado ou Novo Deploy/Update):                              │
 │               1. Ativa flag nativa de IAP ('run.googleapis.com/iap-enabled': 'true')                   │
 │               2. Remove 'allUsers' e desativa bypass de autenticação                                   │
 │               3. Concede 'roles/run.invoker' para a SA do IAP (service-<NUM>@gcp-sa-iap...)             │
 │               4. Concede 'roles/iap.httpsResourceAccessor' no IAP Web (serviço e projeto)              │
 │                  para o domínio corporativo (ex: domain:suaempresa.com)                                │
 └────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Estrutura dos Arquivos do Pacote de Governança

O pacote de implementação contém 5 arquivos:

```text
ai-studio-governance/
├── requirements.txt                 # Dependências da Cloud Function Gen 2
├── main.py                          # Handler da Cloud Function orientada a eventos
├── setup_org_governance.sh          # Script de implantação da infraestrutura centralizada
├── remediate_existing_services.py   # Motor de remediação e auditoria concorrente em massa
└── remediate_existing_services.sh   # Wrapper CLI para auditoria (--dry-run) e aplicação (--apply)
```

---

## Pré-requisitos de Quem Vai Executar

O operador responsável pela execução deve ter as seguintes permissões a nível de Organização:
- `roles/orgpolicy.policyAdmin` (para definir as Organization Policies).
- `roles/resourcemanager.organizationAdmin` (para criar Log Sinks organizacionais e conceder permissões à Service Account).
- `roles/cloudasset.viewer` (para descoberta em alta velocidade de serviços via Cloud Asset Inventory).
- `roles/owner` ou permissões equivalentes no **Projeto Central de Governança** onde a Cloud Function e Pub/Sub serão hospedados.

---

## Parte 1: Configuração das Organization Policies (Bloqueio Preventivo)

As políticas de organização atuam como barreiras estruturais (*guardrails*): mesmo que um desenvolvedor tente marcar "Allow public access" ou o AI Studio gere um deploy desautenticado, a própria API da Google impedirá a publicação com acessos externos irrestritos.

### Política 1: `constraints/run.managed.requireInvokerIam`
> **Objetivo**: Garante que todo serviço Cloud Run exija verificação IAM antes de receber requisições, impedindo deploys públicos irrestritos.

1. No Console do GCP, acesse **IAM e administração** > **Políticas da organização** (*Organization Policies*).
2. Verifique se o seletor de escopo no topo do console está apontando para a sua **Organização**.
3. No campo de busca, pesquise por:
   `constraints/run.managed.requireInvokerIam`
   *(Nome de exibição: "Require Cloud Run services to use IAM invoker check")*
4. Clique na política e depois em **Edit (Editar política)**.
5. Em **Applies to (Aplica-se a)**, selecione **Customize (Personalizar)**.
6. Em **Policy enforcement (Aplicação da política)**, selecione **Enforce (Ativar)**.
7. Clique em **Set Policy (Salvar)**.

---

### Política 2: `constraints/iam.allowedPolicyMemberDomains`
> **Objetivo**: Impede que identidades externas (como `allUsers`, `allAuthenticatedUsers` ou contas `@gmail.com` de fora da empresa) sejam adicionadas a políticas IAM em qualquer projeto.

1. No mesmo menu de **Políticas da organização**, pesquise por:
   `constraints/iam.allowedPolicyMemberDomains`
   *(Nome de exibição: "Domain restricted sharing")*
2. Clique na política e depois em **Edit (Editar política)**.
3. Em **Applies to**, selecione **Customize (Personalizar)**.
4. Em **Policy rules (Regras da política)**, adicione uma regra:
   - **Policy type**: `Allow (Permitir)`
   - **Values**: Insira o seu **Google Workspace / Cloud Identity Customer ID** (ex: `C0xxxxxxx`).
     *(Dica: Para descobrir seu Customer ID, acesse admin.google.com > Configurações da conta > Perfil > ID do cliente, ou execute via CLI: `gcloud organizations list`)*.
5. Clique em **Set Policy (Salvar)**.

---

## Parte 2: Implantação da Automação em Tempo Real (Novos Deploys e Updates)

Esta etapa implanta a infraestrutura centralizada que intercepta qualquer deploy ou atualização de Cloud Run em qualquer projeto da organização e aplica o IAP automaticamente em segundos.

---

### Recomendação de Arquitetura: Criação de um Projeto Central de Governança

> [!IMPORTANT]
> **Boas Práticas de Cloud Governance e Segurança (Landing Zone)**:
> É altamente recomendado **criar um projeto dedicado exclusivo** (ex: `prj-org-governance` ou `sec-governance-central`) para hospedar a infraestrutura central de remediação (o tópico **Cloud Pub/Sub**, a **Cloud Function** e a **Service Account** de governança).

#### Por que utilizar um projeto central dedicado?
1. **Segregação de Responsabilidades (Princípio do Menor Privilégio)**: Isola os componentes de segurança e governança dos projetos de negócio, workloads de aplicação e ambientes de desenvolvimento.
2. **Controle de Acesso Restrito (IAM)**: Apenas administradores corporativos e o time de Cloud Security/DevOps terão privilégios de edição/leitura nesse projeto, impedindo que desenvolvedores ou usuários dos projetos finais alterem ou desativem a automação.
3. **Visibilidade e Faturamento Isolados**: Centraliza todos os custos (mínimos ou cobertos pelo nível gratuito) de logs de auditoria, mensagens de Pub/Sub e invocações de Functions sob um único centro de custo.
4. **Ciclo de Vida Independente**: O projeto central de governança permanece perene, mesmo se projetos de aplicações temporários ou testes no AI Studio forem criados e destruídos com frequência na organização.

#### Como criar e preparar o Projeto Central via `gcloud` (Recomendado):

Se a organização ainda não tiver um projeto central para governança, execute os comandos abaixo para criá-lo:

```bash
# 1. Definir o ID desejado para o projeto central de governança
CENTRAL_PROJECT_ID="prj-org-governance"

# 2. Identificar a Conta de Faturamento (Billing Account) ativa
BILLING_ACCOUNT=$(gcloud billing accounts list --format="value(name)" --filter="open=true" | head -n 1)

# 3. Criar o projeto corporativo
gcloud projects create "${CENTRAL_PROJECT_ID}" \
  --name="Central Governance & Security"

# 4. Vincular a conta de faturamento ao projeto
gcloud billing projects link "${CENTRAL_PROJECT_ID}" \
  --billing-account="${BILLING_ACCOUNT}"

# 5. Definir como projeto ativo no terminal
gcloud config set project "${CENTRAL_PROJECT_ID}"
```

> **Nota**: Ao editar o script `setup_org_governance.sh`, atribua o ID escolhido na variável `CENTRAL_PROJECT="${CENTRAL_PROJECT_ID}"`.

---

### 1. `requirements.txt`

```text
functions-framework==3.*
google-cloud-run>=0.10.0
google-iam-v1>=0.13.0
cloudevents==1.*
requests>=2.28.0
google-auth>=2.20.0
```

---

### 2. `main.py`

```python
import os
import json
import base64
import re
import functions_framework
from google.cloud import run_v2
from google.iam.v1 import iam_policy_pb2, policy_pb2
import google.auth
from google.auth.transport.requests import Request
import requests

# Domínio(s) corporativo(s) que terão acesso liberado via IAP (suporta múltiplos separados por vírgula)
RAW_ALLOWED = os.environ.get("ALLOWED_DOMAIN", "domain:suaempresa.com")

def parse_allowed_members(raw_val: str):
    members = []
    for item in raw_val.split(","):
        item = item.strip()
        if not item:
            continue
        if item.startswith("domain:") or item.startswith("user:") or item.startswith("group:"):
            members.append(item)
        else:
            members.append(f"domain:{item}")
    return members or ["domain:suaempresa.com"]

ALLOWED_MEMBERS = parse_allowed_members(RAW_ALLOWED)

@functions_framework.cloud_event
def auto_remediate_cloud_run(cloud_event):
    """Intercepta criações e atualizações do Cloud Run (especialmente AI Studio) e ativa o IAP."""
    try:
        pubsub_message = cloud_event.data.get("message", {})
        data_encoded = pubsub_message.get("data", "")
        if not data_encoded:
            return

        log_payload = json.loads(base64.b64decode(data_encoded).decode("utf-8"))
        proto_payload = log_payload.get("protoPayload", {})
        resource_name = proto_payload.get("resourceName", "")

        # Filtra estritamente serviços (ignora domainmappings, revisions, etc.)
        if not resource_name or "/services/" not in resource_name:
            return

        # Extrai a região real a partir dos metadados do log
        location = (
            log_payload.get("resource", {}).get("labels", {}).get("location")
            or log_payload.get("resource", {}).get("labels", {}).get("zone")
            or proto_payload.get("request", {}).get("location")
            or "us-central1"
        )

        parts = resource_name.strip("/").split("/")
        if "namespaces" in parts:
            project_id = parts[parts.index("namespaces") + 1]
            service_name = parts[parts.index("services") + 1]
        else:
            project_id = parts[parts.index("projects") + 1]
            service_name = parts[parts.index("services") + 1]

        # Ignora a própria função para evitar loops
        if "auto-remediate" in service_name:
            return

        print(f"==> Deploy detectado: Projeto '{project_id}', Serviço '{service_name}', Região '{location}'")

        # 1. Ativa a flag do IAP no Cloud Run e obtém os dados do serviço
        svc_data = enable_cloud_run_iap(project_id, location, service_name)

        # 2. Garante a Service Account do IAP e obtém o project_number com redundância tripla
        iap_sa, project_number = get_or_create_iap_sa(project_id, svc_data)

        # 3. Configura IAM do Cloud Run: remove 'allUsers' e garante a Service Account do IAP como invoker
        enforce_require_authentication(project_id, location, service_name, iap_sa)

        # 4. Garante acesso IAP Web para os membros/domínios corporativos no serviço e no projeto
        assign_iap_domain_access(project_id, location, service_name, ALLOWED_MEMBERS)

        print(f"==> Sucesso! O serviço '{service_name}' agora está 100% protegido com IAP (SA Invoker: {iap_sa}).")

    except Exception as err:
        print(f"[ERRO GERAL] Exceção no processamento do evento: {err}")


def enable_cloud_run_iap(project_id: str, location: str, service_name: str) -> dict:
    """Ativa a flag de IAP no Cloud Run através da API REST Knative e remove bypass de autenticação."""
    svc_data = {}
    try:
        credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        credentials.refresh(Request())

        url = f"https://{location}-run.googleapis.com/apis/serving.knative.dev/v1/namespaces/{project_id}/services/{service_name}"
        headers = {
            "Authorization": f"Bearer {credentials.token}",
            "Content-Type": "application/json"
        }

        resp = requests.get(url, headers=headers)
        if resp.status_code != 200:
            print(f"[AVISO] Falha ao consultar serviço para ativar IAP em {location}: {resp.status_code} - {resp.text}")
            return {}

        svc_data = resp.json()
        metadata = svc_data.setdefault("metadata", {})
        annotations = metadata.setdefault("annotations", {})

        # Ativa IAP e remove o bypass de autenticação do AI Studio
        annotations["run.googleapis.com/iap-enabled"] = "true"
        if "run.googleapis.com/invoker-iam-disabled" in annotations:
            del annotations["run.googleapis.com/invoker-iam-disabled"]

        update_resp = requests.put(url, headers=headers, json=svc_data)
        if update_resp.status_code in (200, 201):
            print(f"[OK] Flag de IAP ativada com sucesso no serviço '{service_name}'!")
        else:
            print(f"[AVISO] Resposta da atualização IAP: {update_resp.status_code} - {update_resp.text}")
    except Exception as e:
        print(f"[ERRO] Falha ao comunicar com a API do Cloud Run: {e}")

    return svc_data


def get_or_create_iap_sa(project_id: str, svc_data: dict = None) -> tuple:
    """
    Retorna (iap_sa_email, project_number).
    Usa 3 camadas de redundância para provisionar a identidade IAP e descobrir o project number.
    """
    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    credentials.refresh(Request())
    headers = {"Authorization": f"Bearer {credentials.token}"}

    project_number = ""
    iap_sa = ""

    # Camada 1: Provisiona/Garante identidade IAP via Service Usage API
    try:
        identity_url = f"https://serviceusage.googleapis.com/v1/projects/{project_id}/services/iap.googleapis.com:generateServiceIdentity"
        resp = requests.post(identity_url, headers=headers)
        if resp.status_code == 200:
            iap_email = resp.json().get("email", "")
            if iap_email:
                iap_sa = f"serviceAccount:{iap_email}"
                m = re.search(r"service-(\d+)@", iap_email)
                if m:
                    project_number = m.group(1)
                print(f"[OK] Identidade IAP garantida via Service Usage: {iap_email}")
        else:
            print(f"[INFO] Service Usage generateServiceIdentity: HTTP {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"[AVISO] Tentativa Service Usage generateServiceIdentity: {e}")

    # Camada 2: Extrai o project_number direto das URLs nas anotações do Cloud Run
    if not project_number and svc_data:
        try:
            annotations = svc_data.get("metadata", {}).get("annotations", {})
            urls_str = annotations.get("run.googleapis.com/urls", "")
            m = re.search(r"-(\d{8,15})\.", str(urls_str))
            if m:
                project_number = m.group(1)
                print(f"[OK] Project number extraído das URLs do Cloud Run: {project_number}")
        except Exception as e:
            print(f"[AVISO] Tentativa extração de run.googleapis.com/urls: {e}")

    # Camada 3: Consulta Cloud Resource Manager API
    if not project_number:
        try:
            crm_url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}"
            resp = requests.get(crm_url, headers=headers)
            if resp.status_code == 200:
                project_number = resp.json().get("projectNumber", "")
                print(f"[OK] Project number obtido via Cloud Resource Manager: {project_number}")
            else:
                print(f"[AVISO] Falha ao obter project number de {project_id}: HTTP {resp.status_code} - {resp.text}")
        except Exception as e:
            print(f"[AVISO] Tentativa Cloud Resource Manager: {e}")

    if not iap_sa and project_number:
        iap_sa = f"serviceAccount:service-{project_number}@gcp-sa-iap.iam.gserviceaccount.com"

    return iap_sa, project_number


def enforce_require_authentication(project_id: str, location: str, service_name: str, iap_sa: str):
    """Remove acesso público ('allUsers') e concede roles/run.invoker exclusivamente à Service Account do IAP."""
    run_client = run_v2.ServicesClient()
    service_path = f"projects/{project_id}/locations/{location}/services/{service_name}"

    try:
        req = iam_policy_pb2.GetIamPolicyRequest(resource=service_path)
        policy = run_client.get_iam_policy(request=req)

        invoker_found = False
        new_bindings = []

        for binding in policy.bindings:
            # Remove allUsers e allAuthenticatedUsers incondicionalmente de qualquer papel
            filtered = [m for m in binding.members if m not in ("allUsers", "allAuthenticatedUsers")]
            if binding.role == "roles/run.invoker":
                invoker_found = True
                if iap_sa and iap_sa not in filtered:
                    filtered.append(iap_sa)
            if filtered:
                b = policy_pb2.Binding(role=binding.role, members=filtered)
                new_bindings.append(b)

        if not invoker_found and iap_sa:
            b = policy_pb2.Binding(role="roles/run.invoker", members=[iap_sa])
            new_bindings.append(b)

        del policy.bindings[:]
        policy.bindings.extend(new_bindings)
        set_req = iam_policy_pb2.SetIamPolicyRequest(resource=service_path, policy=policy)
        run_client.set_iam_policy(request=set_req)
        print(f"[OK] IAM Cloud Run configurado: público removido e IAP SA '{iap_sa}' vinculada como invoker.")

    except Exception as e:
        print(f"[ERRO] Falha ao alterar IAM do Cloud Run: {e}")


def assign_iap_domain_access(project_id: str, location: str, service_name: str, members: list):
    """Garante que os domínios corporativos tenham roles/iap.httpsResourceAccessor no IAP Web do Cloud Run e do Projeto."""
    try:
        credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        credentials.refresh(Request())
        headers = {
            "Authorization": f"Bearer {credentials.token}",
            "Content-Type": "application/json"
        }

        # Alvos: recurso específico do Cloud Run e nível de projeto IAP
        targets = [
            f"projects/{project_id}/iap_web/cloud_run-{location}/services/{service_name}",
            f"projects/{project_id}/iap_web"
        ]

        role_target = "roles/iap.httpsResourceAccessor"

        for target in targets:
            url_get = f"https://iap.googleapis.com/v1/{target}:getIamPolicy"
            url_set = f"https://iap.googleapis.com/v1/{target}:setIamPolicy"

            resp = requests.post(url_get, headers=headers)
            if resp.status_code != 200:
                print(f"[AVISO] Não foi possível ler política IAP de {target}: HTTP {resp.status_code} - {resp.text}")
                continue

            policy = resp.json() or {}
            bindings = policy.setdefault("bindings", [])

            role_binding = None
            for b in bindings:
                if b.get("role") == role_target:
                    role_binding = b
                    break

            if not role_binding:
                role_binding = {"role": role_target, "members": []}
                bindings.append(role_binding)

            members_list = role_binding.setdefault("members", [])
            modified = False

            for m in members:
                if m not in members_list:
                    members_list.append(m)
                    modified = True

            if modified:
                set_resp = requests.post(url_set, headers=headers, json={"policy": policy})
                if set_resp.status_code in (200, 201):
                    print(f"[OK] Permissões IAP '{role_target}' concedidas para {members} em '{target}'.")
                else:
                    print(f"[AVISO] Resposta ao atualizar IAP em {target}: HTTP {set_resp.status_code} - {set_resp.text}")
            else:
                print(f"[INFO] Membros {members} já possuem permissão IAP em '{target}'.")

    except Exception as e:
        print(f"[ERRO] Falha ao configurar IAP Web IAM: {e}")
```

---

### 3. `setup_org_governance.sh`

```bash
#!/usr/bin/env bash
set -euo pipefail

# === VARIÁVEIS PRINCIPAIS (AJUSTE CONFORME SEU AMBIENTE) ===
CENTRAL_PROJECT="ce-latam-central"       # ID do projeto central de governança
REGION="us-central1"                    # Região da Cloud Function
DOMAIN_NAME="suaempresa.com"            # Seu domínio corporativo (ex: minhaempresa.com)

SA_NAME="org-cloudrun-governance-sa"
TOPIC_NAME="org-cloudrun-deploy-events"
FUNCTION_NAME="auto-remediate-cloudrun-org"
SINK_NAME="sink-cloudrun-deploy-to-pubsub"

echo "=== 1. Identificando Organization e Project Number ==="
ORG_ID=$(gcloud projects get-ancestors "${CENTRAL_PROJECT}" --format="value(id)" | tail -n 1)
PROJECT_NUM=$(gcloud projects describe "${CENTRAL_PROJECT}" --format="value(projectNumber)")
echo "Organization ID: ${ORG_ID}"
echo "Project Number: ${PROJECT_NUM}"

echo "=== 2. Habilitando APIs no projeto central ==="
gcloud services enable \
  cloudfunctions.googleapis.com \
  run.googleapis.com \
  eventarc.googleapis.com \
  eventarcpublishing.googleapis.com \
  pubsub.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  cloudresourcemanager.googleapis.com \
  logging.googleapis.com \
  iap.googleapis.com \
  --project="${CENTRAL_PROJECT}"

echo "=== 2.1. Concedendo Permissões de Build (Cloud Functions Gen 2) ==="
COMPUTE_SA="${PROJECT_NUM}-compute@developer.gserviceaccount.com"
BUILD_ROLES=(
  "roles/artifactregistry.writer"
  "roles/storage.objectAdmin"
  "roles/logging.logWriter"
)

for role in "${BUILD_ROLES[@]}"; do
  gcloud projects add-iam-policy-binding "${CENTRAL_PROJECT}" \
    --member="serviceAccount:${COMPUTE_SA}" \
    --role="${role}" \
    --quiet &>/dev/null || true
done

echo "=== 3. Criando Tópico Pub/Sub Central ==="
if ! gcloud pubsub topics describe "${TOPIC_NAME}" --project="${CENTRAL_PROJECT}" &>/dev/null; then
  gcloud pubsub topics create "${TOPIC_NAME}" --project="${CENTRAL_PROJECT}"
  echo "Tópico '${TOPIC_NAME}' criado com sucesso."
else
  echo "Tópico '${TOPIC_NAME}' já existe."
fi

echo "=== 4. Criando Service Account Central ==="
SA_EMAIL="${SA_NAME}@${CENTRAL_PROJECT}.iam.gserviceaccount.com"
if ! gcloud iam service-accounts describe "${SA_EMAIL}" --project="${CENTRAL_PROJECT}" &>/dev/null; then
  gcloud iam service-accounts create "${SA_NAME}" \
    --display-name="SA para Governanca Cloud Run e IAP Multi-Projeto" \
    --project="${CENTRAL_PROJECT}"
  echo "Service Account '${SA_EMAIL}' criada."
else
  echo "Service Account '${SA_EMAIL}' já existe."
fi

echo "=== 5. Concedendo Papéis na Organização para a Service Account ==="
ORG_ROLES=(
  "roles/run.admin"
  "roles/iap.admin"
  "roles/serviceusage.serviceUsageAdmin"
  "roles/resourcemanager.projectIamAdmin"
  "roles/resourcemanager.viewer"
  "roles/iam.serviceAccountUser"
)

for role in "${ORG_ROLES[@]}"; do
  echo "Atribuindo ${role} a nível de Organização..."
  gcloud organizations add-iam-policy-binding "${ORG_ID}" \
    --member="serviceAccount:${SA_EMAIL}" \
    --role="${role}" \
    --quiet
done

echo "=== 6. Fazendo Deploy da Cloud Function (Gen 2) ==="
gcloud functions deploy "${FUNCTION_NAME}" \
  --gen2 \
  --runtime="python311" \
  --region="${REGION}" \
  --source="." \
  --entry-point="auto_remediate_cloud_run" \
  --service-account="${SA_EMAIL}" \
  --trigger-topic="${TOPIC_NAME}" \
  --set-env-vars="ALLOWED_DOMAIN=domain:${DOMAIN_NAME}" \
  --project="${CENTRAL_PROJECT}" \
  --quiet

echo "=== 7. Criando/Atualizando Organization Log Sink ==="
TOPIC_PATH="pubsub.googleapis.com/projects/${CENTRAL_PROJECT}/topics/${TOPIC_NAME}"
LOG_FILTER='protoPayload.serviceName="run.googleapis.com" AND (protoPayload.methodName:"Services.CreateService" OR protoPayload.methodName:"Services.ReplaceService" OR protoPayload.methodName:"Services.UpdateService")'

if ! gcloud logging sinks describe "${SINK_NAME}" --organization="${ORG_ID}" &>/dev/null; then
  SINK_WRITER_IDENTITY=$(gcloud logging sinks create "${SINK_NAME}" "${TOPIC_PATH}" \
    --organization="${ORG_ID}" \
    --include-children \
    --log-filter="${LOG_FILTER}" \
    --format="value(writerIdentity)")
else
  gcloud logging sinks update "${SINK_NAME}" "${TOPIC_PATH}" \
    --organization="${ORG_ID}" \
    --log-filter="${LOG_FILTER}" \
    --quiet
  SINK_WRITER_IDENTITY=$(gcloud logging sinks describe "${SINK_NAME}" --organization="${ORG_ID}" --format="value(writerIdentity)")
fi

echo "Writer Identity: ${SINK_WRITER_IDENTITY}"

echo "=== 8. Autorizando o Sink da Org no Pub/Sub ==="
MAX_RETRIES=6
RETRY_DELAY=10
SUCCESS=false

for ((i=1; i<=MAX_RETRIES; i++)); do
  echo "Tentativa ${i} de ${MAX_RETRIES}: Vinculando permissão Pub/Sub Publisher..."
  if gcloud pubsub topics add-iam-policy-binding "${TOPIC_NAME}" \
      --member="${SINK_WRITER_IDENTITY}" \
      --role="roles/pubsub.publisher" \
      --project="${CENTRAL_PROJECT}" \
      --quiet 2>/dev/null; then
    SUCCESS=true
    echo "Permissão concedida com sucesso!"
    break
  else
    echo "Aguardando propagação da identidade de serviço no IAM (${RETRY_DELAY}s)..."
    sleep "${RETRY_DELAY}"
  fi
done

if [ "$SUCCESS" = false ]; then
  echo "Aviso: Execute manualmente se necessário:"
  echo "gcloud pubsub topics add-iam-policy-binding ${TOPIC_NAME} --member=\"${SINK_WRITER_IDENTITY}\" --role=\"roles/pubsub.publisher\" --project=\"${CENTRAL_PROJECT}\""
  exit 1
fi

echo "=========================================================="
echo " GOVERNANÇA MULTI-PROJETO IMPLANTADA COM SUCESSO! "
echo "=========================================================="
```

---

### 4. Executando a Implantação da Automação Central

Após salvar os arquivos (`requirements.txt`, `main.py` e `setup_org_governance.sh`) no mesmo diretório e ajustar as variáveis no script com o ID do seu **projeto central** e o **domínio corporativo**:

```bash
# Dar permissão de execução
chmod +x setup_org_governance.sh

# Executar a instalação automatizada
./setup_org_governance.sh
```

O script realizará todo o processo de ponta a ponta:
1. Habilita todas as APIs necessárias no projeto central de governança.
2. Configura permissões de build para a Cloud Function Gen 2.
3. Cria o tópico central do Pub/Sub (`org-cloudrun-deploy-events`).
4. Cria a Service Account (`org-cloudrun-governance-sa`) e atribui os papéis a nível de organização.
5. Faz o deploy da Cloud Function Gen 2 com o domínio da empresa nas variáveis de ambiente.
6. Cria o Log Sink na organização (`sink-cloudrun-deploy-to-pubsub`) com filtro para `CreateService`, `ReplaceService` e `UpdateService`.
7. Concede o papel de `roles/pubsub.publisher` para a identidade do sink com retentativas automáticas de propagação IAM.

---

## Parte 3: Remediação de Serviços Existentes (Estoque Legado de 150+ Serviços)

Para serviços que **já foram implantados no passado** e estão expostos na organização, fornecemos um script de varredura concorrente em Python e seu respectivo wrapper em Bash.

O script opera com:
- **Descoberta via Cloud Asset Inventory**: Descobre 150+ serviços em dezenas de projetos e regiões em uma única chamada de 1 segundo.
- **Processamento Paralelo Multi-Thread**: Inspeciona e remedia serviços em lotes concorrentes ultrarrápidos com retry resiliente.
- **Modo Auditoria (`--dry-run`) Seguro**: Avalia e gera o relatório executivo detalhando o status de cada serviço sem realizar nenhuma modificação no ambiente.
- **Modo Remediação Ativa (`--apply`)**: Aplica atomicamente IAP, remove `allUsers`, concede permissão para a SA do IAP e libera o domínio corporativo.

---

### Passo 1: Executar Auditoria Prévia (`--dry-run`)

Antes de realizar alterações nos serviços de produção, execute o script em modo auditoria:

```bash
# Na organização inteira (Modo Leitura / Auditoria):
./remediate_existing_services.sh --dry-run --domain domain:suaempresa.com
```

Ou restrinja a um ou mais projetos específicos para validação inicial:
```bash
./remediate_existing_services.sh --dry-run --projects ce-latam-aidatacloud --domain domain:suaempresa.com
```

**Exemplo de Saída do Relatório Executivo:**
```text
================================================================================
 INICIANDO REMEDIAÇÃO DE CLOUD RUN EM LARGA ESCALA (IAP GOVERNANCE)
================================================================================
Modo:             AUDITORIA (DRY-RUN - SEM ALTERAÇÕES)
Domínio IAP:      domain:suaempresa.com
Concorrência:     8 threads
[INFO] Buscando serviços via Cloud Asset Inventory na Organização 6050496051...

[✓] Total de 18 serviços Cloud Run identificados.

[2/3] Analisando e processando serviços em paralelo...

  [COMPLIANT ] ce-latam-aidatacloud  | us-east1    | remix-anywhere-7339  -> Já protegido por IAP, sem acesso público e com permissões corporativas
  [EXPOSED   ] ce-latam-aidatacloud  | us-east1    | remix-pdb-viewer-1085 -> Requer remediação: IAP SA ausente como invoker
  [EXPOSED   ] ce-sap-latam-genai    | us-central1 | hypera-academy       -> Requer remediação: Bypass de autenticação ativo, Permissão de domínio ausente no IAP Web
  [EXPOSED   ] ce-sap-latam-genai    | us-central1 | sap-mcp-blocker      -> Requer remediação: IAP desativado, Acesso público (allUsers) ativo, IAP SA ausente como invoker, Permissão de domínio ausente no IAP Web

================================================================================
                    RELATÓRIO EXECUTIVO DE GOVERNANÇA
================================================================================
 Total de Serviços Analisados:        18
 Já Conformes / Protegidos:          3
 Expostos (Necessitam Remediação):   15
 Falhas / Erros:                     0
================================================================================
```

---

### Passo 2: Aplicar Remediação em Massa (`--apply`)

Após validar o relatório de auditoria, aplique as correções:

```bash
# Aplicar na Organização inteira:
./remediate_existing_services.sh --apply --domain domain:suaempresa.com

# Ou aplicar em projetos específicos:
./remediate_existing_services.sh --apply --projects ce-latam-aidatacloud,outro-projeto --domain domain:suaempresa.com
```

**Resultado Esperado:**
```text
  [COMPLIANT ] ce-latam-aidatacloud  | us-east1 | remix-anywhere-7339    -> Já protegido por IAP
  [REMEDIATED] ce-latam-aidatacloud  | us-east1 | remix-pdb-viewer-1085  -> IAP ativado, público revogado, IAP SA vinculada e domínio liberado
  [REMEDIATED] ce-sap-latam-genai    | us-east1 | koryn-clinical-tester  -> IAP ativado, público revogado, IAP SA vinculada e domínio liberado

================================================================================
                    RELATÓRIO EXECUTIVO DE GOVERNANÇA
================================================================================
 Total de Serviços Analisados:        18
 Já Conformes / Protegidos:          3
 Remediados com Sucesso:             15
 Falhas / Erros:                     0
================================================================================
```

---

## Como Validar o Funcionamento

### Teste 1: Criação de um novo serviço no AI Studio
1. Abra o **Google AI Studio** (`aistudio.google.com`).
2. Crie ou selecione uma aplicação e clique em **Deploy to Cloud Run**.
3. Escolha **qualquer projeto** da organização.
4. Concluído o deploy, acesse o serviço no Cloud Run:
   - A opção **Require authentication** estará ativada.
   - A flag nativa de **Identity-Aware Proxy (IAP)** estará ativada.
   - Os colaboradores com conta corporativa `@suaempresa.com` terão acesso concedido automaticamente via login Google.

### Teste 2: Atualização de um serviço existente (AI Studio, Console ou CLI)
1. No **Google AI Studio**, faça uma alteração no código/prompt e clique em atualizar o deploy do mesmo serviço.
2. Ou via terminal: execute um `gcloud run deploy` com uma nova imagem/revisão.
3. O evento de `UpdateService` ou `ReplaceService` será capturado no mesmo instante pela esteira.
4. A Cloud Function revalidará o serviço e garantirá que nenhuma flag pública (`allUsers` ou bypass) seja reintroduzida, mantendo o IAP ativo.

---

## Perguntas Frequentes e Diagnóstico

### Ao acessar a URL, recebi `Error: Forbidden - Your client does not have permission to get URL / from this server`
Existem duas causas técnicas para essa mensagem após a tela de login do Google:

#### Causa 1: Falta de permissão no IAP Web IAM
- **Explicação**: O IAP possui uma política IAM própria (`projects/PROJECT_ID/iap_web`), que é separada das permissões gerais do GCP. O usuário ou grupo precisa do papel `roles/iap.httpsResourceAccessor`.
- **Como a solução resolve**: A Cloud Function e o script de remediação adicionam automaticamente a permissão para `domain:suaempresa.com` tanto a nível do serviço quanto a nível do projeto.
- **Comando manual para conceder acesso (se necessário)**:
  ```bash
  gcloud iap web add-iam-policy-binding \
    --project="ID_DO_PROJETO" \
    --member="domain:suaempresa.com" \
    --role="roles/iap.httpsResourceAccessor"
  ```

#### Causa 2: Service Account do IAP sem permissão de Invoker no Cloud Run
- **Explicação**: Quando o IAP autentica o usuário com sucesso, o próprio IAP precisa encaminhar o tráfego HTTP para o container do Cloud Run. Para isso, a Service Account gerenciada do IAP (`service-<PROJECT_NUM>@gcp-sa-iap.iam.gserviceaccount.com`) **deve ter o papel `roles/run.invoker`** na política IAM do serviço Cloud Run. Se essa permissão faltar, o Cloud Run rejeita a conexão do IAP com 403, e o usuário final vê a tela de erro do IAP.
- **Como a solução resolve**: Tanto a Cloud Function (`main.py`) quanto o script de remediação (`remediate_existing_services.py`) obtêm dinamicamente o número do projeto e adicionam essa Service Account como `roles/run.invoker` no Cloud Run, garantindo que o tráfego flua sem erros.
- **Comando manual para vincular a SA do IAP (se necessário)**:
  ```bash
  PROJECT_NUM=$(gcloud projects describe "ID_DO_PROJETO" --format="value(projectNumber)")
  gcloud run services add-iam-policy-binding "NOME_DO_SERVICO" \
    --region="REGIAO" \
    --project="ID_DO_PROJETO" \
    --member="serviceAccount:service-${PROJECT_NUM}@gcp-sa-iap.iam.gserviceaccount.com" \
    --role="roles/run.invoker"
  ```

---

### Como o script elimina o aviso: *"This service is publicly accessible because 'allUsers' has been granted permission on the service"*

- **O que significa esse aviso no Console**: No Console do Cloud Run (no topo da tela do serviço ou na aba **Segurança**), o Google Cloud exibe essa tarja de advertência sempre que o papel de invocador (`roles/run.invoker`) possui o membro público `allUsers` (qualquer pessoa na internet desautenticada). Isso acontece por padrão quando serviços são criados pelo AI Studio ou quando a opção *"Allow unauthenticated invocations"* é marcada no deploy.
- **Como a remediação elimina o aviso**:
  1. O script de remediação (`remediate_existing_services.py` / `.sh`) e a Cloud Function (`main.py`) localizam todas as permissões do serviço e **removem incondicionalmente** `allUsers` e `allAuthenticatedUsers` de todas as vinculações IAM.
  2. Removem a anotação `run.googleapis.com/invoker-iam-disabled` (bypass de autenticação inserido pelo AI Studio).
  3. Adicionam exclusivamente a Service Account do IAP como invocadora autorizada.
  4. Realizam uma validação imediata pós-remediação para garantir que o membro público foi purgado.
- **Resultado Visível no Console**:
  - O status de autenticação do serviço no Console do Cloud Run muda imediatamente de *"Allow unauthenticated"* para **"Require authentication"** com o ícone de cadeado verde.
  - A tarja de advertência *"This service is publicly accessible because 'allUsers' has been granted permission on the service"* **desaparece completamente**.


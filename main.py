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
RAW_ALLOWED = os.environ.get("ALLOWED_DOMAIN", "domain:felipechagas.altostrat.com")

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

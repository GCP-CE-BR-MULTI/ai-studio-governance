import os
import json
import base64
import functions_framework
from google.cloud import run_v2
from google.iam.v1 import iam_policy_pb2
from google.api_core.exceptions import GoogleAPICallError
import google.auth
from google.auth.transport.requests import Request
import requests

# Domínio corporativo que terá acesso liberado via IAP
DEFAULT_DOMAIN = os.environ.get("ALLOWED_DOMAIN", "domain:felipechagas.altostrat.com")

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

        # 1. Ativa a flag do IAP no Cloud Run e obtém o project number
        project_number = enable_cloud_run_iap(project_id, location, service_name)

        # 2. Configura IAM do Cloud Run: remove 'allUsers' e garante a Service Account do IAP como invoker
        enforce_require_authentication(project_id, location, service_name, project_number)

        # 3. Garante acesso IAP Web para o domínio corporativo no serviço e no projeto
        assign_iap_domain_access(project_id, location, service_name, DEFAULT_DOMAIN)

        print(f"==> Sucesso! O serviço '{service_name}' agora está 100% protegido com IAP.")

    except Exception as err:
        print(f"[ERRO GERAL] Exceção no processamento do evento: {err}")


def get_project_number(project_id: str) -> str:
    """Obtém o project number via Cloud Resource Manager API."""
    try:
        credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        credentials.refresh(Request())
        headers = {"Authorization": f"Bearer {credentials.token}"}
        resp = requests.get(f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}", headers=headers)
        if resp.status_code == 200:
            return resp.json().get("projectNumber", "")
        else:
            print(f"[AVISO] Falha ao obter project number de {project_id}: HTTP {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"[AVISO] Falha ao obter project number de {project_id}: {e}")
    return ""


def enable_cloud_run_iap(project_id: str, location: str, service_name: str) -> str:
    """Ativa a flag de IAP no Cloud Run através da API REST Knative/Cloud Run e retorna o project number."""
    project_number = ""
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
            return ""

        svc_data = resp.json()
        metadata = svc_data.setdefault("metadata", {})
        annotations = metadata.setdefault("annotations", {})
        project_number = metadata.get("namespace", "")

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

    return project_number


def enforce_require_authentication(project_id: str, location: str, service_name: str, project_number: str = ""):
    """Remove acesso público ('allUsers') e concede roles/run.invoker à Service Account do IAP."""
    run_client = run_v2.ServicesClient()
    service_path = f"projects/{project_id}/locations/{location}/services/{service_name}"

    try:
        if not project_number or not project_number.isdigit():
            project_number = get_project_number(project_id)

        iap_sa = f"serviceAccount:service-{project_number}@gcp-sa-iap.iam.gserviceaccount.com" if project_number else ""

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
            binding.members[:] = filtered
            if binding.members:
                new_bindings.append(binding)

        if not invoker_found and iap_sa:
            binding_proto = iam_policy_pb2.Binding()
            binding_proto.role = "roles/run.invoker"
            binding_proto.members.append(iap_sa)
            new_bindings.append(binding_proto)

        policy.bindings[:] = new_bindings
        set_req = iam_policy_pb2.SetIamPolicyRequest(resource=service_path, policy=policy)
        run_client.set_iam_policy(request=set_req)
        print(f"[OK] IAM Cloud Run configurado: público removido e IAP SA '{iap_sa}' vinculada como invoker.")

    except Exception as e:
        print(f"[ERRO] Falha ao alterar IAM do Cloud Run: {e}")


def assign_iap_domain_access(project_id: str, location: str, service_name: str, member: str):
    """Garante que o domínio corporativo tenha roles/iap.httpsResourceAccessor no IAP Web do Cloud Run e do Projeto."""
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
                print(f"[AVISO] Não foi possível ler política IAP de {target}: {resp.status_code} - {resp.text}")
                continue

            policy = resp.json() or {}
            bindings = policy.setdefault("bindings", [])

            role_found = False
            member_exists = False

            for b in bindings:
                if b.get("role") == role_target:
                    role_found = True
                    members_list = b.setdefault("members", [])
                    if member in members_list:
                        member_exists = True
                    else:
                        members_list.append(member)
                    break

            if not role_found:
                bindings.append({
                    "role": role_target,
                    "members": [member]
                })

            if not member_exists:
                set_resp = requests.post(url_set, headers=headers, json={"policy": policy})
                if set_resp.status_code in (200, 201):
                    print(f"[OK] Permissão IAP '{role_target}' concedida para '{member}' em '{target}'.")
                else:
                    print(f"[AVISO] Resposta ao atualizar IAP em {target}: {set_resp.status_code} - {set_resp.text}")
            else:
                print(f"[INFO] '{member}' já possui permissão IAP em '{target}'.")

    except Exception as e:
        print(f"[ERRO] Falha ao configurar IAP Web IAM: {e}")

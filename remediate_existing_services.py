#!/usr/bin/env python3
"""
Script de Remediação em Massa de Serviços Cloud Run Existentes em Larga Escala.
Varre a organização ou projetos selecionados, identifica serviços Cloud Run expostos
ou sem IAP, e aplica a governança completa:
  1. Ativa a flag nativa de IAP ('run.googleapis.com/iap-enabled': 'true').
  2. Remove 'allUsers' e 'allAuthenticatedUsers' da IAM Policy do Cloud Run.
  3. Adiciona a Service Account do IAP ('service-<PROJECT_NUM>@gcp-sa-iap...') como invoker.
  4. Garante acesso no IAP Web ('roles/iap.httpsResourceAccessor') para o domínio corporativo.
"""

import sys
import os
import argparse
import subprocess
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple

import requests
from urllib3.util import Retry
from requests.adapters import HTTPAdapter

# Códigos ANSI para saída colorida
class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

@dataclass
class ServiceTarget:
    project_id: str
    project_number: str
    region: str
    service_name: str
    status: str = "PENDING"
    details: str = ""

def create_resilient_session() -> requests.Session:
    """Cria uma sessão HTTP com política de retry automático contra falhas transitórias de rede."""
    session = requests.Session()
    retries = Retry(
        total=4,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        raise_on_status=False
    )
    adapter = HTTPAdapter(max_retries=retries, pool_connections=20, pool_maxsize=20)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

def get_auth_token() -> str:
    """Obtém token de autorização atualizado usando gcloud ou credenciais de ambiente."""
    try:
        token = subprocess.check_output(
            ["gcloud", "auth", "print-access-token"],
            text=True, stderr=subprocess.DEVNULL
        ).strip()
        if token:
            return token
    except Exception:
        pass

    try:
        import google.auth
        from google.auth.transport.requests import Request
        creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        creds.refresh(Request())
        return creds.token
    except Exception as e:
        print(f"{Colors.RED}[ERRO CRÍTICO] Falha ao obter credenciais GCP. Execute 'gcloud auth login' ou configure ADC: {e}{Colors.RESET}")
        sys.exit(1)

def discover_organization_id() -> Optional[str]:
    """Descobre o ID da organização através dos projetos acessíveis."""
    try:
        out = subprocess.check_output(
            ["gcloud", "organizations", "list", "--format=value(ID)", "--limit=1"],
            text=True, stderr=subprocess.DEVNULL
        ).strip()
        if out:
            return out
    except Exception:
        pass
    return None

def discover_projects(org_id: Optional[str] = None) -> List[Tuple[str, str]]:
    """Retorna lista de tuplas (project_id, project_number) ativos."""
    projects = []
    try:
        cmd = ["gcloud", "projects", "list", "--filter=lifecycleState:ACTIVE", "--format=json(projectId,projectNumber)"]
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        data = json.loads(out)
        for p in data:
            pid = p.get("projectId")
            pnum = str(p.get("projectNumber", ""))
            if pid:
                projects.append((pid, pnum))
    except Exception as e:
        print(f"{Colors.RED}[ERRO] Falha ao listar projetos: {e}{Colors.RESET}")
    return projects

def discover_services_via_asset_inventory(org_id: str) -> List[ServiceTarget]:
    """Descobre todos os serviços Cloud Run na Organização em uma única chamada usando Cloud Asset Inventory."""
    services = []
    print(f"{Colors.BLUE}[INFO] Buscando serviços via Cloud Asset Inventory na Organização {org_id}...{Colors.RESET}")
    try:
        cmd = [
            "gcloud", "asset", "search-all-resources",
            "--asset-types=run.googleapis.com/Service",
            f"--scope=organizations/{org_id}",
            "--format=json(name,project,location)"
        ]
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        items = json.loads(out)
        for item in items:
            name_uri = item.get("name", "") # //run.googleapis.com/projects/{pid}/locations/{loc}/services/{name}
            parts = name_uri.strip("/").split("/")
            if "services" in parts and "projects" in parts and "locations" in parts:
                project_id = parts[parts.index("projects") + 1]
                location = parts[parts.index("locations") + 1]
                service_name = parts[parts.index("services") + 1]
                project_num = item.get("project", "").replace("projects/", "")

                # Ignora funções de governança
                if "auto-remediate" in service_name:
                    continue

                services.append(ServiceTarget(
                    project_id=project_id,
                    project_number=project_num,
                    region=location,
                    service_name=service_name
                ))
    except Exception as e:
        print(f"{Colors.YELLOW}[AVISO] Falha ao usar Cloud Asset Inventory ({e}). Usando modo iterativo por projeto.{Colors.RESET}")
        return []
    return services

def discover_services_in_project(project_id: str, project_number: str) -> List[ServiceTarget]:
    """Descobre serviços Cloud Run em um projeto específico."""
    services = []
    try:
        cmd = [
            "gcloud", "run", "services", "list",
            f"--project={project_id}",
            "--format=json(metadata.name,metadata.labels,metadata.namespace)"
        ]
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        items = json.loads(out)
        for item in items:
            service_name = item.get("metadata", {}).get("name", "")
            labels = item.get("metadata", {}).get("labels", {})
            region = labels.get("cloud.googleapis.com/location") or item.get("region", "") or "us-central1"
            pnum = item.get("metadata", {}).get("namespace", "") or project_number

            if "auto-remediate" in service_name:
                continue

            services.append(ServiceTarget(
                project_id=project_id,
                project_number=pnum,
                region=region,
                service_name=service_name
            ))
    except Exception:
        pass
    return services

def get_project_number(project_id: str, headers: Dict[str, str], session: requests.Session) -> str:
    """Recupera o project number se não estiver disponível."""
    try:
        resp = session.get(f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}", headers=headers, timeout=10)
        if resp.status_code == 200:
            return resp.json().get("projectNumber", "")
    except Exception:
        pass
    return ""

def remediate_single_service(target: ServiceTarget, token: str, allowed_domain: str, dry_run: bool = False) -> ServiceTarget:
    """Avalia e remedia um único serviço Cloud Run com tolerância a falhas."""
    session = create_resilient_session()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        # 1. Consulta o serviço via Knative API
        url_knative = f"https://{target.region}-run.googleapis.com/apis/serving.knative.dev/v1/namespaces/{target.project_id}/services/{target.service_name}"
        resp = session.get(url_knative, headers=headers, timeout=15)
        if resp.status_code != 200:
            target.status = "ERROR"
            target.details = f"Knative API retornou HTTP {resp.status_code}"
            return target

        svc_data = resp.json()
        metadata = svc_data.setdefault("metadata", {})
        annotations = metadata.setdefault("annotations", {})

        iap_already_enabled = annotations.get("run.googleapis.com/iap-enabled") == "true"
        invoker_iam_disabled = "run.googleapis.com/invoker-iam-disabled" in annotations

        # 2. Project Number & IAP Service Account
        pnum = target.project_number or metadata.get("namespace", "")
        if not pnum or not pnum.isdigit():
            pnum = get_project_number(target.project_id, headers, session)
            target.project_number = pnum

        iap_sa = f"serviceAccount:service-{pnum}@gcp-sa-iap.iam.gserviceaccount.com" if pnum else ""

        # 3. Consulta IAM Policy do Cloud Run via REST v2
        url_run_iam_get = f"https://run.googleapis.com/v2/projects/{target.project_id}/locations/{target.region}/services/{target.service_name}:getIamPolicy"
        resp_iam = session.get(url_run_iam_get, headers=headers, timeout=15)
        run_policy = resp_iam.json() if resp_iam.status_code == 200 else {}
        run_bindings = run_policy.get("bindings", [])

        has_public_access = False
        has_iap_invoker = False

        for b in run_bindings:
            if b.get("role") == "roles/run.invoker":
                members = b.get("members", [])
                if any(m in ("allUsers", "allAuthenticatedUsers") for m in members):
                    has_public_access = True
                if iap_sa and iap_sa in members:
                    has_iap_invoker = True

        # 4. Consulta IAP Web IAM Policy
        url_iap_svc_get = f"https://iap.googleapis.com/v1/projects/{target.project_id}/iap_web/cloud_run-{target.region}/services/{target.service_name}:getIamPolicy"
        resp_iap = session.post(url_iap_svc_get, headers=headers, timeout=15)
        iap_policy = resp_iap.json() if resp_iap.status_code == 200 else {}
        iap_bindings = iap_policy.get("bindings", [])
        has_domain_iap = any(
            b.get("role") == "roles/iap.httpsResourceAccessor" and allowed_domain in b.get("members", [])
            for b in iap_bindings
        )

        is_compliant = iap_already_enabled and (not invoker_iam_disabled) and (not has_public_access) and has_iap_invoker and has_domain_iap

        if is_compliant:
            target.status = "COMPLIANT"
            target.details = "Já protegido por IAP, sem acesso público e com permissões corporativas"
            return target

        # Se estiver em modo DRY-RUN
        if dry_run:
            target.status = "EXPOSED"
            issues = []
            if not iap_already_enabled:
                issues.append("IAP desativado")
            if invoker_iam_disabled:
                issues.append("Bypass de autenticação ativo")
            if has_public_access:
                issues.append("Acesso público (allUsers) ativo")
            if not has_iap_invoker:
                issues.append("IAP SA ausente como invoker")
            if not has_domain_iap:
                issues.append("Permissão de domínio ausente no IAP Web")
            target.details = f"Requer remediação: {', '.join(issues)}"
            return target

        # =========================================================================
        # APLICAÇÃO DA REMEDIAÇÃO
        # =========================================================================
        # A. Ativa flag de IAP na Knative API
        annotations["run.googleapis.com/iap-enabled"] = "true"
        if "run.googleapis.com/invoker-iam-disabled" in annotations:
            del annotations["run.googleapis.com/invoker-iam-disabled"]

        put_resp = session.put(url_knative, headers=headers, json=svc_data, timeout=15)
        if put_resp.status_code not in (200, 201):
            target.status = "ERROR"
            target.details = f"Falha ao ativar IAP annotation: HTTP {put_resp.status_code}"
            return target

        # B. Corrige Cloud Run IAM Policy via REST v2 (Expurgo total de allUsers)
        invoker_found = False
        new_bindings = []
        for b in run_bindings:
            # Remove allUsers e allAuthenticatedUsers incondicionalmente de QUALQUER papel
            clean_members = [m for m in b.get("members", []) if m not in ("allUsers", "allAuthenticatedUsers")]
            if b.get("role") == "roles/run.invoker":
                invoker_found = True
                if iap_sa and iap_sa not in clean_members:
                    clean_members.append(iap_sa)
            b["members"] = clean_members
            if b.get("members"):
                new_bindings.append(b)

        if not invoker_found and iap_sa:
            new_bindings.append({
                "role": "roles/run.invoker",
                "members": [iap_sa]
            })

        run_policy["bindings"] = new_bindings
        url_run_iam_set = f"https://run.googleapis.com/v2/projects/{target.project_id}/locations/{target.region}/services/{target.service_name}:setIamPolicy"
        set_run_resp = session.post(url_run_iam_set, headers=headers, json={"policy": run_policy}, timeout=15)
        if set_run_resp.status_code not in (200, 201):
            target.status = "ERROR"
            target.details = f"Falha ao atualizar Cloud Run IAM: HTTP {set_run_resp.status_code}"
            return target

        # Validação pós-remediação: confirma que 'allUsers' foi 100% eliminado
        check_iam = session.get(url_run_iam_get, headers=headers, timeout=15)
        if check_iam.status_code == 200:
            final_bindings = check_iam.json().get("bindings", [])
            has_remaining_allusers = any(
                any(m in ("allUsers", "allAuthenticatedUsers") for m in b.get("members", []))
                for b in final_bindings
            )
            if has_remaining_allusers:
                target.status = "WARNING"
                target.details = "IAP ativado, mas 'allUsers' ainda persiste (verifique herança de projeto/organização)"
                return target

        # C. Concede permissão IAP Web (serviço e projeto)
        targets_iap = [
            f"projects/{target.project_id}/iap_web/cloud_run-{target.region}/services/{target.service_name}",
            f"projects/{target.project_id}/iap_web"
        ]
        role_target = "roles/iap.httpsResourceAccessor"

        for ti in targets_iap:
            u_get = f"https://iap.googleapis.com/v1/{ti}:getIamPolicy"
            u_set = f"https://iap.googleapis.com/v1/{ti}:setIamPolicy"
            r_g = session.post(u_get, headers=headers, timeout=15)
            pol = r_g.json() if r_g.status_code == 200 else {}
            b_list = pol.setdefault("bindings", [])

            rf = False
            for b in b_list:
                if b.get("role") == role_target:
                    rf = True
                    if allowed_domain not in b.setdefault("members", []):
                        b["members"].append(allowed_domain)
                    break
            if not rf:
                b_list.append({"role": role_target, "members": [allowed_domain]})

            session.post(u_set, headers=headers, json={"policy": pol}, timeout=15)

        target.status = "REMEDIATED"
        target.details = f"Acesso público 'allUsers' revogado, IAP ativado e domínio '{allowed_domain}' liberado"

    except Exception as e:
        target.status = "ERROR"
        target.details = f"Exceção durante remediação: {e}"

    return target

def main():
    parser = argparse.ArgumentParser(description="Remediação em Massa de Serviços Cloud Run para Governança IAP.")
    parser.add_argument("--org-id", type=str, help="ID numérico da organização Google Cloud.")
    parser.add_argument("--projects", type=str, help="Lista de IDs de projetos separados por vírgula (opcional).")
    parser.add_argument("--allowed-domain", type=str, default=os.environ.get("ALLOWED_DOMAIN", "domain:felipechagas.altostrat.com"),
                        help="Domínio com prefixo IAM a ser liberado no IAP (ex: domain:minhaempresa.com).")
    parser.add_argument("--dry-run", action="store_true", help="Modo auditoria: apenas inspeciona sem alterar recursos.")
    parser.add_argument("--concurrency", type=int, default=6, help="Número de threads simultâneas para processamento.")

    args = parser.parse_args()

    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN} INICIANDO REMEDIAÇÃO DE CLOUD RUN EM LARGA ESCALA (IAP GOVERNANCE){Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.RESET}")
    print(f"Modo:             {'AUDITORIA (DRY-RUN - SEM ALTERAÇÕES)' if args.dry_run else 'REMEDIAÇÃO ATIVA (APLICAR ALTERAÇÕES)'}")
    print(f"Domínio IAP:      {args.allowed_domain}")
    print(f"Concorrência:     {args.concurrency} threads")

    token = get_auth_token()

    # 1. Descoberta de Serviços
    all_targets: List[ServiceTarget] = []

    if args.projects:
        project_ids = [p.strip() for p in args.projects.split(",") if p.strip()]
        print(f"\n{Colors.BLUE}[1/3] Descobrindo serviços nos projetos informados: {', '.join(project_ids)}{Colors.RESET}")
        for pid in project_ids:
            found = discover_services_in_project(pid, "")
            all_targets.extend(found)
    else:
        org_id = args.org_id or discover_organization_id()
        if org_id:
            all_targets = discover_services_via_asset_inventory(org_id)

        if not all_targets:
            print(f"\n{Colors.BLUE}[1/3] Listando projetos da Organização...{Colors.RESET}")
            projects = discover_projects(org_id)
            print(f"Encontrados {len(projects)} projetos. Buscando serviços Cloud Run...")
            for pid, pnum in projects:
                found = discover_services_in_project(pid, pnum)
                all_targets.extend(found)

    print(f"\n{Colors.GREEN}[✓] Total de {len(all_targets)} serviços Cloud Run identificados.{Colors.RESET}")

    if not all_targets:
        print(f"{Colors.YELLOW}Nenhum serviço Cloud Run encontrado para analisar. Encerrando.{Colors.RESET}")
        return

    # 2. Processamento Concorrente
    print(f"\n{Colors.BLUE}[2/3] Analisando e processando serviços em paralelo...{Colors.RESET}\n")

    results: List[ServiceTarget] = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        future_map = {
            executor.submit(remediate_single_service, t, token, args.allowed_domain, args.dry_run): t
            for t in all_targets
        }

        for future in as_completed(future_map):
            try:
                res = future.result()
            except Exception as e:
                t = future_map[future]
                res = ServiceTarget(
                    project_id=t.project_id,
                    project_number=t.project_number,
                    region=t.region,
                    service_name=t.service_name,
                    status="ERROR",
                    details=f"Erro fatal de execução: {e}"
                )
            results.append(res)

            # Log em tempo real formatado
            status_color = Colors.GREEN if res.status in ("COMPLIANT", "REMEDIATED") else (Colors.YELLOW if res.status == "EXPOSED" else Colors.RED)
            print(f"  {status_color}[{res.status:10}]{Colors.RESET} {res.project_id:25} | {res.region:11} | {res.service_name:38} -> {res.details}")

    # 3. Relatório Executivo
    total = len(results)
    compliant = sum(1 for r in results if r.status == "COMPLIANT")
    remediated = sum(1 for r in results if r.status == "REMEDIATED")
    exposed = sum(1 for r in results if r.status == "EXPOSED")
    errors = sum(1 for r in results if r.status == "ERROR")

    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}                    RELATÓRIO EXECUTIVO DE GOVERNANÇA{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.RESET}")
    print(f" Total de Serviços Analisados:        {total}")
    print(f" Já Conformes / Protegidos:          {Colors.GREEN}{compliant}{Colors.RESET}")
    if args.dry_run:
        print(f" Expostos (Necessitam Remediação):   {Colors.YELLOW}{exposed}{Colors.RESET}")
    else:
        print(f" Remediados com Sucesso:             {Colors.GREEN}{remediated}{Colors.RESET}")
    print(f" Falhas / Erros:                     {Colors.RED if errors else Colors.GREEN}{errors}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*80}{Colors.RESET}\n")

if __name__ == "__main__":
    main()

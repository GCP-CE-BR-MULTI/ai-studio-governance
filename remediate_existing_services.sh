#!/usr/bin/env bash
# ==============================================================================
# Script de Remediação em Larga Escala de Serviços Cloud Run
# Executa auditoria ou remediação em massa para proteger serviços com IAP.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="$(which python3 || echo "python")"

# Configurações Padrão
DEFAULT_DOMAIN="domain:felipechagas.altostrat.com"
ALLOWED_DOMAIN="${ALLOWED_DOMAIN:-$DEFAULT_DOMAIN}"
DRY_RUN_FLAG=""
TARGET_PROJECTS=""
TARGET_ORG=""
CONCURRENCY=8

print_usage() {
  echo "Uso: $0 [opções]"
  echo ""
  echo "Opções:"
  echo "  --dry-run                 Executa em modo auditoria (somente leitura, não faz alterações)."
  echo "  --apply                   Executa a remediação ativa (aplica IAP e restringe acessos)."
  echo "  --domain <DOMINIO_IAM>    Domínio corporativo permitido no IAP (padrão: $DEFAULT_DOMAIN)."
  echo "  --projects <p1,p2,...>    Limita a execução a projetos específicos separados por vírgula."
  echo "  --org-id <ORG_ID>         Especifica o ID da organização GCP (ex: 6050496051)."
  echo "  --concurrency <N>         Número de threads simultâneas (padrão: 8)."
  echo "  -h, --help                Exibe esta ajuda."
  echo ""
  echo "Exemplos:"
  echo "  # 1. Auditoria prévia na organização inteira (Seguro):"
  echo "  $0 --dry-run"
  echo ""
  echo "  # 2. Executar auditoria em um único projeto de homologação:"
  echo "  $0 --dry-run --projects ce-latam-aidatacloud"
  echo ""
  echo "  # 3. Aplicar remediação em massa na organização inteira:"
  echo "  $0 --apply --domain domain:minhaempresa.com"
  exit 1
}

# Parse argumentos
if [ $# -eq 0 ]; then
  print_usage
fi

MODE_SET=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN_FLAG="--dry-run"
      MODE_SET=true
      shift
      ;;
    --apply)
      DRY_RUN_FLAG=""
      MODE_SET=true
      shift
      ;;
    --domain)
      ALLOWED_DOMAIN="$2"
      shift 2
      ;;
    --projects)
      TARGET_PROJECTS="--projects $2"
      shift 2
      ;;
    --org-id)
      TARGET_ORG="--org-id $2"
      shift 2
      ;;
    --concurrency)
      CONCURRENCY="$2"
      shift 2
      ;;
    -h|--help)
      print_usage
      ;;
    *)
      echo "Opção desconhecida: $1"
      print_usage
      ;;
  esac
done

if [ "$MODE_SET" = false ]; then
  echo "ERRO: É necessário especificar '--dry-run' ou '--apply'."
  print_usage
fi

# Verifica se python3 e requests estão disponíveis
if ! "$PYTHON_BIN" -c "import requests" &>/dev/null; then
  echo "Instalando dependência 'requests'..."
  "$PYTHON_BIN" -m pip install requests --quiet
fi

# Executa o script Python
exec "$PYTHON_BIN" "${SCRIPT_DIR}/remediate_existing_services.py" \
  ${DRY_RUN_FLAG} \
  --allowed-domain "${ALLOWED_DOMAIN}" \
  --concurrency "${CONCURRENCY}" \
  ${TARGET_PROJECTS} \
  ${TARGET_ORG}

#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# SCRIPT DE GOVERNANÇA AUTOMATIZADA MULTI-PROJETO: CLOUD RUN + IAP
# ==============================================================================

# === VARIÁVEIS PRINCIPAIS (Ajuste para o ambiente do cliente) ===
CENTRAL_PROJECT="ce-latam-central"
REGION="us-central1"
DOMAIN_NAME="felipechagas.altostrat.com"

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

# Filtro abrangente: captura criações, substituições e atualizações (AI Studio, Console e CLI)
LOG_FILTER='protoPayload.serviceName="run.googleapis.com" AND (protoPayload.methodName:"Services.CreateService" OR protoPayload.methodName:"Services.ReplaceService" OR protoPayload.methodName:"Services.UpdateService")'

if ! gcloud logging sinks describe "${SINK_NAME}" --organization="${ORG_ID}" &>/dev/null; then
  SINK_WRITER_IDENTITY=$(gcloud logging sinks create "${SINK_NAME}" "${TOPIC_PATH}" \
    --organization="${ORG_ID}" \
    --include-children \
    --log-filter="${LOG_FILTER}" \
    --format="value(writerIdentity)")
else
  # No update do gcloud logging sinks, o TOPIC_PATH é passado como argumento posicional
  gcloud logging sinks update "${SINK_NAME}" "${TOPIC_PATH}" \
    --organization="${ORG_ID}" \
    --log-filter="${LOG_FILTER}" \
    --quiet
  SINK_WRITER_IDENTITY=$(gcloud logging sinks describe "${SINK_NAME}" --organization="${ORG_ID}" --format="value(writerIdentity)")
fi

echo "Writer Identity: ${SINK_WRITER_IDENTITY}"

echo "=== 8. Autorizando o Sink da Org no Pub/Sub (com retry resiliente) ==="
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

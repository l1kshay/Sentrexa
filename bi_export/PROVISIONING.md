# GCP provisioning for the BigQuery analytics layer

All authentication is **keyless** — the GCP project enforces
`iam.disableServiceAccountKeyCreation`, so there is no service-account JSON key
anywhere. CI uses Workload Identity Federation; local runs and the BI tools use
your own Google account via ADC / OAuth.

Values used: project `sentrexa` (number `<PROJECT_NUMBER>`), repo
`l1kshay/Sentrexa`, dataset location `US`.

## One-time setup (run as project Owner)

```bash
# APIs
gcloud services enable bigquery.googleapis.com iamcredentials.googleapis.com sts.googleapis.com

# Dataset
bq --location=US mk --dataset --description "Sentrexa analytics star schema" sentrexa:analytics

# Sync service account (no key is ever created for it)
gcloud iam service-accounts create sentrexa-bq-sync \
  --display-name="Sentrexa BigQuery sync (WIF, keyless)"

# BigQuery permissions for the sync SA
gcloud projects add-iam-policy-binding sentrexa \
  --member="serviceAccount:sentrexa-bq-sync@sentrexa.iam.gserviceaccount.com" \
  --role="roles/bigquery.jobUser"
gcloud projects add-iam-policy-binding sentrexa \
  --member="serviceAccount:sentrexa-bq-sync@sentrexa.iam.gserviceaccount.com" \
  --role="roles/bigquery.dataEditor"
# (dataset-scoped dataEditor via `bq add-iam-policy-binding sentrexa:analytics`
#  is preferable but currently requires Google allowlisting; project-level covers it.)

# Workload Identity Pool + OIDC provider, locked to this repo
gcloud iam workload-identity-pools create github-pool \
  --location="global" --display-name="GitHub Actions pool"

gcloud iam workload-identity-pools providers create-oidc github-provider \
  --location="global" --workload-identity-pool="github-pool" \
  --display-name="GitHub OIDC" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition="assertion.repository == 'l1kshay/Sentrexa'"

# Let workflows from the repo impersonate the sync SA
gcloud iam service-accounts add-iam-policy-binding \
  sentrexa-bq-sync@sentrexa.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/github-pool/attribute.repository/l1kshay/Sentrexa"

# Local keyless auth (opens your browser)
gcloud auth application-default login
gcloud auth application-default set-quota-project sentrexa
```

## GitHub Actions secrets (identifiers only — no credentials)

| Secret | Value |
|--------|-------|
| `GCP_PROJECT_ID` | `sentrexa` |
| `GCP_SYNC_SA` | `sentrexa-bq-sync@sentrexa.iam.gserviceaccount.com` |
| `GCP_WIF_PROVIDER` | `projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/github-pool/providers/github-provider` |
| `DATABASE_URL_RO` | (already set for the pipeline workflow) |

## BI tools

Looker Studio, Power BI, and Tableau each connect with **"Sign in with Google"
(OAuth)** using the project-Owner account. No reader service account, no key
file. Step-by-step: [`docs/BI_CONNECTIONS.md`](../docs/BI_CONNECTIONS.md).

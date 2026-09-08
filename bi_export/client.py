"""BigQuery client + dataset helpers.

Authentication is entirely keyless, via Application Default Credentials:

* **Local** - ``gcloud auth application-default login`` (your own project-Owner
  account). Optionally ``gcloud auth application-default set-quota-project
  sentrexa``.
* **GitHub Actions** - Workload Identity Federation. ``google-github-actions/auth``
  writes a short-lived credential-config file and points
  ``GOOGLE_APPLICATION_CREDENTIALS`` at it; the client below picks it up with no
  code change.

There is no service-account JSON key file anywhere in this project.
"""

from __future__ import annotations

from google.cloud import bigquery

from config.settings import settings


def bigquery_client() -> bigquery.Client:
    """A BigQuery client for the configured project, using ADC."""
    return bigquery.Client(
        project=settings.bigquery.require_project(),
        location=settings.bigquery.location,
    )


def dataset_ref() -> str:
    """``<project>.<dataset>`` - the analytics dataset id."""
    return settings.bigquery.dataset_ref


def table_ref(name: str) -> str:
    """``<project>.<dataset>.<name>``."""
    return f"{dataset_ref()}.{name}"

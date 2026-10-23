# SPDX-License-Identifier: MIT
"""Test bootstrap.

The production scripts live in folders with hyphens in their filenames,
which is not a valid Python module identifier, so we import them by path
using ``importlib.util`` and expose them as fixtures.
"""

import importlib.util
import os
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_module(name: str, path: Path):
    """Import a Python file by path and return the resulting module."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Absolute path to the project root."""
    return PROJECT_ROOT


@pytest.fixture
def validation_module(monkeypatch):
    """Load source/validation/customer-managed-validation.py as a module.

    sys.argv is reset so module-level argparse calls never see pytest's args.
    """
    monkeypatch.setattr(sys, "argv", ["customer-managed-validation.py"])
    return _load_module(
        "customer_managed_validation",
        PROJECT_ROOT / "source" / "validation" / "customer-managed-validation.py",
    )


@pytest.fixture
def role_validation_module(monkeypatch):
    """Load source/validation/role-validation.py as a module."""
    monkeypatch.setattr(sys, "argv", ["role-validation.py"])
    return _load_module(
        "role_validation",
        PROJECT_ROOT / "source" / "validation" / "role-validation.py",
    )


@pytest.fixture
def deploy_module(monkeypatch):
    """Load source/customer-managed-policies/customer-managed-deploy.py as a module."""
    monkeypatch.setattr(sys, "argv", ["customer-managed-deploy.py"])
    return _load_module(
        "customer_managed_deploy",
        PROJECT_ROOT
        / "source"
        / "customer-managed-policies"
        / "customer-managed-deploy.py",
    )


@pytest.fixture
def aws_credentials(monkeypatch):
    """Mocked AWS credentials so boto3 inside moto does not try to read ~/.aws.

    Also sets the two secret-scoped environment variables the deploy /
    role-validation scripts now require:

    * ``EXTERNAL_ID`` — mandatory for every cross-account AssumeRole.
    * ``ALLOWED_ACCOUNT_IDS`` — operator-managed allowlist. Tests use moto's
      default account ID (``123456789012``), so that is the only entry.

    Individual tests that need to exercise "env var missing" paths call
    ``monkeypatch.delenv`` after this fixture runs.
    """
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("EXTERNAL_ID", "test-external-id-1234567890")
    monkeypatch.setenv("ALLOWED_ACCOUNT_IDS", "123456789012")


@pytest.fixture(autouse=True)
def _reset_allowed_account_ids_cache():
    """Clear the module-level allowlist cache between tests.

    ``get_allowed_account_ids`` memoises its result for the lifetime of the
    process, which would leak state across tests that mutate the
    ``ALLOWED_ACCOUNT_IDS`` env var.
    """
    for module_name in ("customer_managed_deploy", "role_validation"):
        module = sys.modules.get(module_name)
        if module is not None and hasattr(module, "_ALLOWED_ACCOUNT_IDS_CACHE"):
            module._ALLOWED_ACCOUNT_IDS_CACHE = None
    yield
    for module_name in ("customer_managed_deploy", "role_validation"):
        module = sys.modules.get(module_name)
        if module is not None and hasattr(module, "_ALLOWED_ACCOUNT_IDS_CACHE"):
            module._ALLOWED_ACCOUNT_IDS_CACHE = None

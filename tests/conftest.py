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
    """Mocked AWS credentials so boto3 inside moto does not try to read ~/.aws."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

"""Tests for partition-aware target-region discovery."""

import importlib.util
from pathlib import Path
import sys


_REPO_ROOT = Path(__file__).resolve().parents[1]
_APP_PATH = (
    _REPO_ROOT
    / "aiml-security-assessment"
    / "functions"
    / "security"
    / "resolve_regions"
    / "app.py"
)
_SPEC = importlib.util.spec_from_file_location("resolve_regions_app", _APP_PATH)
resolve_regions_app = importlib.util.module_from_spec(_SPEC)
sys.modules["resolve_regions_app"] = resolve_regions_app
_SPEC.loader.exec_module(resolve_regions_app)


class FakeSession:
    def __init__(self, partition, available_regions):
        self.partition = partition
        self.available_regions = available_regions
        self.calls = []

    def get_partition_for_region(self, region):
        self.calls.append(("partition", region))
        return self.partition

    def get_available_regions(self, service, partition_name):
        self.calls.append((service, partition_name))
        value = self.available_regions.get(service, [])
        if isinstance(value, Exception):
            raise value
        return value


def test_service_discovery_includes_agent_registry():
    assert resolve_regions_app.AGENT_REGISTRY_SERVICE == "agent-registry-control"
    assert resolve_regions_app.AGENT_REGISTRY_SERVICE in resolve_regions_app.SERVICES


def test_all_uses_partition_catalog_when_new_service_metadata_is_empty(
    monkeypatch,
):
    session = FakeSession(
        partition="aws",
        available_regions={
            "ec2": ["eu-west-1", "us-east-1", "us-west-2"],
            "bedrock": ["us-east-1"],
            "sagemaker": ["us-east-1", "us-west-2"],
            "bedrock-agentcore-control": [],
            "agent-registry-control": [],
        },
    )
    monkeypatch.setattr(resolve_regions_app.boto3, "Session", lambda: session)
    monkeypatch.setenv("TARGET_REGIONS", "all")
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    assert resolve_regions_app.resolve_regions() == [
        "eu-west-1",
        "us-east-1",
        "us-west-2",
    ]
    assert ("agent-registry-control", "aws") in session.calls


def test_all_does_not_cross_the_current_partition(monkeypatch):
    session = FakeSession(
        partition="aws-us-gov",
        available_regions={
            "ec2": ["us-gov-east-1", "us-gov-west-1"],
            "bedrock": [],
            "sagemaker": [],
            "bedrock-agentcore-control": [],
            "agent-registry-control": [],
        },
    )
    monkeypatch.setattr(resolve_regions_app.boto3, "Session", lambda: session)
    monkeypatch.setenv("TARGET_REGIONS", "all")
    monkeypatch.setenv("AWS_REGION", "us-gov-west-1")

    assert resolve_regions_app.resolve_regions() == [
        "us-gov-east-1",
        "us-gov-west-1",
    ]
    assert all(
        partition == "aws-us-gov"
        for service, partition in session.calls
        if service != "partition"
    )


def test_get_available_regions_preserves_zero_argument_contract(monkeypatch):
    session = FakeSession(
        partition="aws",
        available_regions={
            "ec2": ["us-east-1", "us-west-2"],
            "bedrock": ["us-east-1"],
            "sagemaker": ["us-west-2"],
            "bedrock-agentcore-control": [],
            "agent-registry-control": [],
        },
    )
    monkeypatch.setattr(resolve_regions_app.boto3, "Session", lambda: session)
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    assert resolve_regions_app.get_available_regions() == [
        "us-east-1",
        "us-west-2",
    ]


def test_explicit_regions_do_not_query_endpoint_metadata(monkeypatch):
    monkeypatch.setattr(
        resolve_regions_app.boto3,
        "Session",
        lambda: (_ for _ in ()).throw(AssertionError("Session should not be created")),
    )
    monkeypatch.setenv("TARGET_REGIONS", "us-east-1, us-west-2")

    assert resolve_regions_app.resolve_regions() == ["us-east-1", "us-west-2"]

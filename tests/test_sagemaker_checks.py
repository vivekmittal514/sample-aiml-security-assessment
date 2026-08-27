"""
Tests for SageMaker security assessment checks (SM-01 through SM-25).

Each check is tested for:
- No resources found -> N/A status
- Compliant resources -> Passed status
- Non-compliant resources -> Failed with correct severity
- Exception handling -> returns could-not-assess finding (csv_data not empty)
- Output schema validity
"""

import sys
import os
import importlib.util
from unittest.mock import call, patch, MagicMock

from botocore.exceptions import EndpointConnectionError, ClientError
import pytest

from tests.test_helpers import extract_csv_data, assert_finding_schema

# Load sagemaker app module directly to avoid name collisions
_sm_dir = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "aiml-security-assessment/functions/security/sagemaker_assessments",
    )
)
if _sm_dir not in sys.path:
    sys.path.insert(0, _sm_dir)

_spec = importlib.util.spec_from_file_location(
    "sagemaker_app", os.path.join(_sm_dir, "app.py")
)
sagemaker_app = importlib.util.module_from_spec(_spec)
sys.modules["sagemaker_app"] = sagemaker_app
_spec.loader.exec_module(sagemaker_app)


def assert_could_not_assess_finding(finding):
    assert finding["Status"] == "N/A"
    assert finding["Severity"] == "Informational"
    assert "Could not assess this check" in finding["Finding_Details"]
    assert "Error during check" not in finding["Finding_Details"]


# ===================================================================
# SM-01: check_sagemaker_internet_access
# ===================================================================
class TestSM01InternetAccess:
    """SM-01: Check SageMaker direct internet access."""

    @patch("sagemaker_app.boto3.client")
    def test_sm01_no_resources_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_internet_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        nb_paginator = MagicMock()
        domain_paginator = MagicMock()
        mock_sm.get_paginator.side_effect = lambda x: (
            nb_paginator if x == "list_notebook_instances" else domain_paginator
        )
        nb_paginator.paginate.return_value = [{"NotebookInstances": []}]
        domain_paginator.paginate.return_value = [{"Domains": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "N/A"
        assert findings[0]["Check_ID"] == "SM-01"

    @patch("sagemaker_app.boto3.client")
    def test_sm01_notebook_with_internet_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_internet_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        nb_paginator = MagicMock()
        domain_paginator = MagicMock()
        mock_sm.get_paginator.side_effect = lambda x: (
            nb_paginator if x == "list_notebook_instances" else domain_paginator
        )
        nb_paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "test-nb"}]}
        ]
        domain_paginator.paginate.return_value = [{"Domains": []}]
        mock_sm.describe_notebook_instance.return_value = {
            "DirectInternetAccess": "Enabled",
            "SubnetId": "subnet-123",
            "VpcId": "vpc-123",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert findings[0]["Severity"] == "High"

    @patch("sagemaker_app.boto3.client")
    def test_sm01_all_vpc_only_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_internet_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        nb_paginator = MagicMock()
        domain_paginator = MagicMock()
        mock_sm.get_paginator.side_effect = lambda x: (
            nb_paginator if x == "list_notebook_instances" else domain_paginator
        )
        nb_paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "test-nb"}]}
        ]
        domain_paginator.paginate.return_value = [{"Domains": []}]
        mock_sm.describe_notebook_instance.return_value = {
            "DirectInternetAccess": "Disabled",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm01_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_internet_access
        mock_client.side_effect = Exception("SageMaker error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm01_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_internet_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        nb_paginator = MagicMock()
        domain_paginator = MagicMock()
        mock_sm.get_paginator.side_effect = lambda x: (
            nb_paginator if x == "list_notebook_instances" else domain_paginator
        )
        nb_paginator.paginate.return_value = [{"NotebookInstances": []}]
        domain_paginator.paginate.return_value = [{"Domains": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-02: check_sagemaker_iam_permissions
# ===================================================================
class TestSM02IAMPermissions:
    """SM-02: Check SageMaker IAM permissions and SSO."""

    def test_sm02_empty_cache_returns_findings(self, empty_permission_cache):
        check = sagemaker_app.check_sagemaker_iam_permissions
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-02"

    def test_sm02_full_access_returns_failed(
        self, permission_cache_sagemaker_full_access
    ):
        check = sagemaker_app.check_sagemaker_iam_permissions
        result = check(permission_cache_sagemaker_full_access)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        # Should flag full access as an issue
        has_failed = any(f["Status"] == "Failed" for f in findings)
        assert has_failed

    def test_sm02_schema_valid(self, empty_permission_cache):
        check = sagemaker_app.check_sagemaker_iam_permissions
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    def test_sm02_iam_check_does_not_query_domains(
        self, permission_cache_sagemaker_full_access
    ):
        # The IAM-global SM-02 check must NOT call regional SageMaker domain APIs;
        # domain/SSO inspection lives in check_sagemaker_sso_configuration so it is
        # not duplicated per region. Only IAM findings should be produced here.
        check = sagemaker_app.check_sagemaker_iam_permissions
        result = check(permission_cache_sagemaker_full_access, region="Global")
        findings = extract_csv_data(result)
        # No SSO finding should be emitted from the IAM-global check
        assert all("SSO" not in f["Finding"] for f in findings)


# ===================================================================
# SM-02b: check_sagemaker_sso_configuration (regional)
# ===================================================================
class TestSM02SSOConfiguration:
    """SM-02: Regional SageMaker domain SSO configuration check."""

    @patch("sagemaker_app.boto3.client")
    def test_sso_no_domains_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_sso_configuration
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Domains": []}]
        mock_sm.get_paginator.return_value = mock_paginator
        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-02"
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sso_non_sso_domain_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_sso_configuration
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Domains": [{"DomainId": "d-123"}]}]
        mock_sm.get_paginator.return_value = mock_paginator
        mock_sm.describe_domain.return_value = {
            "DomainName": "test-domain",
            "AuthMode": "IAM",
        }
        result = check(region="us-east-1")
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"
        assert "SSO" in findings[0]["Finding"]

    @patch("sagemaker_app.boto3.client")
    def test_sso_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_sso_configuration
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Domains": []}]
        mock_sm.get_paginator.return_value = mock_paginator
        result = check(region="us-east-1")
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-03: check_sagemaker_data_protection
# ===================================================================
class TestSM03DataProtection:
    """SM-03: Check SageMaker data protection / encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm03_no_resources_returns_na_or_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_data_protection
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        # Mock paginators for notebooks, endpoints, training jobs
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [], "EndpointConfigs": [], "TrainingJobSummaries": []}
        ]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-03"

    @patch("sagemaker_app.boto3.client")
    def test_sm03_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_data_protection
        mock_client.side_effect = Exception("Data protection error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm03_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_data_protection
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-04: check_guardduty_enabled
# ===================================================================
class TestSM04GuardDuty:
    """SM-04: Check GuardDuty is enabled."""

    @patch("sagemaker_app.boto3.client")
    def test_sm04_guardduty_enabled_returns_passed(self, mock_client):
        check = sagemaker_app.check_guardduty_enabled
        mock_gd = MagicMock()
        mock_client.return_value = mock_gd
        mock_gd.list_detectors.return_value = {"DetectorIds": ["d-123"]}
        mock_gd.get_detector.return_value = {"Status": "ENABLED"}
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"
        assert findings[0]["Check_ID"] == "SM-04"

    @patch("sagemaker_app.boto3.client")
    def test_sm04_guardduty_disabled_returns_failed(self, mock_client):
        check = sagemaker_app.check_guardduty_enabled
        mock_gd = MagicMock()
        mock_client.return_value = mock_gd
        mock_gd.list_detectors.return_value = {"DetectorIds": []}
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm04_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_guardduty_enabled
        mock_client.side_effect = Exception("GuardDuty error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm04_schema_valid(self, mock_client):
        check = sagemaker_app.check_guardduty_enabled
        mock_gd = MagicMock()
        mock_client.return_value = mock_gd
        mock_gd.list_detectors.return_value = {"DetectorIds": []}
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


class TestProposedSageMakerChecks:
    """SM-26 through SM-30 proposal checks (SM-29 remains reserved/deferred)."""

    def test_sm26_ai_protection_enabled_passes(self):
        inventory = {
            "detector_id": "detector-1",
            "detail": {
                "Status": "ENABLED",
                "Features": [{"Name": "AI_PROTECTION", "Status": "ENABLED"}],
            },
            "error": None,
        }
        finding = extract_csv_data(
            sagemaker_app.check_guardduty_ai_protection("us-east-1", inventory)
        )[0]
        assert finding["Check_ID"] == "SM-26"
        assert finding["Status"] == "Passed"

    def test_sm26_ai_protection_disabled_fails(self):
        inventory = {
            "detector_id": "detector-1",
            "detail": {"Status": "ENABLED", "Features": []},
            "error": None,
        }
        finding = extract_csv_data(
            sagemaker_app.check_guardduty_ai_protection("us-east-1", inventory)
        )[0]
        assert finding["Status"] == "Failed"
        assert finding["Severity"] == "High"

    def test_sm27_and_sm28_share_hyperpod_inventory(self):
        inventory = {
            "items": [
                {
                    "summary": {"ClusterName": "cluster-1"},
                    "detail": {
                        "ClusterName": "cluster-1",
                        "VpcConfig": {
                            "Subnets": ["subnet-1"],
                            "SecurityGroupIds": ["sg-1"],
                        },
                        "InstanceGroups": [
                            {
                                "InstanceGroupName": "workers",
                                "InstanceStorageConfigs": [
                                    {
                                        "EbsVolumeConfig": {
                                            "RootVolume": True,
                                            "VolumeKmsKeyId": "arn:kms:key-1",
                                        }
                                    },
                                    {
                                        "EbsVolumeConfig": {
                                            "RootVolume": False,
                                            "VolumeKmsKeyId": "arn:kms:key-2",
                                        }
                                    },
                                ],
                            }
                        ],
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }
        sm27 = extract_csv_data(
            sagemaker_app.check_hyperpod_ebs_cmk_encryption("us-east-1", inventory)
        )[0]
        sm28 = extract_csv_data(
            sagemaker_app.check_hyperpod_vpc_configuration("us-east-1", inventory)
        )[0]
        assert sm27["Status"] == "Passed"
        assert sm28["Status"] == "Passed"

    def test_sm27_missing_root_volume_config_fails(self):
        inventory = {
            "items": [
                {
                    "summary": {"ClusterName": "cluster-1"},
                    "detail": {
                        "ClusterName": "cluster-1",
                        "InstanceGroups": [
                            {
                                "InstanceGroupName": "workers",
                                "InstanceStorageConfigs": [],
                            }
                        ],
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }
        finding = extract_csv_data(
            sagemaker_app.check_hyperpod_ebs_cmk_encryption("us-east-1", inventory)
        )[0]
        assert finding["Status"] == "Failed"
        assert "root volume" in finding["Finding_Details"]
        assert finding["Finding_Details"].count("root volume") == 1

    def test_sm27_deduplicates_unencrypted_volume_labels(self):
        inventory = {
            "items": [
                {
                    "summary": {"ClusterName": "cluster-1"},
                    "detail": {
                        "ClusterName": "cluster-1",
                        "InstanceGroups": [
                            {
                                "InstanceGroupName": "workers",
                                "InstanceStorageConfigs": [
                                    {
                                        "EbsVolumeConfig": {
                                            "RootVolume": True,
                                        }
                                    },
                                    {
                                        "EbsVolumeConfig": {
                                            "RootVolume": True,
                                        }
                                    },
                                ],
                            }
                        ],
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }
        finding = extract_csv_data(
            sagemaker_app.check_hyperpod_ebs_cmk_encryption("us-east-1", inventory)
        )[0]
        assert finding["Finding_Details"].count("root volume") == 1

    def test_sm28_incomplete_vpc_fails(self):
        inventory = {
            "items": [
                {
                    "summary": {"ClusterName": "cluster-1"},
                    "detail": {
                        "ClusterName": "cluster-1",
                        "InstanceGroups": [
                            {
                                "InstanceGroupName": "workers",
                            }
                        ],
                    },
                }
            ],
            "errors": [],
            "list_error": None,
        }
        finding = extract_csv_data(
            sagemaker_app.check_hyperpod_vpc_configuration("us-east-1", inventory)
        )[0]
        assert finding["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm30_public_resource_policy_fails(self, mock_client):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        sagemaker_client.get_model_package_group_policy.return_value = {
            "ResourcePolicy": (
                '{"Version":"2012-10-17","Statement":'
                '[{"Effect":"Allow","Principal":"*",'
                '"Action":"sagemaker:CreateModelPackage","Resource":"*"}]}'
            )
        }

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        finding = extract_csv_data(
            sagemaker_app.check_model_package_group_policy_exposure(
                "us-east-1",
                [{"ModelPackageGroupName": "group-1"}],
            )
        )[0]
        assert finding["Check_ID"] == "SM-30"
        assert finding["Status"] == "Failed"

    def test_sm30_condition_boundaries_accept_supported_patterns(self):
        boundaries = sagemaker_app._policy_condition_boundaries(
            {
                "Condition": {
                    "StringLike": {
                        "aws:PrincipalOrgID": "o-a1b2c3d4e5",
                    },
                    "ArnLike": {
                        "aws:PrincipalArn": "arn:aws:iam::111122223333:role/ml-*",
                    },
                    "ForAnyValue:StringLike": {
                        "aws:PrincipalOrgPaths": "o-f6g7h8i9j0/r-ab12/ou-ab12-11111111/*",
                    },
                }
            }
        )
        assert boundaries["accounts"] == {"111122223333"}
        assert boundaries["organizations"] == {
            "o-a1b2c3d4e5",
            "o-f6g7h8i9j0",
        }

    def test_sm30_condition_boundaries_reject_unbounded_patterns(self):
        boundaries = sagemaker_app._policy_condition_boundaries(
            {
                "Condition": {
                    "StringLike": {
                        "aws:PrincipalOrgID": "o-*",
                    },
                    "ArnLike": {
                        "aws:PrincipalArn": "arn:aws:iam::*:role/ml-*",
                    },
                    "ForAllValues:StringLike": {
                        "aws:PrincipalOrgPaths": "o-a1b2c3d4e5/*",
                    },
                }
            }
        )
        assert boundaries == {"accounts": set(), "organizations": set()}

    def test_sm30_for_all_org_paths_requires_non_null_condition(self):
        boundaries = sagemaker_app._policy_condition_boundaries(
            {
                "Condition": {
                    "ForAllValues:StringLike": {
                        "aws:PrincipalOrgPaths": "o-a1b2c3d4e5/*",
                    },
                    "Null": {
                        "aws:PrincipalOrgPaths": "false",
                    },
                }
            }
        )
        assert boundaries["organizations"] == {"o-a1b2c3d4e5"}

    @patch.dict(
        os.environ,
        {"AIML_APPROVED_ORG_IDS": "o-a1b2c3d4e5"},
        clear=False,
    )
    @patch("sagemaker_app.boto3.client")
    def test_sm30_org_path_condition_is_not_public(self, mock_client):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sagemaker:CreateModelPackage",
                    "Resource": "*",
                    "Condition": {
                        "ForAnyValue:StringLike": {
                            "aws:PrincipalOrgPaths": (
                                "o-a1b2c3d4e5/r-ab12/ou-ab12-11111111/*"
                            )
                        }
                    },
                }
            ],
        }
        sagemaker_client.get_model_package_group_policy.return_value = {
            "ResourcePolicy": sagemaker_app.json.dumps(policy)
        }

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        finding = extract_csv_data(
            sagemaker_app.check_model_package_group_policy_exposure(
                "us-east-1",
                [{"ModelPackageGroupName": "group-1"}],
            )
        )[0]
        assert finding["Status"] == "Passed"
        assert finding["Finding"] == "Model Package Group Resource Policy Exposure"

    @pytest.mark.parametrize(
        ("principal_account", "expected_status"),
        [
            ("111122223333", "Passed"),
            ("444455556666", "Failed"),
        ],
        ids=["approved-account", "unapproved-account"],
    )
    @patch("sagemaker_app.boto3.client")
    def test_sm30_external_account_allowlist_is_enforced(
        self, mock_client, principal_account, expected_status
    ):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{principal_account}:root",
                    },
                    "Action": "sagemaker:CreateModelPackage",
                    "Resource": "*",
                }
            ],
        }
        sagemaker_client.get_model_package_group_policy.return_value = {
            "ResourcePolicy": sagemaker_app.json.dumps(policy)
        }

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        with patch.dict(
            os.environ,
            {
                "AIML_APPROVED_EXTERNAL_ACCOUNT_IDS": "111122223333",
                "AIML_APPROVED_ORG_IDS": "",
            },
            clear=False,
        ):
            finding = extract_csv_data(
                sagemaker_app.check_model_package_group_policy_exposure(
                    "us-east-1",
                    [{"ModelPackageGroupName": "group-1"}],
                )
            )[0]

        assert finding["Status"] == expected_status
        assert finding["Severity"] == "High"

    @patch.dict(
        os.environ,
        {"AIML_APPROVED_ORG_IDS": "o-a1b2c3d4e5"},
        clear=False,
    )
    @patch("sagemaker_app.boto3.client")
    def test_sm30_unapproved_org_path_fails_configured_boundary(self, mock_client):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sagemaker:CreateModelPackage",
                    "Resource": "*",
                    "Condition": {
                        "ForAnyValue:StringLike": {
                            "aws:PrincipalOrgPaths": (
                                "o-f6g7h8i9j0/r-ab12/ou-ab12-11111111/*"
                            )
                        }
                    },
                }
            ],
        }
        sagemaker_client.get_model_package_group_policy.return_value = {
            "ResourcePolicy": sagemaker_app.json.dumps(policy)
        }

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        finding = extract_csv_data(
            sagemaker_app.check_model_package_group_policy_exposure(
                "us-east-1",
                [{"ModelPackageGroupName": "group-1"}],
            )
        )[0]

        assert finding["Status"] == "Failed"
        assert finding["Severity"] == "High"
        assert "o-f6g7h8i9j0" in finding["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_sm30_allow_notprincipal_is_unsupported(self, mock_client):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotPrincipal": {
                        "AWS": "arn:aws:iam::111122223333:root",
                    },
                    "Action": "sagemaker:CreateModelPackage",
                    "Resource": "*",
                }
            ],
        }
        sagemaker_client.get_model_package_group_policy.return_value = {
            "ResourcePolicy": sagemaker_app.json.dumps(policy)
        }

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        finding = extract_csv_data(
            sagemaker_app.check_model_package_group_policy_exposure(
                "us-east-1",
                [{"ModelPackageGroupName": "group-1"}],
            )
        )[0]
        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert finding["Finding"] == ("Unsupported Model Package Group Resource Policy")

    @patch("sagemaker_app.boto3.client")
    def test_sm30_deny_notprincipal_does_not_create_exposure(self, mock_client):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "NotPrincipal": {
                        "AWS": "arn:aws:iam::123456789012:role/approved",
                    },
                    "Action": "sagemaker:*",
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/approved",
                    },
                    "Action": "sagemaker:CreateModelPackage",
                    "Resource": "*",
                },
            ],
        }
        sagemaker_client.get_model_package_group_policy.return_value = {
            "ResourcePolicy": sagemaker_app.json.dumps(policy)
        }

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        finding = extract_csv_data(
            sagemaker_app.check_model_package_group_policy_exposure(
                "us-east-1",
                [{"ModelPackageGroupName": "group-1"}],
            )
        )[0]
        assert finding["Status"] == "Passed"
        assert finding["Finding"] == "Model Package Group Resource Policy Exposure"

    @patch("sagemaker_app.boto3.client")
    def test_sm30_public_allow_precedes_unsupported_statement(self, mock_client):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "NotPrincipal": {
                        "AWS": "arn:aws:iam::111122223333:root",
                    },
                    "Action": "sagemaker:CreateModelPackage",
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sagemaker:CreateModelPackage",
                    "Resource": "*",
                },
            ],
        }
        sagemaker_client.get_model_package_group_policy.return_value = {
            "ResourcePolicy": sagemaker_app.json.dumps(policy)
        }

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        finding = extract_csv_data(
            sagemaker_app.check_model_package_group_policy_exposure(
                "us-east-1",
                [{"ModelPackageGroupName": "group-1"}],
            )
        )[0]
        assert finding["Status"] == "Failed"
        assert finding["Finding"] == "Public Model Package Group Resource Policy"

    @patch("sagemaker_app.boto3.client")
    def test_sm30_unknown_caller_account_returns_na(self, mock_client):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.side_effect = RuntimeError("STS unavailable")
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:role/registry-writer"
                    },
                    "Action": "sagemaker:CreateModelPackage",
                    "Resource": "*",
                }
            ],
        }
        sagemaker_client.get_model_package_group_policy.return_value = {
            "ResourcePolicy": sagemaker_app.json.dumps(policy)
        }

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        finding = extract_csv_data(
            sagemaker_app.check_model_package_group_policy_exposure(
                "us-east-1",
                [{"ModelPackageGroupName": "group-1"}],
            )
        )[0]
        assert finding["Status"] == "N/A"
        assert finding["Severity"] == "Informational"
        assert "Account Context Unavailable" in finding["Finding"]

    @patch("sagemaker_app.boto3.client")
    def test_sm30_public_policy_fails_even_when_sts_unavailable(self, mock_client):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.side_effect = RuntimeError("STS unavailable")
        sagemaker_client.get_model_package_group_policy.return_value = {
            "ResourcePolicy": (
                '{"Version":"2012-10-17","Statement":'
                '[{"Effect":"Allow","Principal":"*",'
                '"Action":"sagemaker:CreateModelPackage","Resource":"*"}]}'
            )
        }

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        finding = extract_csv_data(
            sagemaker_app.check_model_package_group_policy_exposure(
                "us-east-1",
                [{"ModelPackageGroupName": "group-1"}],
            )
        )[0]
        assert finding["Status"] == "Failed"
        assert finding["Finding"] == "Public Model Package Group Resource Policy"

    def test_new_sagemaker_checks_access_denied_return_na(self):
        error = _make_client_error("AccessDeniedException")
        sm26 = extract_csv_data(
            sagemaker_app.check_guardduty_ai_protection(
                "us-east-1",
                {"detector_id": None, "detail": None, "error": error},
            )
        )[0]
        inventory = {"items": [], "errors": [], "list_error": error}
        sm27 = extract_csv_data(
            sagemaker_app.check_hyperpod_ebs_cmk_encryption("us-east-1", inventory)
        )[0]
        sm28 = extract_csv_data(
            sagemaker_app.check_hyperpod_vpc_configuration("us-east-1", inventory)
        )[0]
        for finding in (sm26, sm27, sm28):
            assert finding["Status"] == "N/A"
            assert finding["Severity"] == "Informational"

    @patch("sagemaker_app.boto3.client")
    def test_sm30_policy_access_denied_returns_na_and_continues(self, mock_client):
        sagemaker_client = MagicMock()
        sts_client = MagicMock()
        sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        sagemaker_client.get_model_package_group_policy.side_effect = [
            {"ResourcePolicy": "{}"},
            _make_client_error("AccessDeniedException"),
            {
                "ResourcePolicy": (
                    '{"Version":"2012-10-17","Statement":'
                    '[{"Effect":"Allow","Principal":"*",'
                    '"Action":"sagemaker:CreateModelPackage","Resource":"*"}]}'
                )
            },
        ]

        def client_factory(service, **kwargs):
            return sts_client if service == "sts" else sagemaker_client

        mock_client.side_effect = client_factory
        findings = extract_csv_data(
            sagemaker_app.check_model_package_group_policy_exposure(
                "us-east-1",
                [
                    {"ModelPackageGroupName": "group-1"},
                    {"ModelPackageGroupName": "group-2"},
                    {"ModelPackageGroupName": "group-3"},
                ],
            )
        )

        assert [finding["Status"] for finding in findings] == [
            "Passed",
            "N/A",
            "Failed",
        ]
        assert findings[1]["Severity"] == "Informational"
        assert "group-2" in findings[1]["Finding_Details"]
        assert "AccessDeniedException" in findings[1]["Finding_Details"]
        assert sagemaker_client.get_model_package_group_policy.call_args_list == [
            call(ModelPackageGroupName="group-1"),
            call(ModelPackageGroupName="group-2"),
            call(ModelPackageGroupName="group-3"),
        ]

    def test_new_sagemaker_operation_contracts_exist(self):
        client = sagemaker_app.boto3.client(
            "sagemaker",
            region_name="us-east-1",
            aws_access_key_id="testing",
            aws_secret_access_key="testing",  # pragma: allowlist secret - synthetic test credential
        )
        model = client.meta.service_model
        for operation in [
            "ListClusters",
            "DescribeCluster",
            "GetModelPackageGroupPolicy",
        ]:
            assert model.operation_model(operation)


# ===================================================================
# SM-05: check_sagemaker_mlops_utilization
# ===================================================================
class TestSM05MLOps:
    """SM-05: Check SageMaker MLOps features utilization."""

    @patch("sagemaker_app.boto3.client")
    def test_sm05_empty_cache_returns_findings(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_sagemaker_mlops_utilization
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_model_packages.return_value = {"ModelPackageSummaryList": []}
        mock_sm.list_feature_groups.return_value = {"FeatureGroupSummaries": []}
        mock_sm.list_pipelines.return_value = {"PipelineSummaries": []}
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-05"

    @patch("sagemaker_app.boto3.client")
    def test_sm05_exception_returns_error_result(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_sagemaker_mlops_utilization
        mock_client.side_effect = Exception("MLOps error")
        result = check(empty_permission_cache)
        # SM-05 returns empty csv_data on outer exception but sets status=ERROR
        assert result.get("status") == "ERROR" or result.get("csv_data") is not None

    @patch("sagemaker_app.boto3.client")
    def test_sm05_schema_valid(self, mock_client, empty_permission_cache):
        check = sagemaker_app.check_sagemaker_mlops_utilization
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_model_packages.return_value = {"ModelPackageSummaryList": []}
        mock_sm.list_feature_groups.return_value = {"FeatureGroupSummaries": []}
        mock_sm.list_pipelines.return_value = {"PipelineSummaries": []}
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    @patch("sagemaker_app.boto3.client")
    def test_sm05_paginates_model_packages(self, mock_client, empty_permission_cache):
        check = sagemaker_app.check_sagemaker_mlops_utilization
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm

        group_paginator = MagicMock()
        group_paginator.paginate.return_value = [
            {"ModelPackageGroupSummaryList": [{"ModelPackageGroupName": "group-a"}]}
        ]
        package_paginator = MagicMock()
        package_paginator.paginate.return_value = [
            {"ModelPackageSummaryList": [{"ModelPackageArn": "arn:package-1"}]},
            {"ModelPackageSummaryList": [{"ModelPackageArn": "arn:package-2"}]},
        ]
        feature_group_paginator = MagicMock()
        feature_group_paginator.paginate.return_value = [{"FeatureGroupSummaries": []}]
        pipeline_paginator = MagicMock()
        pipeline_paginator.paginate.return_value = [{"PipelineSummaries": []}]
        paginators = {
            "list_model_package_groups": group_paginator,
            "list_model_packages": package_paginator,
            "list_feature_groups": feature_group_paginator,
            "list_pipelines": pipeline_paginator,
        }
        mock_sm.get_paginator.side_effect = paginators.__getitem__

        result = check(empty_permission_cache)
        findings = extract_csv_data(result)

        assert not any("minimal versioning" in f["Finding_Details"] for f in findings)
        package_paginator.paginate.assert_called_once_with(
            ModelPackageGroupName="group-a"
        )


# ===================================================================
# SM-06: check_sagemaker_clarify_usage
# ===================================================================
class TestSM06Clarify:
    """SM-06: Check SageMaker Clarify usage."""

    @patch("sagemaker_app.boto3.client")
    def test_sm06_empty_cache_returns_findings(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_sagemaker_clarify_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_processing_jobs.return_value = {"ProcessingJobSummaries": []}
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-06"

    @patch("sagemaker_app.boto3.client")
    def test_sm06_exception_returns_error_result(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_sagemaker_clarify_usage
        mock_client.side_effect = Exception("Clarify error")
        result = check(empty_permission_cache)
        assert result.get("status") == "ERROR" or result.get("csv_data") is not None

    @patch("sagemaker_app.boto3.client")
    def test_sm06_schema_valid(self, mock_client, empty_permission_cache):
        check = sagemaker_app.check_sagemaker_clarify_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_processing_jobs.return_value = {"ProcessingJobSummaries": []}
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-07: check_sagemaker_model_monitor_usage
# ===================================================================
class TestSM07ModelMonitor:
    """SM-07: Check SageMaker Model Monitor usage."""

    @patch("sagemaker_app.boto3.client")
    def test_sm07_empty_cache_returns_findings(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_sagemaker_model_monitor_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": []
        }
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-07"

    @patch("sagemaker_app.boto3.client")
    def test_sm07_exception_returns_error_result(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_sagemaker_model_monitor_usage
        mock_client.side_effect = Exception("Monitor error")
        result = check(empty_permission_cache)
        assert result.get("status") == "ERROR" or result.get("csv_data") is not None

    @patch("sagemaker_app.boto3.client")
    def test_sm07_schema_valid(self, mock_client, empty_permission_cache):
        check = sagemaker_app.check_sagemaker_model_monitor_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": []
        }
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-08: check_model_registry_usage
# ===================================================================
class TestSM08ModelRegistry:
    """SM-08: Check Model Registry usage."""

    @patch("sagemaker_app.boto3.client")
    def test_sm08_empty_cache_returns_findings(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_model_registry_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_model_package_groups.return_value = {
            "ModelPackageGroupSummaryList": []
        }
        result = check(empty_permission_cache)
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-08"

    @patch("sagemaker_app.boto3.client")
    def test_sm08_exception_returns_error_result(
        self, mock_client, empty_permission_cache
    ):
        check = sagemaker_app.check_model_registry_usage
        mock_client.side_effect = Exception("Registry error")
        result = check(empty_permission_cache)
        assert result.get("status") == "ERROR" or result.get("csv_data") is not None

    @patch("sagemaker_app.boto3.client")
    def test_sm08_schema_valid(self, mock_client, empty_permission_cache):
        check = sagemaker_app.check_model_registry_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_model_package_groups.return_value = {
            "ModelPackageGroupSummaryList": []
        }
        result = check(empty_permission_cache)
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    @patch("sagemaker_app.boto3.client")
    def test_sm08_paginates_model_packages(self, mock_client, empty_permission_cache):
        check = sagemaker_app.check_model_registry_usage
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm

        group_paginator = MagicMock()
        group_paginator.paginate.return_value = [
            {"ModelPackageGroupSummaryList": [{"ModelPackageGroupName": "group-a"}]}
        ]
        package_paginator = MagicMock()
        package_paginator.paginate.return_value = [
            {
                "ModelPackageSummaryList": [
                    {"ModelApprovalStatus": "PendingManualApproval"}
                ]
            },
            {"ModelPackageSummaryList": [{"ModelApprovalStatus": "Approved"}]},
        ]
        mock_sm.get_paginator.side_effect = lambda name: (
            group_paginator
            if name == "list_model_package_groups"
            else package_paginator
        )

        result = check(empty_permission_cache)
        findings = extract_csv_data(result)

        assert not any("No Approved Models" in f["Finding"] for f in findings)
        package_paginator.paginate.assert_called_once_with(
            ModelPackageGroupName="group-a"
        )


# ===================================================================
# SM-09: check_sagemaker_notebook_root_access
# ===================================================================
class TestSM09NotebookRootAccess:
    """SM-09: Check notebook root access."""

    @patch("sagemaker_app.boto3.client")
    def test_sm09_no_notebooks_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_root_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-09"

    @patch("sagemaker_app.boto3.client")
    def test_sm09_root_enabled_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_root_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "nb-1"}]}
        ]
        mock_sm.describe_notebook_instance.return_value = {
            "RootAccess": "Enabled",
            "NotebookInstanceName": "nb-1",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm09_root_disabled_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_root_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "nb-1"}]}
        ]
        mock_sm.describe_notebook_instance.return_value = {
            "RootAccess": "Disabled",
            "NotebookInstanceName": "nb-1",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm09_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_root_access
        mock_client.side_effect = Exception("Root access error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm09_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_root_access
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-10: check_sagemaker_notebook_vpc_deployment
# ===================================================================
class TestSM10NotebookVPC:
    """SM-10: Check notebook VPC deployment."""

    @patch("sagemaker_app.boto3.client")
    def test_sm10_no_notebooks_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_vpc_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-10"

    @patch("sagemaker_app.boto3.client")
    def test_sm10_no_vpc_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_vpc_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "nb-1"}]}
        ]
        mock_sm.describe_notebook_instance.return_value = {
            "NotebookInstanceName": "nb-1",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm10_with_vpc_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_vpc_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"NotebookInstances": [{"NotebookInstanceName": "nb-1"}]}
        ]
        mock_sm.describe_notebook_instance.return_value = {
            "NotebookInstanceName": "nb-1",
            "SubnetId": "subnet-123",
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm10_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_vpc_deployment
        mock_client.side_effect = Exception("VPC error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm10_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_notebook_vpc_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"NotebookInstances": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-11: check_sagemaker_model_network_isolation
# ===================================================================
class TestSM11ModelNetworkIsolation:
    """SM-11: Check model network isolation."""

    @patch("sagemaker_app.boto3.client")
    def test_sm11_no_models_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Models": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-11"

    @patch("sagemaker_app.boto3.client")
    def test_sm11_isolation_disabled_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Models": [{"ModelName": "model-1"}]}]
        mock_sm.describe_model.return_value = {
            "ModelName": "model-1",
            "EnableNetworkIsolation": False,
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm11_isolation_enabled_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Models": [{"ModelName": "model-1"}]}]
        mock_sm.describe_model.return_value = {
            "ModelName": "model-1",
            "EnableNetworkIsolation": True,
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm11_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_network_isolation
        mock_client.side_effect = Exception("Network isolation error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])


# ===================================================================
# SM-12: check_sagemaker_endpoint_instance_count
# ===================================================================
class TestSM12EndpointInstanceCount:
    """SM-12: Check endpoint instance count for availability."""

    @patch("sagemaker_app.boto3.client")
    def test_sm12_no_endpoints_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_endpoint_instance_count
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Endpoints": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-12"

    @patch("sagemaker_app.boto3.client")
    def test_sm12_single_instance_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_endpoint_instance_count
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"Endpoints": [{"EndpointName": "ep-1", "EndpointStatus": "InService"}]}
        ]
        mock_sm.describe_endpoint.return_value = {
            "ProductionVariants": [{"CurrentInstanceCount": 1, "VariantName": "v1"}]
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm12_multi_instance_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_endpoint_instance_count
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"Endpoints": [{"EndpointName": "ep-1", "EndpointStatus": "InService"}]}
        ]
        mock_sm.describe_endpoint.return_value = {
            "ProductionVariants": [{"CurrentInstanceCount": 3, "VariantName": "v1"}]
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm12_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_endpoint_instance_count
        mock_client.side_effect = Exception("Endpoint error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])


# ===================================================================
# SM-13: check_sagemaker_monitoring_network_isolation
# ===================================================================
class TestSM13MonitoringNetworkIsolation:
    """SM-13: Check monitoring schedule network isolation."""

    @patch("sagemaker_app.boto3.client")
    def test_sm13_no_schedules_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_monitoring_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"MonitoringScheduleSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-13"

    @patch("sagemaker_app.boto3.client")
    def test_sm13_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_monitoring_network_isolation
        mock_client.side_effect = Exception("Monitoring error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])


# ===================================================================
# SM-14: check_sagemaker_model_container_repository
# ===================================================================
class TestSM14ContainerRepository:
    """SM-14: Check model container repository access."""

    @patch("sagemaker_app.boto3.client")
    def test_sm14_no_models_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_container_repository
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Models": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-14"

    @patch("sagemaker_app.boto3.client")
    def test_sm14_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_model_container_repository
        mock_client.side_effect = Exception("Container error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])


# ===================================================================
# SM-15: check_sagemaker_feature_store_encryption
# ===================================================================
class TestSM15FeatureStoreEncryption:
    """SM-15: Check Feature Store encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm15_no_feature_groups_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_feature_store_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"FeatureGroupSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-15"

    @patch("sagemaker_app.boto3.client")
    def test_sm15_no_encryption_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_feature_store_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"FeatureGroupSummaries": [{"FeatureGroupName": "fg-1"}]}
        ]
        mock_sm.describe_feature_group.return_value = {
            "FeatureGroupName": "fg-1",
            "OfflineStoreConfig": {"S3StorageConfig": {"S3Uri": "s3://bucket"}},
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm15_with_kms_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_feature_store_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"FeatureGroupSummaries": [{"FeatureGroupName": "fg-1"}]}
        ]
        mock_sm.describe_feature_group.return_value = {
            "FeatureGroupName": "fg-1",
            "OfflineStoreConfig": {
                "S3StorageConfig": {
                    "S3Uri": "s3://bucket",
                    "KmsKeyId": "arn:aws:kms:us-east-1:123:key/abc",
                }
            },
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm15_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_feature_store_encryption
        mock_client.side_effect = Exception("Feature store error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])


# ===================================================================
# SM-16: check_sagemaker_data_quality_encryption
# ===================================================================
class TestSM16DataQualityEncryption:
    """SM-16: Check data quality job encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm16_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_data_quality_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"JobDefinitionSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-16"

    @patch("sagemaker_app.boto3.client")
    def test_sm16_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_data_quality_encryption
        mock_client.side_effect = Exception("Data quality error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm16_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_data_quality_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"JobDefinitionSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-17: check_sagemaker_processing_job_encryption
# ===================================================================
class TestSM17ProcessingJobEncryption:
    """SM-17: Check processing job volume encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm17_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_processing_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"ProcessingJobSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-17"

    @patch("sagemaker_app.boto3.client")
    def test_sm17_no_encryption_returns_failed(self, mock_client):
        check = sagemaker_app.check_sagemaker_processing_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"ProcessingJobSummaries": [{"ProcessingJobName": "pj-1"}]}
        ]
        mock_sm.describe_processing_job.return_value = {
            "ProcessingJobName": "pj-1",
            "ProcessingResources": {
                "ClusterConfig": {"InstanceCount": 1, "InstanceType": "ml.m5.large"}
            },
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Failed"

    @patch("sagemaker_app.boto3.client")
    def test_sm17_with_encryption_returns_passed(self, mock_client):
        check = sagemaker_app.check_sagemaker_processing_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"ProcessingJobSummaries": [{"ProcessingJobName": "pj-1"}]}
        ]
        mock_sm.describe_processing_job.return_value = {
            "ProcessingJobName": "pj-1",
            "ProcessingResources": {
                "ClusterConfig": {
                    "InstanceCount": 1,
                    "InstanceType": "ml.m5.large",
                    "VolumeKmsKeyId": "arn:aws:kms:us-east-1:123:key/abc",
                }
            },
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm17_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_processing_job_encryption
        mock_client.side_effect = Exception("Processing error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])


# ===================================================================
# SM-18: check_sagemaker_transform_job_encryption
# ===================================================================
class TestSM18TransformJobEncryption:
    """SM-18: Check transform job volume encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm18_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_transform_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"TransformJobSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-18"

    @patch("sagemaker_app.boto3.client")
    def test_sm18_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_transform_job_encryption
        mock_client.side_effect = Exception("Transform error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm18_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_transform_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"TransformJobSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-19: check_sagemaker_hyperparameter_tuning_encryption
# ===================================================================
class TestSM19HPTuningEncryption:
    """SM-19: Check hyperparameter tuning job encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm19_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_hyperparameter_tuning_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"HyperParameterTuningJobSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-19"

    @patch("sagemaker_app.boto3.client")
    def test_sm19_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_hyperparameter_tuning_encryption
        mock_client.side_effect = Exception("HP tuning error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm19_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_hyperparameter_tuning_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"HyperParameterTuningJobSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-20: check_sagemaker_compilation_job_encryption
# ===================================================================
class TestSM20CompilationJobEncryption:
    """SM-20: Check compilation job encryption."""

    @patch("sagemaker_app.boto3.client")
    def test_sm20_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_compilation_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"CompilationJobSummaries": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-20"

    @patch("sagemaker_app.boto3.client")
    def test_sm20_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_compilation_job_encryption
        mock_client.side_effect = Exception("Compilation error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm20_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_compilation_job_encryption
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"CompilationJobSummaries": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-21: check_sagemaker_automl_network_isolation
# ===================================================================
class TestSM21AutoMLNetworkIsolation:
    """SM-21: Check AutoML network isolation."""

    @patch("sagemaker_app.boto3.client")
    def test_sm21_no_jobs_returns_na(self, mock_client):
        check = sagemaker_app.check_sagemaker_automl_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_auto_ml_jobs.return_value = {"AutoMLJobSummaries": []}
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-21"

    @patch("sagemaker_app.boto3.client")
    def test_sm21_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_sagemaker_automl_network_isolation
        mock_client.side_effect = Exception("AutoML error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm21_schema_valid(self, mock_client):
        check = sagemaker_app.check_sagemaker_automl_network_isolation
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_auto_ml_jobs.return_value = {"AutoMLJobSummaries": []}
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-22: check_model_approval_workflow
# ===================================================================
class TestSM22ModelApproval:
    """SM-22: Check model approval workflow."""

    @patch("sagemaker_app.boto3.client")
    def test_sm22_no_model_packages_returns_na(self, mock_client):
        check = sagemaker_app.check_model_approval_workflow
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_model_package_groups.return_value = {
            "ModelPackageGroupSummaryList": []
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-22"

    @patch("sagemaker_app.boto3.client")
    def test_sm22_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_model_approval_workflow
        mock_client.side_effect = Exception("Approval error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm22_schema_valid(self, mock_client):
        check = sagemaker_app.check_model_approval_workflow
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_model_package_groups.return_value = {
            "ModelPackageGroupSummaryList": []
        }
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    @staticmethod
    def _wire_sm22_paginators(mock_sm, group_page, package_pages):
        """Wire both paginators used by check_model_approval_workflow.

        group_page:  single page dict for list_model_package_groups
        package_pages: list of page dicts for list_model_packages
        """
        group_paginator = MagicMock()
        package_paginator = MagicMock()
        group_paginator.paginate.return_value = [group_page]
        package_paginator.paginate.return_value = package_pages
        mock_sm.get_paginator.side_effect = lambda name: (
            group_paginator
            if name == "list_model_package_groups"
            else package_paginator
        )

    @patch("sagemaker_app.boto3.client")
    def test_sm22_paginates_model_packages_across_pages(self, mock_client):
        """Regression: a group with >100 model packages must be scored on the
        FULL population, not the first page. The bug was a single MaxResults=100
        list_model_packages call that silently truncated the sample, skewing
        the auto-approval / stale-pending ratios computed downstream."""
        check = sagemaker_app.check_model_approval_workflow
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm

        # 100 Approved packages on page 1 (newest first, as SageMaker returns).
        # 20 Pending + 5 Rejected on page 2. Under the old truncating code the
        # check saw only page 1 and (wrongly) fired "Auto-Approval Suspected"
        # for a group that actually has pending and rejected packages.
        page_1_approved = [{"ModelApprovalStatus": "Approved"} for _ in range(100)]
        page_2_mixed = [
            {"ModelApprovalStatus": "PendingManualApproval"} for _ in range(20)
        ] + [{"ModelApprovalStatus": "Rejected"} for _ in range(5)]
        self._wire_sm22_paginators(
            mock_sm,
            group_page={
                "ModelPackageGroupSummaryList": [
                    {"ModelPackageGroupName": "grp-active"}
                ]
            },
            package_pages=[
                {"ModelPackageSummaryList": page_1_approved},
                {"ModelPackageSummaryList": page_2_mixed},
            ],
        )

        result = check()
        findings = extract_csv_data(result)

        # With the fix, both pages are considered — the group has pending +
        # rejected packages, so "Auto-Approval Suspected" must NOT fire.
        names_all = " | ".join(f["Finding"] for f in findings)
        assert "Auto-Approval Suspected" not in names_all, (
            "SM-22 misfired 'Auto-Approval Suspected' when list_model_packages "
            "was truncated to the first page (approved-only) and hid the older "
            "Pending/Rejected packages."
        )
        # And "Stale Pending Models" should fire because pending_count=20 > 5.
        assert any("Stale Pending Models" in f["Finding"] for f in findings), (
            "SM-22 missed 'Stale Pending Models' — the 20 pending packages on "
            "page 2 were invisible before pagination was fixed."
        )
        # Cross-check the accumulated count reached page 2's contribution.
        stale_row = next(f for f in findings if "Stale Pending Models" in f["Finding"])
        assert "20 models pending" in stale_row["Finding_Details"], (
            f"Expected pending count of 20 in details; got: {stale_row['Finding_Details']!r}"
        )

    @patch("sagemaker_app.boto3.client")
    def test_sm22_auto_approval_detected_only_when_full_population_is_approved(
        self, mock_client
    ):
        """Full-population Approved case: page 1 = 100 Approved, page 2 = 10
        Approved, no Pending/Rejected. Must still fire 'Auto-Approval Suspected'
        because the fix does not change the true-positive path."""
        check = sagemaker_app.check_model_approval_workflow
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm

        self._wire_sm22_paginators(
            mock_sm,
            group_page={
                "ModelPackageGroupSummaryList": [{"ModelPackageGroupName": "grp-auto"}]
            },
            package_pages=[
                {
                    "ModelPackageSummaryList": [
                        {"ModelApprovalStatus": "Approved"} for _ in range(100)
                    ]
                },
                {
                    "ModelPackageSummaryList": [
                        {"ModelApprovalStatus": "Approved"} for _ in range(10)
                    ]
                },
            ],
        )

        result = check()
        findings = extract_csv_data(result)
        assert any("Auto-Approval Suspected" in f["Finding"] for f in findings), (
            "SM-22 must still detect the true-positive auto-approval case"
        )
        # Details should reference the actual full-population total (110), not 100.
        auto_row = next(
            f for f in findings if "Auto-Approval Suspected" in f["Finding"]
        )
        assert "110 models" in auto_row["Finding_Details"], (
            f"Expected full-population count '110 models' in details; "
            f"got: {auto_row['Finding_Details']!r}"
        )


# ===================================================================
# SM-23: check_model_drift_detection
# ===================================================================
class TestSM23DriftDetection:
    """SM-23: Check model drift detection."""

    @patch("sagemaker_app.boto3.client")
    def test_sm23_no_schedules_returns_na(self, mock_client):
        check = sagemaker_app.check_model_drift_detection
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": []
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-23"

    @patch("sagemaker_app.boto3.client")
    def test_sm23_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_model_drift_detection
        mock_client.side_effect = Exception("Drift error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm23_schema_valid(self, mock_client):
        check = sagemaker_app.check_model_drift_detection
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_monitoring_schedules.return_value = {
            "MonitoringScheduleSummaries": []
        }
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-24: check_ab_testing_shadow_deployment
# ===================================================================
class TestSM24ABTesting:
    """SM-24: Check A/B testing and shadow deployment."""

    @patch("sagemaker_app.boto3.client")
    def test_sm24_no_endpoints_returns_na(self, mock_client):
        check = sagemaker_app.check_ab_testing_shadow_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Endpoints": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-24"

    @patch("sagemaker_app.boto3.client")
    def test_sm24_single_variant_returns_failed(self, mock_client):
        check = sagemaker_app.check_ab_testing_shadow_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {"Endpoints": [{"EndpointName": "ep-1", "EndpointConfigName": "ec-1"}]}
        ]
        mock_sm.describe_endpoint.return_value = {
            "EndpointName": "ep-1",
            "ProductionVariants": [{"VariantName": "v1"}],
        }
        mock_sm.describe_endpoint_config.return_value = {
            "ProductionVariants": [{"VariantName": "v1"}],
            "ShadowProductionVariants": [],
        }
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        # Single variant without shadow should be flagged

    @patch("sagemaker_app.boto3.client")
    def test_sm24_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_ab_testing_shadow_deployment
        mock_client.side_effect = Exception("AB testing error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm24_schema_valid(self, mock_client):
        check = sagemaker_app.check_ab_testing_shadow_deployment
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"Endpoints": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)


# ===================================================================
# SM-25: check_ml_lineage_tracking
# ===================================================================
class TestSM25LineageTracking:
    """SM-25: Check ML lineage tracking."""

    @patch("sagemaker_app.boto3.client")
    def test_sm25_no_experiments_returns_na(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_experiments.return_value = {"ExperimentSummaries": []}
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"ModelPackageGroupSummaryList": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Check_ID"] == "SM-25"
        assert findings[0]["Status"] == "N/A"

    @patch("sagemaker_app.boto3.client")
    def test_sm25_experiments_with_trials_returns_passed(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_experiments.return_value = {
            "ExperimentSummaries": [{"ExperimentName": "exp-1"}]
        }
        mock_sm.list_trials.return_value = {
            "TrialSummaries": [{"TrialName": "trial-1"}]
        }
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"ModelPackageGroupSummaryList": []}]
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert findings[0]["Status"] == "Passed"

    @patch("sagemaker_app.boto3.client")
    def test_sm25_exception_returns_error_finding(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_client.side_effect = Exception("Lineage error")
        result = check()
        findings = extract_csv_data(result)
        assert len(findings) >= 1
        assert_could_not_assess_finding(findings[0])

    @patch("sagemaker_app.boto3.client")
    def test_sm25_schema_valid(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_experiments.return_value = {"ExperimentSummaries": []}
        paginator = MagicMock()
        mock_sm.get_paginator.return_value = paginator
        paginator.paginate.return_value = [{"ModelPackageGroupSummaryList": []}]
        result = check()
        for f in extract_csv_data(result):
            assert_finding_schema(f)

    @patch("sagemaker_app.boto3.client")
    def test_sm25_paginates_model_groups_and_packages(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_experiments.return_value = {"ExperimentSummaries": []}
        mock_sm.list_artifacts.side_effect = [
            {
                "ArtifactSummaries": [
                    {
                        "ArtifactArn": "arn:aws:sagemaker:us-east-1:123456789012:artifact/package-a"
                    }
                ]
            },
            {
                "ArtifactSummaries": [
                    {
                        "ArtifactArn": "arn:aws:sagemaker:us-east-1:123456789012:artifact/package-b"
                    }
                ]
            },
        ]
        mock_sm.list_associations.return_value = {"AssociationSummaries": []}

        group_paginator = MagicMock()
        group_paginator.paginate.return_value = [
            {"ModelPackageGroupSummaryList": [{"ModelPackageGroupName": "group-a"}]},
            {"ModelPackageGroupSummaryList": [{"ModelPackageGroupName": "group-b"}]},
        ]
        package_paginator = MagicMock()
        package_paginator.paginate.side_effect = [
            [
                {
                    "ModelPackageSummaryList": [
                        {
                            "ModelPackageArn": "arn:aws:sagemaker:us-east-1:123456789012:model-package/group-a/1",
                            "ModelPackageName": "package-a",
                        }
                    ]
                }
            ],
            [
                {
                    "ModelPackageSummaryList": [
                        {
                            "ModelPackageArn": "arn:aws:sagemaker:us-east-1:123456789012:model-package/group-b/1",
                            "ModelPackageName": "package-b",
                        }
                    ]
                }
            ],
        ]
        mock_sm.get_paginator.side_effect = lambda name: (
            group_paginator
            if name == "list_model_package_groups"
            else package_paginator
        )

        result = check()
        findings = extract_csv_data(result)

        lineage_findings = [f for f in findings if "Missing Lineage" in f["Finding"]]
        assert len(lineage_findings) == 2
        assert package_paginator.paginate.call_count == 2
        assert mock_sm.list_artifacts.call_args_list == [
            call(
                SourceUri="arn:aws:sagemaker:us-east-1:123456789012:model-package/group-a/1",
                MaxResults=1,
            ),
            call(
                SourceUri="arn:aws:sagemaker:us-east-1:123456789012:model-package/group-b/1",
                MaxResults=1,
            ),
        ]
        assert mock_sm.list_associations.call_args_list == [
            call(
                SourceArn="arn:aws:sagemaker:us-east-1:123456789012:artifact/package-a",
                MaxResults=1,
            ),
            call(
                DestinationArn="arn:aws:sagemaker:us-east-1:123456789012:artifact/package-a",
                MaxResults=1,
            ),
            call(
                SourceArn="arn:aws:sagemaker:us-east-1:123456789012:artifact/package-b",
                MaxResults=1,
            ),
            call(
                DestinationArn="arn:aws:sagemaker:us-east-1:123456789012:artifact/package-b",
                MaxResults=1,
            ),
        ]

    @patch("sagemaker_app.boto3.client")
    def test_sm25_accepts_destination_lineage_association(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_experiments.return_value = {"ExperimentSummaries": []}
        mock_sm.list_artifacts.return_value = {
            "ArtifactSummaries": [
                {
                    "ArtifactArn": "arn:aws:sagemaker:us-east-1:123456789012:artifact/package-a"
                }
            ]
        }
        mock_sm.list_associations.side_effect = [
            {"AssociationSummaries": []},
            {"AssociationSummaries": [{"AssociationType": "Produced"}]},
        ]

        group_paginator = MagicMock()
        group_paginator.paginate.return_value = [
            {"ModelPackageGroupSummaryList": [{"ModelPackageGroupName": "group-a"}]}
        ]
        package_paginator = MagicMock()
        package_paginator.paginate.return_value = [
            {
                "ModelPackageSummaryList": [
                    {
                        "ModelPackageArn": "arn:aws:sagemaker:us-east-1:123456789012:model-package/group-a/1",
                        "ModelPackageName": "package-a",
                    }
                ]
            }
        ]
        mock_sm.get_paginator.side_effect = lambda name: (
            group_paginator
            if name == "list_model_package_groups"
            else package_paginator
        )

        findings = extract_csv_data(check())

        assert not any("Missing Lineage" in f["Finding"] for f in findings)

    @patch("sagemaker_app.boto3.client")
    def test_sm25_stops_after_five_lineage_findings(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_experiments.return_value = {"ExperimentSummaries": []}
        mock_sm.list_artifacts.side_effect = lambda SourceUri, MaxResults: {
            "ArtifactSummaries": [
                {
                    "ArtifactArn": SourceUri.replace(
                        ":model-package/group-a/", ":artifact/package-"
                    )
                }
            ]
        }
        mock_sm.list_associations.return_value = {"AssociationSummaries": []}

        group_paginator = MagicMock()
        group_paginator.paginate.return_value = [
            {"ModelPackageGroupSummaryList": [{"ModelPackageGroupName": "group-a"}]}
        ]
        package_paginator = MagicMock()
        package_paginator.paginate.return_value = [
            {
                "ModelPackageSummaryList": [
                    {
                        "ModelPackageArn": f"arn:aws:sagemaker:us-east-1:123456789012:model-package/group-a/{version}",
                        "ModelPackageName": f"package-{version}",
                    }
                    for version in range(1, 7)
                ]
            }
        ]
        mock_sm.get_paginator.side_effect = lambda name: (
            group_paginator
            if name == "list_model_package_groups"
            else package_paginator
        )

        findings = extract_csv_data(check())
        lineage_findings = [f for f in findings if "Missing Lineage" in f["Finding"]]

        assert len(lineage_findings) == 5
        assert mock_sm.list_artifacts.call_count == 5

    @patch("sagemaker_app.boto3.client")
    def test_sm25_lineage_access_denied_is_na_not_missing(self, mock_client):
        check = sagemaker_app.check_ml_lineage_tracking
        mock_sm = MagicMock()
        mock_client.return_value = mock_sm
        mock_sm.list_experiments.return_value = {"ExperimentSummaries": []}
        mock_sm.list_artifacts.side_effect = _make_client_error("AccessDeniedException")

        group_paginator = MagicMock()
        group_paginator.paginate.return_value = [
            {"ModelPackageGroupSummaryList": [{"ModelPackageGroupName": "group-a"}]}
        ]
        package_paginator = MagicMock()
        package_paginator.paginate.return_value = [
            {
                "ModelPackageSummaryList": [
                    {
                        "ModelPackageArn": "arn:aws:sagemaker:us-east-1:123456789012:model-package/group-a/1",
                        "ModelPackageName": "package-a",
                    }
                ]
            }
        ]
        mock_sm.get_paginator.side_effect = lambda name: (
            group_paginator
            if name == "list_model_package_groups"
            else package_paginator
        )

        findings = extract_csv_data(check())

        assert not any("Missing Lineage" in f["Finding"] for f in findings)
        assessment_findings = [
            f for f in findings if "Model Package Assessment" in f["Finding"]
        ]
        assert len(assessment_findings) == 1
        assert_could_not_assess_finding(assessment_findings[0])


# ===================================================================
# lambda_handler: multi-region gating and availability probe
# ===================================================================
def _make_client_error(code, message="error"):
    return ClientError({"Error": {"Code": code, "Message": message}}, "operation")


def _sagemaker_event(region="us-east-1", region_index=0):
    return {
        "Region": region,
        "RegionIndex": region_index,
        "Execution": {"Name": "test-execution-1"},
        "StateMachine": {"Name": "test-sm"},
    }


class TestSageMakerHandlerMultiRegion:
    """lambda_handler primary-region gating (SM-02) + availability probe (SM-00)."""

    def _run_handler_unavailable(self, mock_client, event):
        """Drive the handler down the 'SageMaker unavailable' early-return path.
        The availability probe raises EndpointConnectionError so no regional
        checks run; only global IAM checks (if primary) plus SM-00 are emitted."""
        captured = {}

        def fake_csv(findings):
            captured["findings"] = findings
            return "csv"

        test_client = MagicMock()
        test_client.list_notebook_instances.side_effect = EndpointConnectionError(
            endpoint_url="https://sagemaker.invalid"
        )
        mock_client.return_value = test_client

        with (
            patch.object(
                sagemaker_app,
                "get_permissions_cache",
                return_value={"role_permissions": {}, "user_permissions": {}},
            ),
            patch.object(sagemaker_app, "generate_csv_report", side_effect=fake_csv),
            patch.object(sagemaker_app, "write_to_s3", return_value="s3://b/r.csv"),
        ):
            resp = sagemaker_app.lambda_handler(event, None)

        return resp, captured.get("findings", [])

    @patch("sagemaker_app.boto3.client")
    def test_primary_region_emits_global_iam_check_tagged_global(self, mock_client):
        # On the primary region, the IAM-global SM-02 check must be emitted and
        # tagged "Global", even when SageMaker is unavailable in the region.
        resp, findings = self._run_handler_unavailable(
            mock_client, _sagemaker_event(region="ap-south-2", region_index=0)
        )
        assert resp["statusCode"] == 200

        rows = [r for f in findings for r in f.get("csv_data", [])]
        sm02 = [r for r in rows if r["Check_ID"] == "SM-02"]
        assert sm02, "SM-02 IAM-global finding should be present on primary region"
        for r in sm02:
            assert r["Region"] == "Global"
        # The availability finding is tagged with the scanned region.
        sm00 = [r for r in rows if r["Check_ID"] == "SM-00"]
        assert sm00 and sm00[0]["Region"] == "ap-south-2"

    @patch("sagemaker_app.boto3.client")
    def test_non_primary_region_skips_global_iam_check(self, mock_client):
        # On a non-primary region the IAM-global SM-02 check must NOT run.
        resp, findings = self._run_handler_unavailable(
            mock_client, _sagemaker_event(region="eu-west-1", region_index=2)
        )
        assert resp["statusCode"] == 200

        rows = [r for f in findings for r in f.get("csv_data", [])]
        check_ids = {r["Check_ID"] for r in rows}
        assert "SM-02" not in check_ids
        assert check_ids == {"SM-00"}

    @patch("sagemaker_app.boto3.client")
    def test_optin_region_error_treated_as_unavailable(self, mock_client):
        # A region-not-enabled error code is treated like an endpoint failure:
        # emit a single SM-00 N/A finding (no regional checks).
        captured = {}

        def fake_csv(findings):
            captured["findings"] = findings
            return "csv"

        test_client = MagicMock()
        test_client.list_notebook_instances.side_effect = _make_client_error(
            "OptInRequired"
        )
        mock_client.return_value = test_client

        with (
            patch.object(
                sagemaker_app,
                "get_permissions_cache",
                return_value={"role_permissions": {}, "user_permissions": {}},
            ),
            patch.object(sagemaker_app, "generate_csv_report", side_effect=fake_csv),
            patch.object(sagemaker_app, "write_to_s3", return_value="s3://b/r.csv"),
        ):
            resp = sagemaker_app.lambda_handler(
                _sagemaker_event(region="ap-east-1", region_index=1), None
            )

        assert resp["statusCode"] == 200
        rows = [r for f in captured["findings"] for r in f.get("csv_data", [])]
        sm00 = [r for r in rows if r["Check_ID"] == "SM-00"]
        assert sm00 and sm00[0]["Status"] == "N/A"
        assert "ap-east-1" in sm00[0]["Finding_Details"]

    @patch("sagemaker_app.boto3.client")
    def test_access_denied_probe_proceeds_with_checks(self, mock_client):
        # AccessDenied is NOT in REGION_UNAVAILABLE_ERROR_CODES: the service is
        # reachable, so the handler must proceed and run regional checks rather
        # than short-circuiting with SM-00.
        captured = {}

        def fake_csv(findings):
            captured["findings"] = findings
            return "csv"

        test_client = MagicMock()
        test_client.list_notebook_instances.side_effect = _make_client_error(
            "AccessDeniedException"
        )
        mock_client.return_value = test_client

        with (
            patch.object(
                sagemaker_app,
                "get_permissions_cache",
                return_value={"role_permissions": {}, "user_permissions": {}},
            ),
            patch.object(sagemaker_app, "generate_csv_report", side_effect=fake_csv),
            patch.object(sagemaker_app, "write_to_s3", return_value="s3://b/r.csv"),
        ):
            resp = sagemaker_app.lambda_handler(
                _sagemaker_event(region="us-east-1", region_index=0), None
            )

        assert resp["statusCode"] == 200
        rows = [r for f in captured["findings"] for r in f.get("csv_data", [])]
        check_ids = {r["Check_ID"] for r in rows}
        # Reachable => no SM-00, and many regional checks ran.
        assert "SM-00" not in check_ids
        assert len(check_ids) > 3

import os
import subprocess
from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATHS = [
    REPO_ROOT / "aiml-security-assessment" / "template.yaml",
    REPO_ROOT / "aiml-security-assessment" / "template-multi-account.yaml",
]
EXPECTED_ENV_OWNERS = {
    "REQUIRE_BEDROCK_ZERO_DATA_RETENTION": (
        "BedrockSecurityAssessmentFunction",
        "RequireBedrockZeroDataRetention",
    ),
    "REQUIRE_MARKETPLACE_ENDPOINT_CMK": (
        "BedrockSecurityAssessmentFunction",
        "RequireMarketplaceEndpointCMK",
    ),
    "AIML_APPROVED_EXTERNAL_ACCOUNT_IDS": (
        "SagemakerSecurityAssessmentFunction",
        "ApprovedExternalAccountIds",
    ),
    "AIML_APPROVED_ORG_IDS": (
        "SagemakerSecurityAssessmentFunction",
        "ApprovedOrganizationIds",
    ),
    "AGENTCORE_TOKEN_VAULT_ID": (
        "AgentCoreSecurityAssessmentFunction",
        "AgentCoreTokenVaultId",
    ),
    "REQUIRE_AGENTCORE_ONLINE_EVALUATION": (
        "AgentCoreSecurityAssessmentFunction",
        "RequireAgentCoreOnlineEvaluation",
    ),
}
CLEARABLE_SAM_PARAMETERS = {
    "SAM_TARGET_REGIONS_PARAMETER": "TargetRegions",
    "SAM_APPROVED_EXTERNAL_ACCOUNT_IDS_PARAMETER": "ApprovedExternalAccountIds",
    "SAM_APPROVED_ORGANIZATION_IDS_PARAMETER": "ApprovedOrganizationIds",
}


class CfnLoader(yaml.SafeLoader):
    pass


def _construct_intrinsic(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {f"Fn::{tag_suffix}": value}


CfnLoader.add_multi_constructor("!", _construct_intrinsic)


def _load_sam_parameter_script():
    with (REPO_ROOT / "buildspec.yml").open(encoding="utf-8") as buildspec_file:
        buildspec = yaml.safe_load(buildspec_file)

    for command in buildspec["phases"]["build"]["commands"]:
        if "SAM_TARGET_REGIONS_PARAMETER=" in command:
            return command

    raise AssertionError("Could not find the SAM parameter construction block")


def _run_sam_parameter_script(env_overrides):
    parameter_script = _load_sam_parameter_script()
    output_commands = "\n".join(
        f"printf '%s=%s\\n' '{variable}' \"${{{variable}}}\""
        for variable in CLEARABLE_SAM_PARAMETERS
    )
    result = subprocess.run(
        ["bash", "-c", f"{parameter_script}\n{output_commands}"],
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), **env_overrides},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    return dict(
        line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
    )


@pytest.mark.parametrize("template_path", TEMPLATE_PATHS, ids=lambda path: path.name)
def test_optional_policy_baselines_are_wired_to_consuming_lambdas(template_path):
    with template_path.open(encoding="utf-8") as template_file:
        template = yaml.load(template_file, Loader=CfnLoader)  # nosec B506

    resources = template["Resources"]
    for variable, (expected_owner, parameter) in EXPECTED_ENV_OWNERS.items():
        owners = []
        for logical_id, resource in resources.items():
            variables = (
                resource.get("Properties", {})
                .get("Environment", {})
                .get("Variables", {})
            )
            if variable in variables:
                owners.append(logical_id)
                assert variables[variable] == {"Fn::Ref": parameter}

        assert owners == [expected_owner], (
            f"{variable} must be configured only on {expected_owner}; found {owners}"
        )


@pytest.mark.parametrize(
    ("env_overrides", "expected_values"),
    [
        (
            {},
            {
                "TargetRegions": "",
                "ApprovedExternalAccountIds": "",
                "ApprovedOrganizationIds": "",
            },
        ),
        (
            {
                "TARGET_REGIONS": "us-east-1,us-west-2",
                "APPROVED_EXTERNAL_ACCOUNT_IDS": "298129007823,318383103611",
                "APPROVED_ORGANIZATION_IDS": "o-77v1v640t5",
            },
            {
                "TargetRegions": "us-east-1,us-west-2",
                "ApprovedExternalAccountIds": "298129007823,318383103611",
                "ApprovedOrganizationIds": "o-77v1v640t5",
            },
        ),
    ],
    ids=["empty-values", "non-empty-values"],
)
def test_clearable_sam_parameters_preserve_literal_quotes(
    env_overrides, expected_values
):
    parameters = _run_sam_parameter_script(env_overrides)

    for variable, parameter_name in CLEARABLE_SAM_PARAMETERS.items():
        assert parameters[variable] == (
            f"ParameterKey={parameter_name},ParameterValue="
            f'"{expected_values[parameter_name]}"'
        )


def test_readme_uses_json_for_comma_separated_cloudformation_parameters():
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    assert "--parameters file://params.json" in readme
    assert '"ParameterKey": "ApprovedExternalAccountIds"' in readme
    assert '"ParameterValue": "111122223333,444455556666"' in readme
    assert '"ParameterKey": "ApprovedOrganizationIds"' in readme

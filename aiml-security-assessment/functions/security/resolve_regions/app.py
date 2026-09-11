"""
Resolve Target Regions Lambda Function

Resolves the list of AWS regions to scan based on the TARGET_REGIONS
environment variable. Returns a list for the Step Functions Map state
to iterate over.
"""

import os
import logging
import re
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

BEDROCK_SERVICE = "bedrock"
SAGEMAKER_SERVICE = "sagemaker"
AGENTCORE_SERVICE = "bedrock-agentcore-control"
AGENT_REGISTRY_SERVICE = "agent-registry-control"
REGION_CATALOG_SERVICE = "ec2"

SERVICES = [
    BEDROCK_SERVICE,
    SAGEMAKER_SERVICE,
    AGENTCORE_SERVICE,
    AGENT_REGISTRY_SERVICE,
]
PARTITION_FALLBACK_SERVICES = {
    AGENTCORE_SERVICE,
    AGENT_REGISTRY_SERVICE,
}


def get_available_regions(current_region: str = ""):
    """Get the union of regions that may host the assessed regional services.

    Some newer services have botocore service and endpoint-rule models but no
    entries in the legacy endpoint metadata used by ``get_available_regions``.
    For those services, use the current partition's EC2 region catalog so an
    ``all`` scan does not silently omit regions where resources may exist.
    Unsupported service/region combinations are handled by the assessment
    Lambdas as informational N/A results.
    """
    if not current_region:
        current_region = os.environ.get(
            "AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        )

    session = boto3.Session()
    try:
        partition = session.get_partition_for_region(current_region)
    except Exception as error:
        logger.warning(
            f"Could not determine partition for {current_region}: {error}; "
            "falling back to the aws partition"
        )
        partition = "aws"

    try:
        partition_regions = set(
            session.get_available_regions(
                REGION_CATALOG_SERVICE, partition_name=partition
            )
        )
    except Exception as error:
        logger.warning(f"Could not get the {partition} region catalog: {error}")
        partition_regions = set()

    all_regions = set()
    for service in SERVICES:
        try:
            regions = session.get_available_regions(service, partition_name=partition)
        except Exception as error:
            logger.warning(f"Could not get regions for {service}: {error}")
            regions = []

        if regions:
            all_regions.update(regions)
        elif service in PARTITION_FALLBACK_SERVICES:
            logger.info(
                f"No endpoint-region metadata found for {service}; "
                f"using the {partition} partition region catalog"
            )
            all_regions.update(partition_regions)

    return sorted(all_regions)


def resolve_regions():
    """Resolve target regions from environment variable."""
    target_regions = os.environ.get("TARGET_REGIONS", "").strip()
    current_region = os.environ.get(
        "AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    )

    if not target_regions:
        return [current_region]

    if target_regions.lower() == "all":
        regions = get_available_regions(current_region)
        if not regions:
            logger.warning("No regions discovered, falling back to current region")
            return [current_region]
        return regions

    return [r.strip() for r in re.split(r"[,\s]+", target_regions) if r.strip()]


def lambda_handler(event, context):
    """Main Lambda handler. Returns region list for Map state."""
    logger.info(f"Event: {event}")

    regions = resolve_regions()
    logger.info(f"Resolved {len(regions)} target regions: {regions}")

    return {"regions": regions}

# ReSCO AI/ML Assessment Framework

## Overview
ReSCO AI/ML Assessment Framework is a serverless solution designed to perform comprehensive Resilience, Security, and Cost Optimization (ReSCO) assessments for AI/ML workloads on AWS. The initial release focuses on security assessments for Amazon Bedrock and Amazon SageMaker workloads.


## Features

### Current Features (43 Security Checks)

**Amazon Bedrock** (14 checks)
- Network Isolation (VPC endpoints, private connectivity)
- Data Protection (guardrails, logging, encryption)
- Identity and Access Management (least privilege, unused permissions)
- Knowledge Base encryption verification
- Guardrail IAM enforcement
- Custom model encryption (KMS)
- Invocation logging encryption
- Flows guardrail configuration

**Amazon SageMaker** (16 checks)
- Compute and network isolation (VPC deployment, internet access controls)
- Authentication and authorization (IAM permissions, least privilege)
- Data protection (encryption at rest, KMS key management)
- Governance and Auditability (model registry, training job encryption)
- Notebook root access restrictions (SageMaker.3)
- Notebook VPC deployment (SageMaker.2)
- Model network isolation (SageMaker.4)
- Endpoint instance count for high availability (SageMaker.5)
- Monitoring job network isolation
- Model container repository validation
- Feature store encryption verification
- Data quality job encryption

**Amazon Bedrock AgentCore** (13 checks)
- Runtime VPC Configuration
- Memory Encryption (KMS)
- Gateway Security and encryption
- Observability Settings (logging, metrics)
- Network egress controls (NAT/VPC endpoints)
- ECR repository encryption
- VPC endpoint usage
- Service-linked role verification
- Resource-based policy configuration
- Policy engine encryption

## Prerequisites
- AWS Account with appropriate permissions
- Python 3.12+ - [Install Python](https://www.python.org/downloads/)
- SAM CLI - [Install the SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html)
- Docker - [Install Docker community edition](https://hub.docker.com/search/?type=edition&offering=community)

## Installation
Please refer to the [main repository README.md](../README.md) for complete installation and deployment instructions.

## Project Structure
```
resco-aiml-assessment/
├── template.yaml                         # SAM template
├── functions/
│   └── security/ 
│       ├── bedrock_assessments/          # Bedrock assessment functions (14 checks)
│       ├── sagemaker_assessments/        # SageMaker assessment functions (16 checks)
│       ├── agentcore_assessments/        # AgentCore assessment functions (13 checks)
│       ├── cleanup_bucket/               # S3 bucket cleanup function
│       ├── iam_permission_caching/       # IAM permission cache function
│       └── generate_consolidated_report/ # HTML report generation
└── statemachine/                         # Contains the state machine definition
```

## Step Functions Workflow
![Step Functions Workflow](images/stepfunctions_graph.png)

## References
- [AWS Security Best Practices](https://docs.aws.amazon.com/security/)
- [Amazon Bedrock Security](https://docs.aws.amazon.com/bedrock/latest/userguide/security.html)
- [Amazon SageMaker Security](https://docs.aws.amazon.com/sagemaker/latest/dg/security.html)
- [AWS SAM Developer Guide](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html)

# AWS Resource Cleanup Automation

Automated infrastructure for cleaning up AWS resources across multiple regions with retry logic and exclusion patterns.

## Overview

This project provides a complete AWS cleanup automation solution using:
- **AWS Lambda**: Executes cleanup logic across AWS services
- **AWS Step Functions**: Orchestrates the workflow with automatic retries
- **CloudFormation**: Infrastructure as Code for easy deployment
- **Exclusion Patterns**: Wildcard-based resource protection

## Quick Start

### Option 1: Deploy with CloudFormation (Recommended)

For automated infrastructure provisioning, see the [CloudFormation deployment guide](cloudformation/README.md).

```powershell
cd cloudformation
.\package-lambdas.ps1 -UploadToS3 -S3Bucket your-bucket
.\deploy-stack.ps1 -StackName cleanup-automation
```

### Option 2: Manual Deployment

For manual setup, follow the original manual provisioning steps in the lambda and step-function directories.

## Project Structure

```
Cleanup-Automation/
├── cloudformation/              # CloudFormation templates and deployment scripts
│   ├── cleanup-automation-stack.yaml    # Main CloudFormation template
│   ├── parameters.json                  # Stack parameters
│   ├── package-lambdas.ps1             # Lambda packaging script
│   ├── deploy-stack.ps1                # Stack deployment script
│   ├── example-exclusions.yaml         # Example exclusion patterns
│   └── README.md                       # Detailed deployment guide
├── lambda/                      # Lambda function code
│   ├── cleanup-lambda/         # Main cleanup Lambda
│   │   ├── lambda_function.py  # Lambda handler
│   │   └── cleanup_script.py   # Cleanup logic
│   ├── retry-lambda/           # Retry checkpoint Lambda
│   │   └── lambda_function.py  # Retry logic handler
│   └── *.json                  # IAM policies (for reference)
├── step-function/              # Step Functions definition
│   ├── state-machine.json      # State machine definition
│   └── *.json                  # IAM policies (for reference)
└── package/                    # Python dependencies (PyYAML)
```

## Features

### Supported AWS Services

**Compute & Containers:**
- EC2 Instances, EBS Volumes, Snapshots, AMIs
- ECS Clusters & Services
- EKS Clusters & Node Groups
- Elastic Beanstalk
- Lambda Functions

**Storage:**
- S3 Buckets (with versioning)
- EBS Volumes & Snapshots

**Databases:**
- RDS Instances & Clusters
- DynamoDB Tables
- ElastiCache & MemoryDB

**Networking:**
- Load Balancers (ALB, NLB, Classic)
- Elastic IPs

**Other Services:**
- CloudFormation Stacks
- ECR Repositories
- SQS Queues & SNS Topics
- OpenSearch Serverless Collections

### Key Capabilities

✅ **Dry Run Mode**: Preview deletions before executing
✅ **Exclusion Patterns**: Wildcard-based resource protection
✅ **Automatic Retries**: Built-in retry logic with exponential backoff
✅ **Multi-Region**: Clean up resources across multiple regions
✅ **CloudWatch Logging**: Complete audit trail
✅ **X-Ray Tracing**: Detailed execution insights
✅ **CloudTrail Protection**: Built-in safeguards for CloudTrail buckets

## Usage

### Execute with Dry Run

```powershell
aws stepfunctions start-execution `
  --state-machine-arn <your-state-machine-arn> `
  --input '{
    "input": {
      "regions": ["us-east-1"],
      "dryRun": true,
      "exclusions": {
        "s3": ["prod-*"],
        "rds": ["production-*"]
      }
    }
  }'
```

### Execute Actual Cleanup

⚠️ **WARNING**: This permanently deletes resources!

```powershell
aws stepfunctions start-execution `
  --state-machine-arn <your-state-machine-arn> `
  --input '{
    "input": {
      "regions": ["us-east-1"],
      "dryRun": false,
      "exclusions": {
        "s3": ["prod-*", "cloudtrail-*"],
        "rds": ["production-*"],
        "ec2": ["i-prod*"]
      }
    }
  }'
```

## Documentation

- [CloudFormation Deployment Guide](cloudformation/README.md) - Complete deployment instructions
- [Example Exclusions](cloudformation/example-exclusions.yaml) - Exclusion pattern examples
- [IAM Policies](lambda/) - Reference IAM policies
- [State Machine Definition](step-function/state-machine.json) - Step Functions workflow

## Security Considerations

🔒 **Important Security Notes:**

1. **Least Privilege**: Review and restrict IAM permissions as needed
2. **CloudTrail Protection**: Built-in DENY policy for CloudTrail buckets
3. **Exclusions Required**: Always use exclusions for critical resources
4. **Dry Run First**: Test with `dryRun: true` before actual deletion
5. **Audit Logging**: All operations logged to CloudWatch

## Monitoring

View logs in CloudWatch:
- `/aws/lambda/<StackName>-ResourceCleanupHandler`
- `/aws/lambda/<StackName>-RetryDecisionHandler`
- `/aws/lambda/<StackName>-PriorIntimationHandler`
- `/aws/states/<StackName>-CleanupStateMachine`

## Cost Optimization

This automation is designed for cost savings by cleaning up unused resources:
- Lambda: Pay per execution
- Step Functions: Pay per state transition
- CloudWatch: 30-day log retention (configurable)

## Contributing

To extend the cleanup functionality:
1. Add new service cleanup functions in `cleanup_script.py`
2. Update IAM policies in the CloudFormation template
3. Test with dry run mode
4. Update documentation

## License

Provided as-is for internal use. Test thoroughly before production use.

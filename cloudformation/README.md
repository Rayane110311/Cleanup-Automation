# AWS Resource Cleanup Automation - CloudFormation Deployment

This directory contains CloudFormation templates and deployment scripts to automate the provisioning of the AWS Resource Cleanup infrastructure.

## Architecture Overview

The solution consists of:

- **Cleanup Lambda Function**: Executes the resource deletion script across specified regions
- **Retry Checkpoint Lambda**: Manages retry logic and failure handling
- **Step Functions State Machine**: Orchestrates the cleanup workflow with automatic retries
- **IAM Roles & Policies**: Granular permissions for Lambda execution and resource deletion
- **CloudWatch Log Groups**: Centralized logging for monitoring and debugging

## Prerequisites

1. **AWS CLI**: Install and configure AWS CLI with appropriate credentials
   ```powershell
   aws configure
   ```

2. **VPC Configuration**: You need an existing VPC with:
   - **Private Subnets**: At least 2 private subnets (for high availability)
   - **NAT Gateway**: Required for Lambda to access AWS services and the internet
   - **VPC Endpoints** (Optional but recommended): For better performance and lower costs
     - S3 VPC Endpoint
     - DynamoDB VPC Endpoint
     - EC2 VPC Endpoint

3. **AWS Account**: You need appropriate permissions to:
   - Create IAM roles and policies
   - Create Lambda functions
   - Create Step Functions state machines
   - Upload files to S3
   - Create EC2 Security Groups

4. **S3 Bucket**: An S3 bucket to store Lambda deployment packages
   ```powershell
   aws s3 mb s3://your-deployment-bucket --region us-east-1
   ```

## Deployment Steps

### Step 1: Package Lambda Functions

Run the packaging script to create deployment ZIP files:

```powershell
cd cloudformation
.\package-lambdas.ps1
```

This creates three ZIP files in the `cloudformation/build/` directory:
- `cleanup-lambda.zip` - Main cleanup Lambda
- `retry-lambda.zip` - Retry checkpoint Lambda
- `pyyaml-layer.zip` - PyYAML Lambda layer

**Optional**: Upload directly to S3 during packaging:
```powershell
.\package-lambdas.ps1 -UploadToS3 -S3Bucket your-deployment-bucket
```

### Step 2: Upload to S3 (if not done in Step 1)

```powershell
aws s3 cp build/cleanup-lambda.zip s3://your-deployment-bucket/
aws s3 cp build/retry-lambda.zip s3://your-deployment-bucket/
aws s3 cp build/pyyaml-layer.zip s3://your-deployment-bucket/
```

### Step 3: Configure Parameters

Edit `parameters.json` and update the following **required** values:

**VPC Configuration:**
- `VpcId`: Your VPC ID (e.g., `vpc-1234567890abcdef0`)
- `SubnetIds`: Comma-separated list of private subnet IDs (e.g., `subnet-abc123,subnet-def456`)
- `AllowedCidrBlock`: CIDR block for inbound traffic (default: `10.0.0.0/8`)

**S3 Deployment Configuration:**
- `LambdaCodeS3Bucket`: Your S3 bucket name
- `PyYAMLLayerS3Bucket`: Your S3 bucket name (usually the same)

**Optional adjustments:**
- `LambdaMemorySize`: Memory allocation for cleanup Lambda (default: 512 MB)
- `LambdaTimeout`: Timeout for cleanup Lambda (default: 900 seconds)
- `MaxRetryAttempts`: Number of retry attempts (default: 5)
- `RetryDelaySeconds`: Delay between retries (default: 120 seconds)

**Important VPC Notes:**
- Use **private subnets** with NAT Gateway for Lambda deployment
- The Lambda function needs internet access to call AWS APIs
- Consider using VPC endpoints to reduce NAT Gateway data transfer costs

### Step 4: Deploy CloudFormation Stack

Deploy the stack using the deployment script:

```powershell
.\deploy-stack.ps1 -StackName cleanup-automation-stack -Region us-east-1
```

**Options:**
- `-StackName`: Name for your CloudFormation stack (default: cleanup-automation-stack)
- `-Region`: AWS region for deployment (default: us-east-1)
- `-ParametersFile`: Custom parameters file (default: parameters.json)
- `-ValidateOnly`: Only validate template without deploying

**Example:**
```powershell
.\deploy-stack.ps1 -StackName my-cleanup-stack -Region us-west-2 -ValidateOnly
```

### Step 5: Verify Deployment

After successful deployment, verify the resources:

```powershell
# List stack resources
aws cloudformation describe-stack-resources --stack-name cleanup-automation-stack

# Get stack outputs
aws cloudformation describe-stacks --stack-name cleanup-automation-stack --query "Stacks[0].Outputs"
```

## Usage

### Execute Cleanup with Dry Run

Test the cleanup process without deleting any resources:

```powershell
# Get the State Machine ARN from stack outputs
$stateMachineArn = aws cloudformation describe-stacks `
    --stack-name cleanup-automation-stack `
    --query "Stacks[0].Outputs[?OutputKey=='StateMachineArn'].OutputValue" `
    --output text

# Start execution with dry run
aws stepfunctions start-execution `
    --state-machine-arn $stateMachineArn `
    --input '{
      "input": {
        "regions": ["us-east-1", "us-west-2"],
        "dryRun": true,
        "exclusions": {
          "s3": ["prod-*", "backup-*"],
          "rds": ["production-*"],
          "ec2": ["i-prod*"]
        }
      }
    }'
```

### Execute Actual Cleanup

⚠️ **WARNING**: This will permanently delete resources!

```powershell
aws stepfunctions start-execution `
    --state-machine-arn $stateMachineArn `
    --input '{
      "input": {
        "regions": ["us-east-1"],
        "dryRun": false,
        "exclusions": {
          "s3": ["prod-*", "backup-*", "cloudtrail-*"],
          "rds": ["production-*"],
          "ec2": ["i-prod*"]
        }
      }
    }'
```

### Input Parameters

The Step Functions execution accepts the following input:

```json
{
  "input": {
    "regions": ["us-east-1", "us-west-2"],  // Required: List of AWS regions to scan
    "dryRun": true,                          // Required: true=preview, false=delete
    "exclusions": {                          // Optional: Resources to exclude
      "s3": ["prod-*", "backup-*"],          // S3 bucket patterns to exclude
      "rds": ["production-*"],               // RDS instance patterns
      "ec2": ["i-prod*"],                    // EC2 instance patterns
      "lambda": ["critical-*"],              // Lambda function patterns
      "dynamodb": ["production-*"],          // DynamoDB table patterns
      "cloudformation": ["infrastructure-*"],// CloudFormation stack patterns
      "eks": ["prod-*"],                     // EKS cluster patterns
      "ecs": ["prod-*"],                     // ECS cluster patterns
      "elasticache": ["prod-*"],             // ElastiCache cluster patterns
      "opensearch": ["prod-*"]               // OpenSearch collection patterns
    }
  }
}
```

**Exclusion Patterns:**
- Use wildcard `*` for pattern matching
- Patterns are case-sensitive
- Examples:
  - `prod-*`: Matches anything starting with "prod-"
  - `*-production`: Matches anything ending with "-production"
  - `*prod*`: Matches anything containing "prod"

## Monitoring

### View Execution Status

```powershell
# List recent executions
aws stepfunctions list-executions --state-machine-arn $stateMachineArn

# Get execution details
aws stepfunctions describe-execution --execution-arn <execution-arn>

# Get execution history
aws stepfunctions get-execution-history --execution-arn <execution-arn>
```

### CloudWatch Logs

Logs are available in CloudWatch Log Groups:
- `/aws/lambda/<StackName>-ResourceCleanupHandler`
- `/aws/lambda/<StackName>-RetryDecisionHandler`
- `/aws/states/<StackName>-CleanupStateMachine`

View logs:
```powershell
# Resource Cleanup Handler logs
aws logs tail /aws/lambda/cleanup-automation-stack-ResourceCleanupHandler --follow

# Retry Decision Handler logs
aws logs tail /aws/lambda/cleanup-automation-stack-RetryDecisionHandler --follow

# State Machine logs
aws logs tail /aws/states/cleanup-automation-stack-CleanupStateMachine --follow
```

### X-Ray Tracing

If X-Ray tracing is enabled (default), view traces in the AWS X-Ray console for detailed execution insights.

## Resources Cleaned

The cleanup automation handles the following AWS resources:

### Compute & Containers
- EC2 Instances
- ECS Clusters & Services
- EKS Clusters & Node Groups
- Elastic Beanstalk Environments & Applications
- Lambda Functions

### Storage
- S3 Buckets (with versioning support)
- EBS Volumes
- EBS Snapshots
- AMIs

### Databases
- RDS Instances & Clusters
- RDS Snapshots
- DynamoDB Tables
- ElastiCache Clusters
- MemoryDB Clusters

### Networking
- Elastic IPs
- Application Load Balancers (ALB)
- Network Load Balancers (NLB)
- Classic Load Balancers

### Other Services
- CloudFormation Stacks
- ECR Repositories
- SQS Queues
- SNS Topics
- OpenSearch Serverless Collections

## Updating the Stack

To update the stack with new configurations or code:

1. Update the Lambda code or CloudFormation template
2. Repackage Lambda functions if code changed:
   ```powershell
   .\package-lambdas.ps1 -UploadToS3 -S3Bucket your-deployment-bucket
   ```
3. Update parameters if needed
4. Redeploy the stack:
   ```powershell
   .\deploy-stack.ps1 -StackName cleanup-automation-stack
   ```

## Deleting the Stack

To remove all resources created by this CloudFormation stack:

```powershell
aws cloudformation delete-stack --stack-name cleanup-automation-stack

# Wait for deletion to complete
aws cloudformation wait stack-delete-complete --stack-name cleanup-automation-stack
```

**Note**: This will delete the automation infrastructure but will NOT delete the resources that were cleaned up by the automation.

## Troubleshooting

### Stack Creation Fails

1. Check CloudFormation events:
   ```powershell
   aws cloudformation describe-stack-events --stack-name cleanup-automation-stack --max-items 20
   ```

2. Verify S3 bucket exists and Lambda packages are uploaded
3. Ensure you have appropriate IAM permissions

### Lambda Execution Fails

1. Check Lambda logs in CloudWatch
2. Verify IAM role has necessary permissions
3. Check Lambda timeout settings (increase if needed)
4. Verify exclusion patterns are correct

### Step Functions Execution Fails

1. View execution details in Step Functions console
2. Check individual Lambda invocations
3. Review retry logic and increase max attempts if needed

## Security Considerations

⚠️ **IMPORTANT SECURITY NOTES**:

1. **Least Privilege**: The Lambda execution role has broad deletion permissions. Review and restrict as needed for your environment.

2. **CloudTrail Protection**: The stack includes a DENY policy for CloudTrail S3 buckets (pattern: `cloudtrail-*`)

3. **Exclusions**: Always use exclusions to protect critical resources

4. **Dry Run First**: Always test with `dryRun: true` before actual deletion

5. **MFA Protection**: Consider requiring MFA for stack operations

6. **Audit Trail**: All executions are logged to CloudWatch

## Cost Considerations

- **Lambda**: Pay per invocation and execution time
- **Step Functions**: Pay per state transition
- **CloudWatch Logs**: Storage costs for log retention (30 days default)
- **X-Ray**: Tracing costs if enabled

## Support

For issues or questions:
1. Check CloudWatch logs
2. Review Step Functions execution history
3. Verify IAM permissions
4. Ensure all prerequisites are met

## License

This automation is provided as-is for internal use. Review and test thoroughly before using in production environments.

# PowerShell script to deploy CloudFormation stack
param(
    [Parameter(Mandatory=$false)]
    [string]$StackName = "cleanup-automation-stack",
    
    [Parameter(Mandatory=$false)]
    [string]$ParametersFile = "parameters.json",
    
    [Parameter(Mandatory=$false)]
    [string]$Region = "us-east-1",
    
    [Parameter(Mandatory=$false)]
    [switch]$ValidateOnly = $false
)

$ErrorActionPreference = "Stop"

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "CloudFormation Stack Deployment" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

$templateFile = Join-Path $PSScriptRoot "cleanup-automation-stack.yaml"
$paramsFile = Join-Path $PSScriptRoot $ParametersFile

# Check if files exist
if (-not (Test-Path $templateFile)) {
    Write-Host "⚠ Error: Template file not found: $templateFile" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $paramsFile)) {
    Write-Host "⚠ Error: Parameters file not found: $paramsFile" -ForegroundColor Red
    exit 1
}

# Check if AWS CLI is available
try {
    aws --version | Out-Null
} catch {
    Write-Host "⚠ Error: AWS CLI not found. Please install AWS CLI first." -ForegroundColor Red
    exit 1
}

Write-Host "`nConfiguration:" -ForegroundColor Yellow
Write-Host "  Stack Name: $StackName" -ForegroundColor White
Write-Host "  Region: $Region" -ForegroundColor White
Write-Host "  Template: $templateFile" -ForegroundColor White
Write-Host "  Parameters: $paramsFile" -ForegroundColor White

# Validate template
Write-Host "`nValidating CloudFormation template..." -ForegroundColor Yellow
try {
    aws cloudformation validate-template `
        --template-body "file://$templateFile" `
        --region $Region | Out-Null
    Write-Host "✓ Template validation successful!" -ForegroundColor Green
} catch {
    Write-Host "⚠ Template validation failed!" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

if ($ValidateOnly) {
    Write-Host "`nValidation complete. Exiting (--ValidateOnly flag set)." -ForegroundColor Cyan
    exit 0
}

# Check if stack exists
Write-Host "`nChecking if stack exists..." -ForegroundColor Yellow
$stackExists = $false
try {
    aws cloudformation describe-stacks `
        --stack-name $StackName `
        --region $Region 2>$null | Out-Null
    $stackExists = $true
    Write-Host "✓ Stack exists. Will update stack." -ForegroundColor Yellow
} catch {
    Write-Host "✓ Stack does not exist. Will create new stack." -ForegroundColor Green
}

# Deploy stack
Write-Host "`n=====================================" -ForegroundColor Cyan
if ($stackExists) {
    Write-Host "Updating Stack: $StackName" -ForegroundColor Yellow
    Write-Host "=====================================" -ForegroundColor Cyan
    
    try {
        aws cloudformation update-stack `
            --stack-name $StackName `
            --template-body "file://$templateFile" `
            --parameters "file://$paramsFile" `
            --capabilities CAPABILITY_NAMED_IAM `
            --region $Region
        
        Write-Host "`nStack update initiated. Waiting for completion..." -ForegroundColor Yellow
        
        aws cloudformation wait stack-update-complete `
            --stack-name $StackName `
            --region $Region
        
        Write-Host "✓ Stack update completed successfully!" -ForegroundColor Green
    } catch {
        $errorMsg = $_.Exception.Message
        if ($errorMsg -like "*No updates are to be performed*") {
            Write-Host "✓ No changes detected. Stack is up to date." -ForegroundColor Green
        } else {
            Write-Host "⚠ Stack update failed!" -ForegroundColor Red
            Write-Host $errorMsg -ForegroundColor Red
            exit 1
        }
    }
} else {
    Write-Host "Creating Stack: $StackName" -ForegroundColor Green
    Write-Host "=====================================" -ForegroundColor Cyan
    
    try {
        aws cloudformation create-stack `
            --stack-name $StackName `
            --template-body "file://$templateFile" `
            --parameters "file://$paramsFile" `
            --capabilities CAPABILITY_NAMED_IAM `
            --region $Region
        
        Write-Host "`nStack creation initiated. Waiting for completion..." -ForegroundColor Yellow
        Write-Host "This may take several minutes..." -ForegroundColor Gray
        
        aws cloudformation wait stack-create-complete `
            --stack-name $StackName `
            --region $Region
        
        Write-Host "✓ Stack creation completed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "⚠ Stack creation failed!" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        
        Write-Host "`nRetrieving stack events for troubleshooting..." -ForegroundColor Yellow
        aws cloudformation describe-stack-events `
            --stack-name $StackName `
            --region $Region `
            --max-items 10
        
        exit 1
    }
}

# Display stack outputs
Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "Stack Outputs" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

try {
    $outputs = aws cloudformation describe-stacks `
        --stack-name $StackName `
        --region $Region `
        --query "Stacks[0].Outputs" `
        --output json | ConvertFrom-Json
    
    foreach ($output in $outputs) {
        Write-Host "$($output.OutputKey):" -ForegroundColor Yellow
        Write-Host "  $($output.OutputValue)" -ForegroundColor White
        if ($output.Description) {
            Write-Host "  ($($output.Description))" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "Could not retrieve stack outputs" -ForegroundColor Yellow
}

Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "Deployment Complete!" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Cyan

Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "  1. Test the Step Functions state machine with a dry run" -ForegroundColor White
Write-Host "  2. Review CloudWatch logs for any issues" -ForegroundColor White
Write-Host "  3. Execute cleanup with actual deletion (use with caution!)" -ForegroundColor White

Write-Host "`nTo execute the cleanup:" -ForegroundColor Yellow
Write-Host @"
  aws stepfunctions start-execution \
    --state-machine-arn <StateMachineArn> \
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
"@ -ForegroundColor Gray

Write-Host ""

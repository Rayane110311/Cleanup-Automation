# PowerShell script to package Lambda functions and layer for deployment
# This script creates ZIP files for deployment to S3

param(
    [Parameter(Mandatory=$false)]
    [string]$S3Bucket = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$UploadToS3 = $false
)

$ErrorActionPreference = "Stop"

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Lambda Packaging Script" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

# Get the root directory
$rootDir = Split-Path -Parent $PSScriptRoot
$buildDir = Join-Path $PSScriptRoot "build"
$lambdaDir = Join-Path $rootDir "lambda"
$packageDir = Join-Path $rootDir "package"

# Create build directory
if (Test-Path $buildDir) {
    Write-Host "Cleaning existing build directory..." -ForegroundColor Yellow
    Remove-Item -Path $buildDir -Recurse -Force
}
New-Item -ItemType Directory -Path $buildDir | Out-Null

Write-Host "`nStep 1: Packaging Cleanup Lambda..." -ForegroundColor Green
$cleanupDir = Join-Path $lambdaDir "cleanup-lambda"
$cleanupZip = Join-Path $buildDir "cleanup-lambda.zip"

# Create temp directory for cleanup lambda
$tempCleanup = Join-Path $buildDir "temp-cleanup"
New-Item -ItemType Directory -Path $tempCleanup | Out-Null

# Copy cleanup lambda files
Copy-Item -Path (Join-Path $cleanupDir "lambda_function.py") -Destination $tempCleanup
Copy-Item -Path (Join-Path $cleanupDir "cleanup_script.py") -Destination $tempCleanup

# Create ZIP for cleanup lambda
Compress-Archive -Path "$tempCleanup\*" -DestinationPath $cleanupZip -Force
Write-Host "  ✓ Created: $cleanupZip" -ForegroundColor Green

Write-Host "`nStep 2: Packaging Retry Lambda..." -ForegroundColor Green
$retryDir = Join-Path $lambdaDir "retry-lambda"
$retryZip = Join-Path $buildDir "retry-lambda.zip"

# Create temp directory for retry lambda
$tempRetry = Join-Path $buildDir "temp-retry"
New-Item -ItemType Directory -Path $tempRetry | Out-Null

# Copy retry lambda files
Copy-Item -Path (Join-Path $retryDir "lambda_function.py") -Destination $tempRetry

# Create ZIP for retry lambda
Compress-Archive -Path "$tempRetry\*" -DestinationPath $retryZip -Force
Write-Host "  ✓ Created: $retryZip" -ForegroundColor Green

Write-Host "`nStep 3: Packaging PyYAML Layer..." -ForegroundColor Green
$layerZip = Join-Path $buildDir "pyyaml-layer.zip"

# Create layer structure
$tempLayer = Join-Path $buildDir "temp-layer"
$pythonDir = Join-Path $tempLayer "python"
New-Item -ItemType Directory -Path $pythonDir -Force | Out-Null

# Copy package contents to layer
if (Test-Path $packageDir) {
    Copy-Item -Path "$packageDir\*" -Destination $pythonDir -Recurse -Force
    Write-Host "  ✓ Copied PyYAML package contents" -ForegroundColor Green
} else {
    Write-Host "  ⚠ Warning: Package directory not found. You may need to install PyYAML manually." -ForegroundColor Yellow
    Write-Host "    Run: pip install pyyaml -t $pythonDir" -ForegroundColor Yellow
}

# Create ZIP for layer
Compress-Archive -Path "$tempLayer\*" -DestinationPath $layerZip -Force
Write-Host "  ✓ Created: $layerZip" -ForegroundColor Green

# Clean up temp directories
Write-Host "`nCleaning up temporary files..." -ForegroundColor Yellow
Remove-Item -Path $tempCleanup -Recurse -Force
Remove-Item -Path $tempRetry -Recurse -Force
Remove-Item -Path $tempLayer -Recurse -Force

Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "Packaging Complete!" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "`nGenerated files in: $buildDir" -ForegroundColor White
Write-Host "  - cleanup-lambda.zip" -ForegroundColor White
Write-Host "  - retry-lambda.zip" -ForegroundColor White
Write-Host "  - pyyaml-layer.zip" -ForegroundColor White

# Upload to S3 if requested
if ($UploadToS3) {
    if ([string]::IsNullOrWhiteSpace($S3Bucket)) {
        Write-Host "`n⚠ Error: S3Bucket parameter is required when using -UploadToS3" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "`n=====================================" -ForegroundColor Cyan
    Write-Host "Uploading to S3" -ForegroundColor Cyan
    Write-Host "=====================================" -ForegroundColor Cyan
    
    # Check if AWS CLI is available
    try {
        aws --version | Out-Null
    } catch {
        Write-Host "⚠ Error: AWS CLI not found. Please install AWS CLI first." -ForegroundColor Red
        exit 1
    }
    
    Write-Host "`nUploading files to s3://$S3Bucket/..." -ForegroundColor Yellow
    
    aws s3 cp $cleanupZip "s3://$S3Bucket/cleanup-lambda.zip"
    aws s3 cp $retryZip "s3://$S3Bucket/retry-lambda.zip"
    aws s3 cp $layerZip "s3://$S3Bucket/pyyaml-layer.zip"
    
    Write-Host "`n✓ Upload complete!" -ForegroundColor Green
    Write-Host "`nNext steps:" -ForegroundColor Cyan
    Write-Host "  1. Update parameters.json with your S3 bucket name: $S3Bucket" -ForegroundColor White
    Write-Host "  2. Deploy the CloudFormation stack" -ForegroundColor White
} else {
    Write-Host "`nNext steps:" -ForegroundColor Cyan
    Write-Host "  1. Upload the ZIP files to your S3 bucket:" -ForegroundColor White
    Write-Host "     aws s3 cp build/cleanup-lambda.zip s3://YOUR-BUCKET/" -ForegroundColor Gray
    Write-Host "     aws s3 cp build/retry-lambda.zip s3://YOUR-BUCKET/" -ForegroundColor Gray
    Write-Host "     aws s3 cp build/pyyaml-layer.zip s3://YOUR-BUCKET/" -ForegroundColor Gray
    Write-Host "`n  2. Update parameters.json with your S3 bucket name" -ForegroundColor White
    Write-Host "`n  3. Deploy the CloudFormation stack using deploy-stack.ps1" -ForegroundColor White
    Write-Host "`n  Or run this script with -UploadToS3 -S3Bucket YOUR-BUCKET to upload automatically" -ForegroundColor Yellow
}

Write-Host ""

import json
import logging
import os
from cleanup_script import execute_cleanup_tasks, load_exclusions

# Configure logging for Lambda
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    AWS Lambda handler to invoke the cleanup script.
    
    Expected event structure:
    {
        "profile": "default",  # Optional, defaults to Lambda execution role
        "regions": ["us-east-1", "eu-west-1"],
        "dry_run": true,  # true for dry-run, false for actual deletion
        "exclusion_file_s3": {  # Optional
            "bucket": "my-config-bucket",
            "key": "exclusions.yaml"
        },
        "exclusions": {  # Optional, inline exclusions
            "s3": ["prod-*"],
            "rds": ["production-db"]
        }
    }
    
    Returns:
    {
        "statusCode": 200,
        "body": {
            "message": "Cleanup completed successfully",
            "phase": "dry_run" or "deletion"
        }
    }
    """
    
    try:
        # Parse input parameters
        profile = event.get('profile', None)  # None uses Lambda execution role
        regions = event.get('regions', [])
        dry_run = event.get('dry_run', True)  # Default to safe dry-run mode
        
        # Validate required parameters
        if not regions:
            raise ValueError("'regions' parameter is required and must be a non-empty list")
        
        # Load exclusions
        exclusions = {}
        
        # Option 1: Load from S3
        if 'exclusion_file_s3' in event:
            s3_config = event['exclusion_file_s3']
            bucket = s3_config.get('bucket')
            key = s3_config.get('key')
            
            if bucket and key:
                exclusions = load_exclusions_from_s3(bucket, key)
                logger.info(f"Loaded exclusions from s3://{bucket}/{key}")
        
        # Option 2: Use inline exclusions (overrides S3 if both provided)
        if 'exclusions' in event:
            exclusions = event['exclusions']
            logger.info("Using inline exclusions from event")
        
        # Log execution parameters
        phase = "DRY RUN" if dry_run else "DELETION"
        logger.info(f"=== Starting {phase} Phase ===")
        logger.info(f"Profile: {profile or 'Lambda Execution Role'}")
        logger.info(f"Regions: {regions}")
        logger.info(f"Exclusions: {len(exclusions)} service(s) configured")
        
        # Execute cleanup
        success = execute_cleanup_tasks(
            profile=profile,
            regions=regions,
            dry_run=dry_run,
            exclusions=exclusions
        )
        
        if not success:
            return {
                'statusCode': 500,
                'body': json.dumps({
                    'message': 'Cleanup failed - check logs for details',
                    'phase': 'dry_run' if dry_run else 'deletion'
                })
            }
        
        # Success response
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'{phase} phase completed successfully',
                'phase': 'dry_run' if dry_run else 'deletion',
                'regions_processed': regions
            })
        }
        
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        return {
            'statusCode': 400,
            'body': json.dumps({
                'error': 'Invalid input',
                'message': str(e)
            })
        }
    
    except Exception as e:
        logger.error(f"Unexpected error in lambda_handler: {str(e)}", exc_info=True)
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Internal error',
                'message': str(e)
            })
        }


def load_exclusions_from_s3(bucket, key):
    """
    Load exclusion YAML file from S3.
    
    :param bucket: S3 bucket name
    :param key: S3 object key
    :return: Dictionary of exclusion rules
    """
    import boto3
    import yaml
    from botocore.exceptions import ClientError
    
    try:
        s3_client = boto3.client('s3')
        response = s3_client.get_object(Bucket=bucket, Key=key)
        content = response['Body'].read().decode('utf-8')
        
        data = yaml.safe_load(content)
        return data.get('exclude', {})
        
    except ClientError as e:
        logger.error(f"Failed to load exclusions from S3: {e}")
        raise
    except yaml.YAMLError as e:
        logger.error(f"Failed to parse YAML from S3: {e}")
        raise


# For local testing
if __name__ == "__main__":
    # Test event for dry-run
    test_event = {
        "regions": ["us-east-1"],
        "dry_run": True,
        "exclusions": {
            "s3": ["prod-*", "backup-*"],
            "rds": ["production-db"],
            "ec2": ["i-*prod*"]
        }
    }
    
    # Mock context
    class MockContext:
        def __init__(self):
            self.function_name = "cleanup-function"
            self.memory_limit_in_mb = 512
            self.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:cleanup-function"
            self.aws_request_id = "test-request-id"
    
    result = lambda_handler(test_event, MockContext())
    print(json.dumps(result, indent=2))

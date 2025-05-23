import boto3
import json
import os
from datetime import datetime
from pathlib import Path

def custom_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def print_policy_document(doc):
    print(json.dumps(doc, indent=4, sort_keys=True))

def safe_filename(filename):
    """Convert S3 key to safe local filename/path"""
    # Replace problematic characters
    safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_./\\"
    return ''.join(c if c in safe_chars else '_' for c in filename)

def download_s3_object(s3_client, bucket_name, obj_key, local_base_path):
    """Download S3 object and create necessary directories"""
    try:
        # Create safe local path
        safe_key = safe_filename(obj_key)
        local_path = Path(local_base_path) / safe_key
        
        # Create parent directories
        local_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Download file
        print(f"  Downloading: {obj_key} -> {local_path}")
        s3_client.download_file(bucket_name, obj_key, str(local_path))
        return True
    except Exception as e:
        print(f"  ❌ Error downloading {obj_key}: {e}")
        return False

def list_and_download_bucket(s3_client, bucket_name):
    """Recursively list and download all objects from a bucket"""
    print(f"\n=== Processing Bucket: {bucket_name} ===")
    
    # Create local directory for bucket
    bucket_dir = Path("s3_downloads") / safe_filename(bucket_name)
    bucket_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Get bucket location
        try:
            location = s3_client.get_bucket_location(Bucket=bucket_name)
            print(f"Bucket region: {location.get('LocationConstraint', 'us-east-1')}")
        except Exception as e:
            print(f"Could not get bucket location: {e}")
        
        # List all objects (handles pagination)
        paginator = s3_client.get_paginator('list_objects_v2')
        page_iterator = paginator.paginate(Bucket=bucket_name)
        
        total_objects = 0
        downloaded_count = 0
        total_size = 0
        
        for page in page_iterator:
            if 'Contents' in page:
                for obj in page['Contents']:
                    total_objects += 1
                    obj_key = obj['Key']
                    obj_size = obj['Size']
                    total_size += obj_size
                    
                    print(f"Object {total_objects}: {obj_key} ({obj_size} bytes)")
                    
                    # Download the object
                    if download_s3_object(s3_client, bucket_name, obj_key, bucket_dir):
                        downloaded_count += 1
        
        print(f"\nBucket Summary:")
        print(f"  Total objects: {total_objects}")
        print(f"  Successfully downloaded: {downloaded_count}")
        print(f"  Total size: {total_size:,} bytes ({total_size/1024/1024:.2f} MB)")
        
    except Exception as e:
        print(f"❌ Error processing bucket {bucket_name}: {e}")

# Prompting for credentials and inputs
access_key = input("Enter AWS Access Key ID: ").strip()
secret_access_key = input("Enter AWS Secret Access Key: ").strip()
region = input("Enter AWS Region [default: us-east-1]: ").strip() or 'us-east-1'
bucket = input("Enter specific S3 Bucket name (leave blank to scan all accessible buckets): ").strip()

# Initiating AWS session
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

# Print STS identity
username = None
try:
    sts_caller_info = sts_client.get_caller_identity()
    print(f"UserId: {sts_caller_info['UserId']}")
    print(f"Account: {sts_caller_info['Account']}")
    print(f"ARN: {sts_caller_info['Arn']}")

    arn_parts = sts_caller_info['Arn'].split('/')
    if len(arn_parts) >= 2:
        username = arn_parts[-1]
except Exception as e:
    print(f"Error getting caller identity: {e}")

# IAM user policy/group info
if username:
    print(f"\n=== IAM Info for User: {username} ===")
    try:
        # Attached managed policies
        attached_policies = iam_client.list_attached_user_policies(UserName=username)
        print("\nAttached Managed Policies:")
        for policy in attached_policies.get("AttachedPolicies", []):
            print(f" - {policy['PolicyName']} (ARN: {policy['PolicyArn']})")
            policy_detail = iam_client.get_policy(PolicyArn=policy["PolicyArn"])
            version_id = policy_detail["Policy"]["DefaultVersionId"]
            policy_version = iam_client.get_policy_version(
                PolicyArn=policy["PolicyArn"],
                VersionId=version_id
            )
            print(f"   Permissions for {policy['PolicyName']}:")
            print_policy_document(policy_version["PolicyVersion"]["Document"])

        # Inline policies
        inline_policies = iam_client.list_user_policies(UserName=username)
        print("\nInline Policies:")
        for policy_name in inline_policies.get("PolicyNames", []):
            print(f" - {policy_name}")
            policy_doc = iam_client.get_user_policy(UserName=username, PolicyName=policy_name)
            print("   Permissions:")
            print_policy_document(policy_doc["PolicyDocument"])

        # Group memberships
        user_groups = iam_client.list_groups_for_user(UserName=username)
        print("\nGroups:")
        for group in user_groups.get("Groups", []):
            group_name = group['GroupName']
            print(f" - {group_name} (ARN: {group['Arn']})")

            # Managed policies attached to group
            attached_group_policies = iam_client.list_attached_group_policies(GroupName=group_name)
            for policy in attached_group_policies.get("AttachedPolicies", []):
                print(f"   Attached Managed Policy: {policy['PolicyName']} (ARN: {policy['PolicyArn']})")
                policy_detail = iam_client.get_policy(PolicyArn=policy["PolicyArn"])
                version_id = policy_detail["Policy"]["DefaultVersionId"]
                policy_version = iam_client.get_policy_version(
                    PolicyArn=policy["PolicyArn"],
                    VersionId=version_id
                )
                print(f"     Permissions for {policy['PolicyName']}:")
                print_policy_document(policy_version["PolicyVersion"]["Document"])

            # Inline group policies
            inline_group_policies = iam_client.list_group_policies(GroupName=group_name)
            for policy_name in inline_group_policies.get("PolicyNames", []):
                print(f"   Inline Policy: {policy_name}")
                policy_doc = iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)
                print(f"     Permissions:")
                print_policy_document(policy_doc["PolicyDocument"])

    except Exception as e:
        print(f"Error fetching IAM details for {username}: {e}")

# S3 Bucket Discovery and Download
print(f"\n=== S3 Bucket Analysis ===")

# Create main download directory
Path("s3_downloads").mkdir(exist_ok=True)

if bucket:
    # Download specific bucket
    list_and_download_bucket(s3_client, bucket)
else:
    # List all accessible buckets and download from each
    try:
        buckets_response = s3_client.list_buckets()
        buckets = buckets_response.get('Buckets', [])
        
        print(f"Found {len(buckets)} accessible buckets:")
        for i, bucket_info in enumerate(buckets, 1):
            bucket_name = bucket_info['Name']
            creation_date = bucket_info['CreationDate']
            print(f"{i}. {bucket_name} (Created: {creation_date})")
        
        if buckets:
            print(f"\nProceeding to download from all {len(buckets)} buckets...")
            for bucket_info in buckets:
                bucket_name = bucket_info['Name']
                list_and_download_bucket(s3_client, bucket_name)
        else:
            print("No accessible buckets found.")
            
    except Exception as e:
        print(f"Error listing buckets: {e}")

# List secrets
try:
    secrets_list = secrets_client.list_secrets()
    print("\n=== Secrets List ===")
    print(json.dumps(secrets_list, indent=4, sort_keys=True, default=custom_serializer))
    for secret in secrets_list.get("SecretList", []):
        name = secret.get("Name")
        if name:
            try:
                secret_dump = secrets_client.get_secret_value(SecretId=name)
                print(f"\nSecret: {name}")
                print(json.dumps(secret_dump, indent=4, sort_keys=True, default=custom_serializer))
            except Exception as e:
                print(f"Error retrieving secret '{name}': {e}")
except Exception as e:
    print(f"Error listing secrets: {e}")

# Role discovery and assumption
print("\n=== Role Assumption Analysis ===")
try:
    marker = None
    matching_roles = []
    while True:
        roles_response = iam_client.list_roles(Marker=marker) if marker else iam_client.list_roles()
        for role in roles_response["Roles"]:
            role_name = role["RoleName"]
            role_arn = role["Arn"]
            trust_policy = role["AssumeRolePolicyDocument"]
            trust_policy_json = json.dumps(trust_policy)

            # Check if user or ARN appears in trust relationship
            if username and (username in trust_policy_json or sts_caller_info['Arn'] in trust_policy_json):
                print(f"\nRole '{role_name}' might be assumable by user '{username}'")
                print(f" - Role ARN: {role_arn}")
                print(" - Trust Policy:")
                print_policy_document(trust_policy)
                matching_roles.append(role_name)

                # Try to assume it
                try:
                    assume_response = sts_client.assume_role(
                        RoleArn=role_arn,
                        RoleSessionName=f"TestSession-{username}"
                    )
                    print(" ✅ AssumeRole succeeded!")
                    credentials = assume_response["Credentials"]
                    print("Temporary session credentials:")
                    print(f" - AccessKeyId: {credentials['AccessKeyId']}")
                    print(f" - SecretAccessKey: {credentials['SecretAccessKey']}")
                    print(f" - SessionToken: {credentials['SessionToken']}")
                    print(f" - Expiration: {credentials['Expiration']}")
                except Exception as assume_error:
                    print(f" ❌ Could not assume role '{role_name}': {assume_error}")

        if roles_response.get("IsTruncated"):
            marker = roles_response["Marker"]
        else:
            break

    if not matching_roles:
        print("No assumable roles found for the current user.")
except Exception as e:
    print(f"Error while listing/analyzing roles: {e}")

print(f"\n=== Summary ===")
print(f"✅ AWS Security Assessment Complete")
print(f"📁 S3 downloads saved to: ./s3_downloads/")
print(f"🔍 Check the output above for IAM permissions, secrets, and role analysis")
import boto3
import json
import os
from datetime import datetime

def custom_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def print_policy_document(doc):
    print(json.dumps(doc, indent=4, sort_keys=True))

# Prompting for credentials and inputs
access_key = input("Enter AWS Access Key ID: ").strip()
secret_access_key = input("Enter AWS Secret Access Key: ").strip()
region = input("Enter AWS Region [default: us-east-1]: ").strip() or 'us-east-1'
bucket = input("Enter S3 Bucket name (leave blank to skip S3 download): ").strip()

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

# If a bucket is provided, download files
if bucket:
    try:
        os.makedirs(bucket, exist_ok=True)
        os.chdir(bucket)
        bucket_objects = s3_client.list_objects_v2(Bucket=bucket)
        for obj in bucket_objects.get("Contents", []):
            file_name = obj["Key"]
            print(f"File {file_name} found!")
            with open(file_name, "wb") as file:
                s3_client.download_fileobj(bucket, file_name, file)
                print(f"Downloaded {file_name}")
    except Exception as e:
        print(f"Error handling S3 bucket '{bucket}': {e}")

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

```
 ██████╗██╗      ██████╗ ██╗   ██╗██████╗ ████████╗ █████╗ ██████╗ 
██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗
██║     ██║     ██║   ██║██║   ██║██║  ██║   ██║   ███████║██████╔╝
██║     ██║     ██║   ██║██║   ██║██║  ██║   ██║   ██╔══██║██╔═══╝ 
╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝   ██║   ██║  ██║██║     
 ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝       
```
https://github.com/user-attachments/assets/ef236848-f054-495d-8f36-b215f9ed9105

## Webpage Preview
![Webpage](https://github.com/user-attachments/assets/dc3f43b1-8955-490c-b55e-6c93797e82a8)

## Features

- **Permissions Bruteforce** 
  - Uses every permission call API to test which one the user has
  - Passes them to priv esc suggester to find possible paths
  
- **Identity Inspection**  
  - Retrieves and prints details about the current IAM identity using STS.

- **IAM Policy Enumeration**  
  - Lists attached and inline policies for IAM users.  
  - Extracts group memberships and attached/inlined group policies.
  - Extracts all versions of manahed policies

- **SNS Discovery**
  - Able to find SNS and subscribe to them
  - List all SNS subscriptions

- **Secrets Discovery**  
  - Lists all secrets in AWS Secrets Manager.  
  - Retrieves and prints contents of each secret securely.

- **S3 Bucket Support**  
  - Downloads all objects from a specified bucket into a local directory.
 
- **Beanstalk Support**
  - Bruteforces all regions for beanstalkn instances and looking for eviroment veriables

- **Lambda functions**
  - Get-Download-Enum Lambda functions and all region

- **EC2 Instance Analysis**
  - **Network Targets**: Public/private IPs, DNS names, network interfaces
  - **Attack Surface**: Security groups with detailed rules, open ports, internet-facing services
  - **Data & Privilege Escalation**: EBS volumes (encrypted/unencrypted), IAM profiles, user data, tags
  - **System Info**: Instance types, platforms, key pairs, availability zones
  - **Multi-region scanning** with comprehensive summaries

- **ECS Container Analysis**

  - **Container Orchestration**: Clusters, services, tasks, and container instances across all regions
  - **Network Exposure**: Public/private IPs, ENI attachments, load balancer configurations, service discovery
  - **Attack Surface**: Security groups, network configurations, public task access, function URLs, execute command capabilities
  - **Container Security**: Task definitions, environment variables, secrets, privileged containers, resource limits
  - **Service Architecture**: Auto-scaling policies, deployment configurations, health checks, service registries
  - **Data & Access**: IAM task roles, execution roles, volume mounts, logging configurations, container insights
  - **Runtime Analysis**: Running/stopped tasks, container status, resource utilization, network bindings
  - **Multi-region scanning** with detailed cluster topology and comprehensive security assessments

- **Assumable Role Detection**
  - Analyzes trust policies of IAM roles to identify assumable roles based on your current identity.  
  - Attempts to assume those roles and logs results.
  - Gets the attached policies of that role

- **Priv Escalation Suggester**
  - Grabs all permissions.
  - Checks what combinations of permissions you have to escalate your priv.
  - Suggest paths and inludes links

- **Formatted JSON Output**  
  - Policies and secrets are printed with clear formatting for easy review and logging.

---

## Usage

```
# Use specific profile (no credential prompts)
python3 CloudTap.py --keys init

# List available profiles
python3 CloudTap.py --list-profiles

# Use custom .env file
python3 CloudTap.py --keys myprofile --env-file /path/to/.env

# Traditional manual input (original behavior)
python3 CloudTap.py
```

---

## 🧰 Requirements

- Python 3.x  
- `boto3`
- `colorama`
- `tqdm`
- `loguru`
- AWS Access Key ID and Secret Access Key with appropriate IAM permissions

---

## Proposed Output JSON Format

CloudTap can output a consolidated JSON document so the collected data can be consumed by other tools or a web interface. Each section is optional depending on the modules executed.

```json
{
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "profile": "default",
    "regions_scanned": ["us-east-1"],
    "tool_version": "1.0.0"
  },
  "identity": {
    "UserId": "...",
    "Account": "...",
    "Arn": "...",
    "credentialType": "temporary"
  },
  "permissions": {
    "enumerated": ["s3:ListBuckets"],
    "bruteforced": ["ec2:DescribeInstances"]
  },
  "iam": {
    "users": [],
    "roles": [],
    "policies": []
  },
  "ec2": {
    "regions": {
      "us-east-1": {
        "instances": [],
        "volumes": []
      }
    }
  },
  "s3": {"buckets": []},
  "secrets_manager": {"secrets": []},
  "sns": {"topics": [], "subscriptions": []},
  "beanstalk": {"applications": [], "environments": []},
  "lambda": {"functions": []},
  "ecs": {"clusters": []},
  "privilege_escalation": {"paths": []}
}
```

A more complete skeleton is available in [`docs/output_schema.json`](docs/output_schema.json).


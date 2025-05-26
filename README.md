```
 ██████╗██╗      ██████╗ ██╗   ██╗██████╗ ████████╗ █████╗ ██████╗ 
██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗
██║     ██║     ██║   ██║██║   ██║██║  ██║   ██║   ███████║██████╔╝
██║     ██║     ██║   ██║██║   ██║██║  ██║   ██║   ██╔══██║██╔═══╝ 
╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝   ██║   ██║  ██║██║     
 ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝       
```                                                                   
## Features

- **Identity Inspection**  
  Retrieves and prints details about the current IAM identity using STS.

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

- **Assumable Role Detection**
  - Analyzes trust policies of IAM roles to identify assumable roles based on your current identity.  
  - Attempts to assume those roles and logs results.
  - Gets the attached policies of that role

- **Formatted JSON Output**  
  - Policies and secrets are printed with clear formatting for easy review and logging.

---

## 🧰 Requirements

- Python 3.x  
- `boto3`
- `colorama`
- `tqdm`
- `loguru`
- AWS Access Key ID and Secret Access Key with appropriate IAM permissions

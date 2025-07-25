import time

import boto3
from botocore.exceptions import ClientError

actions = {}

actions['autoscaling'] = [
    "autoscaling:AttachLoadBalancerTargetGroups",
    "autoscaling:AttachLoadBalancers",
    "autoscaling:CreateAutoScalingGroup",
    "autoscaling:CreateLaunchConfiguration",
    "autoscaling:CreateOrUpdateTags",
    "autoscaling:DeleteAutoScalingGroup",
    "autoscaling:DeleteLaunchConfiguration",
    "autoscaling:DeleteTags",
    "autoscaling:DescribeAutoScalingGroups",
    "autoscaling:DescribeAutoScalingInstances",
    "autoscaling:DescribeLaunchConfigurations",
    "autoscaling:DescribeLoadBalancers",
    "autoscaling:DescribeLoadBalancerTargetGroups",
    "autoscaling:DescribeScalingActivities",
    "autoscaling:DescribeTags",
    "autoscaling:UpdateAutoScalingGroup"
]

actions['aws-marketplace'] = [
    "aws-marketplace:AcceptAgreementApprovalRequest",
    "aws-marketplace:AcceptAgreementRequest",
    "aws-marketplace:CancelAgreement",
    "aws-marketplace:CancelAgreementRequest",
    "aws-marketplace:DescribeAgreement",
    "aws-marketplace:GetAgreementTerms",
    "aws-marketplace:ListEntitlementDetails",
    "aws-marketplace:Subscribe",
    "aws-marketplace:Unsubscribe",
    "aws-marketplace:ViewSubscriptions",
    "aws-marketplace:RegisterUsage",
]

actions['cloudformation'] = [
    "cloudformation:CancelUpdateStack",
    "cloudformation:ContinueUpdateRollback",
    "cloudformation:CreateChangeSet",
    "cloudformation:CreateStack",
    "cloudformation:CreateUploadBucket",
    "cloudformation:DeleteChangeSet",
    "cloudformation:DeleteStack",
    "cloudformation:DescribeChangeSet",
    "cloudformation:DescribeStackEvents",
    "cloudformation:DescribeStackResource",
    "cloudformation:DescribeStackResources",
    "cloudformation:DescribeStackSet",
    "cloudformation:DescribeStackSetOperation",
    "cloudformation:DescribeStacks",
    "cloudformation:ExecuteChangeSet",
    "cloudformation:GetTemplate",
    "cloudformation:GetTemplateSummary",
    "cloudformation:ListChangeSets",
    "cloudformation:ListStackInstances",
    "cloudformation:ListStackResources",
    "cloudformation:ListStacks",
    "cloudformation:RollbackStack",
    "cloudformation:TagResource",
    "cloudformation:UntagResource",
    "cloudformation:UpdateStack",
    "cloudformation:ValidateTemplate"
]

actions['cloudshell'] = [
    "cloudshell:StartEnvironment",
    "cloudshell:StopEnvironment",
    "cloudshell:DeleteEnvironment",
    "cloudshell:CreateSession",
    "cloudshell:CreateEnvironment",
    "cloudshell:GetEnvironmentStatus",
    "cloudshell:PutCredentials",
]

actions['ec2'] = [
    "ec2:AssociateRouteTable",
    "ec2:AssociateVpcCidrBlock",
    "ec2:AttachInternetGateway",
    "ec2:AuthorizeSecurityGroupEgress",
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:CreateInternetGateway",
    "ec2:CreateLaunchTemplate",
    "ec2:CreateRoute",
    "ec2:CreateRouteTable",
    "ec2:CreateSecurityGroup",
    "ec2:CreateSubnet",
    "ec2:CreateTags",
    "ec2:CreateVpc",
    "ec2:DeleteInternetGateway",
    "ec2:DeleteLaunchTemplate",
    "ec2:DeleteRoute",
    "ec2:DeleteRouteTable",
    "ec2:DeleteSecurityGroup",
    "ec2:DeleteSubnet",
    "ec2:DeleteTags",
    "ec2:DeleteVpc",
    "ec2:DescribeInstances",
    "ec2:DescribeInternetGateways",
    "ec2:DescribeInstanceTypes",
    "ec2:DescribeLaunchTemplates",
    "ec2:DescribeLaunchTemplateVersions",
    "ec2:DescribeNatGateways",
    "ec2:DescribeNetworkAcls",
    "ec2:DescribeRegions",
    "ec2:DescribeRouteTables",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeSecurityGroupRules",
    "ec2:DescribeSecurityGroupReferences",
    "ec2:DescribeSubnets",
    "ec2:DescribeTags",
    "ec2:DescribeVpcAttribute",
    "ec2:DescribeVolumeStatus",
    "ec2:DescribeVolumesModifications",
    "ec2:DescribeVolumes",
    "ec2:DescribeVolumeAttribute",
    "ec2:DescribeVpcEndpoints",
    "ec2:DescribeVpcEndpointConnections",
    "ec2:DescribeVpcEndpointServices",
    "ec2:DescribeVpcs",
    "ec2:DescribeVpnConnections",
    "ec2:DescribeVpnGateways",
    "ec2:DetachInternetGateway",
    "ec2:DisassociateRouteTable",
    "ec2:DisassociateVpcCidrBlock",
    "ec2:ModifySubnetAttribute",
    "ec2:ModifyVpcAttribute",
    "ec2:RevokeSecurityGroupEgress",
    "ec2:RevokeSecurityGroupIngress",
    "ec2:RunInstances",
    "ec2:StartInstances",
    "ec2:StopInstances",
    "ec2:TerminateInstances",
    "ec2:DescribeImages",
    "ec2:DescribeImageAttribute",
    "ec2:DescribeImportImageTasks",
    "ec2:DescribeAvailabilityZones",
    "ec2:DescribeAddresses",
    "ec2:DescribeEgressOnlyInternetGateways",
    "ec2:DescribeInstanceAttribute",
    "ec2:DescribeInstanceStatus"
]

actions['ecr'] = [
    "ecr:CreateRepository",
    "ecr:DescribeRepositories",
    "ecr:DescribeImages",
    "ecr:BatchCheckLayerAvailability",
    "ecr:InitiateLayerUpload",
    "ecr:UploadLayerPart",
    "ecr:CompleteLayerUpload",
    "ecr:PutImage",
    "ecr:GetDownloadUrlForLayer",
    "ecr:GetAuthorizationToken",
    "ecr:ListImages",
    "ecr:DeleteRepository",
    "ecr:DeleteRepositoryPolicy",
    "ecr:SetRepositoryPolicy",
    "ecr:BatchGetImage",
    "ecr:BatchDeleteImage",
    "ecr:DescribeRegistry",
    "ecr:GetRepositoryPolicy"
]

actions['elasticloadbalancing'] = [
    "elasticloadbalancing:AddTags",
    "elasticloadbalancing:CreateListener",
    "elasticloadbalancing:CreateLoadBalancer",
    "elasticloadbalancing:CreateRule",
    "elasticloadbalancing:CreateTargetGroup",
    "elasticloadbalancing:DeleteListener",
    "elasticloadbalancing:DeleteLoadBalancer",
    "elasticloadbalancing:DeleteRule",
    "elasticloadbalancing:DeleteTargetGroup",
    "elasticloadbalancing:DescribeListeners",
    "elasticloadbalancing:DescribeLoadBalancerAttributes",
    "elasticloadbalancing:DescribeLoadBalancers",
    "elasticloadbalancing:DescribeRules",
    "elasticloadbalancing:DescribeTags",
    "elasticloadbalancing:DescribeTargetGroupAttributes",
    "elasticloadbalancing:DescribeTargetGroups",
    "elasticloadbalancing:DescribeTargetHealth",
    "elasticloadbalancing:ModifyListener",
    "elasticloadbalancing:ModifyLoadBalancerAttributes",
    "elasticloadbalancing:ModifyTargetGroup",
    "elasticloadbalancing:ModifyTargetGroupAttributes",
    "elasticloadbalancing:RemoveTags"
]

actions['iam'] = [
    "iam:AddRoleToInstanceProfile",
    "iam:AttachRolePolicy",
    "iam:CreateAccessKey",
    "iam:CreateInstanceProfile",
    "iam:CreatePolicy",
    "iam:CreateRole",
    "iam:DeleteAccessKey",
    "iam:DeleteInstanceProfile",
    "iam:DeletePolicy",
    "iam:DeleteRole",
    "iam:DeleteRolePolicy",
    "iam:DetachRolePolicy",
    "iam:GetInstanceProfile",
    "iam:GetPolicy",
    "iam:GetRole",
    "iam:GetRolePolicy",
    "iam:ListAccessKeys",
    "iam:ListAttachedRolePolicies",
    "iam:ListInstanceProfileTags",
    "iam:ListInstanceProfiles",
    "iam:ListInstanceProfilesForRole",
    "iam:ListPolicies",
    "iam:ListPolicyVersions",
    "iam:ListRolePolicies",
    "iam:ListRoles",
    "iam:ListUserPolicies",
    "iam:ListUsers",
    "iam:PassRole",
    "iam:PutRolePolicy",
    "iam:RemoveRoleFromInstanceProfile",
    "iam:SimulatePrincipalPolicy",
    "iam:TagInstanceProfile",
    "iam:UntagInstanceProfile",
    "iam:UpdateAccessKey",
    "iam:UpdateRole"
]

actions['lambda'] = [
    "lambda:AddPermission",
    "lambda:CreateFunction",
    "lambda:DeleteFunction",
    "lambda:DeleteFunctionConcurrency",
    "lambda:DeleteFunctionEventInvokeConfig",
    "lambda:GetAccountSettings",
    "lambda:GetFunction",
    "lambda:GetFunctionConcurrency",
    "lambda:GetFunctionEventInvokeConfig",
    "lambda:GetLayerVersion",
    "lambda:ListFunctionEventInvokeConfigs",
    "lambda:ListFunctions",
    "lambda:ListLayerVersions",
    "lambda:ListLayers",
    "lambda:ListTags",
    "lambda:PutFunctionConcurrency",
    "lambda:PutFunctionEventInvokeConfig",
    "lambda:RemovePermission",
    "lambda:TagResource",
    "lambda:UntagResource",
    "lambda:UpdateFunctionCode",
    "lambda:UpdateFunctionConfiguration",
    "lambda:UpdateFunctionEventInvokeConfig"
]

actions['logs'] = [
    "logs:CreateLogGroup",
    "logs:DeleteLogGroup",
    "logs:DeleteSubscriptionFilter",
    "logs:DescribeLogGroups",
    "logs:DescribeLogStreams",
    "logs:DescribeSubscriptionFilters",
    "logs:FilterLogEvents",
    "logs:GetLogEvents",
    "logs:GetLogGroupFields",
    "logs:ListTagsLogGroup",
    "logs:PutSubscriptionFilter",
    "logs:TagLogGroup",
    "logs:UntagLogGroup"
]

actions['s3'] = [
    "s3:CreateBucket",
    "s3:DeleteBucket",
    "s3:DeleteObject",
    "s3:GetBucketLocation",
    "s3:GetBucketNotification",
    "s3:GetObject",
    "s3:ListAllMyBuckets",
    "s3:ListBucket",
    "s3:PutBucketNotification",
    "s3:PutObject",
    "s3:ListBucketVersions",
    "s3:DeleteObjectVersion"
]

actions['ssm'] = ["ssm:GetParameters"]

actions['scheduler'] = [
    "scheduler:ListSchedules",
    "scheduler:GetSchedule",
    "scheduler:ListTagsForResource",
    "scheduler:CreateSchedule",
    "scheduler:DeleteSchedule",
    "scheduler:UpdateSchedule",
    "scheduler:TagResource",
    "scheduler:UntagResource",
]

actions['events'] = [
    "events:DescribeRule",
    "events:ListRules",
    "events:DeleteRule",
    "events:EnableRule",
    "events:DisableRule",
    "events:PutRule",
    "events:PutTargets",
    "events:RemoveTargets"
]

iam_client = boto3.client('iam')
sts_client = boto3.client('sts')

DEFAULT_REGION = "us-east-1"

SUPPORTED_REGIONS = [
    'eu-north-1',
    'ap-south-1',
    'eu-west-3',
    'us-east-2',
    'eu-central-1',
    'sa-east-1',
    'ap-east-1',
    'us-east-1',
    'ap-northeast-2',
    'eu-west-2',
    'ap-northeast-1',
    'us-west-2',
    'us-west-1',
    'ap-southeast-1',
    'ap-southeast-2',
    'ca-central-1',
]


def is_root_account():
    iam_client = boto3.client('iam')
    try:
        user = iam_client.get_user()
        if 'UserName' not in user['User']:
            return True
        return False
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            # This error indicates that the account is a root account
            return True
        else:
            raise e


def get_current_identity():
    try:
        return sts_client.get_caller_identity()
    except ClientError as e:
        print(f"Error getting identity: {e}")
        return None


def check_permission(arn, account_id, identity_type, actions, region=None, max_retries=3):
    """Check permissions for multiple actions with retry logic and rate limiting"""

    # Convert single action to list for consistency
    if isinstance(actions, str):
        actions = [actions]

    for attempt in range(max_retries):
        try:
            if identity_type == "assumed-role":
                # For assumed roles (including CloudShell)
                role_name = arn.split("/")[1]

                # Prepare context entries
                context_entries = [
                    {
                        'ContextKeyName': 'aws:userid',
                        'ContextKeyValues': [f"{account_id}:{role_name}"],
                        'ContextKeyType': 'string'
                    }
                ]

                # Add region context if specified
                if region:
                    context_entries.append({
                        'ContextKeyName': 'aws:RequestedRegion',
                        'ContextKeyValues': [region],
                        'ContextKeyType': 'string'
                    })

                response = iam_client.simulate_custom_policy(
                    PolicyInputList=[{
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": actions,
                            "Resource": "*"
                        }]
                    }],
                    ActionNames=actions,
                    ContextEntries=context_entries
                )

                # Process results for all actions
                results = {}
                for eval_result in response['EvaluationResults']:
                    action_name = eval_result['EvalActionName']
                    decision = eval_result['EvalDecision']
                    results[action_name] = decision == 'allowed'

                    # Print detailed results for debugging
                    if decision == 'explicitDeny':
                        print(f"EXPLICIT DENY for {action_name}")
                        if 'MatchedStatements' in eval_result:
                            matched_stmt = eval_result['MatchedStatements'][0]
                            denied_policy = matched_stmt['SourcePolicyId']
                            policy_type = matched_stmt['SourcePolicyType']
                            print(f"  Denied by policy: {denied_policy}")
                            print(f"  Policy type: {policy_type}")
                    elif decision == 'implicitDeny':
                        print(f"IMPLICIT DENY for {action_name} - No policy allows this action")
                    elif decision == 'allowed':
                        print(f"ALLOWED for {action_name}")

                return results

            else:
                # For IAM users
                if region:
                    # Add region context for IAM users
                    response = iam_client.simulate_principal_policy(
                        PolicySourceArn=arn,
                        ActionNames=actions,
                        ContextEntries=[
                            {
                                'ContextKeyName': 'aws:RequestedRegion',
                                'ContextKeyValues': [region],
                                'ContextKeyType': 'string'
                            }
                        ]
                    )
                else:
                    response = iam_client.simulate_principal_policy(
                        PolicySourceArn=arn,
                        ActionNames=actions
                    )

                # Process results for all actions
                results = {}
                for eval_result in response['EvaluationResults']:
                    action_name = eval_result['EvalActionName']
                    decision = eval_result['EvalDecision']
                    results[action_name] = decision == 'allowed'

                    # Print detailed results for debugging
                    if decision == 'explicitDeny':
                        print(f"EXPLICIT DENY for {action_name}")
                        if 'MatchedStatements' in eval_result:
                            matched_stmt = eval_result['MatchedStatements'][0]
                            denied_policy = matched_stmt['SourcePolicyId']
                            policy_type = matched_stmt['SourcePolicyType']
                            print(f"  Denied by policy: {denied_policy}")
                            print(f"  Policy type: {policy_type}")
                    elif decision == 'implicitDeny':
                        print(f"IMPLICIT DENY for {action_name} - No policy allows this action")
                    elif decision == 'allowed':
                        print(f"ALLOWED for {action_name}")

                return results

        except ClientError as e:
            error_code = e.response['Error']['Code']

            if error_code == 'Throttling' and attempt < max_retries - 1:
                # Exponential backoff: 0.2s, 0.4s, 0.8s
                sleep_time = 0.2 * (2 ** attempt)
                print(f"Throttling detected for {len(actions)} actions, retrying in {sleep_time}s "
                      f"(attempt {attempt + 1}/{max_retries})")
                time.sleep(sleep_time)
                continue
            else:
                print(f"Error checking permissions for {len(actions)} actions: {e}")
                return {action: False for action in actions}

    return {action: False for action in actions}


def list_user_policies(arn):
    """List all policies attached to the user"""
    try:
        # Extract username from ARN
        username = arn.split('/')[-1]

        print(f"\n=== Policies attached to user: {username} ===\n")

        # Get inline policies
        inline_policies = iam_client.list_user_policies(UserName=username)
        print("Inline Policies:")
        for policy in inline_policies['PolicyNames']:
            print(f"  - {policy}")

        # Get attached managed policies
        attached_policies = iam_client.list_attached_user_policies(
            UserName=username
        )
        print("\nManaged Policies:")
        for policy in attached_policies['AttachedPolicies']:
            print(f"  - {policy['PolicyName']} ({policy['PolicyArn']})")

        # Get groups the user belongs to
        groups = iam_client.list_groups_for_user(UserName=username)
        if 'Groups' in groups:
            print("\nGroups:")
            for group in groups['Groups']:
                print(f"  - {group['GroupName']}")

                # Get policies attached to each group
                group_policies = iam_client.list_attached_group_policies(
                    GroupName=group['GroupName']
                )
                for policy in group_policies['AttachedPolicies']:
                    policy_name = policy['PolicyName']
                    policy_arn = policy['PolicyArn']
                    print(f"    └─ {policy_name} ({policy_arn})")

    except ClientError as e:
        print(f"Error listing policies: {e}")


def get_on_demand_quotas(target=4):
    # Create a Service Quotas client
    client = boto3.client('service-quotas')

    # Define the service and quota codes for EC2 On-Demand G and VT instances
    service_code = 'ec2'
    quota_code = 'L-1216C47A'  # Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances

    # Retrieve the quota details
    response = client.get_service_quota(
        ServiceCode=service_code,
        QuotaCode=quota_code
    )

    # Extract and print quota information
    quota_info = response['Quota']
    print(f"Quota Name: {quota_info['QuotaName']}")
    print(f"Quota Value: {quota_info['Value']}")
    if quota_info['Value'] < target:
        print("Not enough quota to run pipeline please request more")


def main(region=None):
    if is_root_account():
        print("You are already using a root account. You should have all the required permissions.")
        return

    else:
        identity = get_current_identity()
        if identity:
            print(f"Checking permissions for: {identity['Arn']}\n")
        else:
            print("Unable to determine identity.")
            return

        arn = identity['Arn']
        account_id = identity['Account']
        print(f"Account ID: {account_id}")
        print(f"ARN: {arn}")

        if region:
            print(f"Checking permissions for region: {region}")
        else:
            print("Checking permissions globally (no specific region)")

        if ":assumed-role/" in arn:
            print("You are using an assumed role")
            identity_type = "assumed-role"
        else:
            print("You are using an IAM user")
            identity_type = "iam-user"
            # List all policies to help debug permission issues
            list_user_policies(arn)

        # Batch actions by service
        denied_actions = {}  # Store denied actions by service

        for service, action_list in actions.items():
            print(f"\nChecking permissions for service: {service}")
            print(f"Number of actions to check: {len(action_list)}")

            # Pass the list of actions for this service
            permission_results = check_permission(
                arn, account_id, identity_type, action_list, region
            )

            # Display results
            granted_count = 0
            denied_count = 0
            service_denied_actions = []  # Track denied actions for this service

            for action in action_list:
                status = "Granted" if permission_results[action] else "Denied"
                if permission_results[action]:
                    granted_count += 1
                else:
                    denied_count += 1
                    service_denied_actions.append(action)
                print(f"  Action: {action} - Permission: {status}")

            print(f"Summary for {service}: {granted_count} granted, {denied_count} denied")

            # Store denied actions for this service if any
            if service_denied_actions:
                denied_actions[service] = service_denied_actions

            # Rate limiting: 5 requests per second = 0.2 seconds between requests
            # Add extra delay between services to be safe
            time.sleep(0.3)

    print("Checking quotas...")
    # check quotas
    get_on_demand_quotas(target=35)

    # Display summary of all denied actions at the end
    if denied_actions:
        print("\n" + "="*60)
        print("SUMMARY OF DENIED PERMISSIONS")
        print("="*60)

        total_denied = sum(len(actions) for actions in denied_actions.values())
        print(f"Total denied actions: {total_denied}")
        print()

        for service, denied_list in denied_actions.items():
            print(f"Service: {service.upper()} ({len(denied_list)} denied)")
            for action in denied_list:
                print(f"  ❌ {action}")
            print()
    else:
        print("\n" + "="*60)
        print("✅ ALL PERMISSIONS GRANTED!")
        print("="*60)


def show_usage():
    """Show usage information"""
    print("Usage: python check_permissions.py [region]")
    print("Examples:")
    print("  python check_permissions.py us-east-1          # Check for us-east-1")
    print("  python check_permissions.py eu-west-1          # Check for eu-west-1")
    print("\nSupported regions:")
    for region in SUPPORTED_REGIONS:
        print(f"  - {region}")


if __name__ == '__main__':
    import sys

    # Check for help flag
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help', 'help']:
        show_usage()
        sys.exit(0)

    # Check if region is provided as command line argument
    region = None
    if len(sys.argv) > 1:
        region = sys.argv[1]
        if region not in SUPPORTED_REGIONS:
            print(f"Region {region} is not supported. Please use one of the following regions:")
            for r in SUPPORTED_REGIONS:
                print(f"  - {r}")
            sys.exit(1)
        print(f"Using region: {region}")
    else:
        print("No region provided, using default region: ", DEFAULT_REGION)
        region = DEFAULT_REGION
        show_usage()

    main(region)

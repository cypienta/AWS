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

actions['ecs'] = [
    "ecs:ListClusters",
    "ecs:DescribeClusters",
    "ecs:CreateCluster",
    "ecs:DeleteCluster",
    "ecs:PutClusterCapacityProviders",
    "ecs:UpdateCluster",
    "ecs:UpdateClusterSettings",
    "ecs:ListServices",
    "ecs:DescribeServices",
    "ecs:CreateService",
    "ecs:DeleteService",
    "ecs:UpdateService",
    "ecs:UpdateServicePrimaryTaskSet",
    "ecs:ListTaskDefinitionFamilies",
    "ecs:ListTaskDefinitions",
    "ecs:ListTasks",
    "ecs:DescribeTaskDefinition",
    "ecs:DescribeTasks",
    "ecs:DescribeTaskSets",
    "ecs:CreateTaskSet",
    "ecs:DeleteTaskDefinitions",
    "ecs:DeleteTaskSet",
    "ecs:DeregisterTaskDefinition",
    "ecs:RegisterTaskDefinition",
    "ecs:StopTask",
    "ecs:SubmitTaskStateChange",
    "ecs:UpdateTaskSet",
    "ecs:ListServicesByNamespace",
    "ecs:ListContainerInstances",
    "ecs:ListAttributes",
    "ecs:CreateCapacityProvider",
    "ecs:DeleteCapacityProvider",
    "ecs:UpdateCapacityProvider",
    "ecs:TagResource",
    "ecs:UntagResource",
    "ecs:DescribeCapacityProviders"
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


def check_permission(action):
    try:
        identity = get_current_identity()
        if not identity:
            return False

        arn = identity['Arn']
        account_id = identity['Account']

        if ":assumed-role/" in arn:
            # For assumed roles (including CloudShell)
            role_name = arn.split("/")[1]
            response = iam_client.simulate_custom_policy(
                PolicyInputList=[{
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": action,
                        "Resource": "*"
                    }]
                }],
                ActionNames=[action],
                ContextEntries=[
                    {
                        'ContextKeyName': 'aws:userid',
                        'ContextKeyValues': [f"{account_id}:{role_name}"],
                        'ContextKeyType': 'string'
                    },
                ]
            )
        else:
            # For IAM users
            response = iam_client.simulate_principal_policy(
                PolicySourceArn=arn,
                ActionNames=[action]
            )

        return response['EvaluationResults'][0]['EvalDecision'] == 'allowed'
    except ClientError as e:
        print(f"Error checking permission for {action}: {e}")
        return False


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


def main():
    if is_root_account():
        print("You are already using a root account. You should have all the required permissions.")
        return

    else:
        identity = get_current_identity()
        if identity:
            print(f"Checking permissions for: {identity['Arn']}\n")
        else:
            print("Unable to determine identity. Proceeding with permission checks.\n")

        for service, action_list in actions.items():
            print(f"Service: {service}")
            for action in action_list:
                has_permission = check_permission(action)
                status = "Granted" if has_permission else "Denied"
                print(f"  Action: {action} - Permission: {status}")
            print()

    print("Checking quotas...")
    # check quotas
    get_on_demand_quotas(target=20)


if __name__ == '__main__':
    main()

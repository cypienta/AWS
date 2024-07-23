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
    "autoscaling:Describe*",
    "autoscaling:UpdateAutoScalingGroup"]

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
    "aws-marketplace:ViewSubscriptions"]

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
    "cloudformation:ValidateTemplate"]

actions['cloudshell'] = ["cloudshell:*"]

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
    "ec2:Describe*",
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
    "ec2:TerminateInstances"]

actions['ecr'] = ["ecr:*"]
actions['ecs'] = ["ecs:*"]

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
    "elasticloadbalancing:RemoveTags"]

actions['iam'] = [
    "iam:AddRoleToInstanceProfile",
    "iam:AttachRolePolicy",
    "iam:CreateAccessKey",
    "iam:CreateInstanceProfile",
    "iam:CreateRole",
    "iam:DeleteAccessKey",
    "iam:DeleteInstanceProfile",
    "iam:DeleteRole",
    "iam:DeleteRolePolicy",
    "iam:DetachRolePolicy",
    "iam:GetInstanceProfile",
    "iam:GetRole",
    "iam:GetRolePolicy",
    "iam:GetUser",
    "iam:GetUserPolicy",
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
    "iam:UpdateRole",]

actions['lambda'] = [
    "lambda:AddPermission",
    "lambda:CreateFunction",
    "lambda:DeleteFunction",
    "lambda:DeleteFunctionConcurrency",
    "lambda:DeleteFunctionEventInvokeConfig",
    "lambda:GetFunction",
    "lambda:GetFunctionConcurrency",
    "lambda:GetFunctionEventInvokeConfig",
    "lambda:GetLayerVersion",
    "lambda:GetProvisionedConcurrencyConfig",
    "lambda:InvokeAsync",
    "lambda:InvokeFunction",
    "lambda:ListFunctionEventInvokeConfigs",
    "lambda:ListFunctions",
    "lambda:ListLayerVersions",
    "lambda:ListLayers",
    "lambda:ListTags",
    "lambda:PutFunctionConcurrency",
    "lambda:PutFunctionEventInvokeConfig",
    "lambda:PutProvisionedConcurrencyConfig",
    "lambda:RemovePermission",
    "lambda:TagResource",
    "lambda:UntagResource",
    "lambda:UpdateFunctionCode",
    "lambda:UpdateFunctionConfiguration",
    "lambda:UpdateFunctionEventInvokeConfig"]

actions['logs'] = [
    "logs:CreateLogGroup",
    "logs:DeleteLogGroup",
    "logs:DeleteSubscriptionFilter",
    "logs:DescribeLogGroups",
    "logs:DescribeSubscriptionFilters",
    "logs:FilterLogEvents",
    "logs:GetLogEvents",
    "logs:GetLogGroupFields",
    "logs:ListTagsLogGroup",
    "logs:PutSubscriptionFilter",
    "logs:TagLogGroup",
    "logs:UntagLogGroup"]

actions['route53'] = [
    "route53:CreateHostedZone",
    "route53:DeleteHostedZone",
    "route53:GetHealthCheck",
    "route53:GetHostedZone",
    "route53:ListHostedZonesByName"]

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
    "s3:PutBucketPolicy",
    "s3:PutObject"]

actions['sagemaker'] = [
    "sagemaker:CreateModel",
    "sagemaker:CreateTransformJob",
    "sagemaker:DeleteModel",
    "sagemaker:DescribeModel",
    "sagemaker:DescribeModelPackage",
    "sagemaker:DescribeTransformJob",
    "sagemaker:ListModels",
    "sagemaker:ListTransformJobs",
    "sagemaker:StopTransformJob"]

actions['servicediscovery'] = [
    "servicediscovery:CreatePrivateDnsNamespace",
    "servicediscovery:CreateService",
    "servicediscovery:DeleteService",
    "servicediscovery:GetNamespace",
    "servicediscovery:GetOperation",
    "servicediscovery:GetService",
    "servicediscovery:ListNamespaces",
    "servicediscovery:ListServices",
    "servicediscovery:UpdateService"]

actions['ssm'] = ["ssm:GetParameters"]

iam_client = boto3.client('iam')
sts_client = boto3.client('sts')

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

def main():
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

if __name__ == '__main__':
    main()


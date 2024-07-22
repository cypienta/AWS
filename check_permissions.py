import boto3
from botocore.exceptions import ClientError

actions = {
    'sagemaker': ['sagemaker:ListEndpoints'],
    'lambda': ['lambda:ListFunctions'],
    's3': ['s3:ListBuckets'],
    'ecs': ['ecs:ListClusters'],
    'ec2': ['ec2:DescribeInstances'],
    'ecr': ['ecr:DescribeRepositories'],
    'iam': ['iam:ListUsers'],
    'cloudformation': ['cloudformation:ListStacks']
}

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


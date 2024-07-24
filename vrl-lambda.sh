set -e
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
export REPO_NAME="cypienta-vrl-lambda"
docker pull public.ecr.aws/p2d2x2s3/cypienta/vrl-lambda:v0.1
aws ecr create-repository --repository-name ${REPO_NAME}
export ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ECR_URI}
docker tag public.ecr.aws/p2d2x2s3/cypienta/vrl-lambda:v0.1 ${ECR_URI}/${REPO_NAME}:v0.1
docker push ${ECR_URI}/${REPO_NAME}:v0.1
echo ${ECR_URI}/${REPO_NAME}:v0.1
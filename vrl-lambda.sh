set -e
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
export REPO_NAME="cypienta-vrl-lambda"
export VRL_TAG="v0.2"
docker pull public.ecr.aws/p2d2x2s3/cypienta/vrl-lambda:${VRL_TAG}
aws ecr create-repository --repository-name ${REPO_NAME}
export ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ECR_URI}
docker tag public.ecr.aws/p2d2x2s3/cypienta/vrl-lambda:${VRL_TAG} ${ECR_URI}/${REPO_NAME}:${VRL_TAG}
docker push ${ECR_URI}/${REPO_NAME}:${VRL_TAG}
echo ${ECR_URI}/${REPO_NAME}:${VRL_TAG}
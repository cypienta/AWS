set -e
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text)
export REPO_NAME="cypienta-vrl-lambda"
export VRL_TAG="v0.2"
docker pull public.ecr.aws/p2d2x2s3/cypienta/vrl-lambda:${VRL_TAG}
# Check if the repository already exists
aws ecr describe-repositories --repository-names "${REPO_NAME}" >/dev/null 2>&1
# If the repository doesn't exist (exit status is not 0), create it
if [ $? -ne 0 ]; then
    echo "Repository does not exist. Creating repository: ${REPO_NAME}"
    aws ecr create-repository --repository-name ${REPO_NAME}
else
    echo "Repository ${REPO_NAME} already exists. Skipping creation."
fi
export ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${ECR_URI}
docker tag public.ecr.aws/p2d2x2s3/cypienta/vrl-lambda:${VRL_TAG} ${ECR_URI}/${REPO_NAME}:${VRL_TAG}
docker push ${ECR_URI}/${REPO_NAME}:${VRL_TAG}
echo ${ECR_URI}/${REPO_NAME}:${VRL_TAG}
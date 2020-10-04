# Elasticsearch Cluster

- [Elasticsearch Cluster](#elasticsearch-cluster)
  - [Prerequisites](#prerequisites)
  - [Account Setup](#account-setup)
  - [Features](#features)
  - [Improvements](#improvements)

## Prerequisites

1. Download bastion host key: `aws s3 cp s3://mitchell-account-resources/fishtech.pem <destination>`
2. SSH to current test environment: `ssh -i ~/.ssh/fishtech.pem -L 9200:vpc-test-ejhpfuooft37hrei456jtvbrau.us-east-1.es.amazonaws.com:443 ec2-user@18.212.132.144` and connect to [Kibana](https://localhost:9200/_plugin/kibana)

## Account Setup

1. Created `mitchell-terraform-backend` for terraform state
2. Created `fishtech.pem` Key Pair to be referenced and used for Bastion hsots

## Features

1. VPC creation
2. Elasticsearch cluster setup
3. Bastion host to connect and port forward to Kibana
4. Lambda function creation to stream CloudWatch logs to Elasticsearch
5. ECS cluster with [hello world webpage](http://fishtech-948506374.us-east-1.elb.amazonaws.com:8080/) with logs streaming to CloudWatch
6. Prowler running daily at 12:00pm UTC with logs streaming to Elasticsearch
7. CloudTrail logs streaming to Elasticsearch
8. Terraform creation of all components (minus the [account-setup](#account-setup) portion)
9. Github actions used for CI/CD
   - PR for prod deployment and using `test` branch to release test environment

## Improvements

1. Use Direct Connect or VPN to remove Bastion host
   - Bastion host is open to the internet at the moment. This could be reduced to at least the IP's of users logging into server, but for demo purposes it is left open with key referenced in prerequisites.
   - Ideally this could be removed in favor of a VPN connection and reverse proxy with some type of OpenId/SAML login portal to access Kibana and administration
2. Add DynamoDB backend locking to prevent concurrent deployments which could corrupt the backend state
3. Lock down a few more security group rules and IAM permissions. A thorough review of IAM permissions and security group rules to make sure everything is least privileged as there are a few too many open rules (i.e. Lambda function has too many permissions needed)
4. Test environment is currently deployed for reduced costs. The prod environment is available in the `environments/prod` directory which includes multi-AZ deployment with multiple master nodes for resiliency.
5. Export Load Balancer logs to CloudWatch and send to Elasticsearch
6. Export VPC Flow Logs to Elasticsearch

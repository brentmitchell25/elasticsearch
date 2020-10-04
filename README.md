# Elasticsearch Cluster

- [Elasticsearch Cluster](#elasticsearch-cluster)
  - [Prerequisites](#prerequisites)
  - [Account Setup](#account-setup)
  - [Features](#features)
  - [Improvements](#improvements)

## Prerequisites

1. Download bastion host key: `aws s3 cp s3://mitchell-account-resources/fishtech.pem <destination>

## Account Setup

1. Created `mitchell-terraform-backend` for terraform state
2. Created `fishtech.pem` Key Pair to be referenced and used for Bastion hsots

## Features

1. VPC creation
2. Elasticsearch cluster setup
3. Bastion host to connect and port forward to Kibana
4. ECS cluster with [hello world webpage](http://fishtech-948506374.us-east-1.elb.amazonaws.com:8080/)
5. Lambda function creation to stream CloudWatch logs to Elasticsearch
6. Prowler running daily at 12:00pm UTC with logs streaming to Elasticsearch
7. Cloudtrail logs streaming to Elasticsearch
8. Terraform creation of all components
9. Github actions used for CI/CD
      - PR for prod deployment and using `test` branch to release test environment

## Improvements

1. Use Direct Connect or VPN to remove Bastion host
     - Bastion host is open to the internet at the moment. This could be reduced to at least the IP's of users logging into server, but for demo purposes it is left open with key referenced in prerequisites.
     - Ideally this could be removed in favor of a VPN connect and reverse proxy with some type of OpenId/SAML login portal to access Kibana and administration


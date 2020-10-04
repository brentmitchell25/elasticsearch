terraform {
  backend "s3" {
    region = "us-east-1"
    bucket = "mitchell-terraform-backend"
    key    = "test/elasticsearch/terraform.tfstate"
  }
}

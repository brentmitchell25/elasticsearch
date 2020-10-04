resource "aws_security_group" "bastion_ssh" {
  name        = "allow_ssh"
  description = "Allow SSH inbound traffic"
  vpc_id      = var.vpc_id

  ingress {
    description = "SSH to VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    env = var.environment
    app = var.application
  }
}

module "bastion" {
  source          = "cloudposse/ec2-bastion-server/aws"
  name            = "fishtech-bastion"
  namespace       = "bastion"
  ssh_user        = var.ssh_user
  stage           = var.environment
  subnets         = var.subnets
  vpc_id          = var.vpc_id
  key_name        = var.key_name
  ami             = var.ami
  security_groups = [aws_security_group.bastion_ssh.id]
  tags = {
    env = var.environment
    app = var.application
  }
}

resource "aws_ecs_cluster" "cluster" {
  name = "${var.application}-${var.environment}"

  tags = {
    app = var.application
    env = var.environment
  }
}


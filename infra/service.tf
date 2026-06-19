# The persistent governance service (E6.7) as a long-running managed container task.
# This is the ECS Fargate footprint for deployers who run the standing service
# outside Kubernetes; the deploy/ Helm chart is the equivalent for a cluster. The
# task pulls the service role image, reads the runtime secret, and serves the API,
# the product UI, /metrics, and the approval screen on port 8000.
resource "aws_ecs_cluster" "main" {
  name = "${var.name_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name        = "${var.name_prefix}-cluster"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_log_group" "service" {
  name              = "/ecs/${var.name_prefix}-service"
  retention_in_days = 90

  tags = {
    Environment = var.environment
    Component   = "service"
  }
}

# The image reference and the execution role arn are deployment-specific (the
# registry the role images are pushed to, and the IAM role with KMS sign and
# Secrets Manager read). They are inputs a deployer supplies; the task definition
# wires them declaratively.
variable "service_image" {
  description = "Fully-qualified service role image reference (registry/deadline-room-service:tag)."
  type        = string
  default     = ""
}

variable "execution_role_arn" {
  description = "IAM role arn the ECS task assumes (KMS sign + Secrets Manager read + log write). Created by the deployer's IAM module."
  type        = string
  default     = ""
}

resource "aws_ecs_task_definition" "service" {
  family                   = "${var.name_prefix}-service"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.execution_role_arn

  container_definitions = jsonencode([
    {
      name      = "service"
      image     = var.service_image
      essential = true
      command   = ["python", "-m", "uvicorn", "web.app_server:app", "--host", "0.0.0.0", "--port", "8000"]
      portMappings = [
        {
          containerPort = 8000
          protocol      = "tcp"
        }
      ]
      environment = [
        { name = "DEADLINE_ROOM_DATA_DIR", value = "/data/corpus" }
      ]
      secrets = [
        { name = "BAND_API_KEY", valueFrom = "${aws_secretsmanager_secret.runtime.arn}:BAND_API_KEY::" },
        { name = "FEATHERLESS_API_KEY", valueFrom = "${aws_secretsmanager_secret.runtime.arn}:FEATHERLESS_API_KEY::" },
        { name = "DEADLINE_ROOM_KMS_KEY_ARN", valueFrom = "${aws_secretsmanager_secret.runtime.arn}:DEADLINE_ROOM_KMS_KEY_ARN::" }
      ]
      healthCheck = {
        command     = ["CMD-SHELL", "python -c \"import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/healthz').status==200 else 1)\""]
        interval    = 15
        timeout     = 5
        retries     = 3
        startPeriod = 10
      }
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.service.name
          "awslogs-region"        = var.region
          "awslogs-stream-prefix" = "service"
        }
      }
    }
  ])

  tags = {
    Environment = var.environment
    Component   = "service"
  }
}

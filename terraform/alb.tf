# ===== APPLICATION LOAD BALANCER =====

resource "aws_lb" "main" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  enable_deletion_protection       = false
  enable_http2                     = true
  enable_cross_zone_load_balancing = true

  tags = {
    Name = "${var.project_name}-alb"
  }
}

# ===== TARGET GROUPS =====

# APISIX Gateway Target Group (HTTP)
resource "aws_lb_target_group" "apisix_http" {
  name        = "${var.project_name}-apisix-http-tg"
  port        = 9080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "instance"
  deregistration_delay = 120

  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/apisix/status"
    matcher             = "200"
    port                = "9080"
  }

  tags = {
    Name = "${var.project_name}-apisix-http-tg"
  }
}

# APISIX Gateway Target Group (HTTPS)
# resource "aws_lb_target_group" "apisix_https" {
#   name        = "${var.project_name}-apisix-https-tg"
#   port        = 9443
#   protocol    = "HTTPS"
#   vpc_id      = aws_vpc.main.id
#   target_type = "instance"
#   deregistration_delay = 120

#   health_check {
#     healthy_threshold   = 2
#     unhealthy_threshold = 3
#     timeout             = 5
#     interval            = 30
#     path                = "/apisix/status"
#     matcher             = "200"
#     port                = "9080"
#     protocol            = "HTTP"
#   }

#   tags = {
#     Name = "${var.project_name}-apisix-https-tg"
#   }
# }

# ===== ALB LISTENERS =====

# HTTP Listener (port 80 -> APISIX 9080)
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.apisix_http.arn
  }
}

# # HTTPS Listener (port 443 -> APISIX 9443)
# resource "aws_lb_listener" "https" {
#   load_balancer_arn = aws_lb.main.arn
#   port              = 443
#   protocol          = "HTTPS"
#   certificate_arn   = aws_acm_certificate.main.arn
#   ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"

#   default_action {
#     type             = "forward"
#     target_group_arn = aws_lb_target_group.apisix_https.arn
#   }
# }

# # ===== FETCH CERTIFICATES FROM SECRETS MANAGER =====

# data "aws_secretsmanager_secret_version" "gateway_cert" {
#   secret_id = aws_secretsmanager_secret.gateway_cert.id
# }

# data "aws_secretsmanager_secret_version" "gateway_key" {
#   secret_id = aws_secretsmanager_secret.gateway_key.id
# }

# data "aws_secretsmanager_secret_version" "ca_cert" {
#   secret_id = aws_secretsmanager_secret.ca_cert.id
# }

# # ===== ACM CERTIFICATE =====

# resource "aws_acm_certificate" "main" {
#   private_key      = data.aws_secretsmanager_secret_version.gateway_key.secret_string
#   certificate_body = data.aws_secretsmanager_secret_version.gateway_cert.secret_string
#   certificate_chain = data.aws_secretsmanager_secret_version.ca_cert.secret_string

#   tags = {
#     Name = "${var.project_name}-alb-cert"
#   }

#   lifecycle {
#     create_before_destroy = true
#   }

#   depends_on = [
#     aws_secretsmanager_secret_version.gateway_cert,
#     aws_secretsmanager_secret_version.gateway_key,
#     aws_secretsmanager_secret_version.ca_cert
#   ]
# }

data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_launch_template" "apisix" {
  name_prefix   = "${var.project_name}-apisix-"
  image_id      = data.aws_ami.amazon_linux_2.id
  instance_type = var.apisix_instance_type
  key_name = aws_key_pair.main.key_name

  vpc_security_group_ids = [aws_security_group.apisix.id]
  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_profile.name
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.project_name}-apisix"
    }
  }

  user_data = base64encode(templatefile("${path.module}/user_data/apisix.sh", {
    aws_region                = var.aws_region
    project_name              = var.project_name
    rds_endpoint              = aws_db_instance.keycloak.address
    rds_port                  = aws_db_instance.keycloak.port
    rds_db_name               = var.rds_db_name
    rds_username              = var.rds_username
    keycloak_private_ip       = aws_instance.keycloak.private_ip
    extension_app_private_ip  = aws_instance.extension_app.private_ip
    crm_app_private_ip        = aws_instance.crm_app.private_ip
    apisix_admin_key          = var.apisix_admin_key
    alb_dns_name              = aws_lb.main.dns_name
  }))

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    aws_instance.extension_app,
    aws_instance.crm_app,
    aws_instance.keycloak,
    aws_db_instance.keycloak
  ]
}

# ===== AUTO SCALING GROUP FOR APISIX =====

resource "aws_autoscaling_group" "apisix" {
  name_prefix               = "${var.project_name}-apisix-asg-"
  vpc_zone_identifier       = aws_subnet.private[*].id
  target_group_arns         = [
    aws_lb_target_group.apisix_http.arn, 
    # aws_lb_target_group.apisix_https.arn
  ]
  health_check_type         = "ELB"
  health_check_grace_period = 300

  min_size         = var.apisix_min_count
  max_size         = var.apisix_max_count
  desired_capacity = var.apisix_desired_count

  launch_template {
    id      = aws_launch_template.apisix.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${var.project_name}-apisix"
    propagate_at_launch = true
  }

  tag {
    key                 = "Component"
    value               = "apisix"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ===== SCALING POLICIES =====

# Scale up policy
resource "aws_autoscaling_policy" "apisix_scale_up" {
  name                   = "${var.project_name}-apisix-scale-up"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.apisix.name
  cooldown               = 300
}

# Scale down policy
resource "aws_autoscaling_policy" "apisix_scale_down" {
  name                   = "${var.project_name}-apisix-scale-down"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.apisix.name
  cooldown               = 300
}

# CloudWatch Alarms for Auto Scaling
resource "aws_cloudwatch_metric_alarm" "apisix_cpu_high" {
  alarm_name          = "${var.project_name}-apisix-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 70
  alarm_description   = "This alarm monitors APISIX CPU utilization"
  alarm_actions       = [aws_autoscaling_policy.apisix_scale_up.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.apisix.name
  }
}

resource "aws_cloudwatch_metric_alarm" "apisix_cpu_low" {
  alarm_name          = "${var.project_name}-apisix-cpu-low"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 20
  alarm_description   = "This alarm monitors APISIX CPU utilization"
  alarm_actions       = [aws_autoscaling_policy.apisix_scale_down.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.apisix.name
  }
}

# ===== EC2 INSTANCES =====

# Extension App
resource "aws_instance" "extension_app" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = var.services_instance_type
  vpc_security_group_ids      = [aws_security_group.services.id]
  subnet_id                   = aws_subnet.private[0].id
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  associate_public_ip_address = false
  key_name = aws_key_pair.main.key_name

  user_data = base64encode(templatefile("${path.module}/user_data/extension_app.sh", {
    aws_region           = var.aws_region
    project_name         = var.project_name
    crm_app_private_ip   = aws_instance.crm_app.private_ip
  }))

  tags = {
    Name = "${var.project_name}-extension-app"
  }

  depends_on = [aws_db_instance.keycloak]
}

# CRM App
resource "aws_instance" "crm_app" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = var.services_instance_type
  vpc_security_group_ids      = [aws_security_group.services.id]
  subnet_id                   = aws_subnet.private[1].id
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  associate_public_ip_address = false
  key_name = aws_key_pair.main.key_name

  user_data = base64encode(templatefile("${path.module}/user_data/crm_app.sh", {
    aws_region   = var.aws_region
    project_name = var.project_name
  }))

  tags = {
    Name = "${var.project_name}-crm-app"
  }

  depends_on = [aws_db_instance.keycloak]
}

# Keycloak Instance
resource "aws_instance" "keycloak" {
  ami                         = data.aws_ami.amazon_linux_2.id
  instance_type               = var.services_instance_type
  vpc_security_group_ids      = [aws_security_group.services.id]
  subnet_id                   = aws_subnet.private[0].id
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  associate_public_ip_address = false
  key_name = aws_key_pair.main.key_name

  user_data = base64encode(templatefile("${path.module}/user_data/keycloak.sh", {
    aws_region              = var.aws_region
    project_name            = var.project_name
    rds_endpoint            = aws_db_instance.keycloak.address
    rds_port                = aws_db_instance.keycloak.port
    rds_db_name             = var.rds_db_name
    rds_username            = var.rds_username
    rds_password            = var.rds_password
    keycloak_admin_username = var.keycloak_admin_username
    keycloak_admin_password = var.keycloak_admin_password
    alb_dns_name            = aws_lb.main.dns_name
  }))

  tags = {
    Name = "${var.project_name}-keycloak"
  }

  depends_on = [aws_db_instance.keycloak]
}


# ===== EC2 KEY PAIR =====

resource "tls_private_key" "main" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "main" {
  key_name   = "${var.project_name}-keypair"
  public_key = tls_private_key.main.public_key_openssh
}

resource "local_file" "private_key" {
  filename          = "${path.module}/../${var.project_name}-key.pem"
  content           = tls_private_key.main.private_key_pem
  file_permission   = "0600"
  directory_permission = "0700"
}

resource "aws_secretsmanager_secret" "ssh_private_key" {
  name                    = "${var.project_name}/ssh/private-key"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "ssh_private_key" {
  secret_id      = aws_secretsmanager_secret.ssh_private_key.id
  secret_string  = tls_private_key.main.private_key_pem
}

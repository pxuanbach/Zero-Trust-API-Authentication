# ===== RDS PostgreSQL for Keycloak =====

resource "aws_db_parameter_group" "keycloak" {
  family      = "postgres15"
  name        = lower("${var.project_name}-keycloak-pg-params")
  description = "Parameter group for Keycloak PostgreSQL"

  parameter {
    name  = "log_statement"
    value = "all"
  }

  tags = {
    Name = "${var.project_name}-keycloak-pg-params"
  }
}

resource "aws_db_instance" "keycloak" {
  identifier        = lower("${var.project_name}-keycloak-db")
  engine            = "postgres"
  engine_version    = "15.14"
  instance_class    = var.rds_instance_class
  allocated_storage = var.rds_allocated_storage
  storage_type      = "gp2" 
  storage_encrypted = false
  multi_az          = false

  db_name  = var.rds_db_name
  username = var.rds_username
  password = var.rds_password

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  parameter_group_name   = aws_db_parameter_group.keycloak.name

  backup_retention_period = 1
  backup_window           = "03:00-04:00"
  maintenance_window      = "mon:04:00-mon:05:00"
  
  skip_final_snapshot       = true

  publicly_accessible   = false
  copy_tags_to_snapshot = true

  tags = {
    Name = "${var.project_name}-keycloak-db"
  }

  depends_on = [aws_db_subnet_group.main]
}

# Provider configuration
provider "aws" {
  region = var.aws_region
}

# Fetch the AWS account ID of the current user
data "aws_caller_identity" "current" {}

# Define a custom DB parameter group for DB2
resource "aws_db_parameter_group" "db2_param_group" {
  name   = "rds-db2-terraform-parametergroup"
  family = var.family

  # Set specific parameters for the DB2 instance
  parameter {
    apply_method = "immediate"
    name         = "rds.ibm_customer_id"
    value        = var.ibm_customer_id
  }
  parameter {
    apply_method = "immediate"
    name         = "rds.ibm_site_id"
    value        = var.ibm_site_id
  }
  parameter {
    apply_method = "pending-reboot"
    name         = "db2comm"
    value        = "TCPIP,SSL"
  }
  parameter {
    apply_method = "pending-reboot"
    name         = "ssl_svcename"
    value        = var.ssl_port
  }
  tags = var.tags
}

# Define the Db2 option group
resource "aws_db_option_group" "Db2_option_group" {
  name                     = "rds-db2-terraform-option-group"
  engine_name              = var.db_engine
  major_engine_version     = var.major_engine_version
  option_group_description = "Option group for Db2 RDS databases"
  tags = {
    Name = "Db2 RDS database option group"
  }
}

# Create a security group 
resource "aws_security_group" "db2_sg" {
  name_prefix = "rds-db2-terraform-sg-" # Prefix for the security group name
  description = "Security group for DB2 RDS instance"
  vpc_id      = var.vpc_id # VPC ID where the security group is created

  # Inbound rule allowing TCP connections on port 50400 from within the VPC
  ingress {
    description = "TCP from VPC"
    from_port   = 50400
    to_port     = 50400
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  
  # Inbound rule allowing TLS connections on port 50409 from within the VPC
   ingress {
    description = "TLS from VPC"
    from_port   = 50409
    to_port     = 50409
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
  
  # Outbound rule allowing all traffic to any destination
  egress {
    description = "Allowing all outbound connections"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.tags
}

# Define the database subnet group
resource "aws_db_subnet_group" "db2_subnet_group" {
  name       = "rds-db2-terraform-database-subnet-group"
  subnet_ids = var.subnet_ids # List of subnet IDs for the DB instance

  tags = {
    Name = "RDS Db2 Database Subnet Group"
  }
}

# Create a KMS key for encrypting storage and master user's password on the RDS instance
resource "aws_kms_key" "key_rds_db2" {
  description             = "RDS Db2 Terraform KMS Key"
  key_usage               = "ENCRYPT_DECRYPT" # Symmetric Encryption KMS Key
  enable_key_rotation     = true # Automatic key rotation
  rotation_period_in_days = 180
  deletion_window_in_days = 30 # Window in days before key deletion
  tags                    = var.tags
}

resource "aws_kms_alias" "rds_db2_kms_key_alias" {
  name          = "alias/rds-db2-terraform-kms-key"
  target_key_id = aws_kms_key.key_rds_db2.key_id
}

# # Define the KMS key policy for the RDS KMS key and grant permissions to user
resource "aws_kms_key_policy" "key_rds_db2_policy" {
  key_id = aws_kms_key.key_rds_db2.id
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "key-default-1"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })
}

# # Define the KMS key policy for the RDS KMS key and grant permissions to user
# resource "aws_kms_key_policy" "key_rds_db2_policy" {
#   key_id = aws_kms_key.key_rds_db2.id
#   policy = jsonencode({
#     Version = "2012-10-17"
#     Id      = "key-default-1"
#     Statement = [
#       {
#         Sid    = "Give all permissions on key to root account"
#         Effect = "Allow"
#         Principal = {
#           AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
#         },
#         Action   = "kms:*"
#         Resource = aws_kms_key.key_rds_db2.arn
#       },
#       {
#         Sid    = "Allow use of the key"
#         Effect = "Allow"
#         Principal = {
#           AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:${data.aws_caller_identity.current.user_id}"
#         },
#         Action   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey", "kms:GenerateDataKeyWithoutPlaintext"]
#         Resource = aws_kms_key.key_rds_db2.arn
#       }
#     ]
#   })
# }

# Define the AWS RDS DB instance resource
resource "aws_db_instance" "rdsdb2" {
  identifier             = var.identifier  # Name of the RDS instance
  engine                 = var.db_engine      # Database engine, e.g., "db2-se, db2-ae"
  engine_version         = var.db_engine_version # Version of the DB engine
  instance_class         = var.instance_class # Instance type
  license_model          = var.license_model  # License model, e.g., "license-included, marketplace-license"
  multi_az               = var.multi_az       # Whether to deploy in multiple AZs for HA

  storage_type           = var.storage_type   # Storage type, e.g., "gp3, io1, io2"
  allocated_storage      = var.allocated_storage # Allocated storage in GB
  max_allocated_storage  = var.max_allocated_storage # Maximum storage in GB
  storage_encrypted      = true               # Encrypt the storage
  iops                   = var.iops           # IOPS for storage (required for some types like gp3)
  kms_key_id             = aws_kms_key.key_rds_db2.arn # KMS key for encryption

  db_name                = var.db_name        # Name of the initial database
  port                   = var.tcp_port       # Port number to access the DB
  timezone               = var.time_zone      # Local timezone for the DB instance, default is UTC

  auto_minor_version_upgrade = true          # Disable automatic minor version upgrades
  allow_major_version_upgrade = false         # Disable major version upgrades

  username               = var.db_username    # Master username
  publicly_accessible    = false              # Disable public accessibility

  vpc_security_group_ids = [aws_security_group.db2_sg.id] # Security group for DB instance
  db_subnet_group_name   = aws_db_subnet_group.db2_subnet_group.name # Subnet group for the DB instance

  ca_cert_identifier     = "rds-ca-rsa2048-g1" # CA certificate identifier for RDS

  iam_database_authentication_enabled = false # IAM authentication not supported

  # Use AWS Secrets Manager to manage the master user password
  manage_master_user_password  = true
  master_user_secret_kms_key_id = aws_kms_key.key_rds_db2.arn # KMS key for the Secrets Manager

  # Backup configuration
  backup_retention_period = var.backup_retention  # Days to retain backups
  backup_window           = var.backup_window # Backup window in UTC
  copy_tags_to_snapshot   = true  # Copy tags to snapshots
  skip_final_snapshot     = var.skip_final_snapshot  # Skip final snapshot on deletion
  final_snapshot_identifier = "Db2-RDS-${var.identifier}-final-snaphot" # Identifier for final snapshot
  delete_automated_backups = var.delete_automated_backups # Retain automated backups on deletion

  # Monitoring and logging configuration
  #performance_insights_enabled = false # Disable Performance Insights, not available
  monitoring_interval = var.enhanced_monitoring_enabled ? 60 : 0 # Enhanced monitoring interval in seconds
  monitoring_role_arn = var.enhanced_monitoring_enabled && length(aws_iam_role.rds_monitoring_role) > 0 ? aws_iam_role.rds_monitoring_role[0].arn : null # IAM role for monitoring

  enabled_cloudwatch_logs_exports = ["diag.log","notify.log"] # Enable CloudWatch logs for diag and notify logs

  # Parameter group and option group configuration
  parameter_group_name      = aws_db_parameter_group.db2_param_group.name # Parameter group name
  option_group_name         = aws_db_option_group.Db2_option_group.name # Option group name

  deletion_protection       = var.deletion_protection  # Enable deletion protection
  maintenance_window        = var.maintenance_window # Preferred maintenance window in UTC
  apply_immediately         = true  # Apply changes immediately
  tags                      = var.tags # Apply tags
}

# IAM Policy document for access for your S3 bucket
data "aws_iam_policy_document" "rds_db2_s3_access_policy_doc" {
  statement {
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
      "s3:PutObject",
      "s3:GetObject",
      "s3:AbortMultipartUpload",
      "s3:ListBucket",
      "s3:DeleteObject",
      "s3:GetObjectVersion",
      "s3:ListMultipartUploadParts"
    ]
    resources = [
      "arn:aws:s3:::${var.s3_bucket_name}/*",
      "arn:aws:s3:::${var.s3_bucket_name}"
    ]
  }
}

# Assume role policy document for RDS
data "aws_iam_policy_document" "rds_db2_s3_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["rds.amazonaws.com"]
    }
  }
}

# Define a IAM policy and attach policy document for S3 access
resource "aws_iam_policy" "rds_db2_s3_access_policy" {
  name   = "rds-db2-s3-access-policy"
  policy = data.aws_iam_policy_document.rds_db2_s3_access_policy_doc.json
}

# Create an IAM role and allow RDS to assume the role
resource "aws_iam_role" "rds_db2_s3_access_role" {
  name               = "rds-db2-s3-access-role"
  assume_role_policy = data.aws_iam_policy_document.rds_db2_s3_assume_role_policy.json
}

# Attach the IAM policy to the IAM role
resource "aws_iam_role_policy_attachment" "rds_s3_policy_attachment" {
  policy_arn = aws_iam_policy.rds_db2_s3_access_policy.arn
  role       = aws_iam_role.rds_db2_s3_access_role.name
}

# Associate the IAM role with the RDS instance for S3 integration
resource "aws_db_instance_role_association" "example" {
  db_instance_identifier = aws_db_instance.rdsdb2.identifier
  feature_name           = "S3_INTEGRATION"
  role_arn               = aws_iam_role.rds_db2_s3_access_role.arn
}

# Assume role policy document 
data "aws_iam_policy_document" "rds_monitoring_role_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["monitoring.rds.amazonaws.com"]
    }
  }
}

# Creata an IAM Role and allow RDS Monitoring to assume the role
# We use an exisitng policy AmazonRDSEnhancedMonitoringRole
resource "aws_iam_role" "rds_monitoring_role" {
  count = var.enhanced_monitoring_enabled ? 1 : 0
  name               = "${var.db_name}-terraform-monitoring-role"
  assume_role_policy = data.aws_iam_policy_document.rds_monitoring_role_assume_role_policy.json
  managed_policy_arns = [
    "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
  ]
}

# Create a SNS Topic
resource "aws_sns_topic" "rds_db2_sns_topic" {
  name              = "rds-db2-terraform-sns-topic"
  kms_master_key_id = aws_kms_key.key_rds_db2.arn
}

# Associate an email id to the topic on which alerts will be recieved
resource "aws_sns_topic_subscription" "rds_db2_topic_subscription" {
  topic_arn = aws_sns_topic.rds_db2_sns_topic.arn
  protocol  = "email"
  endpoint  = var.alert_email_address
}

# RDS Event subscription for database events 
resource "aws_db_event_subscription" "rds_events_subscription" {
  depends_on = [aws_db_instance.rdsdb2]
  name      = "rds-db2-terraform-events-subscription"
  sns_topic = aws_sns_topic.rds_db2_sns_topic.arn

  source_type = "db-instance"
  source_ids  = [aws_db_instance.rdsdb2.identifier]

  event_categories = [
    "availability",
    "deletion",
    "failover",
    "failure",
    "low storage",
    "maintenance",
    "notification",
    "recovery",
    "configuration change",
    "security patching"
  ]
  enabled = true
}

# RDS Event subscription for parameter group configuration changes
resource "aws_db_event_subscription" "rds_events_subscription_parameters" {
  name      = "rds-db2-terraform-parameters-events-subscription"
  sns_topic = aws_sns_topic.rds_db2_sns_topic.arn

  source_type = "db-parameter-group"
  source_ids  = [aws_db_parameter_group.db2_param_group.id]

  event_categories = [
    "configuration change"
  ]
  enabled = true
}

# CloudWatch alarm for high CPU usage
resource "aws_cloudwatch_metric_alarm" "rds_db2_high_cpu" {
  alarm_name                = "rds-db2-terraform-high-cpu-alarm"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "3"
  metric_name               = "CPUUtilization"
  namespace                 = "AWS/RDS"
  period                    = "300"
  statistic                 = "Average"
  threshold                 = "90"
  alarm_description         = "RDS CPU usage is above 90% for 15 minutes"
  alarm_actions             = [aws_sns_topic.rds_db2_sns_topic.arn]
  ok_actions                = [aws_sns_topic.rds_db2_sns_topic.arn]
  treat_missing_data        = "breaching"
  dimensions = {
    DBInstanceIdentifier = aws_db_instance.rdsdb2.identifier
  }
}

# Setting up a filter to capture 'Level: Severe' messages in diaglog
resource "aws_cloudwatch_log_metric_filter" "rds_db2_severe_log_filter" {
  name           = "rds-db2-terraform-severe-log-filter"
  pattern        = "\"LEVEL: Severe\""
  log_group_name = "/aws/rds/instance/${aws_db_instance.rdsdb2.identifier}/diag.log"

  metric_transformation {
    name      = "RDS-DB2-Severe-Log-Count"
    namespace = aws_db_instance.rdsdb2.identifier
    value     = "1"
  }
}

# Setting up CloudWatch Alarm for 'Level: Severe' messages in diaglog
resource "aws_cloudwatch_metric_alarm" "rds_db2_severe_log_alarm" {
  alarm_name                = "rds-db2-terraform-severe-log-alarm"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "RDS-DB2-Severe-Log-Count"
  namespace                 =  aws_db_instance.rdsdb2.identifier
  period                    = "60"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Severe message found in diaglog"
  alarm_actions             = [aws_sns_topic.rds_db2_sns_topic.arn]
  ok_actions                = [aws_sns_topic.rds_db2_sns_topic.arn]
  treat_missing_data        = "notBreaching"
}

# # Outputs to display key information after deployment
# output "db_instance_endpoint" {
#   description = "The connection endpoint"
#   value       = try(aws_db_instance.rdsdb2.endpoint, null)
# }

# output "db_instance_master_user_secret_arn" {
#   description = "The ARN of the master user secret"
#   value       = try(aws_db_instance.rdsdb2.master_user_secret[0].secret_arn, null)
# }


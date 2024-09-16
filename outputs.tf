output "rds_endpoint" {
  value = aws_db_instance.rdsdb2.endpoint
}

output "rds_port" {
  value = aws_db_instance.rdsdb2.port
}

output "rds_id" {
  value = aws_db_instance.rdsdb2.id
}

output "rds_instance_class" {
  value = aws_db_instance.rdsdb2.instance_class
}

output "rds_engine" {
  value = aws_db_instance.rdsdb2.engine
}

output "rds_username" {
  value = aws_db_instance.rdsdb2.username
}

output "rds_db_name" {
  value = aws_db_instance.rdsdb2.db_name
}

output "rds_allocated_storage" {
  value = aws_db_instance.rdsdb2.allocated_storage
}

output "rds_storage_type" {
  value = aws_db_instance.rdsdb2.storage_type
}

output "rds_engine_version" {
  value = aws_db_instance.rdsdb2.engine_version
}

output "rds_deletion_protection" {
  value = aws_db_instance.rdsdb2.deletion_protection
}

output "rds_multi_az" {
  value = aws_db_instance.rdsdb2.multi_az
}

output "rds_backup_retention_period" {
  value = aws_db_instance.rdsdb2.backup_retention_period
}

output "rds_backup_window" {
  value = aws_db_instance.rdsdb2.backup_window
}

output "rds_maintenance_window" {
  value = aws_db_instance.rdsdb2.maintenance_window
}

output "rds_parameter_group_name" {
  value = aws_db_instance.rdsdb2.parameter_group_name
}

output "rds_option_group_name" {
  value = aws_db_instance.rdsdb2.option_group_name
}

output "rds_subnet_group_name" {
  value = aws_db_instance.rdsdb2.db_subnet_group_name
}

output "rds_security_group_ids" {
  value = aws_db_instance.rdsdb2.vpc_security_group_ids
}

output "rds_kms_key_id" {
  value = aws_db_instance.rdsdb2.kms_key_id
}
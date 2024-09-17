variable "identifier" {
  description = "The unique name of RDS DB2 Instance"
  type        = string
}

variable "aws_region" {
  description = "The AWS region to deploy to"
  type        = string
}

variable "instance_class" {
  description = "The instance type of the RDS instance"
  type        = string
}

variable "db_name" {
  description = "Database Name"
  type        = string
}

variable "time_zone" {
  description = "Timezone for the database"
  type        = string
}

variable "storage_type" {
  description = "One of 'standard' (magnetic), 'gp2' (general purpose SSD), or 'io1' (provisioned IOPS SSD)"
  type        = string
}

variable "allocated_storage" {
  description = "The allocated storage (in gigabytes)"
  type        = number
}

variable "max_allocated_storage" {
  description = "The maximum size DB can grow (in gigabytes)"
  type        = number
}

variable "iops" {
  description = "Storage IOPS to be allocated"
  type        = number
}

variable "db_username" {
  description = "Username for the master DB user"
  type        = string
}

variable "subnet_ids" {
  description = "A list of VPC subnet IDs"
  type        = list(string)
}

variable "vpc_id" {
  description = "The ID of the VPC where the DB will be created"
  type        = string
}

variable "vpc_cidr" {
  description = "The CIDR block of the VPC"
  type        = string
}

variable "multi_az" {
  description = "Specifies if the RDS instance is multi-AZ"
  type        = bool
}

variable "db_engine" {
  description = "Specifies the DB engine e.g. db2-ae, db2-se"
  type        = string
}

variable "db_engine_version" {
  description = "Specifies the version of the db engine"
  type        = string
}

variable "major_engine_version" {
  description = "Specifies the version of the db engine"
  type        = string
}

variable "family" {
  description = "Specifies the family; used to select db parameter group"
  type        = string
}

variable "license_model" {
  description = "Specifies the licencing model"
  type        = string
  validation {
    condition     = contains(["marketplace-license", "bring-your-own-license"], var.license_model)
    error_message = "Invalid value for license_model, valid values are: marketplace-license, bring-your-own-license"
  }  
}

variable "tcp_port" {
  description = "Specifies the TCP IP port on database will listen"
  type        = number
}

variable "ssl_port" {
  description = "Specifies the TLS SSL port on database will listen"
  type        = number
}

variable "ibm_customer_id" {
  description = "Specifies the customer id, to be used for BYOL"
  type        = string
}

variable "ibm_site_id" {
  description = "Specifies the site id, to be used for BYOL"
  type        = string
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
}

# Condition to check if enhanced monitoring is enabled
variable "enhanced_monitoring_enabled" {
  type    = bool
  default = false
}

variable "s3_bucket_name" {
  description = "Specifies the bucket name for backup or data files"
  type        = string
}

variable "alert_email_address" {
  description = "Specifies the email id to which alerts will be sent"
  type        = string
}

variable "maintenance_window" {
  description = "Specifies the weekly maintenance window in UTC"
  type        = string
}

variable "backup_window" {
  description = "Specifies the daily backup windows in UTC"
  type        = string
}

variable "backup_retention" {
  description = "Specifies the days to retain backups between 7 and 31"
  type        = number
}

variable "delete_automated_backups" {
  description = "Retain automated backups on deletion"
  type        = bool
}

variable "deletion_protection" {
  description = "Enable deletion protection"
  type        = bool
}

variable "skip_final_snapshot" {
  description = "Skip final snapshot on deletion"
  type        = bool
}
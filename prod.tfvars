identifier              = "rds-db2-terraform-prod"
aws_region              = "us-east-2"
instance_class          = "db.r6i.xlarge"
allocated_storage       = 400
storage_type            = "io2"
db_name                 = "RDSDB2"
db_engine               = "db2-se"
db_engine_version       = "11.5"
major_engine_version    = "11.5"
family                  = "db2-se-11.5"
license_model           = "bring-your-own-license"
time_zone               = "US/Eastern"
max_allocated_storage   = 1000
iops                    = 15000
tcp_port                = 50400
ssl_port                = 50409
ibm_customer_id         = "0000000"
ibm_site_id             = "0000000"
db_username             = "db2inst1"
subnet_ids              = ["subnet-XXXXX", "subnet-XXXX"]
vpc_id                  = "vpc-XXXXXXX"
vpc_cidr                = "172.31.0.0/16"
multi_az                = true
enhanced_monitoring_enabled = true
s3_bucket_name          = "example-rds-db2-s3-access"
alert_email_address     = "abc@example.com"
maintenance_window      = "Tue:04:00-Tue:04:30"
backup_window           = "19:00-23:00"
backup_retention        = 15

tags = {
  Environment = "Production"
  Project     = "DB2Deployment"
}

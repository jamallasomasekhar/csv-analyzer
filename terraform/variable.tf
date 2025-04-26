variable "frontend_bucket_name" {
  description = "Name of the S3 bucket for frontend static files"
  type        = string
  default     = "csv-analyzer-frontend-files"
}

variable "ec2_instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t2.micro"
}

variable "ec2_ami" {
  description = "Amazon Machine Image ID for EC2"
  type        = string
  default     = "ami-0c101f26f147fa7fd"  # Amazon Linux 2023 in us-east-1
}

variable "key_name" {
  description = "Name of the key pair for SSH access"
  type        = string
}

variable "ssh_allowed_ip" {
  description = "IP address allowed for SSH access"
  type        = string
  default     = "0.0.0.0"  # Note: In production, restrict this to your own IP
}

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
  
}
variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "csv-analyzer"
  
}
variable "private_key_path" {
  description = "Path to the private key for SSH access"
  type        = string
  default     = "/Users/somasekharjamalla/Downloads/ssh-key.pem"
  
}
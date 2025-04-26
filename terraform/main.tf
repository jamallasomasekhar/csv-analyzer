provider "aws" {
    region = var.aws_region
}
#creating s3 bucket for frontend hosting
resource "aws_s3_bucket" "frontend_bucket" {
    bucket = var.frontend_bucket_name

    tags = {
      Name = "Static website bucket"
    }
}

# configure bucket for statice 
resource "aws_s3_bucket_website_configuration" "frontend_config" {
  bucket = aws_s3_bucket.frontend_bucket.id
  index_document {
    suffix = "index.html"
  }
  error_document {
    key = "error.html"
  }
}
# Make the bucket public
resource "aws_s3_bucket_public_access_block" "frontend_bucket_public_access" {
  bucket = aws_s3_bucket.frontend_bucket.id

  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
  
}

# Bucket policy to allow public read access
resource "aws_s3_bucket_policy" "frontend_policy" {
  bucket = aws_s3_bucket.frontend_bucket.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.frontend_bucket.arn}/*"
      }
    ]
  })
}
# Upload index.html from local directory to S3
resource "aws_s3_object" "index_html" {
  bucket = aws_s3_bucket.frontend_bucket.id
  key    = "index.html"
  source = "../frontend/index.html"
  content_type = "text/html"
  etag   = "${path.module}/frontend/index.html"
}

# Upload error.html from local directory to S3
resource "aws_s3_object" "error_html" {
  bucket = aws_s3_bucket.frontend_bucket.id
  key    = "error.html"
  source = "../frontend/error.html"
  content_type = "text/html"
  etag   = "${path.module}/frontend/error.html"
}

# VPC for our infrastructure
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  
  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# Create public subnet
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true
  
  tags = {
    Name = "${var.project_name}-public-subnet"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  
  tags = {
    Name = "${var.project_name}-igw"
  }
}

# Route table for public subnet
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
  
  tags = {
    Name = "${var.project_name}-public-route-table"
  }
}

# Associate route table with public subnet
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Security group for EC2 backend server
resource "aws_security_group" "backend_sg" {
  name        = "${var.project_name}-backend-sg"
  description = "Allow HTTP, HTTPS and SSH traffic for backend server"
  vpc_id      = aws_vpc.main.id
  
  # HTTP access
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP"
  }
  
  # HTTPS access
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS"
  }
  
  # SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH"
  }

  # API port access (for backend Python server)
  ingress {
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "API Port"
  }
  
  # Outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }
  
  tags = {
    Name = "${var.project_name}-backend-sg"
  }
}

# IAM role for EC2 instance to access S3
resource "aws_iam_role" "ec2_s3_access_role" {
  name = "${var.project_name}-ec2-s3-access-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
  
  tags = {
    Name = "${var.project_name}-ec2-s3-access-role"
  }
}

# IAM policy for EC2 to access S3
resource "aws_iam_policy" "ec2_s3_access_policy" {
  name        = "${var.project_name}-ec2-s3-access-policy"
  description = "Policy for EC2 to access S3"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Effect   = "Allow"
        Resource = [
          aws_s3_bucket.frontend_bucket.arn,
          "${aws_s3_bucket.frontend_bucket.arn}/*"
        ]
      },
      {
        Action = [
          "s3:ListAllMyBuckets"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# Attach policy to role
resource "aws_iam_role_policy_attachment" "ec2_s3_access_attachment" {
  role       = aws_iam_role.ec2_s3_access_role.name
  policy_arn = aws_iam_policy.ec2_s3_access_policy.arn
}

# Instance profile for EC2
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${var.project_name}-ec2-profile"
  role = aws_iam_role.ec2_s3_access_role.name
}
# Prepare backend app.py file for EC2 instance
data "local_file" "app_py" {
  filename = "../backend/app.py"
}

# EC2 instance for backend server
resource "aws_instance" "backend_server" {
  ami                    = var.ec2_ami
  instance_type          = var.ec2_instance_type
  key_name               = var.key_name
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.backend_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name
  
  user_data = <<-EOF
    #!/bin/bash
    # Update packages
    yum update -y
    
    # Install Python, pip, nginx, and git
    yum install -y python3 python3-pip nginx git
    
    # Upgrade pip
    pip3 install --upgrade pip
    
    # Install required Python packages
    pip3 install flask boto3 pandas gunicorn cors flask-cors
    
    # Create application directory
    mkdir -p /opt/csv-analyzer
    
    # Copy app.py file content to the server
    cat > /opt/csv-analyzer/app.py << 'APPFILE'
    ${data.local_file.app_py.content}
    APPFILE
    
    # Create systemd service file
    cat > /etc/systemd/system/csv-analyzer.service << 'SERVICEFILE'
    [Unit]
    Description=CSV Analyzer Backend Service
    After=network.target

    [Service]
    User=root
    WorkingDirectory=/opt/csv-analyzer
    ExecStart=/usr/local/bin/gunicorn -w 4 -b 0.0.0.0:5000 app:app
    Restart=always

    [Install]
    WantedBy=multi-user.target
    SERVICEFILE
    
    # Configure nginx
    cat > /etc/nginx/conf.d/csv-analyzer.conf << 'NGINXFILE'
    server {
        listen 80;
        server_name _;
        
        location / {
            proxy_pass http://127.0.0.1:5000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
    NGINXFILE
    
    # Remove default nginx config
    rm -f /etc/nginx/conf.d/default.conf
    
    # Enable and start services
    systemctl daemon-reload
    systemctl enable csv-analyzer
    systemctl start csv-analyzer
    systemctl enable nginx
    systemctl start nginx
    
    # Create deployment script for GitHub Actions
    mkdir -p /opt/deployment
    cat > /opt/deployment/update_backend.sh << 'DEPLOYFILE'
    #!/bin/bash
    set -e
    
    echo "Updating backend code..."
    cd /opt/csv-analyzer
    cp /tmp/app.py ./app.py
    
    echo "Restarting services..."
    systemctl restart csv-analyzer
    systemctl restart nginx
    
    echo "Deployment completed successfully!"
    DEPLOYFILE
    
    chmod +x /opt/deployment/update_backend.sh
  EOF
  
  tags = {
    Name = "${var.project_name}-backend-server"
  }
}

# IAM policy for Lambda
resource "aws_iam_policy" "lambda_policy" {
  name        = "${var.project_name}-lambda-policy"
  description = "Policy for Lambda to access S3 and CloudWatch"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:ListAllMyBuckets"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# Attach policy to Lambda role
resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}
resource "aws_iam_role" "lambda_role" {
  name = "lambda-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Principal = {
        Service = "lambda.amazonaws.com"
      },
      Effect = "Allow",
      Sid = ""
    }]
  })
}
# Create Lambda function zip file from code
data "archive_file" "lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lambda_function.zip"
  
  source {
    content = <<-EOF
      import json
      import boto3
      import logging

      # Configure logging
      logger = logging.getLogger()
      logger.setLevel(logging.INFO)

      def lambda_handler(event, context):
          logger.info('Starting S3 bucket analysis')
          
          try:
              # Create S3 client
              s3_client = boto3.client('s3')
              
              # List all buckets
              response = s3_client.list_buckets()
              buckets = [bucket['Name'] for bucket in response['Buckets']]
              logger.info(f'Found {len(buckets)} S3 buckets: {buckets}')
              
              # Get bucket from event or use default
              target_bucket = event.get('bucket_name') if event else None
              
              if not target_bucket and len(buckets) > 0:
                  target_bucket = buckets[0]
                  logger.info(f'No bucket specified, using first bucket: {target_bucket}')
              
              bucket_stats = None
              if target_bucket:
                  # Count objects in the specified bucket
                  paginator = s3_client.get_paginator('list_objects_v2')
                  total_objects = 0
                  total_size = 0
                  
                  for page in paginator.paginate(Bucket=target_bucket):
                      if 'Contents' in page:
                          total_objects += len(page['Contents'])
                          total_size += sum(obj['Size'] for obj in page['Contents'])
                  
                  bucket_stats = {
                      "name": target_bucket,
                      "object_count": total_objects,
                      "total_size_bytes": total_size,
                      "total_size_mb": round(total_size / (1024 * 1024), 2)
                  }
                  
                  logger.info(f'Bucket stats for {target_bucket}: {bucket_stats}')
              
              return {
                  'statusCode': 200,
                  'body': json.dumps({
                      'message': 'S3 analysis completed successfully',
                      'bucket_count': len(buckets),
                      'buckets': buckets,
                      'selected_bucket_stats': bucket_stats
                  })
              }
              
          except Exception as e:
              error_message = str(e)
              logger.error(f'Error analyzing S3 buckets: {error_message}')
              
              return {
                  'statusCode': 500,
                  'body': json.dumps({
                      'message': 'Error analyzing S3 buckets',
                      'error': error_message
                  })
              }
    EOF
    filename = "lambda_function.py"
  }
}

# Create Lambda function
resource "aws_lambda_function" "s3_analyzer" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.project_name}-s3-analyzer"
  role             = aws_iam_role.lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.9"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 30
  
  environment {
    variables = {
      FRONTEND_BUCKET = aws_s3_bucket.frontend_bucket.id
    }
  }
  
  tags = {
    Name = "${var.project_name}-s3-analyzer"
  }
}

# Create CloudWatch event rule to trigger Lambda function periodically (optional)
resource "aws_cloudwatch_event_rule" "lambda_schedule" {
  name                = "${var.project_name}-lambda-schedule"
  description         = "Schedule for S3 analyzer Lambda function"
  schedule_expression = "rate(1 day)"
}

# Set Lambda as target for CloudWatch event
resource "aws_cloudwatch_event_target" "lambda_target" {
  rule      = aws_cloudwatch_event_rule.lambda_schedule.name
  target_id = "LambdaFunction"
  arn       = aws_lambda_function.s3_analyzer.arn
}

# Permission for CloudWatch to invoke Lambda
resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id  = "AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_analyzer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.lambda_schedule.arn
}

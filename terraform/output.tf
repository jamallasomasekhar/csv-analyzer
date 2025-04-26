output "frontend_bucket_name" {
  description = "Name of the frontend S3 bucket"
  value       = aws_s3_bucket.frontend_bucket.id
}

output "frontend_website_endpoint" {
  description = "Website endpoint for the frontend S3 bucket"
  value       = aws_s3_bucket_website_configuration.frontend_config.website_endpoint
}

output "backend_server_public_ip" {
  description = "Public IP address of the backend EC2 instance"
  value       = aws_instance.backend_server.public_ip
}

output "backend_server_public_dns" {
  description = "Public DNS name of the backend EC2 instance"
  value       = aws_instance.backend_server.public_dns
}
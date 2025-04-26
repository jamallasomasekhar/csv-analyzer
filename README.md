# csv-analyzer
# csv-analyzer
# Component Details
1. Frontend (S3)
Static Website Hosting
S3 bucket: csv-analyzer-frontend-files
Public access enabled
Website endpoint: csv-analyzer-frontend-files.s3-website-us-east-1.amazonaws.com
Key Files
index.html: Main application interface
error.html: Error page
2. Backend (EC2)
Web Server
Nginx: Reverse proxy
Gunicorn: WSGI server
Python Flask application
Security
Security Group allowing ports:
80 (HTTP)
443 (HTTPS)
22 (SSH)
5000 (API)
3. AWS Services
Lambda Function
Name: csv-analyzer-s3-analyzer
Runtime: Python 3.9
Triggered daily via CloudWatch Events
Analyzes S3 bucket statistics
4. IAM & Security
EC2 Role: Access to S3 operations
Lambda Role: CloudWatch logs and S3 access
Bucket Policy: Public read access for website hosting
# Data Flow
User Access

User accesses the website via S3 static hosting
Frontend makes API calls to EC2 backend
CSV Processing

User uploads CSV file
Backend processes file and returns analysis
Results displayed in frontend table
S3 Information

User requests S3 bucket information
Backend queries AWS S3 API
Displays bucket statistics and objects
Automated Analysis

CloudWatch triggers Lambda daily
Lambda analyzes S3 buckets
Results stored for reporting


# API Endpoints
POST /analyze

Accepts CSV file and threshold
Returns analysis results
GET /s3info

Lists available S3 buckets
Returns bucket statistics
GET /s3info?bucket={bucket_name}




# Archit
<img width="1440" alt="Screenshot 2025-04-26 at 8 09 30 PM" src="https://github.com/user-attachments/assets/1e3e1861-5842-4bf3-9064-8629f703b499" />

<img width="1440" alt="Screenshot 2025-04-26 at 8 09 35 PM" src="https://github.com/user-attachments/assets/71f3af80-5a95-4878-8b04-cdb7fcebe8d9" />






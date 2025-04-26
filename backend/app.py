from flask import Flask, request, jsonify
import pandas as pd
import os
import boto3
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

@app.route('/analyze', methods=['POST'])
def analyze_csv():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
        
    if not file.filename.endswith('.csv'):
        return jsonify({"error": "File must be CSV format"}), 400
    
    # Get threshold parameter with default of 75
    threshold = float(request.form.get('threshold', 75))
    
    # Save uploaded file temporarily
    temp_path = '/tmp/uploaded_file.csv'
    file.save(temp_path)
    
    try:
        # Read CSV file
        df = pd.read_csv(temp_path)
        
        # Verify CSV has required columns
        required_columns = ['name', 'age', 'grade']
        missing_columns = [col for col in required_columns if col not in df.columns]
        
        if missing_columns:
            return jsonify({
                "error": f"CSV missing required columns: {', '.join(missing_columns)}"
            }), 400
        
        # Convert columns to appropriate types
        df['name'] = df['name'].astype(str)
        df['age'] = pd.to_numeric(df['age'], errors='coerce')
        df['grade'] = pd.to_numeric(df['grade'], errors='coerce')
        
        # Filter students above threshold
        above_threshold = df[df['grade'] > threshold]
        
        # Format results
        results = above_threshold[['name', 'age', 'grade']].to_dict('records')
        
        return jsonify({
            "success": True,
            "threshold": threshold,
            "total_students": len(df),
            "students_above_threshold": len(results),
            "students": results
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        # Clean up temporary file
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.route('/s3info', methods=['GET'])
def get_s3_info():
    try:
        # Create boto3 client
        s3_client = boto3.client('s3')
        
        # List all buckets
        response = s3_client.list_buckets()
        buckets = [bucket['Name'] for bucket in response['Buckets']]
        
        # Get bucket name from query parameter
        bucket_name = request.args.get('bucket')
        bucket_stats = None
        
        if bucket_name:
            # Count objects in specified bucket
            paginator = s3_client.get_paginator('list_objects_v2')
            total_objects = 0
            total_size = 0
            
            for page in paginator.paginate(Bucket=bucket_name):
                if 'Contents' in page:
                    total_objects += len(page['Contents'])
                    total_size += sum(obj['Size'] for obj in page['Contents'])
            
            bucket_stats = {
                "name": bucket_name,
                "object_count": total_objects,
                "total_size_bytes": total_size,
                "total_size_mb": round(total_size / (1024 * 1024), 2)
            }
        
        return jsonify({
            "success": True,
            "bucket_count": len(buckets),
            "buckets": buckets,
            "selected_bucket_stats": bucket_stats
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
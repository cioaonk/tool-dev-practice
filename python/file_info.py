#!/usr/bin/env python3
import sys
import hashlib
import base64
import json
import os
import subprocess

def get_file_info(filename):
    """Get file information and return as JSON."""
    try:
        # Check if file exists
        if not os.path.exists(filename):
            return json.dumps({"error": f"File not found: {filename}"}, indent=2)

        # Get file size
        file_size = os.path.getsize(filename)

        # Read file content
        with open(filename, 'rb') as f:
            file_content = f.read()

        # Calculate MD5 hash
        md5_hash = hashlib.md5(file_content).hexdigest()

        # Calculate base64 encoding
        base64_hash = base64.b64encode(file_content).decode('utf-8')

        # Get file type using bash 'file' command
        try:
            file_type = subprocess.check_output(['file', '-b', filename], text=True).strip()
        except subprocess.CalledProcessError:
            file_type = "Unknown"

        # Create result dictionary
        result = {
            "filename": filename,
            "md5sum": md5_hash,
            "file_size": file_size,
            "file_type": file_type,
            "base64_encoded": base64_hash
        }

        return json.dumps(result, indent=2)

    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python3 file_info.py <filename>"}, indent=2))
        sys.exit(1)

    filename = sys.argv[1]
    print(get_file_info(filename))

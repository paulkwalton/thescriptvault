#!/bin/bash

# Define S3 bucket and folder names
BUCKET_NAME="your-s3-bucket-name"
ORIGINAL_FOLDER="path/to/original/folder"
SHELLCODE_FOLDER="path/to/shellcode/folder"

# Local directory for processing files
PROCESSING_DIR="/path/to/local/processing_directory"
mkdir -p "$PROCESSING_DIR"

# Infinite loop to monitor the S3 bucket
while true; do
    # List files in the original folder
    files=$(aws s3 ls "s3://$BUCKET_NAME/$ORIGINAL_FOLDER/" | awk '{print $4}')
    
    for file in $files; do
        # Download the file from S3
        aws s3 cp "s3://$BUCKET_NAME/$ORIGINAL_FOLDER/$file" "$PROCESSING_DIR/$file"
        
        # Generate shellcode using Donut
        ./donut -f 1 -a 2 -o "$PROCESSING_DIR/${file%.*}.bin" -i "$PROCESSING_DIR/$file"
        
        # Upload the shellcode back to the shellcode folder in S3
        aws s3 cp "$PROCESSING_DIR/${file%.*}.bin" "s3://$BUCKET_NAME/$SHELLCODE_FOLDER/${file%.*}.bin"
        
        # Remove the original file from the original folder in S3
        aws s3 rm "s3://$BUCKET_NAME/$ORIGINAL_FOLDER/$file"
        
        # Clean up local files
        rm "$PROCESSING_DIR/$file" "$PROCESSING_DIR/${file%.*}.bin"
    done
    
    # Wait for 5 minutes before checking again
    sleep 300
done

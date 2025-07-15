# CloudSecurity
**Secure Serverless Notes Application**

The goal is to use Frontend on S3/Cloudfront, Backend with API Gateway, Lambda, DynamoDB, all with robust security controls.

<img width="1710" height="1107" alt="Screenshot 2025-07-14 at 7 43 57 PM" src="https://github.com/user-attachments/assets/1ae30ae7-10da-425d-9f6a-b91bdb92f8ad" />

I created this IAM user because of the Principle of Least Privilege. This uses a non-root account for daily tasks, a strong password policy, and secure handling of access keys as well.

I also stored this in an encrypted file, so it isn't easily accessible.

<img width="1710" height="1107" alt="Screenshot 2025-07-14 at 7 47 26 PM" src="https://github.com/user-attachments/assets/93a0d5e3-88ce-402d-98c8-2a44f22ed62d" />

Successful Login as the IAM user.

**Since I'm using MAC, I had to update brew, then run this** echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> /Users/divine/.zprofile
eval "$(/opt/homebrew/bin/brew shellenv)"

I put the command aws configure, then put my Access key & Secret Access Key.

<img width="1710" height="1107" alt="Screenshot 2025-07-14 at 8 02 43 PM" src="https://github.com/user-attachments/assets/62c698af-f44e-4369-b83e-045bf0ea8810" />

This completed the foundational security setup for my AWS environment

**Phase 2** 

Core Application Setup

<img width="1710" height="1107" alt="Screenshot 2025-07-14 at 8 12 20 PM" src="https://github.com/user-attachments/assets/22a48672-00f5-47d7-8df6-5cf2daebfe8d" />

I created A table in DynamoDB (shows the activeness). Also noted the primary key as noteId, and confirmed that encryption at rest is enabled.

**"Encryption at rest means the practice of encrypting data while it's stored on a device or in a storage medium, such as a hard drive, SSD, or cloud storage."**


This is the Lambda function's basic configuration
<img width="1710" height="1107" alt="Screenshot 2025-07-14 at 8 21 15 PM" src="https://github.com/user-attachments/assets/1c191d0d-86d7-4999-a14d-4fc3b0357ba4" />

The Function's name is Notehandler, the runtime is Python 3.9, and it was last modified 6 minutes ago.

import json
import os
import uuid
import boto3
from botocore.exceptions import ClientError

# Initialize DynamoDB client using environment variable for table name
dynamodb = boto3.resource('dynamodb')
table_name = os.environ.get('TABLE_NAME')
if not table_name:
    raise ValueError("TABLE_NAME environment variable is not set.")
table = dynamodb.Table(table_name)

def lambda_handler(event, context):
    http_method = event.get('httpMethod')
    path = event.get('path')
    body = {}
    if event.get('body'):
        try:
            body = json.loads(event['body'])
        except json.JSONDecodeError:
            return {
                'statusCode': 400,
                'body': json.dumps({'message': 'Invalid JSON body'})
            }

    # Temporary CORS headers - we will secure this later
    response_headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*', # TEMPORARY: This will be refined for security
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'
    }

    try:
        if http_method == 'POST' and path == '/notes':
            note_id = str(uuid.uuid4())
            note_content = body.get('content')
            if not note_content:
                return {'statusCode': 400, 'body': json.dumps({'message': 'Content is required'})}
            table.put_item(Item={'noteId': note_id, 'content': note_content})
            return {'statusCode': 201, 'body': json.dumps({'noteId': note_id, 'content': note_content}), 'headers': response_headers}

        elif http_method == 'GET' and path == '/notes':
            response = table.scan()
            return {'statusCode': 200, 'body': json.dumps(response.get('Items', [])), 'headers': response_headers}

        elif http_method == 'GET' and path.startswith('/notes/'):
            note_id = path.split('/')[-1]
            response = table.get_item(Key={'noteId': note_id})
            item = response.get('Item')
            if item:
                return {'statusCode': 200, 'body': json.dumps(item), 'headers': response_headers}
            else:
                return {'statusCode': 404, 'body': json.dumps({'message': 'Note not found'}), 'headers': response_headers}

        elif http_method == 'PUT' and path.startswith('/notes/'):
            note_id = path.split('/')[-1]
            note_content = body.get('content')
            if not note_content:
                return {'statusCode': 400, 'body': json.dumps({'message': 'Content is required'})}
            table.update_item(
                Key={'noteId': note_id},
                UpdateExpression='SET content = :c',
                ExpressionAttributeValues={':c': note_content},
                ReturnValues='UPDATED_NEW'
            )
            return {'statusCode': 200, 'body': json.dumps({'noteId': note_id, 'content': note_content}), 'headers': response_headers}

        elif http_method == 'DELETE' and path.startswith('/notes/'):
            note_id = path.split('/')[-1]
            table.delete_item(Key={'noteId': note_id})
            return {'statusCode': 204, 'body': json.dumps({'message': 'Note deleted'}), 'headers': response_headers}

        elif http_method == 'OPTIONS': # Handle CORS preflight requests
            return {'statusCode': 200, 'body': '', 'headers': response_headers}


        return {'statusCode': 404, 'body': json.dumps({'message': 'Not Found'}), 'headers': response_headers}

    except ClientError as e:
        print(f"DynamoDB Error: {e}")
        return {'statusCode': 500, 'body': json.dumps({'message': 'Internal Server Error', 'error': str(e)}), 'headers': response_headers}
    except Exception as e:
        print(f"General Error: {e}")
        return {'statusCode': 500, 'body': json.dumps({'message': 'Internal Server Error', 'error': str(e)}), 'headers': response_headers}


**This is the Python code for my lambda function**

By default, your Lambda function doesn't have permissions to access DynamoDB. This is a core security best practice called "Least Privilege."

It means:

Security: If your Lambda is ever compromised, an attacker can only access what it's explicitly allowed to. No DynamoDB access means your data is safe.

Control: You must consciously grant specific permissions (e.g., dynamodb:GetItem for a particular table) by adding an IAM policy to your Lambda's execution role. This ensures the function only does precisely what's needed, preventing accidental data access or modification.

This setup significantly reduces your security risk by limiting the "blast radius" of any potential issue.







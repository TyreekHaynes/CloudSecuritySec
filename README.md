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

<img width="1710" height="1107" alt="Screenshot 2025-07-14 at 9 26 29 PM" src="https://github.com/user-attachments/assets/9f40acb3-81a0-4071-a8ff-0f8d83ea99da" />

This is what my API Gateway resources and methods look like.

API name: SecureNotesAPI, Stage name: Stage-cloud, Invoke URL: https://yfhcxv7bmd.execute-api.us-east-2.amazonaws.com/Stage-cloud

In essence, API Gateway just passes the whole request details to your single Lambda, and your Lambda function acts as an internal router for all your API endpoints.

What is a Lambda proxy integration? Lambda Proxy Integration in AWS API Gateway is a simplified and recommended way to connect your API endpoints directly to a Lambda function, acting as a "passthrough" or "proxy.

**This is the HTML for my API Gateway**
{\rtf1\ansi\ansicpg1252\cocoartf2822 \cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;} {\colortbl;\red255\green255\blue255;} {\*\expandedcolortbl;;} \margl1440\margr1440\vieww11520\viewh8400\viewkind0 \pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0 \f0\fs24 \cf0 \ \ \ \ \ \ \ \ \
Secure Notes App
\ \
Create New Note
\ \ Add Note\ \
Your Notes
\
\ Loading notes...\
\ \ \ \ }

**This is my JavaScript**
// IMPORTANT: REPLACE THIS WITH YOUR ACTUAL API GATEWAY INVOKE URL
// Make sure it ends with your stage name, e.g., /prod or /dev
const API_BASE_URL = ' **https://yfhcxv7bmd.execute-api.us-east-2.amazonaws.com/Stage-cloud;**

async function fetchNotes() {
    try {
        const response = await fetch(`${API_BASE_URL}/notes`);
        const notes = await response.json();
        const notesList = document.getElementById('notes-list');
        notesList.innerHTML = '';
        if (notes.length === 0) {
            notesList.innerHTML = '<p>No notes yet. Create one!</p>';
        } else {
            notes.forEach(note => {
                const div = document.createElement('div');
                div.className = 'note-item';
                div.innerHTML = `
                    <strong>ID:</strong> ${note.noteId}<br>
                    <strong>Content:</strong> ${note.content}
                    <button onclick="deleteNote('${note.noteId}')">Delete</button>
                `;
                notesList.appendChild(div);
            });
        }
    } catch (error) {
        console.error('Error fetching notes:', error);
        document.getElementById('notes-list').innerHTML = '<p style="color: red;">Error loading notes.</p>';
    }
}

async function createNote() {
    const noteContent = document.getElementById('noteContent').value;
    if (!noteContent) {
        alert('Note content cannot be empty.');
        return;
    }
    try {
        const response = await fetch(`${API_BASE_URL}/notes`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ content: noteContent })
        });
        const result = await response.json();
        if (response.ok) {
            alert('Note created successfully!');
            document.getElementById('noteContent').value = ''; // Clear input
            fetchNotes(); // Refresh list
        } else {
            alert(`Error: ${result.message || response.statusText}`);
        }
    } catch (error) {
        console.error('Error creating note:', error);
        alert('Failed to create note due to network error.');
    }
}

async function deleteNote(noteId) {
    if (!confirm(`Are you sure you want to delete note ${noteId}?`)) {
        return;
    }
    try {
        const response = await fetch(`${API_BASE_URL}/notes/${noteId}`, {
            method: 'DELETE'
        });
        if (response.status === 204) { // 204 No Content for successful deletion
            alert('Note deleted successfully!');
            fetchNotes(); // Refresh list
        } else {
            const result = await response.json();
            alert(`Error: ${result.message || response.statusText}`);
        }
    } catch (error) {
        console.error('Error deleting note:', error);
        alert('Failed to delete note due to network error.');
    }
}

// Fetch notes when the page loads
window.onload = fetchNotes;


<img width="1710" height="1107" alt="Screenshot 2025-07-14 at 9 59 25 PM" src="https://github.com/user-attachments/assets/0a1f4eea-cb7b-41a3-80b2-824c0c022bdf" />


**Phase 3: IAM Least Privilege & VPC Integration**

**This is the Principle of Least Privilege**
<img width="1710" height="1107" alt="Screenshot 2025-07-14 at 11 07 01 PM" src="https://github.com/user-attachments/assets/b8cbbc36-567d-4dea-9162-ec1e2b356953" />

{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Sid": "VisualEditor0",
			"Effect": "Allow",
			"Action": [
				"dynamodb:PutItem",
				"dynamodb:DeleteItem",
				"dynamodb:GetItem",
				"dynamodb:Scan",
				"dynamodb:UpdateItem"
			],
			"Resource": "arn:aws:dynamodb:us-east-2:086715933972:table/NotesTable"
		}
	]
}

This was the JSON of the DynamoDBNotesAccess.

An Amazon Resource Name (ARN) is a unique identifier for every resource in AWS. Think of it like a unique address for an item in a massive warehouse. By including all these details, an ARN precisely points to a single, specific resource within the entire AWS cloud, regardless of account or region. 

This is crucial for:
IAM Policies: Defining granular permissions ("Allow this user to access only this specific S3 bucket").API Calls: Programmatically interacting with a particular resource.
Cross-Service Integration: One AWS service referencing a resource in another service.



<img width="1710" height="1107" alt="Screenshot 2025-07-14 at 11 14 22 PM" src="https://github.com/user-attachments/assets/80a7411b-3de8-400a-bab3-b00910bd64b1" />

VPC CIDR block was 10.0.0.0/16, and the Private subset CIDR blocks were set to 0.

A VPC with no public subnets and no NAT Gateway represents a highly locked-down and isolated environment. It's chosen when the absolute highest level of security and control over network ingress and egress is paramount, typically for sensitive data, critical applications, or highly regulated workloads. All necessary external communication would then be handled through specific, auditable, and tightly controlled mechanisms that do not involve direct internet exposure.


<img width="1710" height="1107" alt="Screenshot 2025-07-14 at 9 59 25 PM" src="https://github.com/user-attachments/assets/4fc8a7b7-57bc-4eb1-ac02-26e9b2459236" />

This is the Security group for my project, acting as a firewall.  

**Security Group ID sg-086d7dac312386420**






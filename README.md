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


**This is my list of created Endpoints**
<img width="1710" height="1107" alt="Screenshot 2025-07-14 at 11 31 16 PM" src="https://github.com/user-attachments/assets/03692287-6323-4e4c-8917-401419870c7e" />

VPC Endpoints are crucial for security because they allow your resources in a VPC (especially those in private subnets) to privately connect to AWS services (like S3, DynamoDB, Lambda) without traversing the public internet.



<img width="1710" height="1107" alt="Screenshot 2025-07-14 at 11 56 54 PM" src="https://github.com/user-attachments/assets/ed024376-98ca-4437-b9ea-6a53501d2522" />

The AWSLambdaVPCAccessExecutionRole policy is required because when you connect a Lambda function to a VPC, the AWS Lambda service needs permissions (like ec2:CreateNetworkInterface, ec2:DescribeNetworkInterfaces, ec2:DeleteNetworkInterface) to create, describe, and delete Elastic Network Interfaces (ENIs) within your VPC. These ENIs are the mechanism that allows your Lambda function to establish network connectivity with your private VPC resources


<img width="1710" height="1107" alt="Screenshot 2025-07-15 at 12 01 54 AM" src="https://github.com/user-attachments/assets/44749a9e-3611-41a9-b5e4-f15d42482ca1" />

These EC2 permissions allow the AWS Lambda service (acting on behalf of your function's role) to provision, manage, and de-provision the network interfaces that enable your function to exist and communicate within your VPC.

While running Lambda in a VPC boosts security and enables private resource access, it cuts off direct internet access. You must then consciously add back internet access (via NAT Gateway) or private service access (via VPC Endpoints) if your Lambda needs to communicate outside its VPC.



<img width="1710" height="1107" alt="Screenshot 2025-07-15 at 12 10 46 AM" src="https://github.com/user-attachments/assets/2dd3a9cf-4d40-47d5-b217-926162ac979b" />

What it is: A prefix list (pl-xxxxxxxx) is a collection of IP address ranges (CIDR blocks) for specific AWS services (like S3 or DynamoDB), maintained by AWS.

Why it's used as a destination: In your VPC route table, a rule uses this prefix list as a destination. This tells your VPC: "Any traffic going to IPs in this list (i.e., to this AWS service) should go to the specified VPC Endpoint."



<img width="1710" height="1107" alt="Screenshot 2025-07-15 at 10 17 20 PM" src="https://github.com/user-attachments/assets/0c09afbe-b8e3-4eb1-b73e-d5733d0bf00b" />

This is my Lambda function. I added the 'Access-Control-Allow-'


**Phase 4: Frontend Accessibility & Security**


1. When my website loads: You visit https://dg29rje7bg3hi.cloudfront.net/ in your browser, your notes application frontend (HTML, CSS, JavaScript) loads correctly.

 - HTTPS is enforced: The URL in your browser should show https:// and a padlock icon, indicating a secure connection. If you try http:// it should redirect to https://. To ensure you are always on port 443 (Secure) and not port (80).
 - S3 Bucket is Private: Your serverless-web-on-aws1 S3 bucket should NOT be publicly accessible. If you try to access its direct S3 URL (e.g., http://serverless-web-on-aws1.s3-website.us-east-2.amazonaws.com or https://serverless-web-on-aws1.s3.us-east-2.amazonaws.com/index.html), it should result in an AccessDenied error. CloudFront accesses it securely via OAC.

<img width="1710" height="1107" alt="Screenshot 2025-07-15 at 10 29 21 PM" src="https://github.com/user-attachments/assets/5d5eb266-fdb0-4b9f-938c-b3ff02c37c52" />

**Example of the website failing**


2. Full Application Functionality (End-to-End):

All CRUD (Create, Read, Update, Delete) operations for your notes application work correctly:

You can successfully Add new notes.

You can List/View all notes.

You can Update existing notes.

You can Delete notes.


3. Backend & Inter-Service Communication:

Lambda in VPC: Your NoteHandler Lambda function is configured to run inside your VPC (associated with subnets and the LambdaHandlerSG security group).

VPC Endpoints Utilized: Your Lambda function communicates with DynamoDB and S3 (for the backend notes_metadata bucket) entirely through their respective VPC Interface Endpoints (Privatelink), not over the public internet. This ensures private, secure data transfer.

(You can't directly "see" this in action without advanced logging or network flow logs, but the configuration should be set up for it.)

Lambda Outbound Rules: The LambdaHandlerSG Security Group (attached to your Lambda ENI in the VPC) has its Outbound Rules correctly configured to allow HTTPS (Port 443) traffic only to the specific Prefix List IDs for DynamoDB and S3 in your region (and potentially other necessary AWS services like CloudWatch). It should NOT have broad 0.0.0.0/0 outbound rules.


4. CORS Configuration
- Your NoteHandler Lambda function's Python code has the Access-Control-Allow-Origin header set exactly to your CloudFront domain: https://dg29rje7bg3hi.cloudfront.net. This is crucial for your browser to allow frontend-to-backend communication.
 
<img width="1710" height="1107" alt="Screenshot 2025-07-15 at 10 25 59 PM" src="https://github.com/user-attachments/assets/214ed640-8bdd-4325-aa66-0c735e08eb23" />



**Phase 5: With the ensuring when people make notes I made sure to add CloudWatch logs to see when some STARTS, ENDS, and REPORTS.**


<img width="1710" height="1107" alt="Screenshot 2025-07-15 at 10 40 00 PM" src="https://github.com/user-attachments/assets/7256e595-d2b5-42c7-aaaf-df0fbded4872" />


**Deployed CloudWatch Metrics for both Lambda and API Gateway.**

<img width="1710" height="1107" alt="Screenshot 2025-07-15 at 11 09 39 PM" src="https://github.com/user-attachments/assets/00dd0f80-9f9e-4199-bae5-f39578c3bcad" />




**Set up a CloudWatch Alarm and confirmed that it can send emial notifications to you via SNS**

<img width="1710" height="1107" alt="Screenshot 2025-07-15 at 11 11 11 PM" src="https://github.com/user-attachments/assets/616bb0eb-3732-4eb5-80a7-dd18de5866cc" />


**Phase 6: Advanced Security & Cleanup**

1. 

AWSManagedRulesCommonRuleSet (Core rule set - CRS)

What it does: This is the foundational rule set that protects against common web exploits, including SQL injection, cross-site scripting (XSS), HTTP flood attacks, and other OWASP Top 10 risks. It's a general-purpose, broad defense. As well as being unimpactful in cost: This managed rule group itself costs $1.00 per month (prorated hourly), in addition to the base Web ACL fee and per-request charges. It does not have an extra subscription fee

&

2. AWSManagedRulesAmazonIpReputationList

What it does: This rule group blocks requests from known malicious IP addresses identified by Amazon threat intelligence. This includes IPs associated with bots, reconnaissance, and DDoS activities.

Cost impact: This managed rule group also costs $1.00 per month (prorated hourly), in addition to the base Web ACL fee and per-request charges. It does not have an extra subscription fee.

<img width="1710" height="1107" alt="Screenshot 2025-07-15 at 11 30 12 PM" src="https://github.com/user-attachments/assets/1a32cc04-a960-4a64-9c93-9ba1b30663c9" />


I also made another log for firewall detection named "NoteLogs"

<img width="1710" height="1107" alt="Screenshot 2025-07-15 at 11 36 20 PM" src="https://github.com/user-attachments/assets/e75ad97d-7f3a-4a81-bd0b-653e1da4605d" />



**Now my firewall is now taling to the CloudFront and is active spotting CRS and AWSManagedRulesAmazonIpReputationList**

<img width="1710" height="1107" alt="Screenshot 2025-07-15 at 11 40 28 PM" src="https://github.com/user-attachments/assets/6021c1d0-900f-455d-8719-c4686a2b6875" />


**I also created a Cleanup Strategy for Deleting Resources**

AWS WAF Web ACL:

Go to WAF Console (US East - N. Virginia).

Go to "Web ACLs," select your Web ACL (NotesAppWebACL).

Click "Disassociate Web ACL" if it's still associated with CloudFront. Confirm.

Once disassociated, select the Web ACL again and click "Delete Web ACL." Confirm.

CloudFront Distribution:

Go to CloudFront Console.

Select your distribution.

Click "Disable." Confirm. This takes several minutes to propagate.

Once Status changes to Disabled and State is Deployed, select it again and click "Delete." Confirm.

API Gateway:

Go to API Gateway Console.

Select your notes-api REST API.

Click "Actions" dropdown, then "Delete." Confirm by typing delete.

If you created an API Key and Usage Plan, you'll need to delete those separately:

Go to "API Keys," delete your API Key.

Go to "Usage Plans," delete your Usage Plan.

Lambda Function:

Go to Lambda Console.

Select your NoteHandler function.

Click "Actions" dropdown, then "Delete." Confirm.

Crucial Cleanup for Lambda:

IAM Role: Go to IAM Console -> "Roles." Find the execution role for your Lambda (e.g., NoteHandlerRole or similar). If this role is only used by this Lambda, delete it. If other services use it, you might need to modify its permissions instead.

CloudWatch Log Group: Go to CloudWatch Console -> "Log groups." Find the log group for your Lambda (usually /aws/lambda/your-function-name). Select it and click "Delete log group."

CloudWatch Alarms: Go to CloudWatch Console -> "Alarms." Delete any alarms you created for this Lambda.

SNS Topic & Subscription: Go to SNS Console -> "Topics." Delete the NotesAppAlarms topic. This will automatically delete its subscriptions.

DynamoDB Table:

Go to DynamoDB Console.

Go to "Tables." Select your notes table.

Click "Delete." Confirm by typing delete.

S3 Buckets:

Go to S3 Console.

Your frontend bucket (serverless-web-on-aws1): This bucket must be empty before deletion. Select the bucket, click "Empty," type permanently delete, confirm. Then, select the empty bucket and click "Delete," type the bucket name, confirm.

Your backend notes_metadata bucket: If you created one as part of the backend. Empty and delete it the same way.

VPC and VPC Endpoints (Most Complex):

Go to VPC Console.

VPC Endpoints: In the left pane, click "Endpoints." Select your S3 and DynamoDB interface endpoints (e.g., com.amazonaws.us-east-2.s3, com.amazonaws.us-east-2.dynamodb). Click "Actions" -> "Delete VPC endpoints." Confirm.

NAT Gateway (if you created one): If you followed a guide that had you create a NAT Gateway in your public subnet, delete it. This is important as it incurs an hourly charge. Go to "NAT Gateways," select it, "Actions" -> "Delete NAT Gateway."

Elastic IPs (EIPs): If you had a NAT Gateway, it would have consumed an Elastic IP. After deleting the NAT Gateway, go to "Elastic IPs," select the EIP, "Actions" -> "Release Elastic IP addresses."

VPC: Finally, you can delete the VPC itself, but only after all contained resources (instances, ENIs, endpoints, NAT Gateways, etc.) are deleted. Select your custom VPC, "Actions" -> "Delete VPC." The console will usually tell you if there are dependencies left.

**Final Step for Phase 6: Understanding Infrastructure as Code (Iac)**

IaC is crucial for serverless applications due to:

Consistency & Repeatability: Eliminates manual errors, ensuring identical environments across development, staging, and production.

Version Control: Infrastructure definitions are treated as code, allowing tracking, rollbacks, and collaboration.

Automation & Speed: Streamlines entire application stack deployments to a single command.

Disaster Recovery: Enables rapid re-creation of the entire infrastructure if lost.

Cost Management: Provides clear visibility and control over deployed resources.


**How it applies to my project:**

I manually created your S3 bucket, CloudFront distribution, API Gateway, Lambda function, DynamoDB table, VPC, security groups, and WAF rules. With IaC, all of these would be defined in one or a few text files.


For example, a small snippet of what your Lambda function and API Gateway could look like in an AWS SAM template:

AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: A serverless notes application

Resources:
  NoteHandlerFunction:
    Type: AWS::Serverless::Function
    Properties:
      Handler: app.lambda_handler
      Runtime: python3.9
      CodeUri: s3://your-deployment-bucket/your-lambda-code.zip # Or a local path
      MemorySize: 128
      Timeout: 30
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref NotesTable # Grants CRUD to the NotesTable
      Environment:
        Variables:
          TABLE_NAME: !Ref NotesTable
      VpcConfig: # This links your Lambda to your VPC
        SecurityGroupIds:
          - sg-xxxxxxxxxxxxxxxxx # Your Lambda security group
        SubnetIds:
          - subnet-xxxxxxxxxxxxxxxxx # Your private subnets
      Events:
        NotesApi:
          Type: Api
          Properties:
            Path: /notes
            Method: any
            RestApiId: !Ref NotesApi # Refers to the API Gateway below

  NotesApi:
    Type: AWS::Serverless::Api
    Properties:
      StageName: prod
      EndpointConfiguration: REGIONAL
      Cors: # CORS configuration for your CloudFront domain
        AllowHeaders: "'*'"
        AllowMethods: "'*'"
        AllowOrigin: "'https://dg29rje7bg3hi.cloudfront.net'" # Your CloudFront URL
        AllowCredentials: "'true'"
      Auth: # For API Key usage
        DefaultAuthorizer: AWS_IAM
        # We would then define UsagePlan and APIKey resources here too

  NotesTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: notes
      AttributeDefinitions:
        - AttributeName: noteId
          AttributeType: S
      KeySchema:
        - AttributeName: noteId
          KeyType: HASH
      BillingMode: PAY_PER_REQUEST # On-demand

      







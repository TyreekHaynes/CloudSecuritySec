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

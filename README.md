# lambda-wm-revoke-token

A configurable AWS Lambda function that integrates with AWS WAF to automatically block sessions based on watermark revoke tokens. <br> This function processes SNS events containing revoke tokens, validates them with DoveRunner API, and adds blocking rules to AWS WAF.

## Overview

This Lambda function is designed to:
- Process SNS events containing watermark revoke tokens
- Verify revoke tokens with DoveRunner API
- Automatically add blocking rules to AWS WAF to prevent unauthorized access

## Features

- **Automatic Token Validation**: Verifies revoke tokens with DoveRunner API
- **Duplicate Prevention**: Checks if tokens are already registered in WAF
- **Dynamic Rule Generation**: Creates WAF rules with timestamp-based naming
- **Comprehensive Logging**: Detailed logging for monitoring and debugging
- **Configurable**: Easy customization through configuration files

## Prerequisites

- AWS Account with appropriate permissions
- AWS WAF Web ACL configured
- DoveRunner account and API credentials
- Node.js 18.x or higher

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd lambda-wm-revoke-token
   ```

2. **Install dependencies**:
   ```bash
   npm install --production
   ```

## Configuration

### config.json

Configure the following parameters in `config.json`:

```json
{
  "site_id": "YOUR_DOVERUNNER_SITE_ID",
  "account_id": "YOUR_DOVERUNNER_ACCOUNT_ID",
  "access_key": "YOUR_DOVERUNNER_ACCESS_KEY",
  "aws_waf_web_acl_id": "YOUR_AWS_WAF_WEB_ACL_ID",
  "aws_waf_web_acl_name": "YOUR_AWS_WAF_WEB_ACL_NAME"
}
```

#### Configuration Parameters

| Parameter | Description | Required |
|-----------|-------------|----------|
| `site_id` | Your DoveRunner site identifier | Yes |
| `account_id` | Your DoveRunner account ID or email address | Yes |
| `access_key` | Your DoveRunner access key for API authentication | Yes |
| `aws_waf_web_acl_id` | The unique identifier of your AWS WAF Web ACL | Yes |
| `aws_waf_web_acl_name` | The name of your AWS WAF Web ACL | Yes |

## Deployment

### AWS Lambda Deployment

1. **Package the function**:
   ```bash
   zip -r lambda-function.zip . -x "node_modules/.cache/*" "*.git*"
   ```

2. **Create Lambda function using AWS CLI**:
   ```bash
   aws lambda create-function \
     --function-name lambda-wm-revoke-token \
     --runtime nodejs18.x \
     --role arn:aws:iam::YOUR_ACCOUNT:role/lambda-execution-role \
     --handler index.handler \
     --zip-file fileb://lambda-function.zip \
     --timeout 60 \
     --memory-size 256
   ```

3. **Configure SNS trigger**:
   ```bash
   aws lambda add-permission \
     --function-name lambda-wm-revoke-token \
     --statement-id sns-trigger \
     --action lambda:InvokeFunction \
     --principal sns.amazonaws.com \
     --source-arn arn:aws:sns:region:account:topic-name
   ```

### Required AWS Permissions

The Lambda execution role needs the following permissions:

```json
{
   "Version": "2012-10-17",
   "Statement": [
      {
         "Effect": "Allow",
         "Action": [
            "wafv2:GetWebACL",
            "wafv2:UpdateWebACL"
         ]
      }
   ]
}
```

## Usage

### SNS Event Format

The function expects SNS events with the following message format:

```json
{
  "revoke_token": "ABCDEFG",
  "site_id": "YOUR_SITE_ID"
}
```

## Testing

### Unit Tests

Run the unit tests:

```bash
npm test
```

### Test Coverage

Check test coverage:

```bash
npm run test:coverage
```

### Test Structure

- **Unit Tests**: Located in `__tests__/` directory
- **Test Configuration**: `jest.config.js`
- **Coverage Report**: Generated in `coverage/` directory

## Changelog

### Version 1.0.0
- Initial release
- Basic SNS event processing
- DoveRunner API integration
- AWS WAF rule management
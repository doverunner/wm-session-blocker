# lambda-wm-revoke-token

A configurable AWS Lambda function that integrates with AWS WAF to automatically block sessions when an illegal watermark is detected. <br> It subscribes to the DoveRunner **detection status notification** (SNS), and **only when a detection completes (status `FD004`)** does it verify the watermark token with the DoveRunner API and add a blocking rule to AWS WAF.

## Overview

The detection notification is a unified "detection status change" alarm, so the SNS topic delivers messages for several terminal states (completed / error / failed). This Lambda function:
- Processes SNS detection status notifications
- **Revokes (blocks) a session only for a completed detection (`detection_status: "FD004"`)** — error / failed states are skipped
- Verifies the watermark token with DoveRunner API and adds a blocking rule to AWS WAF

## Features

- **Completed-only Revoke**: Blocks a session only when detection completed (`FD004`); error / failed states are skipped
- **Automatic Token Validation**: Verifies watermark tokens with DoveRunner API
- **Duplicate Prevention**: Checks if tokens are already registered in WAF
- **Dynamic Rule Generation**: Creates WAF rules named after the base64url-encoded watermark token (`waf-uri-contains-<base64url-token>`, URI-contains match)
- **Comprehensive Logging**: Detailed logging for monitoring and debugging
- **Configurable**: Easy customization through configuration files

## Prerequisites

- AWS Account with appropriate permissions
- AWS WAF Web ACL configured
- DoveRunner account and API credentials
- Node.js 20.x or higher

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

| Parameter              | Description                                       | Required |
|------------------------|---------------------------------------------------|----------|
| `site_id`              | Your DoveRunner site identifier                   | Yes      |
| `account_id`           | Your DoveRunner account ID or email address       | Yes      |
| `access_key`           | Your DoveRunner access key for API authentication | Yes      |
| `aws_waf_web_acl_id`   | The unique identifier of your AWS WAF Web ACL     | Yes      |
| `aws_waf_web_acl_name` | The name of your AWS WAF Web ACL                  | Yes      |

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
     --runtime nodejs20.x \
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
         ],
         "Resource": "*"
      }
   ]
}
```

## Usage

### SNS Event Format

The SNS message is a detection status notification. The fields present depend on `detection_status`.

| Field              | Description                                                                | Present when        |
|--------------------|----------------------------------------------------------------------------|---------------------|
| `detection_id`     | Detection job id (useful for correlation)                                  | Always              |
| `detection_status` | Detection status code (`FD004` completed / `FD006` error / `FD007` failed) | Always              |
| `watermark_token`  | Watermark key to block                                                     | Completed only      |
| `forensic_mark`    | Detected watermark payload                                                 | Completed only      |
| `error_code`       | Error code                                                                 | Error / failed only |
| `error_message`    | Error message                                                              | Error / failed only |

> `site_id` is no longer included in the payload; the function reads it from `config.json` (each customer subscribes its own SNS topic).
>
> `forensic_mark` is informational only — blocking is performed with `watermark_token`. `FD006` covers more than one error kind (e.g. a general detection error or a media-check error); the specific reason is conveyed by `error_code` / `error_message`.

#### Sample payloads

**Completed — `FD004` (the only case that triggers a revoke):**
```json
{
  "detection_id": 12345,
  "detection_status": "FD004",
  "forensic_mark": "detected watermark payload",
  "watermark_token": "ABCDEFG"
}
```

**Error — `FD006` (skipped, no revoke):**
```json
{
  "detection_id": 12345,
  "detection_status": "FD006",
  "error_code": "D2001",
  "error_message": "Failed to download the media file"
}
```

**Failed — `FD007` (skipped, no revoke):**
```json
{
  "detection_id": 12345,
  "detection_status": "FD007",
  "error_code": "D3001",
  "error_message": "Watermark detection failed"
}
```

> Note: a "canceled/stopped" state (`FD005`) is not delivered by the current detection status notification. The handler skips revoke for any non-`FD004` status, so other states are handled safely.

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

### Version 1.1.0
- Switched the SNS trigger from the revoke-only message to the unified **detection status notification**
- Payload field `revoke_token` renamed to `watermark_token`; `detection_status` and `detection_id` added; `site_id` removed from the payload
- Revoke is now performed **only for a completed detection (`FD004`)**; error / failed states are skipped

### Version 1.0.0
- Initial release
- Basic SNS event processing
- DoveRunner API integration
- AWS WAF rule management
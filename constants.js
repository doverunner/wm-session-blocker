const AWS_SNS_EVENT_SOURCE = 'aws:sns';
const AWS_WAF_SCOPE = 'CLOUDFRONT';
const AWS_WAF_REGION = 'us-east-1';
const API_BASE_URL = 'https://wm-detection.doverunner.com/';
const RULE_BASE_NAME = 'waf-uri-contains-'

module.exports = {
    AWS_SNS_EVENT_SOURCE,
    API_BASE_URL,
    AWS_WAF_SCOPE,
    AWS_WAF_REGION,
    RULE_BASE_NAME
};
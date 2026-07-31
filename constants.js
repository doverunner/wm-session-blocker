const AWS_SNS_EVENT_SOURCE = 'aws:sns';
const AWS_WAF_SCOPE = 'CLOUDFRONT';
const AWS_WAF_REGION = 'us-east-1';
const API_BASE_URL = 'https://wm-detection.doverunner.com/';
const RULE_BASE_NAME = 'waf-uri-contains-';

/**
 * DoveRunner detection status codes carried by `detection_status` in the SNS message.
 *
 * The notification is now a unified "detection status change" alarm, so the SNS topic delivers messages for several terminal states — not only successful detection.
 * A session must be revoked (blocked) ONLY when detection actually completed.
 *
 *   COMPLETED (FD004) : detection finished and a watermark was found.
 *                       Payload carries `watermark_token` and `forensic_mark`
 *
 *   ERROR     (FD006) : detection ended with an error.
 *                       Payload carries `error_code` / `error_message`
 *
 *   FAILED    (FD007) : detection failed.
 *                       Payload carries `error_code` / `error_message`
 *
 * Note: a "canceled/stopped" state (FD005) is NOT delivered by the current detection status notification, so it is not listed here.
 *       The handler skips revoke for ANY non-COMPLETED status, so unexpected states are handled safely regardless.
 */
const DETECTION_STATUS = {
    COMPLETED: 'FD004',
    ERROR: 'FD006',
    FAILED: 'FD007'
};

module.exports = {
    AWS_SNS_EVENT_SOURCE,
    API_BASE_URL,
    AWS_WAF_SCOPE,
    AWS_WAF_REGION,
    RULE_BASE_NAME,
    DETECTION_STATUS
};
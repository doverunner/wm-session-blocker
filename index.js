const { AWS_SNS_EVENT_SOURCE } = require('./constants.js');
const { verifyRevokeToken } = require('./api-modules.js');
const { validateRuleNotDuplicated, createBlockingRule } = require('./aws-waf-modules.js');

/**
 * AWS Lambda handler for processing watermark revoke token requests
 * @param {Object} event - SNS event containing revoke token data
 * @returns {Object} Processing results and any errors
 */
const handler = async (event) => {
    console.log('Received event:', event);
    let messageId;
    let results = [];
    let errors = [];

    for (const record of event.Records) {
        try {
            if (record.EventSource === AWS_SNS_EVENT_SOURCE) {
                console.log('Processing SNS record:', record);
                messageId = record.Sns.MessageId;

                // Expected format: { "revoke_token": "7-byte watermark key", "site_id": "TEST" }
                const messageData = JSON.parse(record.Sns.Message);

                // Step 1: Check if revoke token is already registered in AWS WAF
                await validateRuleNotDuplicated(messageData.revoke_token);

                // Step 2: Verify revoke token with DoveRunner API
                await verifyRevokeToken(messageData.revoke_token);

                // Step 3: Add revoke token blocking rule to AWS WAF
                await createBlockingRule(messageData.revoke_token);

                console.log(`[${messageId}] Successfully processed revoke token: ${messageData.revoke_token}`);
                results.push({
                    statusCode: 200,
                    body: JSON.stringify({
                        messageId: messageId,
                        status: 'Revoke Success!',
                        revokeToken: messageData.revoke_token
                    })
                });
            }
        } catch (error) {
            console.error(`[${messageId}] Failed to process revoke token request:`, error);
            errors.push({
                statusCode: 500,
                body: JSON.stringify({
                    messageId: messageId,
                    status: 'Error',
                    errorMessage: `Failed to process revoke token: ${error.message}`
                })
            });
        }
    }
    return { 
        results: results,
        errors: errors
    };
};

module.exports = { handler };

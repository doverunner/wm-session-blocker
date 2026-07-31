const { AWS_SNS_EVENT_SOURCE, DETECTION_STATUS } = require('./constants.js');
const { verifyWatermarkToken } = require('./api-modules.js');
const { validateRuleNotDuplicated, createBlockingRule } = require('./aws-waf-modules.js');

/**
 * AWS Lambda handler that reacts to DoveRunner detection status notifications.
 *
 * @param {Object} event - SNS event containing detection status notification records
 * @returns {Promise<{results: Object[], errors: Object[]}>} Per-record processing results and errors
 */
const handler = async (event) => {
    const records = event.Records || [];
    console.log(`Received ${records.length} record(s)`);
    const results = [];
    const errors = [];

    for (const record of records) {
        let messageId;
        try {
            // only SNS records are processed; anything else is ignored.
            if (record.EventSource !== AWS_SNS_EVENT_SOURCE) {
                continue;
            }
            messageId = record.Sns.MessageId;

            const messageData = JSON.parse(record.Sns.Message);
            const detectionId = messageData.detection_id;
            const detectionStatus = messageData.detection_status;

            // Revoke is performed ONLY for a completed detection (FD004).
            // Error / failed (and any other non-completed) states are not blocking targets.
            if (detectionStatus !== DETECTION_STATUS.COMPLETED) {
                console.log(`[${messageId}] Skip revoke - detectionId=${detectionId}, detection_status=${detectionStatus} (revoke runs only on ${DETECTION_STATUS.COMPLETED})`);
                results.push({
                    statusCode: 200,
                    body: JSON.stringify({
                        messageId: messageId,
                        status: 'Skipped (not a completed detection)',
                        detectionId: detectionId,
                        detectionStatus: detectionStatus
                    })
                });
                continue;
            }

            const watermarkToken = messageData.watermark_token;
            if (!watermarkToken) {
                throw new Error('watermark_token is missing in the completed detection notification');
            }

            // Step 1: Check if the watermark token is already registered in AWS WAF
            await validateRuleNotDuplicated(watermarkToken);

            // Step 2: Verify the watermark token with DoveRunner API
            await verifyWatermarkToken(watermarkToken);

            // Step 3: Add a blocking rule for the watermark token to AWS WAF
            await createBlockingRule(watermarkToken);

            console.log(`[${messageId}] Revoke completed - detectionId=${detectionId}`);
            results.push({
                statusCode: 200,
                body: JSON.stringify({
                    messageId: messageId,
                    status: 'Revoke Success!',
                    detectionId: detectionId
                })
            });
        } catch (error) {
            console.error(`[${messageId}] Failed to process detection notification:`, error.message);
            errors.push({
                statusCode: 500,
                body: JSON.stringify({
                    messageId: messageId,
                    status: 'Error',
                    errorMessage: `Failed to process detection notification: ${error.message}`
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

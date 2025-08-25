const { AWS_WAF_REGION, AWS_WAF_SCOPE, RULE_BASE_NAME } = require('./constants.js');
const config = require("./config.json");
const {
    WAFV2Client,
    GetWebACLCommand,
    UpdateWebACLCommand
} = require("@aws-sdk/client-wafv2");

const wafClient = new WAFV2Client({ region: AWS_WAF_REGION });

/**
 * Checks if a revoke token is already registered in AWS WAF rules
 * @param {string} revokeToken - The watermark revoke token to check
 * @throws {Error} If token is already registered or check fails
 */
async function validateRuleNotDuplicated(revokeToken) {
    const base64Url = toBase64Url(revokeToken)
    const searchString = '/' + base64Url

    try {
        const getWebAclCmd = new GetWebACLCommand({
            Scope: AWS_WAF_SCOPE,
            Id: config.aws_waf_web_acl_id,
            Name: config.aws_waf_web_acl_name
        });

        const webAclResponse = await wafClient.send(getWebAclCmd);
        const existingRules = webAclResponse.WebACL.Rules || [];

        for (const rule of existingRules) {
            const existingSearchString = rule.Statement?.ByteMatchStatement?.SearchString;
            const isUriPathMatch = rule.Statement?.ByteMatchStatement?.FieldToMatch?.UriPath !== undefined;

            if (existingSearchString && isUriPathMatch) {
                if (Buffer.compare(existingSearchString, Buffer.from(searchString)) === 0) {
                    console.error('[validateRuleNotDuplicated] Duplicate revoke token detected:', {
                        rule_name: rule.Name,
                        rule_priority: rule.Priority,
                        revoke_token: searchString
                    });
                    throw new Error(`Revoke token '${revokeToken}' is already registered in WAF rule: ${rule.Name}`);
                }
            }
        }
    } catch (error) {
        console.error('[validateRuleNotDuplicated] Error checking revoke token in WAF:', error);
        throw error;
    }
}

/**
 * Adds a new WAF rule to block requests containing the revoke token
 * @param {string} revokeToken - The revoke token to block
 * @throws {Error} If rule creation fails
 */
async function createBlockingRule(revokeToken) {
    const base64Url = toBase64Url(revokeToken)
    const searchString = '/' + base64Url;

    try {
        const getWebAclCmd = new GetWebACLCommand({
            Scope: AWS_WAF_SCOPE,
            Id: config.aws_waf_web_acl_id,
            Name: config.aws_waf_web_acl_name
        });
        const webAclResponse = await wafClient.send(getWebAclCmd);
        const currentWebAcl = webAclResponse.WebACL;

        // Define new blocking rule
        // You can customize this rule as you want.
        const newRuleName = `${RULE_BASE_NAME}${base64Url}`;
        const blockingRule = {
            Name: newRuleName,
            Priority: (currentWebAcl.Rules?.length || 0) + 1,
            Statement: {
                ByteMatchStatement: {
                    SearchString: Buffer.from(searchString),
                    FieldToMatch: {
                        UriPath: {}     // Uri Match Rule
                    },
                    TextTransformations: [
                        {
                            Priority: 0,
                            Type: "NONE"
                        }
                    ],
                    PositionalConstraint: "CONTAINS"
                }
            },
            Action: {
                Block: {}
            },
            VisibilityConfig: {
                SampledRequestsEnabled: true,
                CloudWatchMetricsEnabled: true,
                MetricName: newRuleName
            }
        };

        // Add new rule to existing rules
        const updatedRules = [...(currentWebAcl.Rules || []), blockingRule];

        // Update WebACL with new rule
        const updateWebAclCmd = new UpdateWebACLCommand({
            Scope: AWS_WAF_SCOPE,
            Id: config.aws_waf_web_acl_id,
            Name: currentWebAcl.Name,
            DefaultAction: currentWebAcl.DefaultAction,
            Rules: updatedRules,
            VisibilityConfig: currentWebAcl.VisibilityConfig,
            LockToken: webAclResponse.LockToken
        });
        await wafClient.send(updateWebAclCmd);
        console.log('[createBlockingRule] Successfully added blocking rule:', newRuleName);
    } catch (error) {
        console.error('[createBlockingRule] Error adding revoke token blocking rule to WAF:', error);
        throw error;
    }
}

function toBase64Url(input) {
    return input.replace(/=+$/, "").replace(/[+/]/g, m => (m === "+" ? "-" : "_"));
}

module.exports = {
    validateRuleNotDuplicated,
    createBlockingRule
};

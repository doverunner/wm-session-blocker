const {validateRuleNotDuplicated, createBlockingRule} = require('../aws-waf-modules');

jest.mock('@aws-sdk/client-wafv2', () => {
    const mockSend = jest.fn();

    return {
        WAFV2Client: jest.fn().mockImplementation(() => ({
            send: mockSend
        })),
        GetWebACLCommand: jest.fn(),
        UpdateWebACLCommand: jest.fn(),
        mockSend
    };
});

const {mockSend: mockWafSend} = require('@aws-sdk/client-wafv2');

describe('aws-waf-modules test', () => {
    const REVOKE_TOKEN = 'test-revoke-token';
    const toBase64Url = (input) => {
        return input.replace(/=+$/, "").replace(/[+/]/g, m => (m === "+" ? "-" : "_"));
    };
    const BASE64_URL_TOKEN = toBase64Url(REVOKE_TOKEN);
    const SEARCH_STRING = '/' + BASE64_URL_TOKEN;

    beforeEach(() => {
        jest.clearAllMocks();
        console.error = jest.fn();
        console.log = jest.fn();
    });

    describe('validateRuleNotDuplicated test', () => {
        describe('when token is not registered in WAF', () => {
            it('should pass validation', async () => {
                // given
                const mockWebACL = {
                    WebACL: {
                        Rules: [
                            {
                                Name: 'existing-rule',
                                Priority: 1,
                                Statement: {
                                    ByteMatchStatement: {
                                        SearchString: Buffer.from('/different-token')
                                    }
                                }
                            }
                        ]
                    }
                };
                mockWafSend.mockResolvedValue(mockWebACL);

                // when
                const result = validateRuleNotDuplicated(REVOKE_TOKEN);

                // then
                await expect(result).resolves.not.toThrow();
                expect(mockWafSend).toHaveBeenCalledTimes(1);
            });
        });

        describe('when token is already registered in WAF', () => {
            it('should throw duplicate token error', async () => {
                // given
                const existingRuleName = 'existing-rule';
                const mockWebACL = {
                    WebACL: {
                        Rules: [
                            {
                                Name: existingRuleName,
                                Priority: 1,
                                Statement: {
                                    ByteMatchStatement: {
                                        SearchString: Buffer.from(SEARCH_STRING),
                                        FieldToMatch: {
                                            UriPath: {}
                                        },
                                    }
                                }
                            }
                        ]
                    }
                };
                mockWafSend.mockResolvedValue(mockWebACL);

                // when
                const result = validateRuleNotDuplicated(REVOKE_TOKEN);

                // then
                await expect(result).rejects.toThrow(
                    `Revoke token '${REVOKE_TOKEN}' is already registered in WAF rule: ${existingRuleName}`
                );
            });
        });
    });

    describe('createBlockingRule test', () => {
        describe('when adding blocking rule to empty WAF', () => {
            it('should add rule successfully', async () => {
                // given
                const mockWebACL = {
                    WebACL: {
                        Name: 'TEST-web-acl',
                        DefaultAction: {Allow: {}},
                        Rules: [],
                        VisibilityConfig: {
                            SampledRequestsEnabled: true,
                            CloudWatchMetricsEnabled: true,
                            MetricName: 'TEST-web-acl'
                        }
                    },
                    LockToken: 'test-lock-token'
                };
                mockWafSend.mockResolvedValueOnce(mockWebACL);

                // when
                const result = createBlockingRule(REVOKE_TOKEN);

                // then
                await expect(result).resolves.not.toThrow();
                expect(mockWafSend).toHaveBeenCalledTimes(2);
                expect(console.log).toHaveBeenCalledWith(
                    '[createBlockingRule] Successfully added blocking rule:',
                    `waf-uri-contains-${BASE64_URL_TOKEN}`
                );
            });

            it('should handle UpdateWebACL error', async () => {
                // given
                const mockWebACL = {
                    WebACL: {
                        Name: 'TEST-web-acl',
                        DefaultAction: {Allow: {}},
                        Rules: [],
                        VisibilityConfig: {
                            SampledRequestsEnabled: true,
                            CloudWatchMetricsEnabled: true,
                            MetricName: 'TEST-web-acl'
                        }
                    },
                    LockToken: 'test-lock-token'
                };
                const mockError = new Error('WAF UpdateWebACL failed');
                mockWafSend
                    .mockResolvedValueOnce(mockWebACL)
                    .mockRejectedValueOnce(mockError);

                // when & then
                await expect(createBlockingRule(REVOKE_TOKEN)).rejects.toThrow('WAF UpdateWebACL failed');
                expect(console.error).toHaveBeenCalledWith(
                    '[createBlockingRule] Error adding revoke token blocking rule to WAF:',
                    mockError
                );
            });
        });
    });
});
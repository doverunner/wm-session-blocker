const {handler} = require('../index');
const {verifyRevokeToken} = require('../api-modules');
const {validateRuleNotDuplicated, createBlockingRule} = require('../aws-waf-modules');

jest.mock('../api-modules');
jest.mock('../aws-waf-modules');

const mockVerifyRevokeToken = verifyRevokeToken;
const mockValidateRuleNotDuplicated = validateRuleNotDuplicated;
const mockCreateBlockingRule = createBlockingRule;

describe('index handler test', () => {
    const REVOKE_TOKEN = 'test-revoke-token';
    const SITE_ID = 'TEST';
    const TEST_MESSAGE_ID = 'test-message-id';

    beforeEach(() => {
        jest.clearAllMocks();
        console.log = jest.fn();
        console.error = jest.fn();
    });

    const createSNSEvent = (revokeToken = REVOKE_TOKEN, siteId = SITE_ID, messageId = TEST_MESSAGE_ID) => ({
        Records: [
            {
                EventSource: 'aws:sns',
                Sns: {
                    MessageId: messageId,
                    Message: JSON.stringify({
                        revoke_token: revokeToken,
                        site_id: siteId
                    })
                }
            }
        ]
    });

    describe('successful processing test', () => {
        describe('when processing valid SNS event', () => {
            it('should complete all steps successfully', async () => {
                // given
                mockValidateRuleNotDuplicated.mockResolvedValue(undefined);
                mockVerifyRevokeToken.mockResolvedValue(undefined);
                mockCreateBlockingRule.mockResolvedValue(undefined);
                const event = createSNSEvent();

                // when
                const result = await handler(event);

                // then
                expect(mockValidateRuleNotDuplicated).toHaveBeenCalledWith(REVOKE_TOKEN);
                expect(mockVerifyRevokeToken).toHaveBeenCalledWith(REVOKE_TOKEN);
                expect(mockCreateBlockingRule).toHaveBeenCalledWith(REVOKE_TOKEN);

                expect(result.results).toHaveLength(1);
                expect(result.results[0]).toEqual({
                    statusCode: 200,
                    body: JSON.stringify({
                        messageId: TEST_MESSAGE_ID,
                        status: 'Revoke Success!',
                        revokeToken: REVOKE_TOKEN
                    })
                });
                expect(result.errors).toHaveLength(0);
            });
        });
    });

    describe('error handling test', () => {
        describe('when duplicate token is detected', () => {
            it('should return error response', async () => {
                // given
                mockValidateRuleNotDuplicated.mockRejectedValue(
                    new Error('Token already registered')
                );
                const event = createSNSEvent();

                // when
                const result = await handler(event);

                // then
                expect(result.results).toHaveLength(0);
                expect(result.errors).toHaveLength(1);
                expect(result.errors[0]).toEqual({
                    statusCode: 500,
                    body: JSON.stringify({
                        messageId: TEST_MESSAGE_ID,
                        status: 'Error',
                        errorMessage: 'Failed to process revoke token: Token already registered'
                    })
                });
            });
        });

        describe('when token verification fails', () => {
            it('should return error response', async () => {
                // given
                mockValidateRuleNotDuplicated.mockResolvedValue(undefined);
                mockVerifyRevokeToken.mockRejectedValue(
                    new Error('Token verification failed')
                );
                const event = createSNSEvent();

                // when
                const result = await handler(event);

                // then
                expect(result.results).toHaveLength(0);
                expect(result.errors).toHaveLength(1);
                expect(result.errors[0].statusCode).toBe(500);
                const errorBody = JSON.parse(result.errors[0].body);
                expect(errorBody.errorMessage).toEqual('Failed to process revoke token: Token verification failed');
            });
        });

        describe('when WAF rule addition fails', () => {
            it('should return error response', async () => {
                // given
                mockValidateRuleNotDuplicated.mockResolvedValue(undefined);
                mockVerifyRevokeToken.mockResolvedValue(undefined);
                mockCreateBlockingRule.mockRejectedValue(
                    new Error('WAF update failed')
                );
                const event = createSNSEvent();

                // when
                const result = await handler(event);

                // then
                expect(result.results).toHaveLength(0);
                expect(result.errors).toHaveLength(1);
                expect(result.errors[0].statusCode).toBe(500);
                const errorBody = JSON.parse(result.errors[0].body);
                expect(errorBody.errorMessage).toEqual(expect.stringContaining('Failed to process revoke token: WAF update failed'));
            });
        });

        describe('when SNS message contains invalid JSON', () => {
            it('should return error response', async () => {
                // given
                const event = {
                    Records: [
                        {
                            EventSource: 'aws:sns',
                            Sns: {
                                MessageId: TEST_MESSAGE_ID,
                                Message: 'invalid json'
                            }
                        }
                    ]
                };

                // when
                const result = await handler(event);

                // then
                expect(result.results).toHaveLength(0);
                expect(result.errors).toHaveLength(1);
                expect(result.errors[0].statusCode).toBe(500);
                const errorBody = JSON.parse(result.errors[0].body);
                expect(errorBody.errorMessage).toEqual(expect.stringContaining('Failed to process revoke token'));
            });
        });
    });
});
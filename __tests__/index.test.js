const {handler} = require('../index');
const {verifyWatermarkToken} = require('../api-modules');
const {validateRuleNotDuplicated, createBlockingRule} = require('../aws-waf-modules');
const {DETECTION_STATUS} = require('../constants');

jest.mock('../api-modules');
jest.mock('../aws-waf-modules');

const mockVerifyWatermarkToken = verifyWatermarkToken;
const mockValidateRuleNotDuplicated = validateRuleNotDuplicated;
const mockCreateBlockingRule = createBlockingRule;

describe('index handler test', () => {
    const WATERMARK_TOKEN = 'test-watermark-token';
    const TEST_MESSAGE_ID = 'test-message-id';
    const DETECTION_ID = 12345;

    beforeEach(() => {
        jest.clearAllMocks();
        console.log = jest.fn();
        console.error = jest.fn();
    });

    // Completed (FD004) detection notification — carries watermark_token and forensic_mark.
    const createCompletedEvent = (watermarkToken = WATERMARK_TOKEN, messageId = TEST_MESSAGE_ID) => ({
        Records: [
            {
                EventSource: 'aws:sns',
                Sns: {
                    MessageId: messageId,
                    Message: JSON.stringify({
                        detection_id: DETECTION_ID,
                        detection_status: DETECTION_STATUS.COMPLETED,
                        forensic_mark: '0000000000000001',
                        watermark_token: watermarkToken
                    })
                }
            }
        ]
    });

    // Non-completed (error/failed) detection notification — carries error_code / error_message.
    const createStatusEvent = (detectionStatus, messageId = TEST_MESSAGE_ID) => ({
        Records: [
            {
                EventSource: 'aws:sns',
                Sns: {
                    MessageId: messageId,
                    Message: JSON.stringify({
                        detection_id: DETECTION_ID,
                        detection_status: detectionStatus,
                        error_code: 'D2001',
                        error_message: 'detection error'
                    })
                }
            }
        ]
    });

    describe('successful processing test', () => {
        describe('when processing a completed (FD004) detection notification', () => {
            it('should complete all revoke steps successfully', async () => {
                // given
                mockValidateRuleNotDuplicated.mockResolvedValue(undefined);
                mockVerifyWatermarkToken.mockResolvedValue(undefined);
                mockCreateBlockingRule.mockResolvedValue(undefined);
                const event = createCompletedEvent();

                // when
                const result = await handler(event);

                // then
                expect(mockValidateRuleNotDuplicated).toHaveBeenCalledWith(WATERMARK_TOKEN);
                expect(mockVerifyWatermarkToken).toHaveBeenCalledWith(WATERMARK_TOKEN);
                expect(mockCreateBlockingRule).toHaveBeenCalledWith(WATERMARK_TOKEN);

                expect(result.results).toHaveLength(1);
                expect(result.results[0]).toEqual({
                    statusCode: 200,
                    body: JSON.stringify({
                        messageId: TEST_MESSAGE_ID,
                        status: 'Revoke Success!',
                        detectionId: DETECTION_ID
                    })
                });
                expect(result.errors).toHaveLength(0);
            });
        });
    });

    describe('non-completed status test', () => {
        describe.each([
            ['error (FD006)', DETECTION_STATUS.ERROR],
            ['failed (FD007)', DETECTION_STATUS.FAILED]
        ])('when processing a %s notification', (_label, detectionStatus) => {
            it('should skip revoke without calling WAF or verify', async () => {
                // given
                const event = createStatusEvent(detectionStatus);

                // when
                const result = await handler(event);

                // then
                expect(mockValidateRuleNotDuplicated).not.toHaveBeenCalled();
                expect(mockVerifyWatermarkToken).not.toHaveBeenCalled();
                expect(mockCreateBlockingRule).not.toHaveBeenCalled();

                expect(result.errors).toHaveLength(0);
                expect(result.results).toHaveLength(1);
                const body = JSON.parse(result.results[0].body);
                expect(body.status).toContain('Skipped');
                expect(body.detectionId).toBe(DETECTION_ID);
                expect(body.detectionStatus).toBe(detectionStatus);
            });
        });

        describe('when a completed notification is missing watermark_token', () => {
            it('should return error response', async () => {
                // given
                const event = {
                    Records: [
                        {
                            EventSource: 'aws:sns',
                            Sns: {
                                MessageId: TEST_MESSAGE_ID,
                                Message: JSON.stringify({detection_status: DETECTION_STATUS.COMPLETED})
                            }
                        }
                    ]
                };

                // when
                const result = await handler(event);

                // then
                expect(mockCreateBlockingRule).not.toHaveBeenCalled();
                expect(result.results).toHaveLength(0);
                expect(result.errors).toHaveLength(1);
                const errorBody = JSON.parse(result.errors[0].body);
                expect(errorBody.errorMessage).toEqual(expect.stringContaining('watermark_token is missing'));
            });
        });
    });

    describe('edge cases', () => {
        it('should return empty results when event has no Records', async () => {
            const result = await handler({});

            expect(result.results).toHaveLength(0);
            expect(result.errors).toHaveLength(0);
        });

        it('should ignore non-SNS records', async () => {
            const event = { Records: [{ EventSource: 'aws:s3' }] };

            const result = await handler(event);

            expect(result.results).toHaveLength(0);
            expect(result.errors).toHaveLength(0);
        });
    });

    describe('error handling test', () => {
        describe('when duplicate token is detected', () => {
            it('should return error response', async () => {
                // given
                mockValidateRuleNotDuplicated.mockRejectedValue(
                    new Error('Token already registered')
                );
                const event = createCompletedEvent();

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
                        errorMessage: 'Failed to process detection notification: Token already registered'
                    })
                });
            });
        });

        describe('when token verification fails', () => {
            it('should return error response', async () => {
                // given
                mockValidateRuleNotDuplicated.mockResolvedValue(undefined);
                mockVerifyWatermarkToken.mockRejectedValue(
                    new Error('Token verification failed')
                );
                const event = createCompletedEvent();

                // when
                const result = await handler(event);

                // then
                expect(result.results).toHaveLength(0);
                expect(result.errors).toHaveLength(1);
                expect(result.errors[0].statusCode).toBe(500);
                const errorBody = JSON.parse(result.errors[0].body);
                expect(errorBody.errorMessage).toEqual('Failed to process detection notification: Token verification failed');
            });
        });

        describe('when WAF rule addition fails', () => {
            it('should return error response', async () => {
                // given
                mockValidateRuleNotDuplicated.mockResolvedValue(undefined);
                mockVerifyWatermarkToken.mockResolvedValue(undefined);
                mockCreateBlockingRule.mockRejectedValue(
                    new Error('WAF update failed')
                );
                const event = createCompletedEvent();

                // when
                const result = await handler(event);

                // then
                expect(result.results).toHaveLength(0);
                expect(result.errors).toHaveLength(1);
                expect(result.errors[0].statusCode).toBe(500);
                const errorBody = JSON.parse(result.errors[0].body);
                expect(errorBody.errorMessage).toEqual(expect.stringContaining('Failed to process detection notification: WAF update failed'));
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
                expect(errorBody.errorMessage).toEqual(expect.stringContaining('Failed to process detection notification'));
            });
        });
    });
});

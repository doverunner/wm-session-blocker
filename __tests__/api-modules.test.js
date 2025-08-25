const axios = require('axios');
const {verifyRevokeToken} = require('../api-modules');
const {API_BASE_URL} = require("../constants");

jest.mock('axios');
jest.mock('../config.json', () => ({
    site_id: 'TEST'
}));

const mockAxios = axios;

describe('api-modules test', () => {
    const REVOKE_TOKEN = 'test-revoke-token';
    const SITE_ID = 'TEST';

    beforeEach(() => {
        jest.clearAllMocks();
        console.error = jest.fn();
    });

    describe('verifyRevokeToken test', () => {
        describe('when verifying a valid revoke token', () => {
            it('should verify token successfully', async () => {
                // given
                const mockJwtToken = 'mock-jwt-token';
                mockAxios.get.mockResolvedValueOnce({
                    data: {
                        data: {
                            token: mockJwtToken
                        }
                    }
                });
                mockAxios.post.mockResolvedValueOnce({
                    data: {
                        data: {
                            is_valid: true
                        }
                    }
                });

                // when
                const result = verifyRevokeToken(REVOKE_TOKEN);

                // then
                await expect(result).resolves.not.toThrow();

                expect(mockAxios.get).toHaveBeenCalledWith(
                    expect.stringContaining(`${API_BASE_URL}api/token/${SITE_ID}`),
                    expect.objectContaining({
                        headers: expect.objectContaining({
                            'Authorization': expect.stringContaining('Basic'),
                            'Content-Type': 'application/json'
                        }),
                        timeout: 3000
                    })
                );

                expect(mockAxios.post).toHaveBeenCalledWith(
                    expect.stringContaining(`${API_BASE_URL}api/v2/detect/${SITE_ID}/revoke-token/verify`),
                    {revoke_token: REVOKE_TOKEN},
                    expect.objectContaining({
                        headers: expect.objectContaining({
                            'Authorization': mockJwtToken,
                            'Content-Type': 'application/json'
                        }),
                        timeout: 3000
                    })
                );
            });
        });

        describe('when token is invalid', () => {
            it('should throw verification error', async () => {
                // given
                mockAxios.get.mockResolvedValueOnce({
                    data: {
                        data: {
                            token: 'mock-jwt-token'
                        }
                    }
                });
                mockAxios.post.mockResolvedValueOnce({
                    data: {
                        data: {
                            is_valid: false
                        }
                    }
                });

                // when
                const result = verifyRevokeToken(REVOKE_TOKEN);

                // then
                await expect(result).rejects.toThrow('Revoke token verification failed');

                expect(console.error).toHaveBeenCalledWith(
                    '[verifyRevokeToken] Token validation failed:',
                    expect.objectContaining({
                        revoke_token: REVOKE_TOKEN
                    })
                );
            });
        });

        describe('when JWT token retrieval fails', () => {
            it('should throw JWT token error', async () => {
                // given
                mockAxios.get.mockResolvedValueOnce({
                    data: {
                        data: {}
                    }
                });

                // when
                const result = verifyRevokeToken(REVOKE_TOKEN);

                // then
                await expect(result).rejects.toThrow('Failed to retrieve JWT token');
            });
        });
    });
});
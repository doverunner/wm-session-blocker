const axios = require('axios');
const { API_BASE_URL } = require('./constants.js');
const config = require('./config.json');

/**
 * Verifies the validity of a revoke token with DoveRunner API
 * @param {string} revokeToken - 7-byte watermark revoke token to verify
 * @throws {Error} When token verification fails or token is invalid
 */
async function verifyRevokeToken(revokeToken) {
    const jwtToken = await getJwtToken();
    const apiUrl = `${API_BASE_URL}api/v2/detect/${config.site_id}/revoke-token/verify`;

    const response = await axios.post(apiUrl, { revoke_token: revokeToken }, {
        headers: {
            'Authorization': jwtToken,
            'Content-Type': 'application/json'
        },
        timeout: 3000
    });

    const isTokenValid = response.data.data.is_valid;
    if (!isTokenValid) {
        console.error('[verifyRevokeToken] Token validation failed:', {
            revoke_token: revokeToken,
            response: response.data,
            site_id: config.site_id
        });
        throw new Error(`Revoke token verification failed: ${JSON.stringify(response.data)}`);
    }
}

/**
 * Retrieves JWT token from DoveRunner API
 * @returns {Promise<string>} JWT token for API authentication
 * @throws {Error} When token retrieval fails
 */
async function getJwtToken() {
    const apiUrl = `${API_BASE_URL}api/token/${config.site_id}`;
    const authHeader = createBasicAuthHeader(config.account_id, config.access_key);
    const response = await axios.get(apiUrl, {
        headers: {
            'Authorization': authHeader,
            'Content-Type': 'application/json'
        },
        timeout: 3000
    });

    const jwtToken = response.data.data.token;
    if (!jwtToken) {
        console.error('[getJwtToken] JWT token retrieval failed:', {
            response_data: response.data,
            site_id: config.site_id
        });
        throw new Error(`Failed to retrieve JWT token: ${JSON.stringify(response.data)}`);
    }
    return jwtToken;
}

/**
 * Creates Basic Authentication token for DoveRunner API
 * @param {string} accountId - DoveRunner account ID
 * @param {string} accessKey - DoveRunner access key
 * @returns {string} Basic authentication header value
 */
function createBasicAuthHeader(accountId, accessKey) {
    return `Basic ${Buffer.from(`${accountId}:${accessKey}`).toString('base64')}`;
}

module.exports = {
    verifyRevokeToken
};
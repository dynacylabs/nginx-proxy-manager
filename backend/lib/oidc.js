const { Issuer, generators } = require('openid-client');
const settingModel = require('../models/setting');
const logger = require('../logger').global;

let cachedClient = null;
let cachedSettings = null;

/**
 * Get OIDC settings from database
 * @returns {Promise<Object>}
 */
async function getOidcSettings() {
	const settings = await settingModel
		.query()
		.where('id', 'oidc-config')
		.first();
	
	if (!settings || !settings.meta) {
		return null;
	}
	
	return settings.meta;
}

/**
 * Get or create OIDC client
 * @returns {Promise<Object>}
 */
async function getOidcClient() {
	const settings = await getOidcSettings();
	
	if (!settings || !settings.enabled) {
		throw new Error('OIDC is not configured or enabled');
	}
	
	// Check if we can use cached client
	const settingsHash = JSON.stringify(settings);
	if (cachedClient && cachedSettings === settingsHash) {
		return cachedClient;
	}
	
	try {
		logger.info('Initializing OIDC client for issuer: ' + settings.issuer_url);
		
		const issuer = await Issuer.discover(settings.issuer_url);
		logger.info('Discovered issuer: ' + issuer.metadata.issuer);
		
		const client = new issuer.Client({
			client_id: settings.client_id,
			client_secret: settings.client_secret,
			redirect_uris: [settings.redirect_uri],
			response_types: ['code'],
		});
		
		cachedClient = client;
		cachedSettings = settingsHash;
		
		return client;
	} catch (err) {
		logger.error('Failed to initialize OIDC client:', err);
		throw err;
	}
}

/**
 * Generate authorization URL
 * @returns {Promise<Object>} Object containing url and state
 */
async function getAuthorizationUrl() {
	const client = await getOidcClient();
	const settings = await getOidcSettings();
	
	const code_verifier = generators.codeVerifier();
	const code_challenge = generators.codeChallenge(code_verifier);
	const state = generators.state();
	const nonce = generators.nonce();
	
	const scope = settings.scope || 'openid email profile';
	
	const authUrl = client.authorizationUrl({
		scope: scope,
		code_challenge,
		code_challenge_method: 'S256',
		state,
		nonce,
	});
	
	return {
		url: authUrl,
		state,
		nonce,
		code_verifier
	};
}

/**
 * Exchange authorization code for tokens
 * @param {String} code
 * @param {String} code_verifier
 * @param {String} redirect_uri
 * @returns {Promise<Object>}
 */
async function exchangeCode(code, code_verifier, redirect_uri) {
	const client = await getOidcClient();
	
	try {
		// Try normal callback with validation
		const tokenSet = await client.callback(redirect_uri, { code }, {
			code_verifier
		});
		return tokenSet;
	} catch (err) {
		// If iss is missing from response params, try calling token endpoint directly
		if (err.message && err.message.includes('iss missing')) {
			logger.warn('iss missing from authorization response, attempting direct token exchange');
			
			// Manually exchange the code for tokens
			const tokenSet = await client.grant({
				grant_type: 'authorization_code',
				code: code,
				redirect_uri: redirect_uri,
				code_verifier: code_verifier
			});
			
			return tokenSet;
		}
		throw err;
	}
}

/**
 * Get user info from token
 * @param {String} access_token
 * @returns {Promise<Object>}
 */
async function getUserInfo(access_token) {
	const client = await getOidcClient();
	const userinfo = await client.userinfo(access_token);
	return userinfo;
}

/**
 * Clear cached client (useful when settings change)
 */
function clearCache() {
	cachedClient = null;
	cachedSettings = null;
	logger.info('OIDC client cache cleared');
}

module.exports = {
	getOidcSettings,
	getOidcClient,
	getAuthorizationUrl,
	exchangeCode,
	getUserInfo,
	clearCache
};

const express       = require('express');
const internalOidc  = require('../internal/oidc');
const internalToken = require('../internal/token');
const jwtdecode     = require('../lib/express/jwt-decode');
const settingModel  = require('../models/setting');
const oidcLib       = require('../lib/oidc');

let router = express.Router({
	caseSensitive: true,
	strict:        true,
	mergeParams:   true
});

/**
 * /api/oidc/config
 */
router
	.route('/config')
	.options((_, res) => {
		res.sendStatus(204);
	})

	/**
	 * GET /api/oidc/config
	 * 
	 * Get OIDC configuration (public info only)
	 */
	.get(async (req, res, next) => {
		try {
			const settings = await settingModel
				.query()
				.where('id', 'oidc-config')
				.first();

			if (!settings || !settings.meta || !settings.meta.enabled) {
				return res.status(200).send({
					enabled: false
				});
			}

			// Only send public info
			res.status(200).send({
				enabled: true,
				provider_name: settings.meta.provider_name || 'OIDC',
				button_text: settings.meta.button_text || 'Sign in with OIDC'
			});
		} catch (err) {
			next(err);
		}
	})

	/**
	 * PUT /api/oidc/config
	 * 
	 * Update OIDC configuration (admin only)
	 */
	.put(jwtdecode(), async (req, res, next) => {
		try {
			// Check admin permission
			await res.locals.access.can('settings:update');

			const config = req.body;

			// Validate required fields if enabling
			if (config.enabled) {
				if (!config.issuer_url || !config.client_id || !config.client_secret || !config.redirect_uri) {
					return res.status(400).send({
						error: {
							code: 400,
							message: 'Missing required OIDC configuration fields'
						}
					});
				}
			}

			// Update or create settings
			const existingSettings = await settingModel
				.query()
				.where('id', 'oidc-config')
				.first();

			let result;
			if (existingSettings) {
				result = await settingModel
					.query()
					.patchAndFetchById('oidc-config', {
						meta: config
					});
			} else {
				result = await settingModel
					.query()
					.insert({
						id: 'oidc-config',
						name: 'OIDC Configuration',
						description: 'OpenID Connect authentication configuration',
						meta: config
					});
			}

			// Clear cached client
			oidcLib.clearCache();

			res.status(200).send(result);
		} catch (err) {
			next(err);
		}
	});

/**
 * /api/oidc/test
 */
router
	.route('/test')
	.options((_, res) => {
		res.sendStatus(204);
	})

	/**
	 * POST /api/oidc/test
	 * 
	 * Test OIDC configuration without saving (admin only)
	 */
	.post(jwtdecode(), async (req, res, next) => {
		try {
			// Check admin permission
			await res.locals.access.can('settings:update', 'oidc-config');

			const testConfig = req.body;

			// Validate required fields
			if (!testConfig.issuer_url || !testConfig.client_id || !testConfig.client_secret) {
				return res.status(400).send({
					error: {
						code: 400,
						message: 'Missing required OIDC configuration fields for testing'
					}
				});
			}

			// Test the configuration by attempting discovery
			const { Issuer } = require('openid-client');
			
			try {
				const issuer = await Issuer.discover(testConfig.issuer_url);
				
				// Verify the client configuration
				const client = new issuer.Client({
					client_id: testConfig.client_id,
					client_secret: testConfig.client_secret,
					redirect_uris: [testConfig.redirect_uri],
					response_types: ['code']
				});

				res.status(200).send({
					success: true,
					message: 'OIDC configuration is valid',
					issuer: issuer.metadata.issuer,
					authorization_endpoint: issuer.metadata.authorization_endpoint,
					token_endpoint: issuer.metadata.token_endpoint
				});
			} catch (discoveryErr) {
				return res.status(400).send({
					error: {
						code: 400,
						message: 'Failed to discover OIDC issuer: ' + discoveryErr.message
					}
				});
			}
		} catch (err) {
			next(err);
		}
	});

/**
 * /api/oidc/authorize
 */
router
	.route('/authorize')
	.options((_, res) => {
		res.sendStatus(204);
	})

	/**
	 * GET /api/oidc/authorize
	 * 
	 * Initiate OIDC authorization flow
	 */
	.get(async (req, res, next) => {
		try {
			const authData = await internalOidc.getAuthorizationUrl();
			
			// Return auth URL and session data
			// The frontend will need to store state, nonce, and code_verifier
			res.status(200).send(authData);
		} catch (err) {
			next(err);
		}
	});

/**
 * /api/oidc/callback
 */
router
	.route('/callback')
	.options((_, res) => {
		res.sendStatus(204);
	})

	/**
	 * POST /api/oidc/callback
	 * 
	 * Handle OIDC callback
	 */
	.post(async (req, res, next) => {
		try {
			const { code, state, code_verifier, redirect_uri, nonce } = req.body;

			if (!code || !code_verifier || !redirect_uri) {
				return res.status(400).send({
					error: {
						code: 400,
						message: 'Missing required callback parameters'
					}
				});
			}

			const tokenData = await internalOidc.handleCallback({
				code,
				state,
				code_verifier,
				redirect_uri,
				nonce
			});

			res.status(200).send(tokenData);
		} catch (err) {
			next(err);
		}
	});

module.exports = router;

const _          = require('lodash');
const error      = require('../lib/error');
const oidcLib    = require('../lib/oidc');
const userModel  = require('../models/user');
const authModel  = require('../models/auth');
const gravatar   = require('gravatar');
const internalToken = require('./token');
const logger     = require('../logger').global;

module.exports = {

	/**
	 * Get OIDC authorization URL
	 * @returns {Promise<Object>}
	 */
	getAuthorizationUrl: async () => {
		try {
			const authData = await oidcLib.getAuthorizationUrl();
			return authData;
		} catch (err) {
			logger.error('Failed to get OIDC authorization URL:', err);
			throw new error.ConfigurationError('OIDC is not properly configured');
		}
	},

	/**
	 * Handle OIDC callback and create/update user
	 * @param {Object} data
	 * @param {String} data.code
	 * @param {String} data.state
	 * @param {String} data.code_verifier
	 * @param {String} data.redirect_uri
	 * @param {String} data.nonce
	 * @returns {Promise<Object>}
	 */
	handleCallback: async (data) => {
		try {
			// Exchange code for tokens
			const tokenSet = await oidcLib.exchangeCode(
				data.code,
				data.code_verifier,
				data.redirect_uri
			);

			// Verify nonce if provided
			if (data.nonce && tokenSet.claims().nonce !== data.nonce) {
				throw new error.AuthError('Invalid nonce');
			}

			// Get user info
			const claims = tokenSet.claims();
			const userInfo = claims.email ? claims : await oidcLib.getUserInfo(tokenSet.access_token);

			logger.info('OIDC user authenticated:', {
				sub: userInfo.sub,
				email: userInfo.email,
				name: userInfo.name
			});

			// Find or create user
			let user = await userModel
				.query()
				.where('email', userInfo.email.toLowerCase().trim())
				.andWhere('is_deleted', 0)
				.first();

			const settings = await oidcLib.getOidcSettings();
			const provider_name = settings.provider_name || 'oidc';

			if (user) {
				// Update existing user
				logger.info('Updating existing user for OIDC login:', user.id);
				
				user = await userModel
					.query()
					.patchAndFetchById(user.id, {
						is_oidc: 1,
						name: userInfo.name || user.name,
						nickname: userInfo.preferred_username || userInfo.nickname || user.nickname,
						avatar: userInfo.picture || gravatar.url(userInfo.email, {default: 'mm'})
					});

				// Update or create auth record
				let auth = await authModel
					.query()
					.where('user_id', user.id)
					.where('type', 'oidc')
					.first();

				if (auth) {
					await authModel
						.query()
						.patchAndFetchById(auth.id, {
							oidc_provider: provider_name,
							oidc_sub: userInfo.sub,
							meta: {
								email: userInfo.email,
								name: userInfo.name,
								updated_at: new Date().toISOString()
							}
						});
				} else {
					await authModel
						.query()
						.insert({
							user_id: user.id,
							type: 'oidc',
							oidc_provider: provider_name,
							oidc_sub: userInfo.sub,
							secret: '',
							meta: {
								email: userInfo.email,
								name: userInfo.name,
								created_at: new Date().toISOString()
							}
						});
				}
			} else {
				// Check if auto-provisioning is enabled
				if (!settings.auto_provision) {
					throw new error.AuthError('User does not exist and auto-provisioning is disabled');
				}

				// Create new user
				logger.info('Creating new user from OIDC login:', userInfo.email);

				const default_role = settings.default_role || 'user';
				
				user = await userModel
					.query()
					.insertAndFetch({
						email: userInfo.email.toLowerCase().trim(),
						name: userInfo.name || userInfo.email,
						nickname: userInfo.preferred_username || userInfo.nickname || userInfo.email.split('@')[0],
						avatar: userInfo.picture || gravatar.url(userInfo.email, {default: 'mm'}),
						is_disabled: 0,
						is_oidc: 1,
						roles: [default_role]
					});

				// Create auth record
				await authModel
					.query()
					.insert({
						user_id: user.id,
						type: 'oidc',
						oidc_provider: provider_name,
						oidc_sub: userInfo.sub,
						secret: '',
						meta: {
							email: userInfo.email,
							name: userInfo.name,
							created_at: new Date().toISOString()
						}
					});

				logger.info('Created new user:', user.id);
			}

			// Generate JWT token for the application
			return internalToken.getTokenFromUser(user);
		} catch (err) {
			logger.error('OIDC callback error:', err);
			if (err.error === 'invalid_grant') {
				throw new error.AuthError('Invalid or expired authorization code');
			}
			throw err;
		}
	}
};

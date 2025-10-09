const migrate_name = 'oidc-support';
const logger       = require('../logger').migrate;

/**
 * Migrate
 *
 * @see http://knexjs.org/#Schema
 *
 * @param   {Object}  knex
 * @param   {Promise} Promise
 * @returns {Promise}
 */
exports.up = function (knex/*, Promise*/) {
	logger.info('[' + migrate_name + '] Migrating Up...');

	return knex.schema.table('auth', (table) => {
		table.string('oidc_provider', 100).nullable();
		table.string('oidc_sub', 255).nullable();
	})
		.then(() => {
			logger.info('[' + migrate_name + '] auth Table altered');
		})
		.then(() => {
			return knex.schema.table('user', (table) => {
				table.integer('is_oidc').notNull().unsigned().defaultTo(0);
			});
		})
		.then(() => {
			logger.info('[' + migrate_name + '] user Table altered');
		});
};

/**
 * Undo Migrate
 *
 * @param   {Object}  knex
 * @param   {Promise} Promise
 * @returns {Promise}
 */
exports.down = function (knex/*, Promise*/) {
	logger.info('[' + migrate_name + '] Migrating Down...');

	return knex.schema.table('auth', (table) => {
		table.dropColumn('oidc_provider');
		table.dropColumn('oidc_sub');
	})
		.then(() => {
			return knex.schema.table('user', (table) => {
				table.dropColumn('is_oidc');
			});
		});
};

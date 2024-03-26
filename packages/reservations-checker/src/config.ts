import * as process from 'process';
import {
	getDatabaseConfig,
	getDatabaseConnectionString,
	getDevDatabaseConfig,
} from 'common/database';
import type { DatabaseConfig, PrismaConfig } from 'common/database';
import { getEnvOrThrow } from 'common/functions';

export interface Config extends PrismaConfig {
	/**
	 * The name of this application.
	 */
	app: string;

	/**
	 * The stage of the application, e.g. DEV, CODE, PROD.
	 */
	stage: string;

	/**
	 * The stack name, ie playground, deployTools.
	 */
	stack: string;

	databaseConnectionString: string;

	withQueryLogging: boolean;


}

export async function getConfig(): Promise<Config> {
	const queryLogging = (process.env['QUERY_LOGGING'] ?? 'false') === 'true';

	const stage = getEnvOrThrow('STAGE');

	const databaseConfig: DatabaseConfig =
		stage === 'DEV'
			? await getDevDatabaseConfig()
			: await getDatabaseConfig(stage, 'repocop');

	return {
		app: getEnvOrThrow('APP'),
		stage,
		stack: getEnvOrThrow('STACK'),
		databaseConnectionString: getDatabaseConnectionString(databaseConfig),
		withQueryLogging: queryLogging
	};
}

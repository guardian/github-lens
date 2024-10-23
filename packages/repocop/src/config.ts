import * as process from 'process';
import { getEnvOrThrow } from 'common/functions';
import {
	getDatabaseConfig,
	getDatabaseConnectionString,
	getDevDatabaseConfig,
} from 'common/src/database-setup';
import type { DatabaseConfig, PrismaConfig } from 'common/src/database-setup';

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

	/**
	 * The ARN of the Anghammarad SNS topic.
	 */
	anghammaradSnsTopic: string;

	/**
	 * The ARN of the interactive-monitor topic.
	 */
	interactiveMonitorSnsTopic: string;

	/**
	 * Repositories that should not be processed, for example, because they are not owned by a team in Product and Engineering.
	 */
	ignoredRepositoryPrefixes: string[];

	/**
	 * Flag to send digests to teams.
	 */
	sendDigest: boolean;

	/**
	 * The number of repositories to send to the interactive monitor for evaluation.
	 */
	interactivesCount: number;

	/**
	 * Flag to enable branch protection.
	 */
	branchProtectionEnabled: boolean;

	/**
	 * Flag to enable creation of Snyk integration PRs
	 */
	snykIntegrationPREnabled: boolean;

	/**
	 * The ARN of the Snyk Integrator input topic.
	 */
	snykIntegratorTopic: string;

	/**
	 * The ARN of the Dependency Graph Integrator input topic.
	 */
	dependencyGraphIntegratorTopic: string;

	/**
	 * The name of the GitHub organisation that owns the repositories.
	 */
	gitHubOrg: string;
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
		anghammaradSnsTopic: getEnvOrThrow('ANGHAMMARAD_SNS_ARN'),
		interactiveMonitorSnsTopic: getEnvOrThrow('INTERACTIVE_MONITOR_TOPIC_ARN'),
		databaseConnectionString: getDatabaseConnectionString(databaseConfig),
		withQueryLogging: queryLogging,
		sendDigest: process.env.SEND_DIGEST === 'false' ? false : true,
		ignoredRepositoryPrefixes: [
			'guardian/esd-', // ESD team
			'guardian/pluto-', // Multimedia team
		],
		interactivesCount: Number(getEnvOrThrow('INTERACTIVES_COUNT')),
		branchProtectionEnabled: process.env.BRANCH_PROTECTION_ENABLED === 'true',
		snykIntegrationPREnabled:
			process.env.SNYK_INTEGRATION_PR_ENABLED === 'true',
		snykIntegratorTopic: getEnvOrThrow('SNYK_INTEGRATOR_INPUT_TOPIC_ARN'),
		dependencyGraphIntegratorTopic: getEnvOrThrow(
			'DEPENDENCY_GRAPH_INPUT_TOPIC_ARN',
		),
		gitHubOrg: process.env['GITHUB_ORG'] ?? 'guardian',
	};
}

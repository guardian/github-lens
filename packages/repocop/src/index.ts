import { CloudWatchClient } from '@aws-sdk/client-cloudwatch';
import type {
	PrismaClient,
	repocop_github_repository_rules,
} from '@prisma/client';
import { awsClientConfig } from 'common/aws';
import { getPrismaClient } from 'common/database';
import { partition, stageAwareOctokit } from 'common/functions';
import type { Config } from './config';
import { getConfig } from './config';
import {
	collectAndFormatUrgentSnykAlerts,
	evaluateRepositories,
	testExperimentalRepocopFeatures,
} from './evaluation/repository';
import { sendToCloudwatch } from './metrics';
import {
	getDependabotVulnerabilities,
	getRepoOwnership,
	getRepositories,
	getRepositoryBranches,
	getRepositoryLanguages,
	getSnykIssues,
	getSnykProjects,
	getStacks,
	getTeams,
} from './query';
import { protectBranches } from './remediation/branch-protector/branch-protection';
import { sendUnprotectedRepo } from './remediation/snyk-integrator/send-to-sns';
import { sendPotentialInteractives } from './remediation/topics/topic-monitor-interactive';
import { applyProductionTopicAndMessageTeams } from './remediation/topics/topic-monitor-production';
import { createAndSendVulnerabilityDigests } from './remediation/vuln-digest/vuln-digest';
import type {
	AwsCloudFormationStack,
	RepocopVulnerability,
	Severity,
} from './types';
import { isProduction } from './utils';

async function writeEvaluationTable(
	evaluatedRepos: repocop_github_repository_rules[],
	prisma: PrismaClient,
) {
	console.log('Clearing the table');
	await prisma.repocop_github_repository_rules.deleteMany({});

	console.log(`Writing ${evaluatedRepos.length} records to table`);
	await prisma.repocop_github_repository_rules.createMany({
		data: evaluatedRepos,
	});

	console.log('Finished writing to table');
}

function logCounts( //TODO test this
	allVulnerabilities: RepocopVulnerability[],
	severity: Severity,
): string {
	const filteredVulns = [
		...new Set(
			allVulnerabilities
				.filter((v) => v.severity === severity)
				.map((v) => ({
					cves: v.cves.sort().join(', '),
					is_patchable: v.is_patchable,
				})),
		),
	];

	const patchableCount = filteredVulns.filter((v) => v.is_patchable).length;

	return `Found ${filteredVulns.length} ${severity} vulnerabilities, of which ${patchableCount} are patchable`;
}

async function writeVulnerabilitiesTable(
	vulnerabilities: RepocopVulnerability[],
	prisma: PrismaClient,
) {
	console.warn(logCounts(vulnerabilities, 'high'));
	console.warn(logCounts(vulnerabilities, 'critical'));

	console.log('Clearing the vulnerabilities table');
	await prisma.repocop_vulnerabilities.deleteMany({});

	console.log(`Writing ${vulnerabilities.length} vulnerabilities to table`);
	await prisma.repocop_vulnerabilities.createMany({
		data: vulnerabilities,
	});

	console.log('Finished writing to vulnerabilities table');
}

export async function main() {
	const config: Config = await getConfig();

	const prisma = getPrismaClient(config);
	const octokit = await stageAwareOctokit(config.stage);

	const [unarchivedRepos, archivedRepos] = partition(
		await getRepositories(prisma, config.ignoredRepositoryPrefixes),
		(repo) => !repo.archived,
	);
	const branches = await getRepositoryBranches(prisma, unarchivedRepos);
	const repoLanguages = await getRepositoryLanguages(prisma);
	const nonPlaygroundStacks: AwsCloudFormationStack[] = (
		await getStacks(prisma)
	).filter((s) => s.tags.Stack !== 'playground');
	const snykIssues = await getSnykIssues(prisma);
	const snykProjects = await getSnykProjects(prisma);
	const teams = await getTeams(prisma);
	const repoOwners = await getRepoOwnership(prisma);

	const productionRepos = unarchivedRepos.filter((repo) => isProduction(repo));

	const dependabotAlerts = await getDependabotVulnerabilities(
		productionRepos.map((r) => r.name),
		repoOwners,
		octokit,
	);

	const allUrgentSnykVulnerabilities = productionRepos.flatMap((repo) =>
		collectAndFormatUrgentSnykAlerts(
			repo,
			snykIssues,
			snykProjects,
			repoOwners,
		),
	);

	const allVulnerabilities =
		allUrgentSnykVulnerabilities.concat(dependabotAlerts);
	const evaluationResults: repocop_github_repository_rules[] =
		evaluateRepositories(
			unarchivedRepos,
			branches,
			repoOwners,
			repoLanguages,
			allVulnerabilities,
			snykProjects,
		);

	await writeVulnerabilitiesTable(allVulnerabilities, prisma);
	await writeEvaluationTable(evaluationResults, prisma);

	const awsConfig = awsClientConfig(config.stage);
	const cloudwatch = new CloudWatchClient(awsConfig);
	await sendToCloudwatch(evaluationResults, cloudwatch, config);

	testExperimentalRepocopFeatures(
		evaluationResults,
		unarchivedRepos,
		archivedRepos,
		nonPlaygroundStacks,
	);

	await createAndSendVulnerabilityDigests(config, teams, allVulnerabilities);

	await sendUnprotectedRepo(evaluationResults, config, repoLanguages);

	if (config.enableMessaging) {
		await sendPotentialInteractives(evaluationResults, config);

		if (config.branchProtectionEnabled) {
			await protectBranches(
				evaluationResults,
				repoOwners,
				teams,
				config,
				unarchivedRepos,
				octokit,
			);
		}
		await applyProductionTopicAndMessageTeams(
			teams,
			unarchivedRepos,
			nonPlaygroundStacks,
			repoOwners,
			octokit,
			config,
		);
	} else {
		console.log(
			'Messaging is not enabled. Set ENABLE_MESSAGING flag to enable.',
		);
	}

	console.log('Done');
}

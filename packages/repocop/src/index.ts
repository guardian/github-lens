import { CloudWatchClient } from '@aws-sdk/client-cloudwatch';
import type {
	guardian_github_actions_usage,
	PrismaClient,
	repocop_github_repository_rules,
	view_repo_ownership,
} from '@prisma/client';
import { awsClientConfig } from 'common/aws';
import { partition, stageAwareOctokit } from 'common/functions';
import { getPrismaClient } from 'common/src/database-setup';
import type { RepocopVulnerability } from 'common/src/types';
import type { Config } from './config';
import { getConfig } from './config';
import {
	evaluateRepositories,
	testExperimentalRepocopFeatures,
} from './evaluation/repository';
import { sendToCloudwatch } from './metrics';
import {
	getDependabotVulnerabilities,
	getProductionWorkflowUsages,
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
import { sendOneRepoToDepGraphIntegrator } from './remediation/dependency_graph-integrator/send-to-sns';
import { sendUnprotectedRepo } from './remediation/snyk-integrator/send-to-sns';
import { sendPotentialInteractives } from './remediation/topics/topic-monitor-interactive';
import { applyProductionTopicAndMessageTeams } from './remediation/topics/topic-monitor-production';
import { createAndSendVulnerabilityDigests } from './remediation/vuln-digest/vuln-digest';
import type { AwsCloudFormationStack, EvaluationResult } from './types';
import { isOpenSnykIssue, isProduction } from './utils';

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

async function writeVulnerabilitiesTable(
	vulnerabilities: Array<RepocopVulnerability & { repo_owner: string }>,
	prisma: PrismaClient,
) {
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
	const openSnykIssues = (await getSnykIssues(prisma)).filter(isOpenSnykIssue);

	const snykProjects = await getSnykProjects(prisma);
	const teams = await getTeams(prisma);
	const repoOwners = await getRepoOwnership(prisma);

	const productionRepos = unarchivedRepos.filter((repo) => isProduction(repo));
	const productionDependabotVulnerabilities: RepocopVulnerability[] =
		await getDependabotVulnerabilities(
			productionRepos,
			config.gitHubOrg,
			octokit,
		);

	console.log(productionDependabotVulnerabilities);

	// Dependency Graph Integrator
	const productionWorkflowUsages: guardian_github_actions_usage[] =
		await getProductionWorkflowUsages(prisma, productionRepos);

	const evaluationResults: EvaluationResult[] = await evaluateRepositories(
		unarchivedRepos,
		branches,
		repoOwners,
		repoLanguages,
		openSnykIssues,
		snykProjects,
		productionDependabotVulnerabilities,
		productionWorkflowUsages,
	);

	const severityPredicate = (x: RepocopVulnerability) => x.severity === 'high';
	const [high, critical] = partition(
		evaluationResults.flatMap((r) => r.vulnerabilities),
		severityPredicate,
	);

	const highPatchable = high.filter((x) => x.is_patchable).length;
	const criticalPatchable = critical.filter((x) => x.is_patchable).length;

	console.warn(
		`Found ${high.length} out of date high vulnerabilities, of which ${highPatchable} are patchable`,
	);
	console.warn(
		`Found ${critical.length} out of date critical vulnerabilities, of which ${criticalPatchable} are patchable`,
	);

	function combineVulnWithOwners(
		vuln: RepocopVulnerability,
		repoOwners: view_repo_ownership[],
	) {
		const owners = repoOwners.filter(
			(owner) => vuln.full_name === owner.full_repo_name,
		);
		return owners.length > 0
			? owners.map((owner) => ({ ...vuln, repo_owner: owner.github_team_slug }))
			: { ...vuln, repo_owner: 'unknown' };
	}

	/**
	 * Create repocop vulnerabilities and write to repocop_vulnerabilities table
	 */
	const vulnerabilities = evaluationResults
		.flatMap((result) => result.vulnerabilities)
		.flatMap((vuln) => combineVulnWithOwners(vuln, repoOwners));

	await writeVulnerabilitiesTable(vulnerabilities, prisma);

	const repocopRules = evaluationResults.map((r) => r.repocopRules);

	await writeEvaluationTable(repocopRules, prisma);

	const awsConfig = awsClientConfig(config.stage);
	const cloudwatch = new CloudWatchClient(awsConfig);
	await sendToCloudwatch(repocopRules, cloudwatch, config);

	testExperimentalRepocopFeatures(
		evaluationResults,
		unarchivedRepos,
		archivedRepos,
		nonPlaygroundStacks,
	);

	/*
	 * STAGE AWARE FUNCTIONS - these will only make live changes or
	 * message actual teams if STAGE=PROD, or send messages to
	 * downstream lambdas that are also stage aware
	 */

	if (config.snykIntegrationPREnabled) {
		await sendUnprotectedRepo(repocopRules, config, repoLanguages);
	}

	await sendPotentialInteractives(repocopRules, config);

	if (config.branchProtectionEnabled) {
		await protectBranches(
			repocopRules,
			repoOwners,
			config,
			unarchivedRepos,
			octokit,
		);
	}

	await applyProductionTopicAndMessageTeams(
		unarchivedRepos,
		nonPlaygroundStacks,
		repoOwners,
		octokit,
		config,
	);

	await sendOneRepoToDepGraphIntegrator(
		config,
		repoLanguages,
		productionRepos,
		productionWorkflowUsages,
		repoOwners,
	);

	if (config.sendDigest) {
		await createAndSendVulnerabilityDigests(
			config,
			teams,
			repoOwners,
			evaluationResults,
		);
	} else {
		console.log('Digests are not enabled. Set SEND_DIGEST flag to enable.');
	}

	/* END OF STAGE AWARE FUNCTIONS */

	console.log('Done');
}

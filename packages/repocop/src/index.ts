import type {
	PrismaClient,
	repocop_github_repository_rules,
} from '@prisma/client';
import { getPrismaClient } from 'common/database';
import { partition, stageAwareOctokit } from 'common/functions';
import type { Config } from './config';
import { getConfig } from './config';
import {
	getRepoOwnership,
	getRepositories,
	getRepositoryBranches,
	getRepositoryTeams,
	getSnykLatestIssues,
	getSnykProjects,
	getStacks,
	getTeams,
} from './query';
import { protectBranches } from './remediations/branch-protector/branch-protection';
import { sendPotentialInteractives } from './remediations/topics/topic-monitor-interactive';
import { applyProductionTopicAndMessageTeams } from './remediations/topics/topic-monitor-production';
import {
	evaluateRepositories,
	testExperimentalRepocopFeatures,
} from './rules/repository';
import type { AwsCloudFormationStack } from './types';

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

export async function main() {
	const config: Config = await getConfig();
	const prisma = getPrismaClient(config);

	const [unarchivedRepos, archivedRepos] = partition(
		await getRepositories(prisma, config.ignoredRepositoryPrefixes),
		(repo) => !repo.archived,
	);
	const branches = await getRepositoryBranches(prisma, unarchivedRepos);
	const repoTeams = await getRepositoryTeams(prisma);
	const nonPlaygroundStacks: AwsCloudFormationStack[] = (
		await getStacks(prisma)
	).filter((s) => s.tags.Stack !== 'playground');
	const evaluatedRepos: repocop_github_repository_rules[] =
		evaluateRepositories(unarchivedRepos, branches, repoTeams);

	const octokit = await stageAwareOctokit(config.stage);

	testExperimentalRepocopFeatures(
		octokit,
		evaluatedRepos,
		unarchivedRepos,
		archivedRepos,
		nonPlaygroundStacks,
		await getSnykProjects(prisma),
		await getSnykLatestIssues(prisma),
	);

	await writeEvaluationTable(evaluatedRepos, prisma);
	if (config.enableMessaging) {
		await sendPotentialInteractives(evaluatedRepos, config);

		const repoOwners = await getRepoOwnership(prisma);
		const teams = await getTeams(prisma);

		if (config.branchProtectionEnabled) {
			await protectBranches(
				evaluatedRepos,
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

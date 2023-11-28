// import { Anghammarad, RequestedChannel } from '@guardian/anghammarad';
import type { github_repositories, PrismaClient } from '@prisma/client';
// import {
// 	anghammaradThreadKey,
// 	applyTopics,
// 	topicMonitoringProductionTagCtas,
// } from 'common/src/functions';
import type {
	AWSCloudformationStack,
	AWSCloudformationTag,
	GuRepoStack,
} from 'common/types';
import type { Octokit } from 'octokit';
import type { Config } from '../config';
import { findProdCfnStacks, getRepoOwnership, getTeams } from '../query';
import { findContactableOwners } from './shared-utilities';

// async function notifyOneTeam(
// 	fullRepoName: string,
// 	config: Config,
// 	teamSlug: string,
// ) {
// 	const { app, stage, anghammaradSnsTopic } = config;
// 	const client = new Anghammarad();
// 	await client.notify({
// 		subject: `Production topic monitoring (for GitHub team ${teamSlug})`,
// 		message:
// 			`The production topic has applied to ${fullRepoName} as it appears to have a PROD or INFRA stack in AWS.` +
// 			`Repositories should have one of the following topics, to help understand what is in production: production, testing, documentation, hackday, prototype, learning, interactive`,
// 		actions: topicMonitoringProductionTagCtas(fullRepoName, teamSlug),
// 		target: { GithubTeamSlug: teamSlug },
// 		channel: RequestedChannel.PreferHangouts,
// 		sourceSystem: `${app} ${stage}`,
// 		topicArn: anghammaradSnsTopic,
// 		threadKey: anghammaradThreadKey(fullRepoName),
// 	});
// }

export function getRepoNamesWithoutProductionTopic(
	unarchivedRepos: github_repositories[],
): string[] {
	return unarchivedRepos
		.filter(
			(repo) =>
				!repo.topics.includes('production') &&
				!repo.topics.includes('interactive'),
		)
		.map((repo) => repo.full_name)
		.filter((name) => !name?.includes('interactive'))
		.filter((name) => !!name) as string[];
}

export function getGuRepoName(tag: AWSCloudformationTag): string | undefined {
	return tag['gu:repo'];
}

export function getReposInProdWithoutProductionTopic(
	reposWithoutProductionTopic: string[],
	guRepoStacks: GuRepoStack[],
): GuRepoStack[] {
	return guRepoStacks.filter((stack) => {
		const guRepoName: string = stack.guRepoName;
		return reposWithoutProductionTopic.includes(guRepoName);
	});
}

async function findReposInProdWithoutProductionTopic(
	prisma: PrismaClient,
	unarchivedRepos: github_repositories[],
) {
	console.log('Discovering Cloudformation stacks with PROD or INFRA tags');

	const repoNamesWithoutProductionTopic: string[] =
		getRepoNamesWithoutProductionTopic(unarchivedRepos);
	console.log(
		`Found ${repoNamesWithoutProductionTopic.length} repositories without a production or interactive topic`,
	);

	const cfnStacksWithProdInfraTags: AWSCloudformationStack[] =
		await findProdCfnStacks(prisma);

	const guRepoStacks: GuRepoStack[] = cfnStacksWithProdInfraTags
		.filter(
			(stack: AWSCloudformationStack) =>
				getGuRepoName(stack.tags) !== undefined,
		)
		.map((stack: AWSCloudformationStack) => {
			const guRepoName = getGuRepoName(stack.tags) as string;
			return {
				...stack,
				guRepoName,
			};
		});

	console.log(
		`Found ${guRepoStacks.length} repos with a PROD or INFRA Cloudformation stack`,
	);

	const reposInProdWithoutProductionTopic: GuRepoStack[] =
		getReposInProdWithoutProductionTopic(
			repoNamesWithoutProductionTopic,
			guRepoStacks,
		);

	console.log(
		`Found ${reposInProdWithoutProductionTopic.length} repos without a production/interactive topic that have a PROD/ INFRA Cloudformation Stage tag`,
	);

	reposInProdWithoutProductionTopic.map((stack) =>
		console.log(
			'repo:',
			stack.guRepoName,
			'stack:',
			stack.stackName,
			'stack created on:',
			stack.creationTime,
		),
	);

	return reposInProdWithoutProductionTopic;
}

export function removeGuardian(fullRepoName: string): string {
	const reponame = fullRepoName.split('/')[1];
	return reponame ?? '';
}

// async function applyProductionTopicToOneRepoAndMessageTeams(
// 	repoName: string,
// 	teamNameSlugs: string[],
// 	octokit: Octokit,
// 	config: Config,
// ) {
// 	const owner = 'guardian';
// 	const topic = 'production';
// 	await applyTopics(repoName, owner, octokit, topic);
// 	for (const teamNameSlug of teamNameSlugs) {
// 		await notifyOneTeam(`${owner}/repoName`, config, teamNameSlug);
// 	}
// }

export async function applyProductionTopicAndMessageTeams(
	prisma: PrismaClient,
	unarchivedRepos: github_repositories[],
	octokit: Octokit,
	config: Config,
): Promise<void> {
	const repos: GuRepoStack[] = await findReposInProdWithoutProductionTopic(
		prisma,
		unarchivedRepos,
	);

	const fullRepoNames = repos.map((repo) => repo.guRepoName);

	const repoOwners = await getRepoOwnership(prisma);
	const teams = await getTeams(prisma);

	const reposWithContactableOwners = fullRepoNames
		.map((fullRepoName) => {
			return {
				fullName: fullRepoName,
				teamNameSlugs: findContactableOwners(fullRepoName, repoOwners, teams),
			};
		})
		.filter((contactableRepo) => contactableRepo.teamNameSlugs.length > 0);

	console.log(`stage is ${config.stage}`);
	console.log(
		`Found ${reposWithContactableOwners.length} repos with contactable owners`,
	);
	reposWithContactableOwners.map((repo) => console.log(repo));

	if (config.stage === 'PROD') {
		console.log('In PROD');
		// await Promise.all(
		// 	reposWithContactableOwners.map((repo) =>
		// 		applyProductionTopicToOneRepoAndMessageTeams(
		// 			repo.fullName,
		// 			repo.teamNameSlugs,
		// 			octokit,
		// 			config,
		// 		),
		// 	),
		// );
	}
}

import type {
	github_teams,
	PrismaClient,
	repocop_github_repository_rules,
	view_repo_ownership,
} from '@prisma/client';
import { shuffle } from 'common/src/functions';
import type { UpdateMessageEvent } from 'common/types';
import type { Octokit } from 'octokit';
import type { Config } from '../../config';
import { getRepoOwnership, getTeams } from '../../query';
import type { Repository } from '../../types';
import { findContactableOwners } from '../shared-utilities';
import { notify } from './aws-requests';
import {
	getDefaultBranchName,
	isBranchProtected,
	updateBranchProtection,
} from './github-requests';

export function createBranchProtectionEvents(
	evaluatedRepos: repocop_github_repository_rules[],
	repoOwners: view_repo_ownership[],
	teams: github_teams[],
	msgCount: number,
): UpdateMessageEvent[] {
	const reposWithoutBranchProtection = evaluatedRepos.filter(
		(repo) => !repo.branch_protection,
	);
	const reposWithContactableOwners = reposWithoutBranchProtection
		.map((repo) => {
			return {
				fullName: repo.full_name,
				teamNameSlugs: findContactableOwners(repo.full_name, repoOwners, teams),
			};
		})
		.filter((repo) => repo.teamNameSlugs.length > 0);

	const resultsCount = reposWithContactableOwners.length;

	const sliceLength = Math.min(resultsCount, msgCount);

	return shuffle(reposWithContactableOwners).slice(0, sliceLength);
}

export async function protectBranches(
	prisma: PrismaClient,
	evaluatedRepos: repocop_github_repository_rules[],
	config: Config,
	unarchivedRepositories: Repository[],
	octokit: Octokit,
) {
	const repoOwners = await getRepoOwnership(prisma);
	const teams = await getTeams(prisma);

	//repos with a 'production' or 'documentation' topic
	const productionOrDocs = unarchivedRepositories
		.filter(
			(repo) =>
				repo.topics.includes('production') ||
				repo.topics.includes('documentation'),
		)
		.map((repo) => repo.full_name);

	const relevantRepos = evaluatedRepos.filter((repo) =>
		productionOrDocs.includes(repo.full_name),
	);

	const branchProtectionEvents: UpdateMessageEvent[] =
		createBranchProtectionEvents(relevantRepos, repoOwners, teams, 5);

	await Promise.all(
		branchProtectionEvents.map((event) =>
			protectBranch(octokit, config, event),
		),
	);
}

async function protectBranch(
	octokit: Octokit,
	config: Config,
	event: UpdateMessageEvent,
) {
	const [owner, repo] = event.fullName.split('/');

	if (!owner || !repo) {
		throw new Error(`Invalid repo name: ${event.fullName}`);
	}

	let defaultBranchName = undefined;
	try {
		defaultBranchName = await getDefaultBranchName(owner, repo, octokit);
	} catch (error) {
		throw new Error(`Could not find default branch for repo: ${repo}`);
	}

	const branchIsProtected = await isBranchProtected(
		octokit,
		owner,
		repo,
		defaultBranchName,
	);

	const stageIsProd = config.stage === 'PROD';

	if (stageIsProd && !branchIsProtected) {
		await updateBranchProtection(octokit, owner, repo, defaultBranchName);
		for (const slug of event.teamNameSlugs) {
			await notify(event.fullName, config, slug);
		}
		console.log(`Notified teams ${event.teamNameSlugs.join(', ')}}`);
	} else {
		const reason =
			(branchIsProtected ? ' Branch is already protected.' : '') +
			(!stageIsProd ? ' Not running on PROD.' : '');
		console.log(`No action required for ${repo}. ${reason}`);
	}
}

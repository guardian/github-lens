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
import { findContactableOwners, removeRepoOwner } from '../shared-utilities';
import { notify } from './aws-requests';
import {
	getDefaultBranchName,
	updateBranchProtection,
} from './github-requests';
import type { CurrentBranchProtection } from './types';

export function sufficientProtection(
	protection: CurrentBranchProtection,
): boolean {
	const reviwerCount =
		protection.required_pull_request_reviews?.required_approving_review_count ??
		0;
	console.log('Reviewer count: ', reviwerCount);

	const forcePushesBlocked = protection.allow_force_pushes?.enabled == false;
	console.log('Force pushes blocked: ', forcePushesBlocked);
	const deletionsBlocked = protection.allow_deletions?.enabled == false;
	console.log('Deletions blocked: ', deletionsBlocked);
	const reviewRequired =
		protection.required_pull_request_reviews?.require_code_owner_reviews ===
		true;
	console.log('Review required: ', reviewRequired);

	const noAdminBypass = protection.enforce_admins?.enabled ?? false;
	console.log('No admin bypass: ', noAdminBypass);

	return (
		reviewRequired &&
		reviwerCount > 0 &&
		forcePushesBlocked &&
		deletionsBlocked &&
		noAdminBypass
	);
}

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
	const owner = 'guardian';
	const repo = removeRepoOwner(event.fullName);

	let defaultBranch = undefined;
	try {
		defaultBranch = await getDefaultBranchName(owner, repo, octokit);
	} catch (error) {
		throw new Error(`Could not find default branch for repo: ${repo}`);
	}

	const branch = await octokit.rest.repos.getBranch({
		owner,
		repo,
		branch: defaultBranch,
	});

	const completelyUnprotected = !branch.data.protected;

	if (completelyUnprotected || !sufficientProtection(branch.data.protection)) {
		await updateBranchProtection(
			octokit,
			owner,
			repo,
			defaultBranch,
			config.stage,
		);
		for (const team of event.teamNameSlugs) {
			await notify(event.fullName, config, team);
		}
		console.log(`Notified teams ${event.teamNameSlugs.join(', ')}}`);
	} else {
		console.log(`No action required for ${repo}. Branch is already protected.`);
	}
}

import type {
	github_repositories,
	github_repository_branches,
	repocop_github_repository_rules,
} from '@prisma/client';
import type { AWSCloudformationStack } from 'common/types';
import { type RepositoryTeam } from '../query';
import type { RepoAndArchiveStatus, RepoAndStack } from '../types';

/**
 * Evaluate the following rule for a Github repository:
 *   > The default branch name should be "main".
 */
function hasDefaultBranchNameMain(repo: github_repositories): boolean {
	return repo.default_branch === 'main';
}

/**
 * Evaluate the following rule for a Github repository:
 *   > Enable branch protection for the default branch, ensuring changes are reviewed before being deployed.
 */
function hasBranchProtection(
	repo: github_repositories,
	branches: github_repository_branches[],
): boolean {
	const exempt = !(
		repo.topics.includes('production') || repo.topics.includes('documentation')
	);

	const branch = branches.find(
		(branch) =>
			branch.repository_id === repo.id && branch.name === repo.default_branch,
	);
	if (exempt || branch === undefined) {
		return true;
	} else {
		return branch.protected ?? false;
	}
}

/**
 * Evaluate the following rule for a Github repository:
 *   > Grant at least one GitHub team Admin access - typically, the dev team that own the project.
 *   > Repositories without one of the following topics are exempt: production, testing, documentation.
 */
function hasAdminTeam(
	repo: github_repositories,
	teams: RepositoryTeam[],
): boolean {
	// Repos that have explicitly been classified as these topics are exempt.
	// Any other repos, regardless of topic, need to be owned by a team, or assigned one of these topics.
	const exemptedTopics = ['prototype', 'learning', 'hackday', 'interactive'];
	const isExempt =
		repo.topics.filter((topic) => exemptedTopics.includes(topic)).length > 0;

	const adminTeams = teams.filter(
		({ id, role_name }) => id === repo.id && role_name === 'admin',
	);
	const hasAdminTeam = adminTeams.length > 0;

	return isExempt || hasAdminTeam;
}
/**
 * Evaluate the following rule for a Github repository:
 *   > Repositories should have one and only one of the following topics to help understand what is in production.
 *   > Repositories owned only by non-P&E teams are exempt.
 */
function hasStatusTopic(repo: github_repositories): boolean {
	const validTopics = [
		'prototype',
		'learning',
		'hackday',
		'testing',
		'documentation',
		'production',
		'interactive',
	];

	return (
		repo.topics.filter((topic) => validTopics.includes(topic)).length === 1
	);
}

function mostRecentChange(repo: github_repositories): Date | undefined {
	const definiteDates: Date[] = [
		repo.created_at,
		repo.updated_at,
		repo.pushed_at,
	].filter((d) => !!d) as Date[];

	const sortedDates = definiteDates.sort((a, b) => b.getTime() - a.getTime());
	return sortedDates[0] ?? undefined;
}

function isMaintained(repo: github_repositories): boolean {
	const update: Date | undefined = mostRecentChange(repo);
	const now = new Date();
	const twoYearsAgo = new Date();
	twoYearsAgo.setFullYear(now.getFullYear() - 2);
	//avoid false positives and use current moment if no dates are available for now
	//a repo always has a created_at date, so this is unlikely to happen unless something is wrong with cloudquery
	const recentlyUpdated = (update ?? new Date()) > twoYearsAgo;
	const isInteractive = repo.topics.includes('interactive');

	return isInteractive || recentlyUpdated;
}

/**
 * Evaluate the following rule for a Github repository:
 *   > Archived repositories should not have corresponding stacks on AWS.
 */
export function findStacks(
	repo: RepoAndArchiveStatus,
	stacks: AWSCloudformationStack[],
): RepoAndStack {
	const stackMatches = stacks.filter((stack) => {
		return (
			!!stack.stackName &&
			(stack.guRepoName === repo.fullName ||
				stack.stackName.includes(repo.name))
		);
	});
	const stackNames = stackMatches
		.map((stack) => stack.stackName)
		.filter((s) => !!s) as string[];

	return {
		fullName: repo.fullName,
		stacks: stackNames,
	};
}

/**
 * Apply rules to a repository as defined in https://github.com/guardian/recommendations/blob/main/best-practices.md.
 */
export function evaluateOneRepo(
	repo: github_repositories,
	allBranches: github_repository_branches[],
	teams: RepositoryTeam[],
): repocop_github_repository_rules {
	/*
	Either the fullname, or the org and name, or the org and 'unknown'.
	The latter should never happen, it's just how the types have been defined.
	 */
	const fullName = repo.full_name ?? `${repo.org}/${repo.name ?? 'unknown'}`;

	return {
		full_name: fullName,
		default_branch_name: hasDefaultBranchNameMain(repo),
		branch_protection: hasBranchProtection(repo, allBranches),
		team_based_access: false,
		admin_access: hasAdminTeam(repo, teams),
		archiving: isMaintained(repo),
		topics: hasStatusTopic(repo),
		contents: null,
		evaluated_on: new Date(),
	};
}

//TODO test this
export function evaluateRepositories(
	repositories: github_repositories[],
	branches: github_repository_branches[],
	teams: RepositoryTeam[],
): repocop_github_repository_rules[] {
	return repositories.map((r) => {
		const teamsForRepo = teams.filter((t) => t.id === r.id);
		const branchesForRepo = branches.filter((b) => b.repository_id === r.id);
		return evaluateOneRepo(r, branchesForRepo, teamsForRepo);
	});
}

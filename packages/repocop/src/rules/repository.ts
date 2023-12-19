import type {
	github_repository_branches,
	repocop_github_repository_rules,
	snyk_projects,
	snyk_reporting_latest_issues,
} from '@prisma/client';
import type { Octokit } from 'octokit';
import { type RepositoryTeam } from '../query';
import type {
	AwsCloudFormationStack,
	RepoAndStack,
	Repository,
} from '../types';

/**
 * Evaluate the following rule for a Github repository:
 *   > The default branch name should be "main".
 */
function hasDefaultBranchNameMain(repo: Repository): boolean {
	return repo.default_branch === 'main';
}

/**
 * Evaluate the following rule for a Github repository:
 *   > Enable branch protection for the default branch, ensuring changes are reviewed before being deployed.
 */
function hasBranchProtection(
	repo: Repository,
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
function hasAdminTeam(repo: Repository, teams: RepositoryTeam[]): boolean {
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
function hasStatusTopic(repo: Repository): boolean {
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

function mostRecentChange(repo: Repository): Date | undefined {
	const definiteDates: Date[] = [
		repo.created_at,
		repo.updated_at,
		repo.pushed_at,
	].filter((d): d is Date => !!d);

	const sortedDates = definiteDates.sort((a, b) => b.getTime() - a.getTime());
	return sortedDates[0] ?? undefined;
}

function isMaintained(repo: Repository): boolean {
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

interface SnykTags {
	commit?: string;
	branch?: string;
	repo?: string;
}

export function parseSnykTags(snyk_projects: snyk_projects) {
	interface TagValues {
		key: string;
		value: string;
	}

	const tagString = JSON.stringify(snyk_projects.tags);
	const tags = JSON.parse(tagString) as TagValues[];

	const snykTags: SnykTags = {
		commit: tags.find((tag) => tag.key === 'commit')?.value,
		branch: tags.find((tag) => tag.key === 'branch')?.value,
		repo: tags.find((tag) => tag.key === 'repo')?.value,
	};

	return snykTags;
}

//TODO - create a CQ plugin to retrieve languages from the repo, reducing our reliance on the GitHub API
export async function getRepoLanguages(octokit: Octokit, repo: Repository) {
	const languages = await octokit.paginate(
		octokit.rest.repos.listLanguages,
		{
			owner: 'guardian',
			repo: repo.name,
		},
		(response) => {
			return Object.keys(response.data);
		},
	);
	return languages;
}

export function verifyDependencyTracking(
	repo: Repository,
	languages: string[],
	snyk_projects: snyk_projects[],
): boolean {
	if (!repo.topics.includes('production') || repo.archived) {
		return true;
	}

	const ignoredLanguages = ['HTML', 'CSS', 'Shell'];

	const commonSupportedLanguages = [
		'C#',
		'Go',
		'Java',
		'JavaScript',
		'Python',
		'Swift',
		'TypeScript',
	];
	const snykOnlySupportedLanguages = [
		'C',
		'C++',
		'Apex',
		'Bazel',
		'Elixir',
		'Kotlin',
		'PHP',
		'Ruby',
		'Rust',
		'Scala',
		'Objective-C',
		'Visual Basic .NET',
	];

	const supportedDependabotLanguages = ignoredLanguages.concat(
		commonSupportedLanguages,
	);

	const supportedSnykLanguages = ignoredLanguages
		.concat(commonSupportedLanguages)
		.concat(snykOnlySupportedLanguages);

	const allProjectTags = snyk_projects.map((project) => parseSnykTags(project));

	const matchingSnykProject = allProjectTags.find(
		(tags) =>
			//TODO - this is a close enough match for now, but in the future we should use commit hashes
			//to make sure the projects are in sync
			!!repo.full_name &&
			tags.repo == repo.full_name &&
			tags.branch === repo.default_branch,
	);

	const repoIsOnSnyk = !!matchingSnykProject;

	if (repoIsOnSnyk) {
		const containsOnlySnykSupportedLanguages = languages.every((language) =>
			supportedSnykLanguages.includes(language),
		);
		return containsOnlySnykSupportedLanguages;
	} else {
		const containsOnlyDependabotSupportedLanguages = languages.every(
			(language) => supportedDependabotLanguages.includes(language),
		);
		return containsOnlyDependabotSupportedLanguages;
	}
}

/**
 * Evaluate the following rule for a Github repository:
 *   > Production repositories should have dependency tracking enabled.
 */

export const isTracked = async (
	octokit: Octokit,
	repo: Repository,
	snyk_projects: snyk_projects[],
) => {
	const isExempt = !repo.topics.includes('production') || repo.archived;
	if (isExempt) {
		return true;
	}

	const languages = await getRepoLanguages(octokit, repo);
	console.log(`${repo.name} has languages: `, languages);
	const isVerified = verifyDependencyTracking(repo, languages, snyk_projects);
	console.log(`${repo.name} has valid dependency tracking: `, isVerified);
	return isVerified;
};

/**
 * Evaluate the following rule for a Github repository:
 *   > Archived repositories should not have corresponding stacks on AWS.
 */
export function findStacks(
	repo: Repository,
	stacks: AwsCloudFormationStack[],
): RepoAndStack {
	const stackMatches = stacks.filter((stack) => {
		return (
			!!stack.stack_name &&
			(stack.tags['gu:repo'] === repo.full_name ||
				stack.stack_name.includes(repo.name))
		);
	});
	const stackNames = stackMatches
		.map((stack) => stack.stack_name)
		.filter((s) => !!s);

	return {
		fullName: repo.full_name,
		stacks: stackNames,
	};
}

function findArchivedReposWithStacks(
	archivedRepositories: Repository[],
	unarchivedRepositories: Repository[],
	stacks: AwsCloudFormationStack[],
) {
	const archivedRepos = archivedRepositories;
	const unarchivedRepos = unarchivedRepositories;

	const stacksWithoutAnUnarchivedRepoMatch: AwsCloudFormationStack[] =
		stacks.filter((stack) =>
			unarchivedRepos.some(
				(repo) => !(repo.full_name === stack.tags['gu:repo']),
			),
		);

	const archivedReposWithPotentialStacks: RepoAndStack[] = archivedRepos
		.map((repo) => findStacks(repo, stacksWithoutAnUnarchivedRepoMatch))
		.filter((result) => result.stacks.length > 0);

	return archivedReposWithPotentialStacks;
}

export function testExperimentalRepocopFeatures(
	octokit: Octokit,
	evaluatedRepos: repocop_github_repository_rules[],
	unarchivedRepos: Repository[],
	archivedRepos: Repository[],
	nonPlaygroundStacks: AwsCloudFormationStack[],
	snykProjects: snyk_projects[],
	snykIssues: snyk_reporting_latest_issues[],
) {
	console.log('tags example');
	console.log(snykProjects.find((project) => !!project.tags));

	console.log('issues example');
	console.log(snykIssues[0]);

	const unmaintinedReposCount = evaluatedRepos.filter(
		(repo) => repo.archiving === false,
	).length;

	console.log(
		`Found ${unmaintinedReposCount} unmaintained repositories of ${unarchivedRepos.length}.`,
	);

	const archivedWithStacks = findArchivedReposWithStacks(
		archivedRepos,
		unarchivedRepos,
		nonPlaygroundStacks,
	);

	console.log(`Found ${archivedWithStacks.length} archived repos with stacks.`);

	console.log(
		'Archived repos with live stacks, first 10 results:',
		archivedWithStacks.slice(0, 10),
	);

	unarchivedRepos
		.filter((r) => r.topics.includes('production'))
		.slice(0, 10)
		.map((r) => isTracked(octokit, r, snykProjects));
}

/**
 * Apply rules to a repository as defined in https://github.com/guardian/recommendations/blob/main/best-practices.md.
 */
export function evaluateOneRepo(
	repo: Repository,
	allBranches: github_repository_branches[],
	teams: RepositoryTeam[],
): repocop_github_repository_rules {
	/*
	Either the fullname, or the org and name, or the org and 'unknown'.
	The latter should never happen, it's just how the types have been defined.
	 */
	const fullName = repo.full_name;

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

export function evaluateRepositories(
	repositories: Repository[],
	branches: github_repository_branches[],
	teams: RepositoryTeam[],
): repocop_github_repository_rules[] {
	return repositories.map((r) => {
		const teamsForRepo = teams.filter((t) => t.id === r.id);
		const branchesForRepo = branches.filter((b) => b.repository_id === r.id);
		return evaluateOneRepo(r, branchesForRepo, teamsForRepo);
	});
}

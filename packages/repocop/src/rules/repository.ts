import { randomBytes } from 'node:crypto';
import type {
	github_languages,
	github_repository_branches,
	repocop_github_repository_rules,
	snyk_projects,
} from '@prisma/client';
import type { Octokit } from 'octokit';
import type { Config } from '../config';
import {
	createSnykPullRequest,
	createYaml,
} from '../remediations/snyk-integrator/snyk-integrator';
import type {
	AwsCloudFormationStack,
	RepoAndStack,
	Repository,
	TeamRepository,
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
function hasAdminTeam(repo: Repository, teams: TeamRepository[]): boolean {
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

function logUnsupported(
	repo: string,
	repoLanguages: string[],
	supportedLanguages: string[],
	platform: string,
) {
	console.log(
		`${repo} contains the following languages not supported by ${platform}: `,
		repoLanguages.filter((language) => !supportedLanguages.includes(language)),
	);
}

//TODO test
function allLanguagesSupported(
	repo: string,
	repoLanguages: string[],
	supportedLanguages: string[],
	platform: string,
): boolean {
	const containsOnlySupportedLanguages = repoLanguages.every((l) =>
		supportedLanguages.includes(l),
	);
	if (!containsOnlySupportedLanguages) {
		logUnsupported(repo, repoLanguages, supportedLanguages, platform);
	}
	return containsOnlySupportedLanguages;
}

/**
 * Evaluate the following rule for a Github repository:
 *   > Repositories should have their dependencies tracked via Snyk or Dependabot, depending on the languages present.
 */
export function hasDependencyTracking(
	repo: Repository,
	repoLanguages: github_languages[],
	snyk_projects: snyk_projects[],
): boolean {
	if (!repo.topics.includes('production') || repo.archived) {
		return true;
	}

	const langs: string[] =
		repoLanguages.find(
			(repoLanguage) => repoLanguage.full_name === repo.full_name,
		)?.languages ?? [];

	const ignoredLanguages = [
		'HTML',
		'CSS',
		'Shell',
		'Jupyter Notebook',
		'Makefile',
		'Dockerfile',
		'PLpgSQL',
		'Thrift',
		'SCSS',
		'Batchfile',
		'HCL',
		'VCL',
	];

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

	const dependabotLanguages = ignoredLanguages.concat(commonSupportedLanguages);

	const snykLanguages = ignoredLanguages
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

	console.log(matchingSnykProject);

	const repoIsOnSnyk = !!matchingSnykProject;

	if (repoIsOnSnyk) {
		return allLanguagesSupported(repo.name, langs, snykLanguages, 'Snyk');
	} else {
		return allLanguagesSupported(
			repo.name,
			langs,
			dependabotLanguages,
			'Dependabot',
		);
	}
}

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

export async function testExperimentalRepocopFeatures(
	config: Config,
	evaluatedRepos: repocop_github_repository_rules[],
	unarchivedRepos: Repository[],
	archivedRepos: Repository[],
	nonPlaygroundStacks: AwsCloudFormationStack[],
	octokit: Octokit,
) {
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

	console.log('Testing snyk.yml generation');
	console.log(createYaml(['Scala', 'Python', 'Shell'], 'branch'));
	console.log(createYaml(['Go', 'Dockerfile', 'TypeScript'], 'branch'));

	if (config.snykIntegrationPREnabled) {
		console.log('Creating a test Snyk Pull Request against test-repocop-prs');
		const response = await createSnykPullRequest(
			octokit,
			'test-repocop-prs',
			// Introduce a random suffix to allow the same PR to be raised multiple times
			// Useful for testing, but may be less useful in production
			`integrate-snyk-${randomBytes(8).toString('hex')}`,
			['Scala', 'Python', 'Shell'],
		);
		console.log('Pull request successfully created:', response?.data.html_url);
	} else {
		console.log(
			'Skipping creating a test Snyk Pull Request (feature is not enabled)',
		);
	}
}

/**
 * Apply rules to a repository as defined in https://github.com/guardian/recommendations/blob/main/best-practices.md.
 */
export function evaluateOneRepo(
	repo: Repository,
	allBranches: github_repository_branches[],
	teams: TeamRepository[],
	repoLanguages: github_languages[],
	snykProjects: snyk_projects[],
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
		vulnerability_tracking: hasDependencyTracking(
			repo,
			repoLanguages,
			snykProjects,
		),
		evaluated_on: new Date(),
	};
}

export function evaluateRepositories(
	repositories: Repository[],
	branches: github_repository_branches[],
	teams: TeamRepository[],
	repoLanguages: github_languages[],
	snykProjects: snyk_projects[],
): repocop_github_repository_rules[] {
	return repositories.map((r) => {
		const teamsForRepo = teams.filter((t) => t.id === r.id);
		const branchesForRepo = branches.filter((b) => b.repository_id === r.id);
		return evaluateOneRepo(
			r,
			branchesForRepo,
			teamsForRepo,
			repoLanguages,
			snykProjects,
		);
	});
}

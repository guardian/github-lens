import type {
	github_languages,
	github_repository_branches,
	guardian_github_actions_usage,
	PrismaClient,
	view_repo_ownership,
} from '@prisma/client';
import type {
	AugmentedRepository,
	NonEmptyArray,
	RepocopVulnerability,
	Repository,
} from 'common/src/types';
import type { Octokit } from 'octokit';
import { toNonEmptyArray } from '../../common/src/functions';
import { dependabotAlertToRepocopVulnerability } from './evaluation/repository';
import type {
	Alert,
	AwsCloudFormationStack,
	DependabotVulnResponse,
	SnykIssue,
	SnykProject,
	Team,
} from './types';

export async function getRepositories(
	client: PrismaClient,
	ignoredRepositoryPrefixes: string[],
): Promise<Repository[]> {
	console.debug('Discovering repositories');
	const repositories = await client.github_repositories.findMany({
		where: {
			NOT: [
				{
					OR: ignoredRepositoryPrefixes.map((prefix) => {
						return { full_name: { startsWith: prefix } };
					}),
				},
			],
		},
	});

	console.debug(`Found ${repositories.length} repositories`);
	return toNonEmptyArray(repositories.map((r) => r as Repository));
}

// We only care about branches from repos we've selected, so lets only pull those to save us some time/memory
export async function getRepositoryBranches(
	client: PrismaClient,
	repos: Repository[],
): Promise<NonEmptyArray<github_repository_branches>> {
	const branches = await client.github_repository_branches.findMany({
		where: {
			repository_id: { in: repos.map((repo) => repo.id) },
		},
	});

	return toNonEmptyArray(branches);
}

export const getTeams = async (client: PrismaClient): Promise<Team[]> => {
	const teams = (
		await client.github_teams.findMany({
			select: {
				slug: true,
				id: true,
				name: true,
			},
		})
	).map((t) => t as Team);
	console.debug(`Found ${teams.length} teams.`);
	return toNonEmptyArray(teams);
};

export async function getRepoOwnership(
	client: PrismaClient,
): Promise<NonEmptyArray<view_repo_ownership>> {
	const data = await client.view_repo_ownership.findMany();
	console.log(`Found ${data.length} repo ownership records.`);
	return toNonEmptyArray(data);
}

export async function getStacks(
	client: PrismaClient,
): Promise<NonEmptyArray<AwsCloudFormationStack>> {
	const stacks = (
		await client.aws_cloudformation_stacks.findMany({
			select: {
				stack_name: true,
				tags: true,
				creation_time: true,
			},
		})
	).map((stack) => stack as AwsCloudFormationStack);

	console.debug(`Found ${stacks.length} stacks.`);
	return toNonEmptyArray(stacks);
}

export async function getSnykIssues(
	client: PrismaClient,
): Promise<NonEmptyArray<SnykIssue>> {
	const resp = (await client.snyk_issues.findMany({})).map((i) => {
		return {
			id: i.id,
			attributes: i.attributes as unknown as SnykIssue['attributes'],
			relationships: i.relationships as unknown as SnykIssue['relationships'],
		};
	});

	return toNonEmptyArray(resp);
}

export async function getSnykProjects(
	client: PrismaClient,
): Promise<SnykProject[]> {
	return (await client.snyk_projects.findMany({})).map((i) => {
		return i as unknown as SnykProject;
	});
}

export async function getRepositoryLanguages(
	client: PrismaClient,
): Promise<NonEmptyArray<github_languages>> {
	return toNonEmptyArray(await client.github_languages.findMany({}));
}

//Octokit Queries

async function getAlertsForRepo(
	octokit: Octokit,
	orgName: string,
	repoName: string,
): Promise<Alert[] | undefined> {
	const prefix = `${orgName}/`;
	if (repoName.startsWith(prefix)) {
		repoName = repoName.replace(prefix, '');
	}

	try {
		const alert: DependabotVulnResponse =
			await octokit.rest.dependabot.listAlertsForRepo({
				owner: orgName,
				repo: repoName,
				per_page: 100,
				severity: 'critical,high',
				state: 'open',
				sort: 'created',
				direction: 'asc', //retrieve oldest vulnerabilities first
			});

		const openRuntimeDependencies = alert.data.filter(
			(a) => a.dependency.scope !== 'development',
		);
		return openRuntimeDependencies;
	} catch (error) {
		console.debug(
			`Dependabot - ${repoName}: Could not get alerts. Dependabot may not be enabled.`,
		);
		console.debug(error);
		// Return undefined if dependabot is not enabled, to distinguish from
		// the scenario where it is enabled, but there are no alerts
		return undefined;
	}
}

export async function getDependabotVulnerabilities(
	augmentedRepos: AugmentedRepository[],
	orgName: string,
	octokit: Octokit,
) {
	const dependabotVulnerabilities: RepocopVulnerability[] = (
		await Promise.all(
			augmentedRepos.map(async (repo) => {
				const alerts = await getAlertsForRepo(octokit, orgName, repo.name);
				if (alerts) {
					return alerts.map((a) =>
						dependabotAlertToRepocopVulnerability(repo.full_name, a),
					);
				}
				return [];
			}),
		)
	).flat();

	console.log(
		`Found ${dependabotVulnerabilities.length} dependabot vulnerabilities across ${augmentedRepos.length} repos`,
	);

	return dependabotVulnerabilities;
}

export async function getProductionWorkflowUsages(
	client: PrismaClient,
	augmentedProdRepos: AugmentedRepository[],
): Promise<NonEmptyArray<guardian_github_actions_usage>> {
	const actions_usage = await client.guardian_github_actions_usage.findMany({
		where: {
			full_name: { in: augmentedProdRepos.map((repo) => repo.full_name) },
		},
	});
	return toNonEmptyArray(actions_usage);
}

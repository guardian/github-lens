import type {
	github_languages,
	github_repository_branches,
	PrismaClient,
	view_repo_ownership,
} from '@prisma/client';
import type { Octokit } from 'octokit';
import { dependabotAlertToRepocopVulnerability } from './evaluation/repository';
import type {
	Alert,
	AwsCloudFormationStack,
	DependabotVulnResponse,
	NonEmptyArray,
	RepocopVulnerability,
	Repository,
	SnykIssue,
	SnykProject,
	Team,
} from './types';
import { toNonEmptyArray } from './utils';

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
): Promise<SnykIssue[]> {
	return (await client.snyk_issues.findMany({})).map((i) => {
		return {
			id: i.id,
			attributes: i.attributes as unknown as SnykIssue['attributes'],
			relationships: i.relationships as unknown as SnykIssue['relationships'],
		};
	});
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

async function getAlertsForRepo(
	octokit: Octokit,
	name: string,
): Promise<Alert[] | undefined> {
	if (name.startsWith('guardian/')) {
		name = name.replace('guardian/', '');
	}

	try {
		const alert: DependabotVulnResponse =
			await octokit.rest.dependabot.listAlertsForRepo({
				owner: 'guardian',
				repo: name,
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
			`Dependabot - ${name}: Could not get alerts. Dependabot may not be enabled.`,
		);
		console.debug(error);
		return undefined;
	}
}

export async function getDependabotVulnerabilities(
	repos: string[],
	repoOwners: view_repo_ownership[],
	octokit: Octokit,
): Promise<RepocopVulnerability[]> {
	const alerts = await Promise.all(
		repos.flatMap(async (r) => {
			const alerts = (await getAlertsForRepo(octokit, r)) ?? [];
			return alerts
				.filter((a) => a.state === 'open')
				.flatMap(
					(a) => dependabotAlertToRepocopVulnerability(r, a, repoOwners), //TODO move this transformation.
				);
		}),
	);

	return alerts.flat();
}

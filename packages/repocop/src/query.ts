import type {
	github_repository_branches,
	Prisma,
	PrismaClient,
	snyk_projects,
	snyk_reporting_latest_issues,
	view_repo_ownership,
} from '@prisma/client';
import type { GetFindResult } from '@prisma/client/runtime/library';
import type { AwsCloudFormationStack, Repository, Team } from './types';

export async function getRepositories(
	client: PrismaClient,
	ignoredRepositoryPrefixes: string[],
): Promise<Repository[]> {
	console.log('Discovering repositories');
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

	console.log(`Found ${repositories.length} repositories`);
	return repositories.map((r) => r as Repository);
}

// We only care about branches from repos we've selected, so lets only pull those to save us some time/memory
export async function getRepositoryBranches(
	client: PrismaClient,
	repos: Repository[],
): Promise<github_repository_branches[]> {
	const branches = await client.github_repository_branches.findMany({
		where: {
			repository_id: { in: repos.map((repo) => repo.id) },
		},
	});

	return branches;
}

export const getTeams = async (client: PrismaClient): Promise<Team[]> => {
	const teams = (await client.github_teams.findMany({})).map((t) => t as Team);
	console.log(`Parsed ${teams.length} teams.`);
	return teams;
};

export type RepositoryTeam = GetFindResult<
	Prisma.$github_team_repositoriesPayload,
	{
		select: { role_name: boolean; id: boolean };
		where: { id: bigint };
	}
>;

export async function getRepositoryTeams(
	client: PrismaClient,
): Promise<RepositoryTeam[]> {
	const data: RepositoryTeam[] = await client.github_team_repositories.findMany(
		{
			select: {
				id: true,
				role_name: true,
			},
		},
	);

	return data;
}

export async function getRepoOwnership(
	client: PrismaClient,
): Promise<view_repo_ownership[]> {
	const data = await client.view_repo_ownership.findMany();
	console.log(`Found ${data.length} repo ownership records.`);
	return data;
}

export async function getStacks(
	client: PrismaClient,
): Promise<AwsCloudFormationStack[]> {
	return (await client.aws_cloudformation_stacks.findMany({})).map(
		(stack) => stack as AwsCloudFormationStack,
	);
}

export async function getSnykProjects(
	client: PrismaClient,
): Promise<snyk_projects[]> {
	return await client.snyk_projects.findMany({});
}

export async function getSnykLatestIssues(
	client: PrismaClient,
): Promise<snyk_reporting_latest_issues[]> {
	return await client.snyk_reporting_latest_issues.findMany({});
}

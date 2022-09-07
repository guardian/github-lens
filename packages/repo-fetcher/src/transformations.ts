import type { Config } from '../../common/config';
import { getReposForTeam } from '../../common/github/github';
import type {
	RepositoryResponse,
	TeamRepoResponse,
} from '../../common/github/github';

export interface Repository {
	id: number;
	name: string;
	full_name: string;
	private: boolean;
	description: string | null;
	created_at: Date | null;
	updated_at: Date | null;
	pushed_at: Date | null;
	size: number | undefined;
	language: string | null | undefined;
	archived: boolean | undefined;
	open_issues_count: number | undefined;
	is_template: boolean | undefined;
	topics: string[] | undefined;
	default_branch: string | undefined;
	owners: string[];
}

const parseDateString = (
	dateString: string | null | undefined,
): Date | null => {
	if (
		dateString === undefined ||
		dateString === null ||
		dateString.length === 0
	) {
		return null;
	}
	return new Date(dateString);
};

export const transformRepo = (
	repo: RepositoryResponse,
	owners: string[],
): Repository => {
	return {
		id: repo.id,
		name: repo.name,
		full_name: repo.full_name,
		private: repo.private,
		description: repo.description,
		created_at: parseDateString(repo.created_at),
		updated_at: parseDateString(repo.updated_at),
		pushed_at: parseDateString(repo.pushed_at),
		size: repo.size,
		language: repo.language,
		archived: repo.archived,
		open_issues_count: repo.open_issues_count,
		is_template: repo.is_template,
		topics: repo.topics,
		default_branch: repo.default_branch,
		owners: owners,
	};
};

export class RepoAndOwner {
	teamSlug: string;
	repoName: string;
	constructor(teamSlug: string, repoName: string) {
		this.teamSlug = teamSlug;
		this.repoName = repoName;
	}
}

export const getAdminReposFromResponse = (
	repos: TeamRepoResponse,
): string[] => {
	return repos
		.filter((repo) => repo.role_name === 'admin')
		.map((repo) => repo.name);
};

export const createOwnerObjects = async (
	config: Config,
	teamSlug: string,
): Promise<RepoAndOwner[]> => {
	const allRepos: TeamRepoResponse = await getReposForTeam(config, teamSlug);
	const adminRepos: string[] = getAdminReposFromResponse(allRepos);
	return adminRepos.map((repoName) => new RepoAndOwner(teamSlug, repoName));
};

export const findOwnersOfRepo = (
	repoName: string,
	ownerObjects: RepoAndOwner[],
): string[] => {
	return ownerObjects
		.filter((repoAndOwner) => repoAndOwner.repoName == repoName)
		.map((repoAndOwner) => repoAndOwner.teamSlug);
};

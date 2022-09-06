import { putItem } from '../../common/aws/s3';
import { config } from '../../common/config';
import type {
	RepositoriesResponse,
	RepositoryResponse,
} from '../../common/github/github';
import { listRepositories } from '../../common/github/github';

interface Repository {
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

const transform = (repo: RepositoryResponse): Repository => {
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
	};
};

const save = (repos: Repository[]): Promise<void> => {
	const prefix = config.dataKeyPrefix ?? '';
	const key = `${prefix}/github/repos.json`;

	return putItem(key, JSON.stringify(repos), config.dataBucketName);
};

export const main = async (): Promise<void> => {
	console.log('[INFO] starting repo-fetcher');

	const reposResponse: RepositoriesResponse = await listRepositories(config);
	const repos = reposResponse.map(transform);

	await save(repos);
	console.log(`[INFO] found ${repos.length} repos`);
	console.log(`[INFO] finishing repo-fetcher`);
};

if (require.main === module) {
	void (async () => await main())();
}

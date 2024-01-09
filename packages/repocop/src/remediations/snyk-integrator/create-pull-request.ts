import type { Octokit } from 'octokit';
import { composeCreatePullRequest } from 'octokit-plugin-create-pull-request';

interface CreatePullRequestOptions {
	fullRepoName: string;
	title: string;
	body: string;
	branchName: string;
	baseBranch?: string;
	changes: Array<{
		commitMessage: string;
		files: Record<string, string>;
	}>;
}

export async function createPullRequest(
	octokit: Octokit,
	{
		fullRepoName,
		title,
		body,
		branchName,
		baseBranch = 'main',
		changes,
	}: CreatePullRequestOptions,
) {
	return await composeCreatePullRequest(octokit, {
		owner: 'guardian',
		repo: fullRepoName,
		title,
		body,
		head: branchName,
		base: baseBranch,
		changes: changes.map(({ commitMessage, files }) => ({
			commit: commitMessage,
			files: files,
		})),
	});
}

import type { SNSHandler } from 'aws-lambda';
import { getGitHubAppConfig, getGithubClient } from 'common/functions';
import type { GitHubAppConfig } from 'common/types';
import type { Octokit } from 'octokit';
import type { Config } from './config';
import { getConfig } from './config';

async function isFromInteractiveTemplate(
	repo: string,
	owner: string,
	octokit: Octokit,
): Promise<boolean> {
	console.log('retrieving repo data');
	const repoData = await octokit.rest.repos.get({
		owner,
		repo,
	});

	const prefix = 'interactive-atom-template';
	console.log('checking if repo is from interactive template');
	return repoData.data.template_repository?.name.includes(prefix) ?? false;
}

async function applyTopics(repo: string, owner: string, octokit: Octokit) {
	const topics = (await octokit.rest.repos.getAllTopics({ owner, repo })).data
		.names;
	console.log(`${repo}is from interactive template`);
	const names = topics.concat(['interactive']);
	await octokit.rest.repos.replaceAllTopics({ owner, repo, names });
	console.log(`added interactive topic to ${repo}`);
}

async function assessRepo(repo: string, owner: string, config: Config) {
	console.log('received repo', repo);
	const githubAppConfig: GitHubAppConfig = await getGitHubAppConfig();
	const octokit: Octokit = await getGithubClient(githubAppConfig);

	const isInteractive = await isFromInteractiveTemplate(repo, owner, octokit);

	if (isInteractive && config.stage === 'PROD') {
		await applyTopics(repo, owner, octokit);
	} else {
		console.log('No action taken');
	}
}

export const handler: SNSHandler = async (event) => {
	const config = getConfig();
	const owner = 'guardian';
	const events = event.Records.map(
		async (record) => await assessRepo(record.Sns.Message, owner, config),
	);
	await Promise.all(events);
};

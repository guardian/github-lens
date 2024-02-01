import type { SNSHandler } from 'aws-lambda';
import { parseEvent, stageAwareOctokit } from 'common/functions';
import type { SnykIntegratorEvent } from 'common/src/types';
import type { Config } from './config';
import { getConfig } from './config';
import { addPrToProject } from './projects-graphql';
import { getPullRequest } from './pull-requests';
import {
	createSnykPullRequest,
	createYaml,
	generateBranchName,
	generatePr,
} from './snyk-integrator';

export async function main(event: SnykIntegratorEvent) {
	console.log(`Generating Snyk PR for ${event.name}`);
	const config: Config = getConfig();

	const branch = generateBranchName(event.languages);

	const octokit = await stageAwareOctokit(config.stage);

	const existingPullRequest = await getPullRequest(octokit, event.name, branch);

	if (!existingPullRequest) {
		if (config.stage === 'PROD') {
			const response = await createSnykPullRequest(
				octokit,
				event.name,
				branch,
				event.languages,
			);
			console.log(
				'Pull request successfully created:',
				response?.data.html_url,
			);
			await addPrToProject(config.stage, event);
			console.log('Updated project board');
		} else {
			console.log(
				'No existing Snyk integration PR found. Testing snyk.yml generation',
			);
			console.log(createYaml(event.languages, branch));
			console.log('Testing PR generation');
			const [head, body] = generatePr(event.languages, branch);
			console.log('Title:\n', head);
			console.log('Body:\n', body);
		}
	} else {
		console.log(`Existing pull request found with branch ${branch}`);
	}

	console.log('Done');
}

export const handler: SNSHandler = async (event) => {
	const snykIntegratorEvents = parseEvent<SnykIntegratorEvent>(event);

	// eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- we're just testing
	await main(snykIntegratorEvents[0]!);
};

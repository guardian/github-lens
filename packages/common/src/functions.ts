import { SecretsManager } from '@aws-sdk/client-secrets-manager';
import type { Action } from '@guardian/anghammarad';
import { createAppAuth } from '@octokit/auth-app';
import type { SNSEvent } from 'aws-lambda';
import { Octokit } from 'octokit';
import {
	type GitHubAppConfig,
	type GithubAppSecret,
	type NonEmptyArray,
	type Severity,
	SLAs,
} from 'common/src/types';

export async function getGithubClient(githubAppConfig: GitHubAppConfig) {
	const auth = createAppAuth(githubAppConfig.strategyOptions);

	const installationAuthentication = await auth({
		type: 'installation',
		installationId: githubAppConfig.installationId,
	});

	const octokit: Octokit = new Octokit({
		auth: installationAuthentication.token,
	});
	return octokit;
}

export function getEnvOrThrow(key: string): string {
	const value: string | undefined = process.env[key];
	if (value === undefined) {
		throw new Error(`Environment variable ${key} is not set.`);
	}
	return value;
}

export async function getGithubAppSecret(): Promise<string> {
	const SecretId = getEnvOrThrow('GITHUB_APP_SECRET');
	const secretsManager = new SecretsManager();

	const secret = await secretsManager.getSecretValue({ SecretId });
	if (!secret.SecretString) {
		throw new Error(`Secret ${SecretId} has no SecretString`);
	} else {
		return secret.SecretString;
	}
}

export function parseSecretJson(secretString: string): GitHubAppConfig {
	const secretJson = JSON.parse(secretString) as GithubAppSecret;
	const githubAppConfig: GitHubAppConfig = {
		strategyOptions: {
			...secretJson,
			privateKey: atob(secretJson.base64PrivateKey),
		},
		installationId: secretJson.installationId,
	};
	return githubAppConfig;
}

export async function getGitHubAppConfig(): Promise<GitHubAppConfig> {
	const secretString = await getGithubAppSecret();
	const githubAppConfig = parseSecretJson(secretString);
	return githubAppConfig;
}

export async function stageAwareOctokit(stage: string) {
	if (stage === 'CODE' || stage === 'PROD') {
		const githubAppConfig: GitHubAppConfig = await getGitHubAppConfig();
		const octokit: Octokit = await getGithubClient(githubAppConfig);
		return octokit;
	} else {
		const token = getEnvOrThrow('GITHUB_ACCESS_TOKEN');
		return new Octokit({ auth: token });
	}
}

export function parseEvent<T>(event: SNSEvent): T[] {
	return event.Records.map((record) => JSON.parse(record.Sns.Message) as T);
}

export function branchProtectionCtas(
	fullRepoName: string,
	teamSlug: string,
): Action[] {
	const githubUrl = `https://github.com/${fullRepoName}`;
	const grafanaUrl = `https://metrics.gutools.co.uk/d/EOPnljWIz/repocop-compliance?var-team=${teamSlug}&var-rule=All&orgId=1`;
	const protectionUrl = `https://github.com/${fullRepoName}/settings/branches`;

	return [
		{ cta: `View ${fullRepoName} on GitHub`, url: githubUrl },
		{
			cta: `View compliance data for repositories owned by ${teamSlug}`,
			url: grafanaUrl,
		},
		{
			cta: `View branch protection settings for ${fullRepoName}`,
			url: protectionUrl,
		},
	];
}

export function topicMonitoringProductionTagCtas(
	fullRepoName: string,
	teamSlug: string,
): Action[] {
	const githubUrl = `https://github.com/${fullRepoName}`;
	const bestPracticesUrl =
		'https://github.com/guardian/service-catalogue/blob/main/packages/best-practices/best-practices.md';
	const grafanaUrl = `https://metrics.gutools.co.uk/d/EOPnljWIz/repocop-compliance?var-team=${teamSlug}&var-rule=All&orgId=1`;
	const topicsUrl =
		'https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/classifying-your-repository-with-topics#adding-topics-to-your-repository';

	return [
		{ cta: 'Repository', url: githubUrl },
		{ cta: 'Best practice rules', url: bestPracticesUrl },
		{
			cta: `View compliance data for repositories owned by ${teamSlug}`,
			url: grafanaUrl,
		},
		{
			cta: 'How to add a topic',
			url: topicsUrl,
		},
	];
}

export function anghammaradThreadKey(fullRepoName: string) {
	return `service-catalogue-${fullRepoName.replaceAll('/', '-')}`;
}

export function shuffle<T>(array: T[]): T[] {
	return array.sort(() => Math.random() - 0.5);
}

export function partition<T>(
	array: T[],
	predicate: (value: T) => boolean,
): [T[], T[]] {
	const truthy: T[] = [];
	const falsy: T[] = [];
	array.forEach((value) => {
		if (predicate(value)) {
			truthy.push(value);
		} else {
			falsy.push(value);
		}
	});
	return [truthy, falsy];
}

export async function applyTopics(
	repo: string,
	owner: string,
	octokit: Octokit,
	topic: string,
) {
	console.log(`Applying ${topic} topic to ${repo}`);
	const topics = (await octokit.rest.repos.getAllTopics({ owner, repo })).data
		.names;
	const names = topics.concat([topic]);
	await octokit.rest.repos.replaceAllTopics({ owner, repo, names });
}

export function stringToSeverity(severity: string): Severity {
	if (
		severity === 'low' ||
		severity === 'medium' ||
		severity === 'high' ||
		severity === 'critical'
	) {
		return severity;
	} else {
		return 'unknown';
	}
}

export function daysLeftToFix(
	severity: Severity,
	date: Date,
): number | undefined {
	const daysToFix = SLAs[severity];
	if (!daysToFix) {
		return undefined;
	}
	const fixDate = new Date(date);
	fixDate.setDate(fixDate.getDate() + daysToFix);
	const millisecondsInADay = 1000 * 60 * 60 * 24;
	const daysLeftToFix = Math.ceil(
		(fixDate.getTime() - new Date().getTime()) / millisecondsInADay,
	);

	return daysLeftToFix < 0 ? 0 : daysLeftToFix;
}

export function toNonEmptyArray<T>(value: T[]): NonEmptyArray<T> {
	if (value.length === 0) {
		throw new Error(`Expected a non-empty array. Source table may be empty.`);
	}
	return value as NonEmptyArray<T>;
}

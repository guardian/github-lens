import type { PrismaClient, repocop_vulnerabilities } from '@prisma/client';
import {
	daysLeftToFix,
	stringToSeverity,
	toNonEmptyArray,
} from 'common/src/functions';
import { logger } from 'common/src/logs';
import type {
	NonEmptyArray,
	RepocopVulnerability,
	Repository,
} from 'common/src/types';
import type { ObligationResult } from '.';

export type ObligatronRepocopVulnerability = RepocopVulnerability & {
	repo_owner: string;
};

function prismaToCustomType(
	vuln: repocop_vulnerabilities,
): ObligatronRepocopVulnerability {
	return {
		...vuln,
		severity: stringToSeverity(vuln.severity),
	};
}

async function getRepocopVulnerabilities(
	client: PrismaClient,
): Promise<NonEmptyArray<ObligatronRepocopVulnerability>> {
	const rawResponse = await client.repocop_vulnerabilities.findMany({});

	return toNonEmptyArray(rawResponse.map(prismaToCustomType));
}

async function getProductionRepos(client: PrismaClient): Promise<Repository[]> {
	console.debug('Discovering repositories');
	const repositories = await client.github_repositories.findMany({
		where: {
			archived: false,
			topics: {
				has: 'production',
			},
		},
	});

	return toNonEmptyArray(repositories.map((r) => r as Repository));
}

export function evaluateObligationForOneRepo(
	vulns: ObligatronRepocopVulnerability[],
	repo: Repository,
): ObligationResult | undefined {
	const repoVulns = vulns.filter((v) => v.full_name === repo.full_name);
	const repoOwners = [...new Set(repoVulns.flatMap((v) => v.repo_owner))];

	const urlParams = repoOwners
		.map((owner) => `var-repo_owner=${owner}`)
		.join('&');

	if (repoVulns.length > 0) {
		const vulnNames = [...new Set(repoVulns.map((v) => v.package))];
		logger.log({
			message: `Repository ${repo.full_name} has ${repoVulns.length} vulnerable packages: ${vulnNames.join(', ')}`,
			vulnNames,
		});

		return {
			resource: repo.full_name,
			reason: `Repository has ${vulnNames.length} vulnerable packages, ${vulnNames.join(', ')}`,
			url: `https://metrics.gutools.co.uk/d/fdib3p8l85jwgd/?${urlParams}`,
			contacts: { slugs: repoOwners },
		};
	} else {
		return undefined;
	}
}

export async function evaluateDependencyVulnerabilityObligation(
	client: PrismaClient,
): Promise<ObligationResult[]> {
	const repos = await getProductionRepos(client);
	const vulns = (await getRepocopVulnerabilities(client)).filter(
		(v) => daysLeftToFix(v.severity, v.alert_issue_date) === 0,
	);

	const resultsOrUndefined: Array<ObligationResult | undefined> = repos.map(
		(repo) => {
			return evaluateObligationForOneRepo(vulns, repo);
		},
	);

	return resultsOrUndefined.filter(
		(r): r is ObligationResult => r !== undefined,
	);
}

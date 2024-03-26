import type { Action } from '@guardian/anghammarad';
import { Anghammarad, RequestedChannel } from '@guardian/anghammarad';
import type { Config } from '../../config';
import { deduplicateVulnerabilitiesByCve } from '../../evaluation/repository';
import type {
	RepocopVulnerability,
	Team,
	VulnerabilityDigest,
} from '../../types';
import { vulnSortPredicate } from '../../utils';

export function getTopVulns(vulnerabilities: RepocopVulnerability[]) {
	return vulnerabilities
		.sort(vulnSortPredicate)
		.slice(0, 10)
		.sort((v1, v2) => v1.full_name.localeCompare(v2.full_name));
}

function createHumanReadableVulnMessage(vuln: RepocopVulnerability): string {
	const ecosystem =
		vuln.ecosystem === 'maven' ? 'sbt or maven' : vuln.ecosystem;

	return String.raw`[${vuln.full_name}](https://github.com/${vuln.full_name}) contains a [${vuln.severity.toUpperCase()} vulnerability](${vuln.urls[0]}).
Introduced via **${vuln.package}** on ${vuln.alert_issue_date.toDateString()}, from ${ecosystem}.
This vulnerability ${vuln.is_patchable ? 'is ' : 'may *not* be '}patchable.`;
}

export function createDigest( //TODO test this
	team: Team,
	allVulnerabilities: RepocopVulnerability[],
): VulnerabilityDigest | undefined {
	const vulns = deduplicateVulnerabilitiesByCve(
		allVulnerabilities.filter((v) => v.repo_owner === team.slug),
	);

	const totalVulnsCount = vulns.length;

	const vulnerableReposCount = new Set(vulns.map((v) => v.full_name)).size;

	if (totalVulnsCount === 0) {
		return undefined;
	}

	const topVulns = getTopVulns(vulns);
	const listedVulnsCount = topVulns.length;
	const preamble = String.raw`Found ${totalVulnsCount} vulnerabilities across ${vulnerableReposCount} repositories.
Displaying the top ${listedVulnsCount} most urgent.
Note: DevX only aggregates vulnerability information for repositories with a production topic.`;

	const digestString = topVulns
		.map((v) => createHumanReadableVulnMessage(v))
		.join('\n\n');

	const message = `${preamble}\n\n${digestString}`;

	return {
		teamSlug: team.slug,
		subject: `Vulnerability Digest for ${team.name}`,
		message,
	};
}

export function isFirstOrThirdTuesdayOfMonth(date: Date) {
	const isTuesday = date.getDay() === 2;
	const inFirstWeek = date.getDate() <= 7;
	const inThirdWeek = date.getDate() >= 15 && date.getDate() <= 21;
	return isTuesday && (inFirstWeek || inThirdWeek);
}

async function sendVulnerabilityDigests(
	digests: VulnerabilityDigest[],
	config: Config,
) {
	const anghammarad = new Anghammarad();
	console.log(
		`Sending ${digests.length} vulnerability digests: ${digests
			.map((d) => d.teamSlug)
			.join(', ')}`,
	);

	const action: Action = {
		cta: "See 'Prioritise the vulnerabilities' of these docs for vulnerability obligations",
		url: 'https://security-hq.gutools.co.uk/documentation/vulnerability-management',
	};
	return Promise.all(
		digests.map(
			async (digest) =>
				await anghammarad.notify({
					subject: digest.subject,
					message: digest.message,
					actions: [action],
					target: { GithubTeamSlug: digest.teamSlug },
					channel: RequestedChannel.PreferHangouts,
					sourceSystem: `${config.app} ${config.stage}`,
					topicArn: config.anghammaradSnsTopic,
					threadKey: `vulnerability-digest-${digest.teamSlug}`,
				}),
		),
	);
}

export async function createAndSendVulnerabilityDigests(
	config: Config,
	teams: Team[],
	allVulnerabilities: RepocopVulnerability[],
) {
	const digests = teams
		.map((t) => createDigest(t, allVulnerabilities))
		.filter((d): d is VulnerabilityDigest => d !== undefined);

	console.log('Logging vulnerability digests');
	digests.forEach((digest) => console.log(JSON.stringify(digest)));

	if (isFirstOrThirdTuesdayOfMonth(new Date()) && config.stage === 'PROD') {
		await sendVulnerabilityDigests(digests, config);
	} else {
		console.log('Not sending vulnerability digests');
	}
}

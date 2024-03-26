import type { RepocopVulnerability, Team } from '../../types';
import {
	createDigest,
	getTopVulns,
	isFirstOrThirdTuesdayOfMonth,
} from './vuln-digest';

const fullName = 'guardian/repo';
const teamSlug = 'team';
const teamId = BigInt(1);
const teamName = 'Team Name';

const team: Team = { id: teamId, name: teamName, slug: teamSlug };
const anotherTeam: Team = {
	id: BigInt(2),
	name: 'Another Team Name',
	slug: 'another-team',
};

const vuln: RepocopVulnerability = {
	source: 'Dependabot',
	full_name: fullName,
	open: true,
	severity: 'high',
	package: 'leftpad',
	urls: ['example.com'],
	ecosystem: 'pip',
	alert_issue_date: new Date('2023-01-01'),
	is_patchable: true,
	cves: ['CVE-123'],
	repo_owner: teamSlug,
};

const irrelevantVuln: RepocopVulnerability = {
	...vuln,
	full_name: 'guardian/anotherRepo',
	repo_owner: 'another-team',
};

describe('createDigest', () => {
	it('returns undefined when the total vuln count is zero', () => {
		expect(createDigest(team, [irrelevantVuln])).toBeUndefined();
	});

	it('returns a digest when a result contains a vulnerability', () => {
		expect(createDigest(team, [vuln])).toStrictEqual({
			teamSlug,
			subject: `Vulnerability Digest for ${teamName}`,
			message: String.raw`Found 1 vulnerabilities across 1 repositories.
Displaying the top 1 most urgent.
Note: DevX only aggregates vulnerability information for repositories with a production topic.

[guardian/repo](https://github.com/guardian/repo) contains a [HIGH vulnerability](example.com).
Introduced via **leftpad** on Sun Jan 01 2023, from pip.
This vulnerability is patchable.`,
		});
	});

	it('recognises that a SBT dependency could come from Maven', () => {
		const sbtVuln: RepocopVulnerability = {
			...vuln,
			package: 'jackson',
			ecosystem: 'maven',
			alert_issue_date: new Date(),
		};

		expect(createDigest(team, [sbtVuln])?.message).toContain('sbt or maven');
	});

	it('returns the correct digest for the correct team', () => {
		const leftpad: RepocopVulnerability = {
			source: 'Dependabot',
			full_name: fullName,
			open: true,
			severity: 'high',
			package: 'leftpad',
			urls: ['example.com'],
			ecosystem: 'pip',
			alert_issue_date: new Date(),
			is_patchable: true,
			cves: ['CVE-123'],
			repo_owner: teamSlug,
		};
		const rightpad: RepocopVulnerability = {
			source: 'Dependabot',
			full_name: fullName,
			open: true,
			severity: 'high',
			package: 'rightpad',
			urls: ['example.com'],
			ecosystem: 'pip',
			alert_issue_date: new Date(),
			is_patchable: true,
			cves: ['CVE-123'],
			repo_owner: anotherTeam.slug,
		};
		const digest = createDigest(team, [leftpad, rightpad]);
		expect(digest?.teamSlug).toBe(team.slug);
		expect(digest?.message).toContain('leftpad');

		const anotherDigest = createDigest(anotherTeam, [leftpad, rightpad]);
		expect(anotherDigest?.teamSlug).toBe(anotherTeam.slug);
		expect(anotherDigest?.message).toContain('rightpad');
	});
});

describe('getTopVulns', () => {
	it('returns results are sorted by repo', () => {
		const vulns = [
			{ full_name: 'guardian/repo-a', severity: 'critical' },
			{ full_name: 'guardian/repo-b', severity: 'high' },
			{ full_name: 'guardian/repo-a', severity: 'high' },
			{ full_name: 'guardian/repo-c', severity: 'high' },
		] as RepocopVulnerability[];
		expect(getTopVulns(vulns)).toStrictEqual([
			{ full_name: 'guardian/repo-a', severity: 'critical' },
			{ full_name: 'guardian/repo-a', severity: 'high' },
			{ full_name: 'guardian/repo-b', severity: 'high' },
			{ full_name: 'guardian/repo-c', severity: 'high' },
		]);
	});

	const v = {
		full_name: 'guardian/repo-a',
		severity: 'critical',
	};

	const vHigh = {
		...v,
		severity: 'high',
	};

	it('returns 10 results', () => {
		const vulns = new Array(20).fill(v) as RepocopVulnerability[];
		expect(getTopVulns(vulns).length).toBe(10);
	});

	it('returns results sorted by severity', () => {
		const vulns = [
			...(new Array(8).fill(vHigh) as RepocopVulnerability[]),
			...(new Array(8).fill(v) as RepocopVulnerability[]),
		];

		const topVulns = getTopVulns(vulns);

		const criticalCount = topVulns.filter(
			(v) => v.severity === 'critical',
		).length;
		const highCount = topVulns.filter((v) => v.severity === 'high').length;

		expect(criticalCount).toBe(8);
		expect(highCount).toBe(2);
	});
});

describe('isFirstOrThirdTuesdayOfMonth', () => {
	test('should return true if the date is the first or third Tuesday of the month', () => {
		const tuesday = new Date('2024-02-06T00:00:00.000Z'); // First Tuesday
		const result = isFirstOrThirdTuesdayOfMonth(tuesday);
		expect(result).toBe(true);
	});
	test('should return false if the date is not a Tuesday', () => {
		const wednesday = new Date('2024-02-07T00:00:00.000Z'); // First Wednesday
		const result = isFirstOrThirdTuesdayOfMonth(wednesday);
		expect(result).toBe(false);
	});
	test('should return false if the date is the second Tuesday of the month', () => {
		const tuesday = new Date('2024-02-13T00:00:00.000Z'); // Second Tuesday
		const result = isFirstOrThirdTuesdayOfMonth(tuesday);
		expect(result).toBe(false);
	});
});

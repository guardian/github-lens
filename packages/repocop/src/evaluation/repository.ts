import type {
	github_languages,
	github_repository_branches,
	repocop_github_repository_rules,
	view_repo_ownership,
} from '@prisma/client';
import { partition } from 'common/src/functions';
import {
	supportedDependabotLanguages,
	supportedSnykLanguages,
} from '../languages';
import type {
	Alert,
	AwsCloudFormationStack,
	Dependency,
	EvaluationResult,
	RepoAndStack,
	RepocopVulnerability,
	Repository,
	SnykIssue,
	SnykProject,
	Tag,
} from '../types';
import {
	findOwnerSlugs,
	isProduction,
	stringToSeverity,
	vulnSortPredicate,
} from '../utils';

/**
 * Evaluate the following rule for a Github repository:
 *   > The default branch name should be "main".
 */
function hasDefaultBranchNameMain(repo: Repository): boolean {
	return repo.default_branch === 'main';
}

/**
 * Evaluate the following rule for a Github repository:
 *   > Enable branch protection for the default branch, ensuring changes are reviewed before being deployed.
 */
function hasBranchProtection(
	repo: Repository,
	branches: github_repository_branches[],
): boolean {
	const exempt = !(
		repo.topics.includes('production') || repo.topics.includes('documentation')
	);

	const branch = branches.find(
		(branch) =>
			branch.repository_id === repo.id && branch.name === repo.default_branch,
	);
	if (exempt || branch === undefined) {
		return true;
	} else {
		return branch.protected ?? false;
	}
}

/**
 * Evaluate the following rule for a Github repository:
 *   > Grant at least one GitHub team Admin access - typically, the dev team that own the project.
 *   > Repositories without one of the following topics are exempt: production, testing, documentation.
 */
function hasAdminTeam(repo: Repository, teams: view_repo_ownership[]): boolean {
	// Repos that have explicitly been classified as these topics are exempt.
	// Any other repos, regardless of topic, need to be owned by a team, or assigned one of these topics.
	const exemptedTopics = ['prototype', 'learning', 'hackday', 'interactive'];
	const isExempt =
		repo.topics.filter((topic) => exemptedTopics.includes(topic)).length > 0;

	const adminTeams = teams.filter(
		({ full_repo_name, role_name }) =>
			full_repo_name === repo.full_name && role_name === 'admin',
	);
	const hasAdminTeam = adminTeams.length > 0;

	return isExempt || hasAdminTeam;
}
/**
 * Evaluate the following rule for a Github repository:
 *   > Repositories should have one and only one of the following topics to help understand what is in production.
 *   > Repositories owned only by non-P&E teams are exempt.
 */
function hasStatusTopic(repo: Repository): boolean {
	const validTopics = [
		'prototype',
		'learning',
		'hackday',
		'testing',
		'documentation',
		'production',
		'interactive',
	];

	return (
		repo.topics.filter((topic) => validTopics.includes(topic)).length === 1
	);
}

function mostRecentChange(repo: Repository): Date | undefined {
	const definiteDates: Date[] = [
		repo.created_at,
		repo.updated_at,
		repo.pushed_at,
	].filter((d): d is Date => !!d);

	const sortedDates = definiteDates.sort((a, b) => b.getTime() - a.getTime());
	return sortedDates[0] ?? undefined;
}

function isMaintained(repo: Repository): boolean {
	const update: Date | undefined = mostRecentChange(repo);
	const now = new Date();
	const twoYearsAgo = new Date();
	twoYearsAgo.setFullYear(now.getFullYear() - 2);
	//avoid false positives and use current moment if no dates are available for now
	//a repo always has a created_at date, so this is unlikely to happen unless something is wrong with cloudquery
	const recentlyUpdated = (update ?? new Date()) > twoYearsAgo;
	const isInteractive = repo.topics.includes('interactive');

	return isInteractive || recentlyUpdated;
}

/**
 * Evaluate the following rule for a Github repository:
 *   > Repositories should have their dependencies tracked via Snyk or Dependabot, depending on the languages present.
 */
export function hasDependencyTracking(
	repo: Repository,
	repoLanguages: github_languages[],
	reposOnSnyk: string[],
): boolean {
	if (!repo.topics.includes('production') || repo.archived) {
		return true;
	}

	const languages: string[] =
		repoLanguages.find(
			(repoLanguage) => repoLanguage.full_name === repo.full_name,
		)?.languages ?? [];

	//Using both for now so we don't have to delete all the dead snyk project matching code to make the linter happy
	const repoIsOnSnyk = reposOnSnyk.includes(repo.full_name);

	if (repoIsOnSnyk) {
		const containsOnlySnykSupportedLanguages = languages.every((language) =>
			supportedSnykLanguages.includes(language),
		);
		if (!containsOnlySnykSupportedLanguages) {
			console.log(
				`${repo.name} contains the following languages not supported by Snyk: `,
				languages.filter(
					(language) => !supportedSnykLanguages.includes(language),
				),
			);
		}
		return containsOnlySnykSupportedLanguages;
	} else {
		const containsOnlyDependabotSupportedLanguages = languages.every(
			(language) => supportedDependabotLanguages.includes(language),
		);
		if (!containsOnlyDependabotSupportedLanguages) {
			console.log(
				`${repo.name} contains the following languages not supported by Dependabot: `,
				languages.filter(
					(language) => !supportedDependabotLanguages.includes(language),
				),
			);
		}

		return containsOnlyDependabotSupportedLanguages;
	}
}

/**
 * Evaluate the following rule for a Github repository:
 *   > Archived repositories should not have corresponding stacks on AWS.
 */
export function findStacks(
	repo: Repository,
	stacks: AwsCloudFormationStack[],
): RepoAndStack {
	const stackMatches = stacks.filter((stack) => {
		return (
			!!stack.stack_name &&
			(stack.tags['gu:repo'] === repo.full_name ||
				stack.stack_name.includes(repo.name))
		);
	});
	const stackNames = stackMatches
		.map((stack) => stack.stack_name)
		.filter((s) => !!s);

	return {
		fullName: repo.full_name,
		stacks: stackNames,
	};
}

function findArchivedReposWithStacks(
	archivedRepositories: Repository[],
	unarchivedRepositories: Repository[],
	stacks: AwsCloudFormationStack[],
) {
	const archivedRepos = archivedRepositories;
	const unarchivedRepos = unarchivedRepositories;

	const stacksWithoutAnUnarchivedRepoMatch: AwsCloudFormationStack[] =
		stacks.filter((stack) =>
			unarchivedRepos.some(
				(repo) => !(repo.full_name === stack.tags['gu:repo']),
			),
		);

	const archivedReposWithPotentialStacks: RepoAndStack[] = archivedRepos
		.map((repo) => findStacks(repo, stacksWithoutAnUnarchivedRepoMatch))
		.filter((result) => result.stacks.length > 0);

	return archivedReposWithPotentialStacks;
}

function vulnerabilityNeedsAddressing(date: Date, severity: string) {
	const criticalDayCount = 1;
	const highDayCount = 14;

	const criticalVulnCutOff = new Date();
	criticalVulnCutOff.setDate(criticalVulnCutOff.getDate() - criticalDayCount);
	criticalVulnCutOff.setHours(0, 0, 0, 0);

	const highVulnCutOff = new Date();
	highVulnCutOff.setDate(highVulnCutOff.getDate() - highDayCount);
	highVulnCutOff.setHours(0, 0, 0, 0);

	if (severity === 'critical') {
		return date < criticalVulnCutOff;
	} else if (severity === 'high') {
		return date < highVulnCutOff;
	} else {
		return false;
	}
}

export function hasOldAlerts(
	alerts: RepocopVulnerability[],
	repo: Repository,
): boolean {
	if (!isProduction(repo)) {
		return false;
	}
	const oldAlerts = alerts.filter((a) =>
		vulnerabilityNeedsAddressing(new Date(a.alert_issue_date), a.severity),
	);

	if (oldAlerts.length > 0) {
		console.log(
			`${repo.name}: has ${oldAlerts.length} alerts that need addressing`,
		);
		console.debug(oldAlerts);
	}

	return oldAlerts.length > 0;
}

function getIssuesForProject(
	projectId: string,
	issues: SnykIssue[],
): SnykIssue[] {
	return issues.filter(
		(issue) => issue.relationships.scan_item.data.id === projectId,
	);
}

export function collectAndFormatUrgentSnykAlerts(
	repo: Repository,
	snykIssues: SnykIssue[],
	snykProjects: SnykProject[],
	repoOwners: view_repo_ownership[],
): RepocopVulnerability[] {
	if (!isProduction(repo)) {
		return [];
	}

	const snykProjectIdsForRepo = snykProjects
		.filter((project) => {
			const tagValues = project.attributes.tags.map((tag) => tag.value);
			return tagValues.includes(repo.full_name);
		})
		.map((project) => project.id);

	const snykIssuesForRepo: SnykIssue[] = snykProjectIdsForRepo
		.flatMap((projectId) => getIssuesForProject(projectId, snykIssues))
		.filter((i) => !i.attributes.ignored);

	const processedVulns = snykIssuesForRepo.flatMap((v) =>
		snykAlertToRepocopVulnerability(
			repo.full_name,
			v,
			snykProjects,
			repoOwners,
		),
	);

	const relevantVulns = processedVulns.filter(
		(vuln) =>
			(vuln.severity === 'high' || vuln.severity === 'critical') && vuln.open,
	);

	return relevantVulns;
}

export function testExperimentalRepocopFeatures(
	evaluationResults: EvaluationResult[],
	unarchivedRepos: Repository[],
	archivedRepos: Repository[],
	nonPlaygroundStacks: AwsCloudFormationStack[],
) {
	const evaluatedRepos = evaluationResults.map((r) => r.repocopRules);
	const unmaintinedReposCount = evaluatedRepos.filter(
		(repo) => repo.archiving === false,
	).length;

	console.log(
		`Found ${unmaintinedReposCount} unmaintained repositories of ${unarchivedRepos.length}.`,
	);

	const archivedWithStacks = findArchivedReposWithStacks(
		archivedRepos,
		unarchivedRepos,
		nonPlaygroundStacks,
	);

	console.log(`Found ${archivedWithStacks.length} archived repos with stacks.`);

	console.log(
		'Archived repos with live stacks, first 3 results:',
		archivedWithStacks.slice(0, 3),
	);
}

//We will have to deduplicate by CVE and team slug
export function deduplicateVulnerabilitiesByCve(
	vulns: RepocopVulnerability[],
): RepocopVulnerability[] {
	const vulnsWithSortedCVEs = vulns.map((v) => {
		return {
			...v,
			cves: v.cves.sort(),
		};
	});
	const [withCVEs, withoutCVEs] = partition(
		vulnsWithSortedCVEs,
		(v) => v.cves.length > 0,
	);

	//group withCVEs by CVEs
	const dedupedWithCVEs = withCVEs
		.sort(vulnSortPredicate)
		.reduce<Record<string, RepocopVulnerability>>((acc, vuln) => {
			const key = vuln.cves.join(',');
			if (!acc[key]) {
				acc[key] = vuln;
			}
			return acc;
		}, {});

	const dedupedVulns = Object.values(dedupedWithCVEs).concat(withoutCVEs);
	return dedupedVulns;
}

/**
 * Apply rules to a repository as defined in https://github.com/guardian/recommendations/blob/main/best-practices.md.
 */
export function evaluateOneRepo(
	potentialVulnerabilities: RepocopVulnerability[], //TODO test this
	repo: Repository,
	allBranches: github_repository_branches[],
	teams: view_repo_ownership[],
	repoLanguages: github_languages[],
	reposOnSnyk: string[],
): EvaluationResult {
	const vulnerabilities = potentialVulnerabilities.filter(
		(v) => v.full_name === repo.full_name,
	);
	hasOldAlerts(vulnerabilities, repo);

	const repocopRules: repocop_github_repository_rules = {
		full_name: repo.full_name,
		default_branch_name: hasDefaultBranchNameMain(repo),
		branch_protection: hasBranchProtection(repo, allBranches),
		team_based_access: false,
		admin_access: hasAdminTeam(repo, teams),
		archiving: isMaintained(repo),
		topics: hasStatusTopic(repo),
		contents: null,
		vulnerability_tracking: hasDependencyTracking(
			repo,
			repoLanguages,
			reposOnSnyk,
		),
		evaluated_on: new Date(),
	};

	return {
		fullName: repo.full_name,
		repocopRules,
		vulnerabilities: deduplicateVulnerabilitiesByCve(vulnerabilities),
	};
}

export function snykAlertToRepocopVulnerability(
	fullName: string,
	issue: SnykIssue,
	projects: SnykProject[],
	repoOwners: view_repo_ownership[],
): RepocopVulnerability[] {
	const packages = (issue.attributes.coordinates ?? [])
		.flatMap((c) => c.representations)
		.filter((r) => r !== null) as Dependency[];

	const projectIdFromIssue = issue.relationships.scan_item.data.id;

	const ecosystem = projects.find((p) => p.id === projectIdFromIssue)
		?.attributes.type;

	const isPatchable = (issue.attributes.coordinates ?? [])
		.map((c) => c.is_patchable ?? c.is_upgradeable ?? c.is_pinnable ?? false)
		.includes(true);

	const packageName = [
		...new Set(packages.map((p) => p.dependency.package_name)),
	].join(', ');

	const vuln = {
		full_name: fullName,
		open: issue.attributes.status === 'open',
		source: 'Snyk',
		severity: stringToSeverity(issue.attributes.effective_severity_level),
		package: packageName,
		urls: issue.attributes.problems.map((p) => p.url).filter((u) => !!u),
		ecosystem: ecosystem ?? 'unknown ecosystem',
		alert_issue_date: issue.attributes.created_at,
		is_patchable: isPatchable,
		cves: issue.attributes.problems.map((p) => p.id),
	};

	const ownerSlugs = findOwnerSlugs(fullName, repoOwners);

	if (ownerSlugs.length === 0) {
		return [{ ...vuln, repo_owner: 'unknown' }];
	} else {
		return ownerSlugs.map((slug) => ({ ...vuln, repo_owner: slug }));
	}
}

export function dependabotAlertToRepocopVulnerability(
	fullName: string,
	alert: Alert,
	repoOwners: view_repo_ownership[],
): RepocopVulnerability[] {
	const CVEs = alert.security_advisory.identifiers
		.filter((i) => i.type === 'CVE')
		.map((i) => i.value);

	const vuln = {
		open: alert.state === 'open',
		full_name: fullName,
		source: 'Dependabot',
		severity: alert.security_advisory.severity,
		package: alert.security_vulnerability.package.name,
		urls: alert.security_advisory.references.map((ref) => ref.url),
		ecosystem: alert.security_vulnerability.package.ecosystem,
		alert_issue_date: new Date(alert.created_at),
		is_patchable: !!alert.security_vulnerability.first_patched_version,
		cves: CVEs,
	};

	const ownerSlugs = findOwnerSlugs(fullName, repoOwners);

	if (ownerSlugs.length === 0) {
		return [{ ...vuln, repo_owner: 'unknown' }];
	} else {
		return ownerSlugs.map((slug) => ({ ...vuln, repo_owner: slug }));
	}
}

export function evaluateRepositories( //TODO can be tested
	repositories: Repository[],
	branches: github_repository_branches[],
	owners: view_repo_ownership[],
	repoLanguages: github_languages[],
	vulnerabilities: RepocopVulnerability[],
	snykProjects: SnykProject[],
): EvaluationResult[] {
	const evaluatedRepos = repositories.map((r) => {
		const isMainBranchPredicate = (x: Tag) =>
			x.key === 'branch' && (x.value === 'main' || x.value === 'master');

		const reposOnSnyk = snykProjects
			.map((p) => p.attributes.tags)
			.filter((tags) => tags.map(isMainBranchPredicate).includes(true))
			.map((tags) => tags.find((x) => x.key === 'repo')?.value)
			.filter((x) => x !== undefined) as string[];

		const uniqueReposOnSnyk = [...new Set(reposOnSnyk)];
		const teamsForRepo = owners.filter((o) => o.full_repo_name === r.full_name);
		const branchesForRepo = branches.filter((b) => b.repository_id === r.id);

		return evaluateOneRepo(
			vulnerabilities,
			r,
			branchesForRepo,
			teamsForRepo,
			repoLanguages,
			uniqueReposOnSnyk,
		);
	});
	return evaluatedRepos;
}

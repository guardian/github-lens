import type { Action } from '@guardian/anghammarad';
import { Anghammarad, RequestedChannel } from '@guardian/anghammarad';
import type {
	github_languages,
	github_repository_branches,
	repocop_github_repository_rules,
	snyk_projects,
	snyk_reporting_latest_issues,
	view_repo_ownership,
} from '@prisma/client';
import { partition } from 'common/src/functions';
import type { Octokit } from 'octokit';
import type { Config } from '../config';
import {
	supportedDependabotLanguages,
	supportedSnykLanguages,
} from '../languages';
import type {
	Alert,
	AwsCloudFormationStack,
	DependabotVulnResponse,
	EvaluationResult,
	GuardianSnykTags,
	ProjectTag,
	RepoAndStack,
	RepocopVulnerability,
	Repository,
	SnykIssue,
	SnykProject,
	Team,
	TeamRepository,
	VulnerabilityDigest,
} from '../types';
import { isProduction, stringToSeverity, vulnSortPredicate } from '../utils';
import { createDigest } from '../vulnerability-digest';

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
function hasAdminTeam(repo: Repository, teams: TeamRepository[]): boolean {
	// Repos that have explicitly been classified as these topics are exempt.
	// Any other repos, regardless of topic, need to be owned by a team, or assigned one of these topics.
	const exemptedTopics = ['prototype', 'learning', 'hackday', 'interactive'];
	const isExempt =
		repo.topics.filter((topic) => exemptedTopics.includes(topic)).length > 0;

	const adminTeams = teams.filter(
		({ id, role_name }) => id === repo.id && role_name === 'admin',
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

interface SnykTags {
	commit?: string;
	branch?: string;
	repo?: string;
}

export function parseSnykTags(snyk_projects: snyk_projects) {
	interface TagValues {
		key: string;
		value: string;
	}

	const tagString = JSON.stringify(snyk_projects.tags);
	const tags = JSON.parse(tagString) as TagValues[];

	const snykTags: SnykTags = {
		commit: tags.find((tag) => tag.key === 'commit')?.value,
		branch: tags.find((tag) => tag.key === 'branch')?.value,
		repo: tags.find((tag) => tag.key === 'repo')?.value,
	};

	return snykTags;
}

function toGuardianSnykTags(tags: ProjectTag[]): GuardianSnykTags {
	return {
		repo: tags.find((t) => t.key === 'repo')?.value,
		branch: tags.find((t) => t.key === 'branch')?.value,
	};
}

function getTagsFromSnykProject(
	snykProjectsFromRest: SnykProject[],
): GuardianSnykTags[] {
	const allSnykTags = snykProjectsFromRest
		.map((x) => x.attributes.tags)
		.map(toGuardianSnykTags)
		.filter((x) => !!x.repo && !!x.branch);

	const uniqueStringTags: string[] = [
		...new Set(allSnykTags.map((t) => JSON.stringify(t))),
	];

	const uniqueTags = uniqueStringTags.map(
		(t) => JSON.parse(t) as GuardianSnykTags,
	);
	return uniqueTags;
}

/**
 * Evaluate the following rule for a Github repository:
 *   > Repositories should have their dependencies tracked via Snyk or Dependabot, depending on the languages present.
 */
export function hasDependencyTracking(
	repo: Repository,
	repoLanguages: github_languages[],
	snykProjectsFromRest: SnykProject[],
): boolean {
	if (!repo.topics.includes('production') || repo.archived) {
		return true;
	}

	const languages: string[] =
		repoLanguages.find(
			(repoLanguage) => repoLanguage.full_name === repo.full_name,
		)?.languages ?? [];

	//This is a temporary workaround until we get the snyk_projects table back.
	const tags = getTagsFromSnykProject(snykProjectsFromRest);

	function snykProjectExists(repo: Repository, allProjectTags: SnykTags[]) {
		const result = allProjectTags.find(
			(tags) =>
				//TODO - this is a close enough match for now, but in the future we should use commit hashes
				//to make sure the projects are in sync
				!!repo.full_name &&
				tags.repo == repo.full_name &&
				tags.branch === repo.default_branch,
		);
		const exists = result !== undefined;
		return exists;
	}

	//Using both for now so we don't have to delete all the dead snyk project matching code to make the linter happy
	const repoIsOnSnyk = snykProjectExists(repo, tags);

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

export async function getAlertsForRepo(
	octokit: Octokit,
	name: string,
): Promise<Alert[] | undefined> {
	if (name.startsWith('guardian/')) {
		name = name.replace('guardian/', '');
	}

	try {
		const alert: DependabotVulnResponse =
			await octokit.rest.dependabot.listAlertsForRepo({
				owner: 'guardian',
				repo: name,
				per_page: 100,
				severity: 'critical,high',
				state: 'open',
				sort: 'created',
				direction: 'asc', //retrieve oldest vulnerabilities first
			});

		const openRuntimeDependencies = alert.data.filter(
			(a) => a.dependency.scope !== 'development',
		);
		return openRuntimeDependencies;
	} catch (error) {
		console.debug(
			`Dependabot - ${name}: Could not get alerts. Dependabot may not be enabled.`,
		);
		console.debug(error);
		return undefined;
	}
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

function getProjectIssues(
	projectId: string,
	issues: snyk_reporting_latest_issues[],
): snyk_reporting_latest_issues[] {
	return issues.filter((issue) =>
		JSON.stringify(issue.projects).includes(projectId),
	);
}

export function collectAndFormatUrgentSnykAlerts(
	repo: Repository,
	snykIssues: snyk_reporting_latest_issues[],
	snykProjects: SnykProject[],
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

	const snykIssuesForRepo: snyk_reporting_latest_issues[] =
		snykProjectIdsForRepo
			.map((projectId) => getProjectIssues(projectId, snykIssues))
			.flat();
	const processedVulns = snykIssuesForRepo.map((v) =>
		snykAlertToRepocopVulnerability(repo.full_name, v),
	);

	const relevantVulns = processedVulns.filter(
		(vuln) =>
			(vuln.severity === 'high' || vuln.severity === 'critical') && vuln.open,
	);

	return relevantVulns;
}

export function isFirstOrThirdTuesdayOfMonth(date: Date) {
	const isTuesday = date.getDay() === 2;
	const inFirstWeek = date.getDate() <= 7;
	const inThirdWeek = date.getDate() >= 15 && date.getDate() <= 21;
	return isTuesday && (inFirstWeek || inThirdWeek);
}

function sendVulnerabilityDigests(
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
					// target: { GithubTeamSlug: digest.teamSlug },
					target: { Stack: 'testing-alerts ' },
					channel: RequestedChannel.PreferHangouts,
					sourceSystem: `${config.app} ${config.stage}`,
					topicArn: config.anghammaradSnsTopic,
					threadKey: `vulnerability-digest-${digest.teamSlug}`,
				}),
		),
	);
}

export async function testExperimentalRepocopFeatures(
	evaluationResults: EvaluationResult[],
	unarchivedRepos: Repository[],
	archivedRepos: Repository[],
	nonPlaygroundStacks: AwsCloudFormationStack[],
	teams: Team[],
	config: Config,
	repoOwners: view_repo_ownership[],
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

	const someDigests = teams
		.sort((a, b) => a.slug.localeCompare(b.slug))
		.slice(0, 30)
		.map((t) => createDigest(t, repoOwners, evaluationResults))
		.filter((d): d is VulnerabilityDigest => d !== undefined);

	if (
		isFirstOrThirdTuesdayOfMonth(new Date()) /* && config.stage === 'PROD' */
	) {
		await sendVulnerabilityDigests(someDigests, config);
	} else {
		console.log('Logging vulnerability digests');
		someDigests.forEach((digest) => console.log(JSON.stringify(digest)));
	}
}

export function deduplicateVulnerabilitiesByCve(
	vulns: RepocopVulnerability[],
): RepocopVulnerability[] {
	const vulnsWithSortedCVEs = vulns.map((v) => {
		return {
			...v,
			CVEs: v.CVEs.sort(),
		};
	});
	const [withCVEs, withoutCVEs] = partition(
		vulnsWithSortedCVEs,
		(v) => v.CVEs.length > 0,
	);

	//group withCVEs by CVEs
	const dedupedWithCVEs = withCVEs
		.sort(vulnSortPredicate)
		.reduce<Record<string, RepocopVulnerability>>((acc, vuln) => {
			const key = vuln.CVEs.join(',');
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
	dependabotAlertsForRepo: RepocopVulnerability[] | undefined,
	repo: Repository,
	allBranches: github_repository_branches[],
	teams: TeamRepository[],
	repoLanguages: github_languages[],
	latestSnykIssues: snyk_reporting_latest_issues[],
	snykProjectsFromRest: SnykProject[],
): EvaluationResult {
	const snykAlertsForRepo = collectAndFormatUrgentSnykAlerts(
		repo,
		latestSnykIssues,
		snykProjectsFromRest,
	);

	const vulnerabilities = snykAlertsForRepo.concat(
		dependabotAlertsForRepo ?? [],
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
			snykProjectsFromRest,
		),
		evaluated_on: new Date(),
	};

	return {
		fullName: repo.full_name,
		repocopRules,
		vulnerabilities: deduplicateVulnerabilitiesByCve(vulnerabilities),
	};
}

export function dependabotAlertToRepocopVulnerability(
	fullName: string,
	alert: Alert,
): RepocopVulnerability {
	const CVEs = alert.security_advisory.identifiers
		.filter((i) => i.type === 'CVE')
		.map((i) => i.value);

	return {
		open: alert.state === 'open',
		fullName,
		source: 'Dependabot',
		severity: alert.security_advisory.severity,
		package: alert.security_vulnerability.package.name,
		urls: alert.security_advisory.references.map((ref) => ref.url),
		ecosystem: alert.security_vulnerability.package.ecosystem,
		alert_issue_date: alert.created_at,
		isPatchable: !!alert.security_vulnerability.first_patched_version,
		CVEs,
	};
}

export function snykAlertToRepocopVulnerability(
	fullName: string,
	alert: snyk_reporting_latest_issues,
): RepocopVulnerability {
	const issue = alert.issue as unknown as SnykIssue;

	return {
		fullName,
		open: alert.is_fixed !== true && !issue.isIgnored,
		source: 'Snyk',
		severity: stringToSeverity(issue.severity),
		package: issue.package,
		urls: issue.url ? [issue.url] : [],
		ecosystem: issue.packageManager,
		// eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- this is never null in reality
		alert_issue_date: alert.introduced_date!,
		isPatchable: issue.isPatchable || issue.isUpgradable || issue.isPinnable,
		CVEs: issue.Identifiers.CVE ?? [],
	};
}

// export async function evaluateRepositories(
// 	repositories: Repository[],
// 	branches: github_repository_branches[],
// 	teams: TeamRepository[],
// 	repoLanguages: github_languages[],
// 	latestSnykIssues: snyk_reporting_latest_issues[],
// 	snykProjectsFromRest: SnykProject[],
// 	octokit: Octokit,
// ): Promise<EvaluationResult[]> {
// 	const evaluatedRepos = repositories.map(async (r) => {
// 		const dependabotAlerts = isProduction(r)
// 			? (await getAlertsForRepo(octokit, r.name))
// 					?.filter((a) => a.state === 'open')
// 					.map((a) => dependabotAlertToRepocopVulnerability(r.full_name, a))
// 			: [];
// 		const teamsForRepo = teams.filter((t) => t.id === r.id);
// 		const branchesForRepo = branches.filter((b) => b.repository_id === r.id);
// 		return evaluateOneRepo(
// 			dependabotAlerts,
// 			r,
// 			branchesForRepo,
// 			teamsForRepo,
// 			repoLanguages,
// 			latestSnykIssues,
// 			snykProjectsFromRest,
// 		);
// 	});
// 	return Promise.all(evaluatedRepos);
// }

export function evaluateRepositories(
	repositories: Repository[],
	branches: github_repository_branches[],
	teams: TeamRepository[],
	repoLanguages: github_languages[],
	latestSnykIssues: snyk_reporting_latest_issues[],
	snykProjectsFromRest: SnykProject[],
): EvaluationResult[] {
	const evaluatedRepos = repositories.map((r) => {
		const teamsForRepo = teams.filter((t) => t.id === r.id);
		const branchesForRepo = branches.filter((b) => b.repository_id === r.id);
		return evaluateOneRepo(
			undefined,
			r,
			branchesForRepo,
			teamsForRepo,
			repoLanguages,
			latestSnykIssues,
			snykProjectsFromRest,
		);
	});
	return evaluatedRepos;
}

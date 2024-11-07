import type { github_repository_branches } from '@prisma/client';
import type {
	AugmentedRepository,
	RepocopVulnerability,
} from 'common/src/types';
import { example } from '../test-data/example-dependabot-alerts';
import type {
	AwsCloudFormationStack,
	Coordinate,
	SnykIssue,
	SnykProject,
} from '../types';
import {
	collectAndFormatUrgentSnykAlerts,
	deduplicateVulnerabilitiesByCve,
	dependabotAlertToRepocopVulnerability,
	evaluateOneRepo,
	findStacks,
	hasDependencyTracking,
	hasOldAlerts,
	snykAlertToRepocopVulnerability,
	snykVulnIdFilter,
} from './repository';

function evaluateRepoTestHelper(
	augmentedRepo: AugmentedRepository,
	branches: github_repository_branches[] = [],
	dependabotAlerts: RepocopVulnerability[] = [],
	latestSnykIssues: SnykIssue[] = [],
	snykProjects: SnykProject[] = [],
	reposOnSnyk: string[] = [],
) {
	return evaluateOneRepo(
		dependabotAlerts,
		augmentedRepo,
		branches,
		latestSnykIssues,
		snykProjects,
		reposOnSnyk,
	).repocopRules;
}

const nullBranch: github_repository_branches = {
	cq_sync_time: null,
	cq_source_name: null,
	cq_id: '',
	cq_parent_id: null,
	org: 'guardian',
	repository_id: BigInt(0),
	protection: null,
	name: '',
	commit: null,
	protected: null,
};

const sbtWorkflows: string[] = [
	'actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332',
	'scalacenter/sbt-dependency-submission@7ebd561e5280336d3d5b445a59013810ff79325e',
];
const nullAugmentedRepo: AugmentedRepository = {
	full_name: '',
	name: '',
	archived: false,
	id: BigInt(0),
	created_at: new Date(),
	updated_at: null,
	pushed_at: null,
	topics: [],
	default_branch: null,
	gh_admin_team_slugs: [],
	languages: [],
	workflow_usages: [],
};

const thePerfectAugmentedRepo: AugmentedRepository = {
	...nullAugmentedRepo,
	full_name: 'repo1',
	name: 'repo1',
	archived: false,
	id: BigInt(1),
	topics: ['production'],
	default_branch: 'main',
	gh_admin_team_slugs: ['some_team'],
};

const exampleSnykProject: SnykProject = {
	id: 'project1',
	attributes: {
		name: '',
		type: 'npm',
		created: '',
		tags: [
			{
				key: 'repo',
				value: thePerfectAugmentedRepo.full_name,
			},
		],
		origin: '',
		status: '',
	},
};

describe('REPOSITORY_01 - default_branch_name should be false when the default branch is not main', () => {
	test('branch is not main', () => {
		const badRepo = { ...thePerfectAugmentedRepo, default_branch: 'notMain' };
		const repos: AugmentedRepository[] = [thePerfectAugmentedRepo, badRepo];
		const evaluation = repos.map((repo) => evaluateRepoTestHelper(repo));

		expect(evaluation.map((repo) => repo.default_branch_name)).toEqual([
			true,
			false,
		]);
	});
});

describe('REPOSITORY_02 - Repositories should have branch protection', () => {
	const unprotectedMainBranch: github_repository_branches = {
		...nullBranch,
		repository_id: BigInt(1),
		name: 'main',
		protected: false,
		protection: {},
	};
	const protectedMainBranch: github_repository_branches = {
		...unprotectedMainBranch,
		protected: true,
	};

	test('We should get an affirmative result when the default branch is protected', () => {
		const unprotectedSideBranch: github_repository_branches = {
			...unprotectedMainBranch,
			name: 'side-branch',
		};

		const actual = evaluateRepoTestHelper(thePerfectAugmentedRepo, [
			protectedMainBranch,
			unprotectedSideBranch,
		]);

		expect(actual.branch_protection).toEqual(true);
	});
	test('We should get a negative result when the default branch of a production repo is not protected', () => {
		const actual = evaluateRepoTestHelper(thePerfectAugmentedRepo, [
			unprotectedMainBranch,
		]);
		expect(actual.branch_protection).toEqual(false);
	});
	test('Repos with no branches do not need protecting, and should be considered protected', () => {
		const augmentedRepo: AugmentedRepository = {
			...thePerfectAugmentedRepo,
			default_branch: null,
		};

		const actual = evaluateRepoTestHelper(augmentedRepo);
		expect(actual.branch_protection).toEqual(true);
	});
	test('Repos with exempted topics should be considered adequately protected, even if they have an unprotected main branch', () => {
		const augmentedRepo: AugmentedRepository = {
			...thePerfectAugmentedRepo,
			topics: ['hackday'],
		};

		const actual = evaluateRepoTestHelper(augmentedRepo, [
			unprotectedMainBranch,
		]);
		expect(actual.branch_protection).toEqual(true);
	});
});

describe('REPOSITORY_04 - Repository admin access', () => {
	test('Should return false when there is no admin team', () => {
		const augmentedRepo: AugmentedRepository = {
			...nullAugmentedRepo,
			full_name: 'guardian/service-catalogue',
		};

		const actual = evaluateRepoTestHelper(augmentedRepo);
		expect(actual.admin_access).toEqual(false);
	});

	test('Should return true when there is an admin team', () => {
		const augmentedRepo: AugmentedRepository = {
			...thePerfectAugmentedRepo,
			full_name: 'guardian/service-catalogue',
		};

		const actual = evaluateRepoTestHelper(augmentedRepo);
		expect(actual.admin_access).toEqual(true);
	});

	test(`Should validate repositories with a 'hackday' topic`, () => {
		//We are not interested in making sure hackday projects are kept up to date
		const augmentedRepo: AugmentedRepository = {
			...nullAugmentedRepo,
			full_name: 'guardian/service-catalogue',
			id: 1234n,
			topics: ['hackday'],
		};

		const actual = evaluateRepoTestHelper(augmentedRepo);
		expect(actual.admin_access).toEqual(true);
	});

	test(`Should evaluate repositories with a 'production' topic`, () => {
		const augmentedRepo: AugmentedRepository = {
			...nullAugmentedRepo,
			full_name: 'guardian/service-catalogue',
			topics: ['production'],
			gh_admin_team_slugs: ['some_team'],
		};

		const actual = evaluateRepoTestHelper(augmentedRepo);
		expect(actual.admin_access).toEqual(true);
	});

	test(`Should return false if all topics are unrecognised`, () => {
		const augmentedRepo: AugmentedRepository = {
			...nullAugmentedRepo,
			full_name: 'guardian/service-catalogue',
			topics: ['avocado'],
		};

		const actual = evaluateRepoTestHelper(augmentedRepo);
		expect(actual.admin_access).toEqual(false);
	});
});

describe('REPOSITORY_06 - Repository topics', () => {
	test('Should return true when there is a single recognised topic', () => {
		const augmentedRepo: AugmentedRepository = {
			...nullAugmentedRepo,
			topics: ['production'],
		};

		const actual = evaluateRepoTestHelper(augmentedRepo);
		expect(actual.topics).toEqual(true);
	});

	test(`Should validate repos with an interactive topic`, () => {
		const augmentedRepo: AugmentedRepository = {
			...nullAugmentedRepo,
			full_name: 'guardian/service-catalogue',
			topics: ['interactive'],
		};

		const actual = evaluateRepoTestHelper(augmentedRepo);
		expect(actual.topics).toEqual(true);
	});

	test('Should return false when there are multiple recognised topics', () => {
		// Having more than one recognised topic creates confusion about how the repo
		// is being used, and could also confuse repocop.
		const augmentedRepo: AugmentedRepository = {
			...nullAugmentedRepo,
			topics: ['production', 'hackday'],
		};

		const actual = evaluateRepoTestHelper(augmentedRepo);
		expect(actual.topics).toEqual(false);
	});

	test('Should return true when there is are multiple topics, not all are recognised', () => {
		const augmentedRepo: AugmentedRepository = {
			...nullAugmentedRepo,
			topics: ['production', 'android'],
		};

		const actual = evaluateRepoTestHelper(augmentedRepo);
		expect(actual.topics).toEqual(true);
	});

	test('Should return false when there are no topics', () => {
		const augmentedRepo: AugmentedRepository = {
			...nullAugmentedRepo,
		};

		const actual = evaluateRepoTestHelper(augmentedRepo);
		expect(actual.topics).toEqual(false);
	});

	test('Should return false when there are no recognised topics', () => {
		const augmentedRepo: AugmentedRepository = {
			...nullAugmentedRepo,
			topics: ['android', 'mobile'],
		};

		const actual = evaluateRepoTestHelper(augmentedRepo);
		expect(actual.topics).toEqual(false);
	});
});

// No rule for this evaluation yet
describe('NO RULE - Repository maintenance', () => {
	test('should have happened at some point in the last two years', () => {
		const recentRepo: AugmentedRepository = {
			...nullAugmentedRepo,
			created_at: new Date(),
		};

		const oldRepo: AugmentedRepository = {
			...nullAugmentedRepo,
			created_at: new Date('2019-01-01'),
		};

		const recentEval = evaluateRepoTestHelper(recentRepo);
		const oldEval = evaluateRepoTestHelper(oldRepo);
		expect(recentEval.archiving).toEqual(true);
		expect(oldEval.archiving).toEqual(false);
	});
	test('should be based only on the most recent date provided', () => {
		const recentlyUpdatedRepo: AugmentedRepository = {
			...nullAugmentedRepo,
			updated_at: new Date(),
			//these two dates are more than two years in the past, but should be
			//ignored because the updated_at date is more recent
			created_at: new Date('2019-01-01'),
			pushed_at: new Date('2020-01-01'),
		};

		const actual = evaluateRepoTestHelper(recentlyUpdatedRepo);
		expect(actual.archiving).toEqual(true);
	});
	test('is not a concern if no dates are found', () => {
		const recentlyUpdatedRepo: AugmentedRepository = {
			...nullAugmentedRepo,
		};

		const actual = evaluateRepoTestHelper(recentlyUpdatedRepo);
		expect(actual.archiving).toEqual(true);
	});
});

describe('REPOSITORY_08 - Repositories with related stacks on AWS', () => {
	test('should be findable if a stack has a matching tag', () => {
		const full_name = 'guardian/repo1';
		const tags = {
			'gu:repo': full_name,
		};
		const augmentedRepo: AugmentedRepository = {
			...nullAugmentedRepo,
			full_name,
			name: 'repo1',
			archived: false,
		};
		const stack: AwsCloudFormationStack = {
			stack_name: 'mystack',
			creation_time: new Date(),
			tags,
		};
		const result = findStacks(augmentedRepo, [stack]).stacks.length;
		expect(result).toEqual(1);
	});
	test('should be findable if the repo name is part of the stack name', () => {
		const augmentedRepo: AugmentedRepository = {
			...nullAugmentedRepo,
			full_name: 'guardian/repo1',
			name: 'repo1',
			archived: false,
		};

		const stack: AwsCloudFormationStack = {
			stack_name: 'mystack-repo1-PROD',
			tags: {},
			creation_time: new Date(),
		};
		const result = findStacks(augmentedRepo, [stack]).stacks.length;
		expect(result).toEqual(1);
	});
});

describe('REPOSITORY_08 - Repositories without any related stacks on AWS', () => {
	test('should not be findable', () => {
		const augmentedRepo: AugmentedRepository = {
			...nullAugmentedRepo,
			full_name: 'guardian/someRepo',
			name: 'someRepo',
			archived: false,
		};

		const tags = {
			App: 'myApp',
			Stack: 'myStack',
			Stage: 'CODE',
			'gu:repo': 'guardian/someOtherRepo',
			'gu:build-tool': 'unknown',
		};

		const stack1: AwsCloudFormationStack = {
			stack_name: 'stack1',
			tags: { 'gu:repo': 'guardian/someOtherRepo' },
			creation_time: new Date(),
		};
		const stack2: AwsCloudFormationStack = {
			stack_name: 'stack2',
			tags: {
				...tags,
				Stage: 'PROD',
			},
			creation_time: new Date(),
		};
		const result = findStacks(augmentedRepo, [stack1, stack2]).stacks.length;
		expect(result).toEqual(0);
	});
});

describe('REPOSITORY_09 - Dependency tracking', () => {
	const repoWithSnykSupportedLanguages: AugmentedRepository = {
		...nullAugmentedRepo,
		full_name: 'guardian/some-repo',
		name: 'some-repo',
		languages: ['JavaScript', 'Objective-C'],
		topics: ['production'],
	};

	const repoWithDependabotAndDepGraphSupportedLanguages: AugmentedRepository = {
		...nullAugmentedRepo,
		full_name: 'guardian/some-repo',
		name: 'some-repo',
		languages: ['JavaScript', 'Scala'],
		topics: ['production'],
	};

	const repoWithFullySupportedLanguages: AugmentedRepository = {
		...nullAugmentedRepo,
		full_name: 'guardian/some-repo',
		name: 'some-repo',
		languages: ['JavaScript'],
		topics: ['production'],
	};

	const repoWithUnsupportedLanguages: AugmentedRepository = {
		...nullAugmentedRepo,
		full_name: 'guardian/some-repo',
		name: 'some-repo',
		languages: ['Julia'],
		topics: ['production'],
	};

	const archivedRepo: AugmentedRepository = {
		...nullAugmentedRepo,
		full_name: 'guardian/some-repo',
		name: 'some-repo',
		archived: true,
	};

	const repoWithNonProdTags: AugmentedRepository = {
		...nullAugmentedRepo,
		full_name: 'guardian/some-repo',
		name: 'some-repo',
		topics: ['hackday'],
	}

	test('is valid if all languages are supported, and the repo is on snyk', () => {
		const actual = hasDependencyTracking(repoWithSnykSupportedLanguages, [
			'guardian/some-repo',
		]);
		expect(actual).toEqual(true);
	});
	test('is valid if all languages are supported by dependabot, even if the repo is not on snyk', () => {
		const actual = hasDependencyTracking(repoWithFullySupportedLanguages, []);
		expect(actual).toEqual(true);
	});
	test('is not valid if a project is not on snyk, and uses a language dependabot/dependency graph integrator does not support', () => {
		const actual = hasDependencyTracking(repoWithSnykSupportedLanguages, []);
		expect(actual).toEqual(false);
	});
	test('is not valid if a project is not on snyk, uses a language supported by dependency graph integrator but there is no submission workflow for that language', () => {
		const actual = hasDependencyTracking(
			repoWithDependabotAndDepGraphSupportedLanguages,
			[],
		);
		expect(actual).toEqual(false);
	});
	test('is valid if a project is not on snyk, uses a language supported by dependency graph integrator and has associated submission workflow for that language', () => {
		const augmentedRepo: AugmentedRepository = {
			...repoWithDependabotAndDepGraphSupportedLanguages,
			topics: ['production'],
			workflow_usages: sbtWorkflows,
		};
		const actual = hasDependencyTracking(augmentedRepo, []);
		expect(actual).toEqual(true);
	});
	test('is not valid if a project is on snyk, and uses a language not supported by snyk', () => {
		const actual = hasDependencyTracking(repoWithUnsupportedLanguages, []);
		expect(actual).toEqual(false);
	});
	test('is valid if a repository has been archived', () => {
		const actual = hasDependencyTracking(archivedRepo, []);
		expect(actual).toEqual(true);
	});
	test('is valid if a repository has a non-production tag', () => {
		const actual = hasDependencyTracking(repoWithNonProdTags, []);
		expect(actual).toEqual(true);
	});
	test('is valid if a repository has no languages', () => {
		const augmentedRepo: AugmentedRepository = {
			...nullAugmentedRepo,
			topics: ['production'],
			full_name: 'guardian/some-repo',
		};
		const actual = hasDependencyTracking(augmentedRepo, []);
		expect(actual).toEqual(true);
	});
});

const oldCriticalDependabotVuln: RepocopVulnerability = {
	full_name: 'guardian/some-repo',
	open: true,
	source: 'Dependabot',
	severity: 'critical',
	package: 'ansible',
	urls: [],
	ecosystem: 'pip',
	alert_issue_date: new Date('2021-01-01T00:00:00.000Z'),
	is_patchable: true,
	cves: ['CVE-2021-1234'],
	within_sla: false,
};

const newCriticalDependabotVuln: RepocopVulnerability = {
	...oldCriticalDependabotVuln,
	alert_issue_date: new Date(),
};

const oldHighDependabotVuln: RepocopVulnerability = {
	...oldCriticalDependabotVuln,
	severity: 'high',
};

const newHighDependabotVuln: RepocopVulnerability = {
	...oldHighDependabotVuln,
	alert_issue_date: new Date(),
};

describe('NO RULE - Dependabot alerts', () => {
	test('should be flagged if there are critical alerts older than two days', () => {
		expect(
			hasOldAlerts([oldCriticalDependabotVuln], thePerfectAugmentedRepo),
		).toBe(true);
	});
	test('should not be flagged if a critical alert was raised today', () => {
		expect(
			hasOldAlerts([newCriticalDependabotVuln], thePerfectAugmentedRepo),
		).toBe(false);
	});
	test('should be flagged if there are high alerts older than 30 days', () => {
		expect(hasOldAlerts([oldHighDependabotVuln], thePerfectAugmentedRepo)).toBe(
			true,
		);
	});
	test('should not be flagged if a high alert was raised today', () => {
		expect(hasOldAlerts([newHighDependabotVuln], thePerfectAugmentedRepo)).toBe(
			false,
		);
	});
	test('should not be flagged if a high alert was raised 29 days ago', () => {
		const thirteenDaysAgo = new Date();
		thirteenDaysAgo.setDate(thirteenDaysAgo.getDate() - 29);

		const thirteenDayOldHigh: RepocopVulnerability = {
			...oldHighDependabotVuln,
			alert_issue_date: thirteenDaysAgo,
		};

		expect(hasOldAlerts([thirteenDayOldHigh], thePerfectAugmentedRepo)).toBe(
			false,
		);
	});
});

const snykIssue: SnykIssue = {
	id: 'issue1',
	attributes: {
		status: 'open',

		ignored: false,
		problems: [
			{
				id: 'CVE-1234',
				url: 'example.com',
				type: 'vulnerability',
				source: 'NVD',
				updated_at: '', //or Date?
				disclosed_at: '', //or Date?
				discovered_at: '', //or Date?
			},
		],
		created_at: '2020-01-01', //or Date?
		updated_at: '', //or Date?
		coordinates: [
			{
				remedies: null,
				// reachability: 'direct',
				is_upgradeable: true,
				is_fixable_snyk: undefined,
				is_patchable: true,
				representations: [
					{
						dependency: {
							package_name: 'fetch',
							package_version: '1.0.0',
						},
					},
				],
			},
		],
		effective_severity_level: 'high',
	},
	relationships: {
		scan_item: {
			data: { id: 'project1', type: 'project' }, //i think type is only ever project?
		},
		organization: {
			data: { id: '234', type: 'organization' }, //same for organization
		},
	},
};

function fixableVulnerability(
	package_name: string,
	package_version: string,
): Coordinate {
	return {
		remedies: null,
		// reachability: 'direct',
		is_upgradeable: true,
		is_fixable_snyk: true,
		is_patchable: true,
		representations: [
			{
				dependency: {
					package_name,
					package_version,
				},
			},
		],
	};
}

const snykIssue3Coords = {
	...snykIssue,
	attributes: {
		...snykIssue.attributes,
		coordinates: [
			fixableVulnerability('fetch', '1.0.0'),
			fixableVulnerability('fetch', '2.0.0'),
			fixableVulnerability('axios', '3.0.0'),
		],
		effective_severity_level: 'high',
	},
};

describe('NO RULE - Snyk vulnerabilities', () => {
	const unfixable: Coordinate = {
		remedies: null,
		// reachability: 'direct',
		is_upgradeable: undefined,
		is_fixable_snyk: undefined,
		is_patchable: undefined,
		representations: [
			{
				dependency: {
					package_name: 'fetch',
					package_version: '1.0.0',
				},
			},
		],
	};

	test('Should not be detected if no projects or issues are passed', () => {
		const result = collectAndFormatUrgentSnykAlerts(
			thePerfectAugmentedRepo,
			[],
			[],
		);
		expect(result.length).toEqual(0);
	});
	test('Should be detected if a repo, project, and issue match', () => {
		const result = collectAndFormatUrgentSnykAlerts(
			thePerfectAugmentedRepo,
			[snykIssue],
			[exampleSnykProject],
		);
		expect(result.length).toEqual(1);
	});
	test('Should not be detected if a repo, project, and old issue match, but the repo is not in production', () => {
		const nonProdRepo = {
			...thePerfectAugmentedRepo,
			topics: [],
		};
		const result = collectAndFormatUrgentSnykAlerts(
			nonProdRepo,
			[snykIssue],
			[exampleSnykProject],
		);
		expect(result.length).toEqual(0);
	});
	test('Should not detected if a snyk project has no tags', () => {
		const untaggedProject = {
			...exampleSnykProject,
			attributes: { ...exampleSnykProject.attributes, tags: [] },
		};
		const result = collectAndFormatUrgentSnykAlerts(
			thePerfectAugmentedRepo,
			[snykIssue],
			[untaggedProject],
		);
		expect(result.length).toEqual(0);
	});
	test('Should not be detected if they have a low or medium severity', () => {
		const lowSeverity = {
			...snykIssue,
			attributes: { ...snykIssue.attributes, effective_severity_level: 'low' },
		};
		const mediumSeverity = {
			...snykIssue,
			attributes: {
				...snykIssue.attributes,
				effective_severity_level: 'medium',
			},
		};
		const result = collectAndFormatUrgentSnykAlerts(
			thePerfectAugmentedRepo,
			[lowSeverity, mediumSeverity],
			[exampleSnykProject],
		);
		expect(result.length).toEqual(0);
	});
	test('Should not be considered patchable if there is no possible upgrade path', () => {
		const result = collectAndFormatUrgentSnykAlerts(
			thePerfectAugmentedRepo,
			[
				{
					...snykIssue,
					attributes: { ...snykIssue.attributes, coordinates: [unfixable] },
				},
			],
			[exampleSnykProject],
		);
		expect(result.map((r) => r.is_patchable)).toEqual([false]);
	});
	test('Should be considered patchable if there is a possible upgrade path', () => {
		const pinnableIssue: SnykIssue = {
			...snykIssue,
			attributes: {
				...snykIssue.attributes,
				coordinates: [
					{
						...unfixable,
						is_pinnable: true,
					},
				],
			},
		};
		const patchableIssue: SnykIssue = {
			...snykIssue,
			attributes: {
				...snykIssue.attributes,
				coordinates: [
					{
						...unfixable,
						is_patchable: true,
					},
				],
			},
		};
		const upgradableIssue: SnykIssue = {
			...snykIssue,
			attributes: {
				...snykIssue.attributes,
				coordinates: [
					{
						...unfixable,
						is_upgradeable: true,
					},
				],
			},
		};
		const result = collectAndFormatUrgentSnykAlerts(
			thePerfectAugmentedRepo,
			[pinnableIssue, patchableIssue, upgradableIssue],
			[exampleSnykProject],
		);
		expect(result.map((r) => r.is_patchable)).toEqual([true, true, true]);
	});
});

describe('NO RULE - Vulnerabilities from Dependabot', () => {
	const fullName = 'guardian/myrepo';
	const result: RepocopVulnerability[] = example.map((alert) =>
		dependabotAlertToRepocopVulnerability(fullName, alert),
	);

	test('Should be parseable into a common format', () => {
		const expected1: RepocopVulnerability = {
			full_name: fullName,
			source: 'Dependabot',
			open: false,
			severity: 'high',
			package: 'django',
			urls: [
				'https://snyk.io/vuln/some-fake-vuln-id',
				'https://github.com/advisories/GHSA-rf4j-j272-fj86',
				'https://nvd.nist.gov/vuln/detail/CVE-2018-6188',
				'https://usn.ubuntu.com/3559-1/',
				'http://www.securitytracker.com/id/1040422',
			],
			ecosystem: 'pip',
			alert_issue_date: new Date('2022-06-15T07:43:03Z'),
			is_patchable: true,
			cves: ['CVE-2018-6188'],
			within_sla: false,
		};

		const expected2: RepocopVulnerability = {
			full_name: fullName,
			source: 'Dependabot',
			open: true,
			severity: 'medium',
			package: 'ansible',
			urls: [
				'https://nvd.nist.gov/vuln/detail/CVE-2021-20191',
				'https://access.redhat.com/security/cve/cve-2021-20191',
				'https://bugzilla.redhat.com/show_bug.cgi?id=1916813',
			],
			ecosystem: 'pip',
			alert_issue_date: new Date('2022-06-14T15:21:52Z'),
			is_patchable: true,
			cves: ['CVE-2021-20191'],
			within_sla: false,
		};

		expect(result).toStrictEqual([expected1, expected2]);
	});
	test('Should display the most useful URLs first', () => {
		const actual = result.map((r) => r.urls)[0];
		const expected = [
			'https://snyk.io/vuln/some-fake-vuln-id',
			'https://github.com/advisories/GHSA-rf4j-j272-fj86',
		];
		expect(actual?.slice(0, 2)).toEqual(expected);
	});
});

describe('NO RULE - Vulnerabilities from Snyk', () => {
	test('Should be parseable into a common format', () => {
		const fullName = 'guardian/myrepo';
		const result = snykAlertToRepocopVulnerability(fullName, snykIssue, [
			exampleSnykProject,
		]);
		console.log(result);
		expect(result.source).toEqual('Snyk');
		expect(result.open).toEqual(true);
		expect(result).toStrictEqual({
			full_name: fullName,
			open: true,
			source: 'Snyk',
			severity: 'high',
			package: 'fetch',
			urls: ['example.com'],
			ecosystem: 'npm',
			alert_issue_date: new Date('2020-01-01'),
			is_patchable: true,
			cves: ['CVE-1234'],
			within_sla: false,
		});
	});

	test('Should dedupe package names,', () => {
		const fullName = 'guardian/myrepo';
		const result = snykAlertToRepocopVulnerability(fullName, snykIssue3Coords, [
			exampleSnykProject,
		]);
		expect(result.package).toEqual('fetch, axios');
	});
});

describe('Deduplication of repocop vulnerabilities', () => {
	const fullName = 'guardian/myrepo';
	const vuln1: RepocopVulnerability = {
		source: 'Dependabot',
		full_name: fullName,
		open: true,
		severity: 'high',
		package: 'django',
		urls: ['https://nvd.nist.gov/vuln/detail/CVE-2018-6188'],
		ecosystem: 'pip',
		alert_issue_date: new Date('2022-06-15T07:43:03Z'),
		is_patchable: true,
		cves: ['CVE-2018-6188'],
		within_sla: false,
	};
	const vuln2: RepocopVulnerability = {
		full_name: fullName,
		source: 'Snyk',
		open: true,
		severity: 'critical',
		package: 'django',
		urls: ['https://nvd.nist.gov/vuln/detail/CVE-2018-6188'],
		ecosystem: 'pip',
		alert_issue_date: new Date('2022-06-15T07:43:03Z'),
		is_patchable: true,
		cves: ['CVE-2018-6188'],
		within_sla: false,
	};
	const actual = deduplicateVulnerabilitiesByCve([vuln1, vuln2]);
	test('Should happen if two vulnerabilities share the same CVEs', () => {
		console.log(actual);
		expect(actual.length).toStrictEqual(1);
	});
	test('Should return the critical vulnerability, given a choice betwen critical and high', () => {
		expect(actual.map((x) => x.severity)).toStrictEqual(['critical']);
	});
	test('Should not happen if two vulnerabilities have different CVEs', () => {
		const vuln3: RepocopVulnerability = {
			...vuln1,
			cves: ['CVE-2018-6189'],
		};
		const actual = deduplicateVulnerabilitiesByCve([vuln1, vuln3]);
		expect(actual.length).toStrictEqual(2);
	});
	test('Should not happen if no CVEs are provided', () => {
		const vuln4: RepocopVulnerability = {
			...vuln1,
			cves: [],
		};
		const actual = deduplicateVulnerabilitiesByCve([vuln4, vuln4]);
		expect(actual.length).toStrictEqual(2);
	});
});

describe('NO RULE - Snyk vulnerability ID filter', () => {
	test('Should not remove any IDs if no CVE id is present', () => {
		const ids = ['SNYK-1234', 'SNYK-1235'];
		const actual = snykVulnIdFilter(ids);
		expect(actual).toStrictEqual(ids);
	});

	test('Should remove vulnerability IDs that start with Snyk, if a CVE id is present', () => {
		const ids = ['SNYK-1234', 'CVE-1234'];
		const actual = snykVulnIdFilter(ids);
		expect(actual).toStrictEqual(['CVE-1234']);
	});

	test('Should return the original list if only CVEs are present', () => {
		const ids = ['CVE-1234', 'CVE-1235'];
		const actual = snykVulnIdFilter(ids);
		expect(actual).toStrictEqual(ids);
	});
});

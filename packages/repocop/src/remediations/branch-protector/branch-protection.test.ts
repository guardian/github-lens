import type {
	github_teams,
	repocop_github_repository_rules,
	view_repo_ownership,
} from '@prisma/client';
import {
	createBranchProtectionEvents,
	sufficientProtection,
} from './branch-protection';
import type { CurrentBranchProtection } from './types';

const nullOwner: view_repo_ownership = {
	full_name: '',
	github_team_id: BigInt(0),
	github_team_name: '',
	repo_name: '',
	role_name: '',
	archived: false,
	galaxies_team: null,
	team_contact_email: null,
};

const nullTeam: github_teams = {
	cq_sync_time: null,
	cq_source_name: null,
	cq_id: '',
	cq_parent_id: null,
	org: '',
	id: BigInt(0),
	node_id: null,
	name: null,
	description: null,
	url: null,
	slug: null,
	permission: null,
	permissions: null,
	privacy: null,
	members_count: null,
	repos_count: null,
	organization: null,
	html_url: null,
	members_url: null,
	repositories_url: null,
	parent: null,
	ldap_dn: null,
};

describe('Team slugs should be findable for every team associated with a repo', () => {
	test('A repository that is owned by a team should be included in the list of messages', () => {
		const repo = 'guardian/repo1';
		const evaluatedRepo: repocop_github_repository_rules = {
			full_name: repo,
			default_branch_name: true,
			branch_protection: false,
			team_based_access: true,
			admin_access: true,
			archiving: true,
			topics: true,
			contents: true,
			evaluated_on: new Date(),
		};

		const repoOwner: view_repo_ownership = {
			...nullOwner,
			full_name: repo,
			github_team_id: BigInt(1),
			github_team_name: 'Team One',
		};

		const githubTeam: github_teams = {
			...nullTeam,
			id: BigInt(1),
			slug: 'team-one',
		};

		const actual = createBranchProtectionEvents(
			[evaluatedRepo],
			[repoOwner],
			[githubTeam],
			5,
		);

		expect(actual).toEqual([{ fullName: repo, teamNameSlugs: ['team-one'] }]);
	});

	test('A repository that has no owner should not be in the list of messages', () => {
		const repo = 'guardian/repo1';
		const evaluatedRepo: repocop_github_repository_rules = {
			full_name: repo,
			default_branch_name: true,
			branch_protection: false,
			team_based_access: true,
			admin_access: true,
			archiving: true,
			topics: true,
			contents: true,
			evaluated_on: new Date(),
		};

		const githubTeam: github_teams = {
			...nullTeam,
			id: BigInt(1),
			slug: 'team-one',
		};

		const actual = createBranchProtectionEvents(
			[evaluatedRepo],
			[],
			[githubTeam],
			5,
		);

		expect(actual.length).toEqual(0);
	});
});

const veryProtected: CurrentBranchProtection = {
	required_status_checks: {
		checks: [],
		strict: true,
		contexts: [],
	},
	required_pull_request_reviews: {
		dismiss_stale_reviews: true,
		require_code_owner_reviews: true,
		required_approving_review_count: 1,
	},
	enforce_admins: {
		url: '',
		enabled: true,
	},
	restrictions: {
		users: [],
		users_url: '',
		teams: [],
		teams_url: '',
		apps: [],
		apps_url: '',
		url: '',
	},
	allow_force_pushes: {
		enabled: false,
	},
	allow_deletions: {
		enabled: false,
	},
};

describe('Sufficiently protected repositories', () => {
	test('pass the protection gate', () => {
		expect(sufficientProtection(veryProtected)).toBe(true);
	});
});

describe('Branch protection is not sufficient if', () => {
	//TODO add some more ambiguous cases
	test('there are zero required approving reviews', () => {
		const noApprovingReviews: CurrentBranchProtection = {
			...veryProtected,
			required_pull_request_reviews: {
				dismiss_stale_reviews: true,
				//I dont think this is a valid state in reality, but just in case
				require_code_owner_reviews: true,
				required_approving_review_count: 0,
			},
		};
		expect(sufficientProtection(noApprovingReviews)).toBe(false);
	});
	test('code owner reviews are not required', () => {
		const noApprovingReviews: CurrentBranchProtection = {
			...veryProtected,
			required_pull_request_reviews: {
				dismiss_stale_reviews: true,
				//I dont think this is a valid state in reality, but just in case
				require_code_owner_reviews: false,
				required_approving_review_count: 1,
			},
		};
		expect(sufficientProtection(noApprovingReviews)).toBe(false);
	});
	test('there are no review expectations', () => {
		const noApprovingReviews: CurrentBranchProtection = {
			...veryProtected,
			required_pull_request_reviews: {
				dismiss_stale_reviews: true,
				require_code_owner_reviews: false,
				required_approving_review_count: 0,
			},
		};
		expect(sufficientProtection(noApprovingReviews)).toBe(false);
	});
	test('users may force push', () => {
		const canForcePush: CurrentBranchProtection = {
			...veryProtected,
			allow_force_pushes: {
				enabled: true,
			},
		};
		const ambiguousForcePushPolicy: CurrentBranchProtection = {
			...veryProtected,
			allow_force_pushes: undefined,
		};
		expect(sufficientProtection(canForcePush)).toBe(false);
		expect(sufficientProtection(ambiguousForcePushPolicy)).toBe(false);
	});
	test('users may delete the branch', () => {
		const deletionEnabled: CurrentBranchProtection = {
			...veryProtected,
			allow_deletions: {
				enabled: true,
			},
		};
		const ambiguousDeletionPolicy: CurrentBranchProtection = {
			...veryProtected,
			allow_deletions: undefined,
		};
		expect(sufficientProtection(deletionEnabled)).toBe(false);
		expect(sufficientProtection(ambiguousDeletionPolicy)).toBe(false);
	});
	test('admins may bypass existing protections', () => {
		const adminBypass: CurrentBranchProtection = {
			...veryProtected,
			enforce_admins: {
				enabled: false,
				url: '',
			},
		};
		const ambiguousAdminBypass: CurrentBranchProtection = {
			...veryProtected,
			enforce_admins: undefined,
		};
		expect(sufficientProtection(adminBypass)).toBe(false);
		expect(sufficientProtection(ambiguousAdminBypass)).toBe(false);
	});
});

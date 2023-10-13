import type {
	github_teams,
	repocop_github_repository_rules,
	view_repo_ownership,
} from '@prisma/client';
import { createRepository02Messages } from './repository-02';

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
			repository_01: true,
			repository_02: false,
			repository_03: true,
			repository_04: true,
			repository_05: true,
			repository_06: true,
			repository_07: true,
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

		const actual = createRepository02Messages(
			[evaluatedRepo],
			[repoOwner],
			[githubTeam],
		);

		expect(actual).toEqual([{ fullName: repo, teamNameSlugs: ['team-one'] }]);
	});

	test('A repository that has no owner should not be in the list of messages', () => {
		const repo = 'guardian/repo1';
		const evaluatedRepo: repocop_github_repository_rules = {
			full_name: repo,
			repository_01: true,
			repository_02: false,
			repository_03: true,
			repository_04: true,
			repository_05: true,
			repository_06: true,
			repository_07: true,
			evaluated_on: new Date(),
		};

		const githubTeam: github_teams = {
			...nullTeam,
			id: BigInt(1),
			slug: 'team-one',
		};

		const actual = createRepository02Messages(
			[evaluatedRepo],
			[],
			[githubTeam],
		);

		expect(actual.length).toEqual(0);
	});
});

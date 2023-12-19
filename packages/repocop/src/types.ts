import type {
	aws_cloudformation_stacks,
	github_repositories,
	github_teams,
	snyk_projects,
	snyk_reporting_latest_issues,
} from '@prisma/client';

export interface RepoAndStack {
	fullName: string;
	stacks: string[];
}

type TeamFields = Pick<github_teams, 'slug' | 'id' | 'name'>;

export interface Team extends TeamFields {
	slug: NonNullable<TeamFields['slug']>;
	id: NonNullable<TeamFields['id']>;
	name: NonNullable<TeamFields['name']>;
}

type RepositoryFields = Pick<
	github_repositories,
	| 'archived'
	| 'name'
	| 'full_name'
	| 'topics'
	| 'updated_at'
	| 'pushed_at'
	| 'created_at'
	| 'id'
	| 'default_branch'
>;

export interface Repository extends RepositoryFields {
	archived: NonNullable<RepositoryFields['archived']>;
	name: NonNullable<RepositoryFields['name']>;
	full_name: NonNullable<RepositoryFields['full_name']>;
	id: NonNullable<RepositoryFields['id']>;
}

type StackFields = Pick<
	aws_cloudformation_stacks,
	'stack_name' | 'tags' | 'creation_time'
>;

type AWSCloudformationTag = Record<string, string>;

export interface AwsCloudFormationStack extends StackFields {
	stack_name: NonNullable<StackFields['stack_name']>;
	tags: AWSCloudformationTag;
	creation_time: NonNullable<StackFields['creation_time']>;
}

//example snyk_projects response
// {
// 	cq_source_name: 'blah',
// 	cq_sync_time: 2000-01-01T00:00:00.000Z,
// 	cq_id: '????',
// 	cq_parent_id: null,
// 	id: '?????',
// 	name: 'myproject',
// 	origin: 'cli',
// 	issue_counts_by_severity: { low: 0, high: 0, medium: 0, critical: 0 },
// 	tags: [
// 	  { key: 'repo', value: 'guardian/myRepo' },
// 	  {
// 		key: 'commit',
// 		value: 'blahblah'
// 	  }
// 	],
// 	org_id: 'my-org-id'
//   }

type ProjectFields = Pick<snyk_projects, 'id' | 'name'>;
type ProjectTag = {
	key: string;
	value: string;
};

export interface SnykProject extends ProjectFields {
	id: NonNullable<ProjectFields['id']>;
	name: NonNullable<ProjectFields['name']>;
	tags?: ProjectTag[];
}

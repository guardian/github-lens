import { type StrategyOptions } from '@octokit/auth-app';
import type {
	aws_securityhub_findings,
	github_repositories,
	repocop_vulnerabilities,
} from '@prisma/client';

export type SecurityHubSeverity =
	| 'CRITICAL'
	| 'HIGH'
	| 'MEDIUM'
	| 'LOW'
	| 'INFORMATION';

export type GithubAppSecret = {
	appId: string;
	base64PrivateKey: string;
	clientId: string;
	clientSecret: string;
	installationId: string;
};
export interface UpdateMessageEvent {
	fullName: string; // in the format of owner/repo-name
	teamNameSlugs: string[];
}

export type GitHubAppConfig = {
	strategyOptions: StrategyOptions;
	installationId: string;
};

export type DepGraphLanguage = 'Scala' | 'Kotlin';

export interface DependencyGraphIntegratorEvent {
	name: string;
	language: DepGraphLanguage;
	admins: string[];
}

export interface SnykIntegratorEvent {
	name: string;
	languages: string[];
}

//GraphQL types for adding PRs to GitHub Projects
interface PullRequestIdAndAuthor {
	author: {
		login: string;
	};
	id: string;
}

export interface PullRequestDetails {
	organization: {
		repository: {
			pullRequests: {
				nodes: [PullRequestIdAndAuthor];
			};
		};
	};
}

export interface ProjectId {
	organization: {
		projectV2: {
			id: string;
		};
	};
}

export type Severity = Lowercase<SecurityHubSeverity> | 'unknown';

export type RepocopVulnerability = Omit<
	repocop_vulnerabilities,
	'id' | 'repo_owner' | 'severity'
> & {
	severity: Severity;
};

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

export interface AugmentedRepository extends Repository {
	github_team_slugs: string[];
	languages: string[];
	workflow_usages: string[];
}
export interface RepositoryWithDepGraphLanguage extends AugmentedRepository {
	dependency_graph_language: DepGraphLanguage;
}

// The number of days teams have to fix vulnerabilities of a given severity
export const SLAs: Record<Severity, number | undefined> = {
	critical: 2,
	high: 30,
	medium: undefined,
	low: undefined,
	information: undefined,
	unknown: undefined,
};

export type NonEmptyArray<T> = [T, ...T[]];

type Resource = {
	Id: string;
	Tags: Record<string, string> | null;
	Region: string;
	Type: string;
};

export type SecurityHubFinding = Pick<
	aws_securityhub_findings,
	'first_observed_at' | 'aws_account_id' | 'aws_account_name' | 'title'
> & {
	remediation: { Recommendation: { Url: string } };
	severity: { Label: SecurityHubSeverity; Normalized: number };
	resources: Resource[];
	product_fields: { ControlId: string };
	workflow: { Status: 'NEW' | 'NOTIFIED' | 'SUPPRESSED' | 'RESOLVED' }; //https://docs.aws.amazon.com/securityhub/latest/userguide/findings-workflow-status.html
};

import type { AugmentedRepository } from 'common/src/types';
import { removeRepoOwner } from '../shared-utilities';
import {
	checkRepoForLanguage,
	doesRepoHaveDepSubmissionWorkflowForLanguage,
	getReposWithoutDepSubmissionWorkflows,
} from './send-to-sns';

const fullName = 'guardian/repo-name';
const fullName2 = 'guardian/repo2';
const scalaLang = 'Scala';

function createRepository(fullName: string): AugmentedRepository {
	return {
		archived: false,
		name: removeRepoOwner(fullName),
		full_name: fullName,
		id: BigInt(1),
		default_branch: null,
		created_at: null,
		pushed_at: null,
		updated_at: null,
		topics: [],
		gh_admin_team_slugs: [],
		languages: [],
		workflow_usages: [],
	};
}
const withScala = ['Scala', 'TypeScript'];
const withoutScala = ['Rust', 'Typescript'];
const withSbtWorkflow = [
	'actions/checkout@v2',
	'scalacenter/sbt-dependency-submission@v2',
	'aws-actions/configure-aws-credentials@v1',
];
const withoutSbtWorkflow = [
	'actions/checkout@v2',
	'aws-actions/configure-aws-credentials@v1',
];

describe('When trying to find repos using Scala', () => {
	test('return true if Scala is found in the repo', () => {
		const result = checkRepoForLanguage(
			{ ...createRepository(fullName), languages: withScala },
			scalaLang,
		);
		expect(result).toBe(true);
	});
	test('return false if Scala is not found in the repo', () => {
		const result = checkRepoForLanguage(
			{ ...createRepository(fullName), languages: withoutScala },
			scalaLang,
		);
		expect(result).toBe(false);
	});
});

describe('When checking a repo for an existing dependency submission workflow', () => {
	test('return true if repo workflow is present', () => {
		const result = doesRepoHaveDepSubmissionWorkflowForLanguage(
			{
				...createRepository(fullName),
				workflow_usages: withSbtWorkflow,
			},
			'Scala',
		);
		expect(result).toBe(true);
	});
	test('return false if workflow is not present', () => {
		const result = doesRepoHaveDepSubmissionWorkflowForLanguage(
			{
				...createRepository(fullName),
				workflow_usages: withoutSbtWorkflow,
			},
			'Scala',
		);
		expect(result).toBe(false);
	});
});

describe('When getting suitable events to send to SNS', () => {
	test('return the repo when a Scala repo is found without an existing workflow', () => {
		const repoWithoutSbtWorkflow: AugmentedRepository = {
			...createRepository(fullName),
			languages: withScala,
			workflow_usages: withoutSbtWorkflow,
		};
		const repoWithSbtWorkflow: AugmentedRepository = {
			...createRepository(fullName),
			languages: withScala,
			workflow_usages: withSbtWorkflow,
		};
		const result = getReposWithoutDepSubmissionWorkflows([
			repoWithoutSbtWorkflow,
			repoWithSbtWorkflow,
		]);
		const expected = [
			{ ...repoWithoutSbtWorkflow, dependency_graph_language: 'Scala' },
		];

		expect(result).toEqual(expected);
	});
	test('return empty repo array when a Scala repo is found with an existing workflow', () => {
		const result = getReposWithoutDepSubmissionWorkflows([
			{
				...createRepository(fullName),
				languages: withScala,
				workflow_usages: withSbtWorkflow,
			},
		]);
		expect(result).toEqual([]);
	});
	test('return empty array when non-Scala repo is found with without an existing workflow', () => {
		const result = getReposWithoutDepSubmissionWorkflows([
			{
				...createRepository(fullName),
				languages: withoutScala,
				workflow_usages: withoutSbtWorkflow,
			},
		]);
		expect(result).toEqual([]);
	});
	test('return 2 events when 2 Scala repos are found without an existing workflow', () => {
		const reposWithoutWorkflows = [
			{
				...createRepository(fullName),
				languages: withScala,
				workflow_usages: withoutSbtWorkflow,
			},
			{
				...createRepository(fullName2),
				languages: withScala,
				workflow_usages: withoutSbtWorkflow,
			},
		];
		const result = getReposWithoutDepSubmissionWorkflows(reposWithoutWorkflows);
		const expected = reposWithoutWorkflows.map((repo) => ({
			...repo,
			dependency_graph_language: 'Scala',
		}));

		expect(result).toEqual(expected);
	});
});

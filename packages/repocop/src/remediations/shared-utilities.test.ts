import type { aws_cloudformation_stacks } from '@prisma/client';
import type { AWSCloudformationTag, UpdateMessageEvent } from 'common/types';
import {
	createSqsEntry,
	getGuRepoName,
	parseTagsFromStack,
} from './shared-utilities';

const nullStack: aws_cloudformation_stacks = {
	cq_sync_time: null,
	cq_source_name: null,
	cq_id: '',
	cq_parent_id: null,
	account_id: null,
	region: null,
	id: null,
	arn: '',
	tags: null,
	creation_time: null,
	stack_name: null,
	stack_status: null,
	capabilities: [],
	change_set_id: null,
	deletion_time: null,
	description: null,
	disable_rollback: null,
	drift_information: null,
	enable_termination_protection: null,
	last_updated_time: null,
	notification_arns: [],
	outputs: null,
	parameters: null,
	parent_id: null,
	retain_except_on_create: null,
	role_arn: null,
	rollback_configuration: null,
	root_id: null,
	stack_id: null,
	stack_status_reason: null,
	timeout_in_minutes: null,
};

describe('Batch entries should be created for each message', () => {
	test('The batch ID of the message should contain no special characters', () => {
		const event1: UpdateMessageEvent = {
			fullName: 'guardian/repo-1',
			teamNameSlugs: ['team-one'],
		};
		const event2: UpdateMessageEvent = {
			fullName: '!@£$%^&*()l',
			teamNameSlugs: ['team-two'],
		};

		const actual1 = createSqsEntry(event1);
		const actual2 = createSqsEntry(event2);

		expect(actual1.Id).toEqual('guardianrepo1');
		expect(actual2.Id).toEqual('l');
	});
});

describe('getGuRepoName', () => {
	it('should return undefined if the "gu:repo" tag value is not present', () => {
		const cfnTag: AWSCloudformationTag = {
			App: 'app-1',
			Stack: 'stack1',
			Stage: 'PROD',
			'gu:build-tool': 'guardian/some-build-tool',
		};
		const result: string | undefined = getGuRepoName(cfnTag);
		expect(result).toEqual(undefined);
	});

	it('should return only the "gu:repo" tag value', () => {
		const cfnTag: AWSCloudformationTag = {
			App: 'app-1',
			Stack: 'stack1',
			Stage: 'PROD',
			'gu:repo': 'guardian/repo-1',
			'gu:build-tool': 'guardian/some-build-tool',
		};
		const result: string | undefined = getGuRepoName(cfnTag);
		expect(result).toEqual('guardian/repo-1');
	});
});

describe('Parsing the tags from an aws_cloudformation_stacks_object', () => {
	it('should grab the repo name if it exists', () => {
		const stack: aws_cloudformation_stacks = {
			...nullStack,
			stack_name: 'stack-1',
			tags: {
				'gu:repo': 'guardian/repo-1',
				'gu:build-tool': 'guardian/some-build-tool',
			},
		};

		const result = parseTagsFromStack(stack);

		expect(result.guRepoName).toEqual('guardian/repo-1');
	});

	it('should return an undefined repo name if the tag does not exist', () => {
		const stack: aws_cloudformation_stacks = {
			...nullStack,
			stack_name: 'stack-1',
			tags: {
				Stack: 'stack-1',
				Stage: 'PROD',
			},
		};
		const result = parseTagsFromStack(stack);

		expect(result.guRepoName).toBeUndefined();
	});
});

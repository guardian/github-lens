import exp from 'constants';
import { groupFindingsByAccount, transformFinding } from './findings';
import type { Finding, GroupedFindings } from './types';
import type { aws_securityhub_findings } from '@prisma/client';

function mockFinding(awsAccountId: string, title: string): Finding {
	return {
		awsAccountId,
		title,
		controlId: 'A.1',
		awsAccountName: 'mock-account',
		resources: ['arn::mock::123'],
		remediationUrl: 'https://mock.url/mock',
		severity: 'critical',
		priority: 80,
		isWithinSla: true,
	};
}

describe('Grouping logic', () => {
	const TEAM_A_ACCOUNT_ID = '000000000';
	const TEAM_B_ACCOUNT_ID = '111111111';

	it('Should return an empty object if there are no findings to report', () => {
		const findings: Finding[] = [];
		const groupedFindings = groupFindingsByAccount(findings);

		expect(groupedFindings).toStrictEqual<GroupedFindings>({});
	});

	it('Should group findings by AWS account if there are findings to report', () => {
		const mockFinding1 = mockFinding(
			TEAM_A_ACCOUNT_ID,
			'Insecure security group configuration',
		);

		const mockFinding2 = mockFinding(
			TEAM_A_ACCOUNT_ID,
			'Insecure VPC configuration',
		);

		const mockFinding3 = mockFinding(
			TEAM_B_ACCOUNT_ID,
			'Insecure S3 bucket configuration',
		);

		const findings = [mockFinding1, mockFinding2, mockFinding3];
		const groupedFindings = groupFindingsByAccount(findings);

		expect(groupedFindings).toStrictEqual<GroupedFindings>({
			[TEAM_A_ACCOUNT_ID]: [mockFinding1, mockFinding2],
			[TEAM_B_ACCOUNT_ID]: [mockFinding3],
		});
	});

	it('Should report the same finding in two different accounts, if both accounts are affected', () => {
		const mockFinding1 = mockFinding(
			TEAM_A_ACCOUNT_ID,
			'Insecure security group configuration',
		);

		const mockFinding2 = mockFinding(
			TEAM_B_ACCOUNT_ID,
			'Insecure security group configuration',
		);

		const findings = [mockFinding1, mockFinding2];
		const groupedFindings = groupFindingsByAccount(findings);

		expect(groupedFindings).toStrictEqual<GroupedFindings>({
			[TEAM_A_ACCOUNT_ID]: [mockFinding1],
			[TEAM_B_ACCOUNT_ID]: [mockFinding2],
		});
	});
});

const emptyFinding: aws_securityhub_findings = {
	cq_sync_time: null,
	cq_source_name: null,
	cq_id: '',
	cq_parent_id: null,
	request_account_id: '',
	request_region: '',
	aws_account_id: '',
	created_at: new Date(),
	description: '',
	generator_id: '',
	id: '',
	product_arn: '',
	resources: null,
	schema_version: '',
	title: '',
	updated_at: new Date(),
	action: null,
	aws_account_name: null,
	company_name: null,
	compliance: null,
	confidence: null,
	criticality: null,
	finding_provider_fields: null,
	first_observed_at: null,
	generator_details: null,
	last_observed_at: null,
	malware: null,
	network: null,
	network_path: null,
	note: null,
	patch_summary: null,
	process: null,
	processed_at: null,
	product_fields: null,
	product_name: null,
	record_state: null,
	region: '',
	related_findings: null,
	remediation: null,
	sample: null,
	severity: null,
	source_url: null,
	threat_intel_indicators: null,
	threats: null,
	types: [],
	user_defined_fields: null,
	verification_state: null,
	vulnerabilities: null,
	workflow: null,
	workflow_state: null,
};

describe('transformFinding', () => {
	const mockFinding: aws_securityhub_findings = {
		...emptyFinding,
		aws_account_id: '000000000',
		title: 'Insecure security group configuration',
		severity: { Label: 'CRITICAL', Normalized: 80 },
		product_fields: { ControlId: 'A.1' },
		resources: [{ Id: 'arn::mock::123' }],
		remediation: { Recommendation: { Url: 'https://mock.url/mock' } },
		first_observed_at: new Date(),
		aws_account_name: 'mock-account',
	};

	it('Should transform a finding from the database into a Finding object', () => {
		const transformedFinding = transformFinding(mockFinding);

		expect(transformedFinding).toStrictEqual<Finding>({
			awsAccountId: '000000000',
			title: 'Insecure security group configuration',
			severity: 'critical',
			priority: 80,
			controlId: 'A.1',
			resources: ['arn::mock::123'],
			remediationUrl: 'https://mock.url/mock',
			awsAccountName: 'mock-account',
			isWithinSla: true,
		});
	});
	it('Should indicate that a high severity vulnerability observed over 30 days ago is not within SLA', () => {
		const findingOutsideSla = {
			...mockFinding,
			first_observed_at: new Date('2021-01-01'),
			severity: 'high',
		};

		expect(transformFinding(findingOutsideSla).isWithinSla).toBe(false);
	});
});

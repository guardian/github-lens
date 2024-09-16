import { groupFindingsByAccount } from './findings';
import type { Finding, GroupedFindings } from './types';

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

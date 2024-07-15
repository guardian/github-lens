import type { aws_securityhub_findings } from '@prisma/client';
import { daysLeftToFix, stringToSeverity } from 'common/src/functions';
import type { Severity } from 'common/src/types';
import type { Finding, GroupedFindings } from './types';

/**
 * Transforms a SQL row into a finding
 */
export function transformFinding(finding: aws_securityhub_findings): Finding {
	let severity: Severity = 'unknown';
	let priority = null;
	let remediationUrl = null;
	let resources = null;

	if (
		finding.severity &&
		typeof finding.severity === 'object' &&
		'Label' in finding.severity &&
		'Normalized' in finding.severity
	) {
		severity = stringToSeverity(finding.severity['Label'] as string);
		priority = finding.severity['Normalized'] as number;
	}

	if (finding.remediation && typeof finding.remediation === 'object') {
		const remediation = finding.remediation as {
			Recommendation: {
				Url: string | null;
			};
		} | null;
		if (remediation) {
			if (
				'Url' in remediation['Recommendation'] &&
				remediation['Recommendation']['Url']
			) {
				remediationUrl = remediation['Recommendation']['Url'];
			}
		}
	}

	if (finding.resources && Array.isArray(finding.resources)) {
		resources = finding.resources
			.map((r) => {
				if (r && typeof r === 'object' && 'Id' in r) {
					return r['Id'] as string;
				}
				return null;
			})
			.filter(Boolean);
	}

	return {
		awsAccountId: finding.aws_account_id,
		awsAccountName: finding.aws_account_name,
		title: finding.title,
		resources: resources as string[],
		severity,
		priority,
		remediationUrl,
		isWithinSla: isWithinSlaTime(finding.first_observed_at, severity),
	};
}

/**
 * Determines whether a Security Hub finding is within the SLA window
 */
export function isWithinSlaTime(
	firstObservedAt: Date | null,
	severity: Severity | null,
): boolean {
	if (!firstObservedAt) {
		console.warn('No first observed date provided');
		return false;
	}
	if (!severity) {
		console.warn('No severity provided');
		return false;
	}

	const daysToFix = daysLeftToFix(firstObservedAt, severity);
	if (daysToFix === undefined) {
		return false;
	}

	return daysToFix > 0;
}

/**
 * @param findings An array of FSBP findings.
 * @returns An object mapping account numbers to findings.
 * E.g.
 * ```ts
 *  {
 *  accountNumber123: ["finding1", "finding2"],
 *  accountNumber345: ["finding4", "finding5", "finding6"]
 *  }
 * ```
 */
export function groupFindingsByAccount(findings: Finding[]): GroupedFindings {
	const findingsGroupedByAwsAccount: GroupedFindings = {};

	for (const finding of findings) {
		const { awsAccountId } = finding;
		if (!findingsGroupedByAwsAccount[awsAccountId]) {
			findingsGroupedByAwsAccount[awsAccountId] = [];
		}
		findingsGroupedByAwsAccount[awsAccountId].push(finding);
	}

	return findingsGroupedByAwsAccount;
}

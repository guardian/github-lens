import { Anghammarad } from '@guardian/anghammarad';
import { getFsbpFindings } from 'common/src/database-queries';
import { getPrismaClient } from 'common/src/database-setup';
import type { SecurityHubSeverity } from 'common/types';
import { getConfig } from './config';
import { createDigestsFromFindings, sendDigest } from './digests';
import { transformFinding } from './findings';
import type { Digest, Finding } from './types';

type LambdaHandlerProps = {
	severities?: SecurityHubSeverity[];
};

export async function main(input: LambdaHandlerProps) {
	// When manually invoking the function in AWS for testing,
	// it can be cumbersome to manually type this object as an input.
	// Therefore, fall back to default values.
	const { severities = ['CRITICAL', 'HIGH'] } = input;

	// *** SETUP ***
	const config = await getConfig();
	const prisma = getPrismaClient(config);

	// *** DATA GATHERING ***
	console.log(
		`Starting Cloudbuster. Level of severities that will be scanned: ${severities.join(', ')}`,
	);

	const sixtyDaysAgo = new Date();
	sixtyDaysAgo.setDate(sixtyDaysAgo.getDate() - 60);

	const findings: Finding[] = (await getFsbpFindings(prisma, severities))
		.filter((f) => f.first_observed_at && f.first_observed_at > sixtyDaysAgo)
		.map((f) => transformFinding(f));
	const digests: Digest[] = createDigestsFromFindings(findings);

	// *** NOTIFICATION SENDING ***
	const anghammaradClient = new Anghammarad();

	await Promise.all(
		digests.map(
			async (digest) => await sendDigest(anghammaradClient, config, digest),
		),
	);
}

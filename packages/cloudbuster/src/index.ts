import type { PrismaClient } from '@prisma/client';
import { getPrismaClient } from 'common/database';
import { partition } from 'common/src/functions';
import { config } from 'dotenv';
import { getConfig } from './config';
import type { Finding } from './types';

config({ path: `../../.env` }); // Load `.env` file at the root of the repository

export async function main() {
	const config = await getConfig();
	const prisma: PrismaClient = getPrismaClient(config);
	const findings: Finding[] = (
		await prisma.aws_securityhub_findings.findMany()
	).map((f) => f as unknown as Finding);

	const [criticals, highs] = partition(
		findings,
		(f) => f.severity.Label === 'CRITICAL',
	);

	const twoDaysAgo = new Date();
	twoDaysAgo.setDate(twoDaysAgo.getDate() - 2);

	const inDateCriticals = criticals.filter((f) => f.created_at > twoDaysAgo);
	console.log(inDateCriticals.map((f) => f.title));

	const twoWeeksAgo = new Date();
	twoWeeksAgo.setDate(twoWeeksAgo.getDate() - 14);

	const inDateHighs = highs.filter((f) => f.created_at > twoWeeksAgo);
	console.log(inDateHighs.map((f) => f.title));
}

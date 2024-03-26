import { getPrismaClient } from 'common/database';
import type { Config } from './config';
import { getConfig } from './config';
import { getEc2Reservations } from './query';

export async function main() {
	const config: Config = await getConfig();

	const prisma = getPrismaClient(config);

	const myEc2RerservationsResult = await getEc2Reservations(prisma);
	console.log(myEc2RerservationsResult[0]);
}

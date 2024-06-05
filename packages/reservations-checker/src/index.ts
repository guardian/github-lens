import { getPrismaClient } from 'common/database';
import type { Config } from './config';
import { getConfig } from './config';
import { getEc2Reservations } from './query';
import {
	compareReservationsForTwoYears,
	logReservations,
} from './reservations';

export async function main() {
	const config: Config = await getConfig();

	const prisma = getPrismaClient(config);

	const myEc2RerservationsResult = await getEc2Reservations(prisma);

	const currentYear = new Date().getFullYear();
	const lastYear = currentYear - 1;

	compareReservationsForTwoYears(
		myEc2RerservationsResult,
		currentYear,
		lastYear,
	);
}

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

	// Filter reservations for the current year and the last year into separate arrays
	const reservationsCurrentYear = myEc2RerservationsResult.filter(
		(reservation) => reservation.year === currentYear,
	);
	const reservationsLastYear = myEc2RerservationsResult.filter(
		(reservation) => reservation.year === lastYear,
	);

	// logReservations(currentYear, reservationsCurrentYear);
	// logReservations(lastYear, reservationsLastYear);

	compareReservationsForTwoYears(
		reservationsCurrentYear,
		currentYear,
		lastYear,
	);
}

import type { aws_ec2_reserved_instances } from '@prisma/client';

export interface Reservation {
	account_id: string | null;
	year: number | undefined;
	instance_type: string | null;
	availability_zone: string | null;
	instance_count: bigint | null;
}

function groupEc2ReservedIntancesByAccount(
	reservations: Reservation[],
): Record<string, Reservation[]> {
	// Group reservations by account_id
	const groupedReservations = reservations.reduce<
		Record<string, Reservation[]>
	>((groups, reservation) => {
		if (reservation.account_id) {
			const key = reservation.account_id;
			if (!groups[key]) {
				groups[key] = [];
			}
			(groups[key] as Reservation[]).push(reservation);
		}
		return groups;
	}, {});
	return groupedReservations;
}

export function compareReservationsForTwoYears(
	myEc2RerservationsResult: Reservation[],
	year1: number,
	year2: number,
) {
	// Filter reservations for the current year and the last year into separate arrays
	const reservationsYear1 = myEc2RerservationsResult.filter(
		(reservation) => reservation.year === year1,
	);
	const reservationsYear2 = myEc2RerservationsResult.filter(
		(reservation) => reservation.year === year2,
	);
	reservationsYear1.forEach((reservationYear1) => {
		const reservationFound = findReservationInReservationArray(
			reservationYear1,
			reservationsYear2,
		);
		if (reservationFound) {
			console.log(
				`Found reservation for ${reservationYear1.instance_type} ${reservationYear1.availability_zone} in ${year2}`,
			);
			if (reservationYear1.instance_count != reservationFound.instance_count) {
				console.log(
					`Different instance count for ${reservationYear1.instance_type} ${reservationYear1.availability_zone} in ${year1} and ${year2}`,
				);
			}
		}
	});
}

function compareReservations(
	reservation1: Reservation,
	reservation2: Reservation,
) {
	return (
		reservation1.instance_type === reservation2.instance_type &&
		reservation1.availability_zone === reservation2.availability_zone
	);
}

function findReservationInReservationArray(
	reservation: Reservation,
	reservations: Reservation[],
) {
	return reservations.find((res) => compareReservations(reservation, res));
}

export function logReservations(year: number, reservations: Reservation[]) {
	const groupedReservations = groupEc2ReservedIntancesByAccount(reservations);

	// For each account, log the reservations

	const reservationsCountPerInstance: Reservation[] = [];
	Object.entries(groupedReservations).forEach(([accountId, reservations]) => {
		console.log(`\nReservations for ${year} for account ${accountId}:`);
		reservations.forEach((reservation) => {
			reservationsCountPerInstance.push(reservation);
			console.log(
				`${Number(reservation.instance_count)} ${reservation.instance_type}, ${reservation.availability_zone}, ${reservation.year}`,
			);
		});
	});

	const currentYear = new Date().getFullYear();
	const lastYear = currentYear - 1;

	console.log(
		'------- Check Reservations for the current year against the last year',
	);
	reservationsCountPerInstance
		.filter((elem) => elem.year == currentYear)
		.map((reservationCurrentYear) => {
			// check if this is in the last year
			console.log(
				`${reservationCurrentYear.instance_count} ${reservationCurrentYear.instance_type} ${reservationCurrentYear.availability_zone}`,
			);
			const reservationLastYear = reservationsCountPerInstance.find(
				(reservation) =>
					reservation.instance_type === reservationCurrentYear.instance_type &&
					reservation.availability_zone ===
						reservationCurrentYear.availability_zone &&
					reservation.year === lastYear,
			);
			if (reservationLastYear) {
				console.log(`Last year: ${reservationLastYear.instance_count}`);
			}
		});
}

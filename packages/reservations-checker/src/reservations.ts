import type { aws_ec2_reserved_instances } from '@prisma/client';
import { partition } from 'common/src/functions';
import { collectAndFormatUrgentSnykAlerts } from 'repocop/src/evaluation/repository';

export interface Reservation {
	account_id: string | null;
	year: number | undefined;
	instance_type: string | null;
	availability_zone: string | null;
	instance_count: bigint | null;
}

interface ReservationComparision {
	reservationsInBothYears: Reservation[];
	reservationsOnlyInYear1: Reservation[];
	reservationsOnlyInYear2: Reservation[];
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
): ReservationComparision {
	// Filter reservations for the current year and the last year into separate arrays
	const allYear1Reservations = myEc2RerservationsResult.filter(
		(reservation) => reservation.year === year1,
	);
	const allYear2Reservations = myEc2RerservationsResult.filter(
		(reservation) => reservation.year === year2,
	);

	const reservationsInBothYears: Reservation[] = [];
	allYear1Reservations.forEach((reservationYear1) => {
		const reservationFound =
			findReservationInReservationArrayWithSameInstanceTypeAndAvailabilityZone(
				reservationYear1,
				allYear2Reservations,
			);
		if (reservationFound) {
			console.log(
				`Found reservation for ${reservationYear1.instance_type} ${reservationYear1.availability_zone} in ${year2}`,
			);
			//TODO next: three cases: in in both years, is only in year1, now we have to find what is only in year2
			if (reservationYear1.instance_count != reservationFound.instance_count) {
				console.log(
					`Different instance count for ${reservationYear1.instance_type} ${reservationYear1.availability_zone} in ${year1} and ${year2}`,
				);
			}
			reservationsInBothYears.push(reservationYear1);
			reservationsInBothYears.push(reservationFound);
			console.log('Reservations in both years: ', reservationsInBothYears);
		}
	});

	const allSingleYearReservations = myEc2RerservationsResult.filter(
		(r) => !reservationsInBothYears.includes(r),
	);

	const [reservationsOnlyInYear1, reservationsOnlyInYear2] = partition(
		allSingleYearReservations,
		(r: Reservation) => r.year === year1,
	);

	const comparisonResult: ReservationComparision = {
		reservationsInBothYears: reservationsInBothYears.filter(
			(r) => r.year === year1,
		),
		reservationsOnlyInYear1,
		reservationsOnlyInYear2,
	};
	return comparisonResult;
}

export function compareReservationsByInstanceTypeAndAvailabilityZone(
	reservation1: Reservation,
	reservation2: Reservation,
) {
	console.log(
		'Compare reservation 1: ',
		reservation1,
		'to reservation2 :',
		reservation2,
	);
	const result =
		reservation1.instance_type === reservation2.instance_type &&
		reservation1.availability_zone === reservation2.availability_zone;
	console.log('Result: ', result);
	return result;
}

export function findReservationInReservationArrayWithSameInstanceTypeAndAvailabilityZone(
	reservation: Reservation,
	reservations: Reservation[],
) {
	return reservations.find((res) =>
		compareReservationsByInstanceTypeAndAvailabilityZone(reservation, res),
	);
}

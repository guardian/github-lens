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
		const reservationFound =
			findReservationInReservationArrayWithSameInstanceTypeAndAvailabilityZone(
				reservationYear1,
				reservationsYear2,
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
		} else {
			console.log(
				'No reservation found for ',
				reservationYear1.instance_type,
				reservationYear1.availability_zone,
				' in ',
				year2,
			);
		}
	});
}

export function compareReservationsByInstanceTypeAndAvailabilityZone(
	reservation1: Reservation,
	reservation2: Reservation,
) {
	return (
		reservation1.instance_type === reservation2.instance_type &&
		reservation1.availability_zone === reservation2.availability_zone
	);
}

export function findReservationInReservationArrayWithSameInstanceTypeAndAvailabilityZone(
	reservation: Reservation,
	reservations: Reservation[],
) {
	return reservations.find((res) =>
		compareReservationsByInstanceTypeAndAvailabilityZone(reservation, res),
	);
}

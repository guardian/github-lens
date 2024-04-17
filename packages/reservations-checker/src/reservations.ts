import type { aws_ec2_reserved_instances } from '@prisma/client';

interface ReservedInstances {
	account_id: string | null;
	year: number;
	instance_type: string | null;
	availability_zone: string | null;
	instance_count: bigint | null;
}

function groupEc2ReservedIntancesByAccount(
	reservations: ReservedInstances[],
): Record<string, ReservedInstances[]> {
	// Group reservations by account_id
	const groupedReservations = reservations.reduce<
		Record<string, aws_ec2_reserved_instances[]>
	>((groups, reservation) => {
		if (reservation.account_id) {
			const key = reservation.account_id;
			if (!groups[key]) {
				groups[key] = [];
			}
			(groups[key] as aws_ec2_reserved_instances[]).push(reservation);
		}
		return groups;
	}, {});
	return groupedReservations;
}

export function logReservations(
	year: number,
	reservations: aws_ec2_reserved_instances[],
) {
	

	const mappedReservations: ReservedInstances[] = reservations.map((r: aws_ec2_reserved_instances) => {
		console.log(r);
		return  {
			...r,
			year: r.start?.getFullYear(),
		};

		});

	const groupedReservations = groupEc2ReservedIntancesByAccount(mappedReservations);



	// For each account, log the reservations

	const reservationsCountPerInstance: ReservedInstances[] = [];
	Object.entries(groupedReservations).forEach(([accountId, reservations]) => {
		console.log(`\nReservations for ${year} for account ${accountId}:`);
		reservations.forEach((reservation) => {
			reservationsCountPerInstance.push(reservation);
			console.log(
				`${Number(reservation.instance_count)} ${reservation.instance_type}, ${reservation.availability_zone}, ${reservation.start?.toLocaleString(
					'en-GB',
					{
						weekday: 'long',
						day: '2-digit',
						month: '2-digit',
						year: 'numeric',
						hour: '2-digit',
						minute: '2-digit',
					},
				)}`,
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

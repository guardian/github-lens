import type { aws_ec2_reserved_instances } from '@prisma/client';

export function logReservations(
	year: number,
	reservations: aws_ec2_reserved_instances[],
) {
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

	// For each account, log the reservations
	Object.entries(groupedReservations).forEach(([accountId, reservations]) => {
		console.log(`\nReservations for ${year} for account ${accountId}:`);
		reservations.forEach((reservation) => {
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
}

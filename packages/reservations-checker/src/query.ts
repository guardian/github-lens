import type { aws_ec2_reserved_instances, PrismaClient } from '@prisma/client';
import type { Reservation } from './reservations';

export async function getEc2Reservations(
	client: PrismaClient,
): Promise<Reservation[]> {
	console.debug('Getting reservations');
	const ec2ReservationsFromDb =
		await client.aws_ec2_reserved_instances.findMany({});
	return ec2ReservationsFromDb.map(toReservedInstances);
}

function toReservedInstances(
	reservation: aws_ec2_reserved_instances,
): Reservation {
	return {
		account_id: reservation.account_id,
		year: reservation.start?.getFullYear(),
		instance_type: reservation.instance_type,
		availability_zone: reservation.availability_zone,
		instance_count: reservation.instance_count,
	};
}

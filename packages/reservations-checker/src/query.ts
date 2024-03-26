import type { aws_ec2_reserved_instances, PrismaClient } from '@prisma/client';

export async function getEc2Reservations(
	client: PrismaClient,
): Promise<aws_ec2_reserved_instances[]> {
	console.debug('Getting reservations');
	return await client.aws_ec2_reserved_instances.findMany({});
}

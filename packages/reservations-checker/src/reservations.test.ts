import type { aws_ec2_reserved_instances } from '@prisma/client';
import { logReservations } from './reservations';

describe('logReservations', () => {
	it('should log reservations grouped by account id', () => {
		const mockReservations: aws_ec2_reserved_instances[] = [
			{
				account_id: 'account1',
				instance_type: 'type1',
				availability_zone: 'zone1',
				instance_count: 1n,
				start: new Date('2022-01-01T00:00:00Z'),
			},
			{
				account_id: 'account2',
				instance_type: 'type2',
				availability_zone: 'zone2',
				instance_count: 2n,
				start: new Date('2022-01-02T00:00:00Z'),
			},
			{
				account_id: 'account1',
				instance_type: 'type3',
				availability_zone: 'zone3',
				instance_count: 3n,
				start: new Date('2022-01-03T00:00:00Z'),
			},
		];

		const consoleSpy = jest.spyOn(console, 'log');

		logReservations(2022, mockReservations);

		expect(consoleSpy).toHaveBeenCalledWith(
			'\nReservations for 2022 for account account1:',
		);
		expect(consoleSpy).toHaveBeenCalledWith(
			'1 type1, zone1, Saturday, 01/01/2022, 00:00',
		);
		expect(consoleSpy).toHaveBeenCalledWith(
			'3 type3, zone3, Monday, 03/01/2022, 00:00',
		);
		expect(consoleSpy).toHaveBeenCalledWith(
			'\nReservations for 2022 for account account2:',
		);
		expect(consoleSpy).toHaveBeenCalledWith(
			'2 type2, zone2, Sunday, 02/01/2022, 00:00',
		);

		consoleSpy.mockRestore();
	});
});

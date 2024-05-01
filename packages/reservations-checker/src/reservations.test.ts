import type { aws_ec2_reserved_instances } from '@prisma/client';
import { logReservations } from './reservations';

const nullReservation: aws_ec2_reserved_instances = {
	cq_sync_time: new Date(),
	cq_source_name: null,
	cq_id: '',
	cq_parent_id: null,
	account_id: null,
	region: null,
	arn: '',
	tags: '',
	availability_zone: null,
	currency_code: null,
	duration: null,
	end: null,
	fixed_price: null,
	instance_count: null,
	instance_tenancy: null,
	instance_type: null,
	offering_class: null,
	offering_type: '',
	product_description: '',
	recurring_charges: null,
	reserved_instances_id: '',
	scope: '',
	start: new Date(),
	state: '',
	usage_price: null,
};

describe('logReservations', () => {
	it('should log reservations grouped by account id', () => {
		const mockReservations: aws_ec2_reserved_instances[] = [
			{
				...nullReservation,
				account_id: 'account1',
				instance_type: 'type1',
				availability_zone: 'zone1',
				instance_count: 1n,
				start: new Date('2022-01-01T00:00:00Z'),
			},
			{
				...nullReservation,
				account_id: 'account2',
				instance_type: 'type2',
				availability_zone: 'zone2',
				instance_count: 2n,
				start: new Date('2022-01-02T00:00:00Z'),
			},
			{
				...nullReservation,
				account_id: 'account1',
				instance_type: 'type3',
				availability_zone: 'zone3',
				instance_count: 3n,
				start: new Date('2022-01-03T00:00:00Z'),
			},
		];

		const consoleSpy = jest.spyOn(console, 'log');

		const numberFoundInYear: number = logReservations(2022, mockReservations);

		// expect(consoleSpy).toHaveBeenCalledWith(
		// 	'\nReservations for 2022 for account account1:',
		// );
		// expect(consoleSpy).toHaveBeenCalledWith(
		// 	'1 type1, zone1, Saturday, 01/01/2022, 00:00',
		// );
		// expect(consoleSpy).toHaveBeenCalledWith(
		// 	'3 type3, zone3, Monday, 03/01/2022, 00:00',
		// );
		// expect(consoleSpy).toHaveBeenCalledWith(
		// 	'\nReservations for 2022 for account account2:',
		// );
		// expect(consoleSpy).toHaveBeenCalledWith(
		// 	'2 type2, zone2, Sunday, 02/01/2022, 00:00',
		// );

		expect(numberFoundInYear).toBe(3);

		consoleSpy.mockRestore();
	});
});

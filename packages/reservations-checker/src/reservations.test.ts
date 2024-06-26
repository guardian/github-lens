import type { Reservation } from './reservations';
import { compareReservationsForTwoYears } from './reservations';

const smallEu2023: Reservation = {
	account_id: 'account1',
	instance_type: 'small',
	availability_zone: 'eu',
	instance_count: 1n,
	year: 2023,
};
const smallEu2022: Reservation = {
	account_id: 'account2',
	instance_type: 'small',
	availability_zone: 'eu',
	instance_count: 2n,
	year: 2022,
};
const mediumEu2023: Reservation = {
	account_id: 'account1',
	instance_type: 'medium',
	availability_zone: 'eu',
	instance_count: 1n,
	year: 2023,
};
const largeEu2022: Reservation = {
	account_id: 'account2',
	instance_type: 'large',
	availability_zone: 'eu',
	instance_count: 2n,
	year: 2022,
};
const largeUS2023: Reservation = {
	account_id: 'account1',
	instance_type: 'large',
	availability_zone: 'us',
	instance_count: 1n,
	year: 2023,
};
const largeAsia2022: Reservation = {
	account_id: 'account2',
	instance_type: 'large',
	availability_zone: 'asia',
	instance_count: 2n,
	year: 2022,
};

const reservationsTestArray: Reservation[] = [
	smallEu2023,
	smallEu2022,
	mediumEu2023,
	largeEu2022,
	largeUS2023,
	largeAsia2022,
];

const reservationsTestArrayEqual: Reservation[] = [smallEu2023];

const reservationsTestOnlyYear1: Reservation[] = [mediumEu2023, largeUS2023];

const reservationsTestOnlyYear2: Reservation[] = [largeEu2022, largeAsia2022];

describe('compareReservationsForTwoYears', () => {
	it(
		'should return arrays of reservations that have been made in both years for the same instance' +
			' type and availability zone',
		() => {
			const res = compareReservationsForTwoYears(
				reservationsTestArray,
				2023,
				2022,
			).reservationsInBothYears;
			expect(res).toStrictEqual(reservationsTestArrayEqual);
		},
	),
		it(
			'should return arrays of reservations that have been made only in year1 for both instance' +
				' type and availability zone',
			() => {
				const result = compareReservationsForTwoYears(
					reservationsTestArray,
					2023,
					2022,
				);
				console.log('result: ', result);
				console.log(
					'This is the result we want reservationsTestOnlyYear1: ',
					reservationsTestOnlyYear1,
				);
				expect(result.reservationsOnlyInYear1).toStrictEqual(
					reservationsTestOnlyYear1,
				);
			},
		),
		it(
			'should return arrays of reservations that have been made only in year2 for both instance' +
				' type and availability zone',
			() => {
				expect(
					compareReservationsForTwoYears(reservationsTestArray, 2023, 2022)
						.reservationsOnlyInYear2,
				).toStrictEqual(reservationsTestOnlyYear2);
			},
		);
});

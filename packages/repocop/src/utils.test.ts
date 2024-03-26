import type { NonEmptyArray, RepocopVulnerability, Repository } from './types';
import {
	isProduction,
	stringToSeverity,
	toNonEmptyArray,
	vulnSortPredicate,
} from './utils';

describe('isProduction', () => {
	test('should return correct values for prod and non-prod repos', () => {
		const prodRepo: Repository = {
			archived: false,
			full_name: 'test',
			id: 1n,
			name: 'test',
			topics: ['production'],
			default_branch: 'main',
			created_at: new Date(),
			pushed_at: new Date(),
			updated_at: new Date(),
		};
		const nonProdRepo: Repository = {
			...prodRepo,
			topics: [],
		};

		expect(isProduction(prodRepo)).toBe(true);
		expect(isProduction(nonProdRepo)).toBe(false);
	});
});

describe('Failure on empty arrays', () => {
	test('throw an error if input is an empty array', () => {
		const emptyArray: string[] = [];
		const nonEmptyArray: string[] = ['a', 'b'];
		const typedNonEmptyArray: NonEmptyArray<string> = ['a', 'b'];

		expect(() => toNonEmptyArray(emptyArray)).toThrow();
		expect(() => toNonEmptyArray(nonEmptyArray)).not.toThrow();
		expect(toNonEmptyArray(nonEmptyArray)).toEqual(nonEmptyArray);
		expect(toNonEmptyArray(nonEmptyArray)).toEqual(typedNonEmptyArray);
	});
});

describe('stringToSeverity', () => {
	test('should return unknown if it is passed an unexpected string', () => {
		expect(stringToSeverity('foo')).toBe('unknown');
	});
	test('should return the correct severity for valid inputs', () => {
		expect(stringToSeverity('low')).toBe('low');
		expect(stringToSeverity('medium')).toBe('medium');
		expect(stringToSeverity('high')).toBe('high');
		expect(stringToSeverity('critical')).toBe('critical');
	});
});

describe('vulnSortingPredicate', () => {
	test('should order by severity, and then patchability', () => {
		const criticalPatchable: RepocopVulnerability = {
			package: 'test',
			severity: 'critical',
			full_name: 'test',
			ecosystem: 'test',
			is_patchable: true,
			urls: [],
			open: true,
			source: 'Dependabot',
			alert_issue_date: new Date(),
			cves: [],
			repo_owner: 'test',
		};
		const criticalNotPatchable: RepocopVulnerability = {
			...criticalPatchable,
			is_patchable: false,
		};
		const highPatchable: RepocopVulnerability = {
			...criticalPatchable,
			severity: 'high',
		};
		const highNotPatchable: RepocopVulnerability = {
			...highPatchable,
			is_patchable: false,
		};

		const vulns = [
			highNotPatchable,
			criticalPatchable,
			highPatchable,
			criticalNotPatchable,
		];
		const result = vulns.sort(vulnSortPredicate);

		expect(result).toStrictEqual([
			criticalPatchable,
			criticalNotPatchable,
			highPatchable,
			highNotPatchable,
		]);

		const vulns2 = [highNotPatchable, criticalPatchable, criticalPatchable];
		expect(vulns2.sort(vulnSortPredicate)).toStrictEqual([
			criticalPatchable,
			criticalPatchable,
			highNotPatchable,
		]);
	});
});

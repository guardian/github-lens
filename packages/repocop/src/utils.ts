import type {
	AugmentedRepository,
	RepocopVulnerability,
} from 'common/src/types';
import type { SnykIssue } from './types';

export function isProduction(augmentedRepo: AugmentedRepository) {
	return augmentedRepo.topics.includes('production') && !augmentedRepo.archived;
}

const criticalFirstPredicate = (x: RepocopVulnerability) =>
	x.severity === 'critical' ? -1 : 1;

const patchableFirstPredicate = (x: RepocopVulnerability) =>
	x.is_patchable ? -1 : 1;

export const vulnSortPredicate = (
	v1: RepocopVulnerability,
	v2: RepocopVulnerability,
) => {
	if (v1.severity === v2.severity) {
		return patchableFirstPredicate(v1);
	} else {
		return criticalFirstPredicate(v1);
	}
};

export function isOpenSnykIssue(snykIssue: SnykIssue): boolean {
	const isOpen = snykIssue.attributes.status === 'open';
	const isIgnored = snykIssue.attributes.ignored;
	return isOpen && !isIgnored;
}

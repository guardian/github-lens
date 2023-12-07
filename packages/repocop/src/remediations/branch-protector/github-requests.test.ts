import { constructNewBranchProtection } from './github-requests';
import type { CurrentBranchProtection } from './model';

const noBranchProtection: CurrentBranchProtection = {
	required_status_checks: {
		strict: false,
		contexts: [],
		checks: [],
	},
	required_pull_request_reviews: {
		require_code_owner_reviews: false,
		dismiss_stale_reviews: false,
	},
	enforce_admins: {
		enabled: false,
		url: '',
	},
	restrictions: {
		users: [],
		users_url: '',
		teams: [],
		teams_url: '',
		apps: [],
		apps_url: '',
		url: '',
	},
	allow_force_pushes: {
		enabled: true,
	},
	allow_deletions: {
		enabled: true,
	},
};

describe('If a branch was previously completely unprotected', () => {
	const newProtection = constructNewBranchProtection(
		noBranchProtection,
		'owner',
		'repo',
		'branch',
	);
	it('should still have unchanged fields if we have not tried to change them', () => {
		expect(newProtection.required_linear_history).toBeUndefined();
		expect(newProtection.restrictions).toEqual({
			users: [],
			teams: [],
			apps: [],
		});
		expect(newProtection.enforce_admins).toBe(false);
	});
	it('should have status checks enabled', () => {
		expect(newProtection.required_status_checks?.strict).toBe(true);
	});
	it('should have code owner reviews enabled', () => {
		expect(
			newProtection.required_pull_request_reviews?.require_code_owner_reviews,
		).toBe(true);
	});
	it('should have required approving review count set to 1', () => {
		const approvals =
			newProtection.required_pull_request_reviews
				?.required_approving_review_count;
		expect(approvals).toBe(1);
	});
	it('should not allow force pushes', () => {
		expect(newProtection.allow_force_pushes).toBe(false);
	});
	it('should not allow the branch to be deleted', () => {
		expect(newProtection.allow_deletions).toBe(false);
	});
});

describe('If a branch was previously protected with some settings', () => {
	it('should not overwrite settings that enforced a higher level of protection than us', () => {
		const branchProtection: CurrentBranchProtection = {
			...noBranchProtection,
			required_pull_request_reviews: {
				dismiss_stale_reviews: true,
				require_code_owner_reviews: true,
				required_approving_review_count: 2,
			},
		};

		const newProtection = constructNewBranchProtection(
			branchProtection,
			'owner',
			'repo',
			'branch',
		);
		const approvals =
			newProtection.required_pull_request_reviews
				?.required_approving_review_count;
		expect(approvals).toBe(2);
	});
});

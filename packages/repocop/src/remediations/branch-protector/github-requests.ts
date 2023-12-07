import type { Octokit } from 'octokit';
import type {
	CurrentBranchProtection,
	UpdateBranchProtectionParams,
} from './types';

async function getCurrentBranchProtection(
	octokit: Octokit,
	owner: string,
	repo: string,
	branch: string,
): Promise<CurrentBranchProtection> {
	const branchProtectionParams = {
		owner: owner,
		repo: repo,
		branch: branch,
	};
	const branchProtection = await octokit.rest.repos.getBranchProtection(
		branchProtectionParams,
	);

	return branchProtection.data;
}

//TODO test this
export function constructNewBranchProtection(
	protection: CurrentBranchProtection,
	owner: string,
	repo: string,
	branch: string,
): UpdateBranchProtectionParams {
	const required_approving_review_count =
		protection.required_pull_request_reviews?.required_approving_review_count ??
		1;
	const users =
		protection.restrictions?.users.map((user) => user.login as string) ?? [];
	const teams =
		protection.restrictions?.teams.map((team) => team.slug as string) ?? [];
	const apps =
		protection.restrictions?.apps.map((app) => app.slug as string) ?? [];
	const newProtection: UpdateBranchProtectionParams = {
		owner: owner,
		repo: repo,
		branch: branch,
		required_status_checks: {
			strict: true,
			contexts: protection.required_status_checks?.contexts ?? [],
		},
		restrictions: {
			users,
			teams,
			apps,
		},
		enforce_admins: protection.enforce_admins?.enabled ?? true, //do we want to strictly require this? It might be a problem in an emergency
		required_pull_request_reviews: {
			require_code_owner_reviews: true,
			required_approving_review_count,
		},
		allow_force_pushes: false,
		allow_deletions: false,
	};
	return newProtection;
}

export async function updateBranchProtection(
	octokit: Octokit,
	owner: string,
	repo: string,
	branch: string,
	stage: string,
) {
	const protection = await getCurrentBranchProtection(
		octokit,
		owner,
		repo,
		branch,
	);

	console.log(`Applying branch protection to ${repo}`);

	const newProtection = constructNewBranchProtection(
		protection,
		owner,
		repo,
		branch,
	);
	if (stage === 'PROD') {
		try {
			await octokit.rest.repos.updateBranchProtection(newProtection);
		} catch (error) {
			console.error(`Error: branch protection failed for ${repo}`);
			console.error(error);
		}
	} else {
		console.log(`Would have applied branch protection to ${repo}`);
	}
}

export async function getDefaultBranchName(
	owner: string,
	repo: string,
	octokit: Octokit,
) {
	const data = await octokit.rest.repos.get({ owner: owner, repo: repo });
	return data.data.default_branch;
}

//TODO test this
function evaluateProtection(protection: CurrentBranchProtection): boolean {
	const reviwerCount =
		protection.required_pull_request_reviews?.required_approving_review_count ??
		0;

	const forcePushesBlocked = protection.allow_force_pushes?.enabled ?? false;
	const deletionsBlocked = protection.allow_deletions?.enabled ?? false;
	const reviewRequired =
		protection.required_pull_request_reviews?.require_code_owner_reviews ??
		false;

	const noAdminBypass = protection.enforce_admins?.enabled ?? false;

	return (
		reviewRequired &&
		reviwerCount < 1 &&
		forcePushesBlocked &&
		deletionsBlocked &&
		noAdminBypass
	);
}

export async function isBranchProtected(
	octokit: Octokit,
	owner: string,
	repo: string,
	branch: string,
): Promise<boolean> {
	//TODO make this more complicated
	const branchData = await octokit.rest.repos.getBranch({
		owner,
		repo,
		branch,
	});

	if (!branchData.data.protected) {
		return false;
	} else {
		return evaluateProtection(branchData.data.protection);
	}
}

import type { Octokit } from 'octokit';
import type {
	CurrentBranchProtection,
	UpdateBranchProtectionParams,
} from './model';

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
function constructNewBranchProtection(
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
		enforce_admins: true,
		required_pull_request_reviews: {
			require_code_owner_reviews: true,
			required_approving_review_count,
		},
		allow_force_pushes: protection.allow_force_pushes?.enabled,
		allow_deletions: false,
	};
	return newProtection;
}

export async function updateBranchProtection(
	octokit: Octokit,
	owner: string,
	repo: string,
	branch: string,
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
	try {
		await octokit.rest.repos.updateBranchProtection(newProtection);
	} catch (error) {
		console.error(`Error: branch protection failed for ${repo}`);
		console.error(error);
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

export async function isBranchProtected(
	octokit: Octokit,
	owner: string,
	repo: string,
	branch: string,
): Promise<boolean> {
	const branchData = await octokit.rest.repos.getBranch({
		owner,
		repo,
		branch,
	});
	return branchData.data.protected;
}

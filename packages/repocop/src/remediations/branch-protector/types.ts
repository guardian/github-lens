import type { components } from '@octokit/openapi-types';
import type { RestEndpointMethodTypes } from '@octokit/plugin-rest-endpoint-methods/dist-types/generated/parameters-and-response-types';
import type { Endpoints } from '@octokit/types';

export type UpdateBranchProtectionParams =
	Endpoints['PUT /repos/{owner}/{repo}/branches/{branch}/protection']['parameters'];

export type GetBranchProtectionParams =
	RestEndpointMethodTypes['repos']['getBranchProtection']['response'];

export type CurrentBranchProtection =
	components['schemas']['branch-protection'];

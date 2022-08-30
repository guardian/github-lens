import { createAppAuth } from '@octokit/auth-app';
import { throttling } from '@octokit/plugin-throttling';
import { Octokit } from '@octokit/rest';
import { Config } from '../config';
import sleep from '../sleep';
import type { GetResponseDataTypeFromEndpointMethod } from '@octokit/types';


const ThrottledOctokit = Octokit.plugin(throttling);
const defaultPageSize = 100;

interface Options {
    method: string;
    url: string;
    request: {
        retryCount: number;
    };
}

const octokit = new Octokit();
export type RepositoriesResponse = GetResponseDataTypeFromEndpointMethod<
    typeof octokit.repos.listForOrg
    >;
export type TeamsResponse = GetResponseDataTypeFromEndpointMethod<
typeof octokit.teams.list
>;
export type TeamRepoResponse = GetResponseDataTypeFromEndpointMethod<
typeof octokit.teams.listReposInOrg
>;
export type RepositoryResponse = RepositoriesResponse[number];

let _octokit: Octokit | undefined;

const getOctokit = async (config: Config): Promise<Octokit> => {
    if (_octokit) {
        return _octokit;
    }

    const credentials = config.github;

    _octokit = new ThrottledOctokit({
        authStrategy: createAppAuth,
        auth: {
            appId: credentials.appId,
            privateKey: credentials.appPrivateKey,
            installationId: credentials.appInstallationId,
        },
        throttle: {
            onRateLimit: (retryAfter: number, options: Options) => {
                console.log(
                    `[WARN]: Request quota exhausted for request ${options.method} ${options.url}`,
                );

                // Retry twice after hitting a rate limit error, then give up
                if (options.request.retryCount <= 2) {
                    console.log(`[INFO]: Retrying after ${retryAfter} seconds!`);
                    return true;
                }
            },
            onAbuseLimit: async (retryAfter: number, options: Options) => {
                // does not retry, only logs a warning
                console.log(
                    `[WARN]: Abuse detected for request ${options.method} ${options.url}`,
                );

                // Retry once after hitting a rate limit error, then give up
                if (options.request.retryCount <= 1) {
                    console.log(`[INFO]: Retrying after 1 minute ${retryAfter} seconds!`);
                    await sleep(60000);
                    return true;
                }
            },
        },
    });

    return _octokit;
};

export const listRepositories = async (config: Config): Promise<RepositoriesResponse> => {
    const octokit = await getOctokit(config);
    return await octokit.paginate(
        octokit.repos.listForOrg, {
            org: 'guardian',
            per_page: defaultPageSize,
        }, (response) => response.data);
};

export const listTeams = async (config: Config): Promise<TeamsResponse> => {
    const octokit = await getOctokit(config);
    return await octokit.paginate(
        octokit.teams.list, {
            org: 'guardian',
            per_page: defaultPageSize,
        }, (response) => response.data);
};

export const getReposForTeam = async (config: Config, teamName: string): Promise<TeamRepoResponse> => {
    const octokit = await getOctokit(config);
    const request =  await octokit.request("GET /orgs/guardian/teams/{team}/repos", {
        team: teamName,
        per_page: defaultPageSize,
      });
    return request.data;
};
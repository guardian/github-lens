import 'dotenv/config'

export type Config = {
    github: {
        appId: string,
        appPrivateKey: string,
        appInstallationId: string;
    }
}

export const mandatory = (item: string): string => {
    const config = process.env[item];
    if (!config) {
        throw new Error(
            `Missing required env var (${item})!`,
        );
    }
    return config;
}
export const optional = (item: string): string | undefined => process.env[item];

export default {
    github: {
        appId: mandatory('GITHUB_APP_ID'),
        appPrivateKey: mandatory('GITHUB_APP_PRIVATE_KEY'),
        appInstallationId: mandatory('GITHUB_APP_INSTALLATION_ID'),
    }
}

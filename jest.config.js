// eslint-disable-next-line @typescript-eslint/no-var-requires -- can't use import here
const dotenv = require('dotenv');

// Load environment variables from .env file at the root of the repository
dotenv.config({ path: `${__dirname}/.env` });

const transform = {
	'^.+\\.tsx?$': ['esbuild-jest', { target: 'esnext' }],
};

module.exports = {
	verbose: true,
	testEnvironment: 'node',
	projects: [
		{
			displayName: 'cdk',
			transform,
			transformIgnorePatterns: [
				'node_modules/(?!@guardian/private-infrastructure-config)',
			],
			setupFilesAfterEnv: [`<rootDir>/packages/cdk/jest.setup.js`],
			testMatch: ['<rootDir>/packages/cdk/**/*.test.ts'],
		},
		{
			displayName: 'common',
			transform,
			testMatch: ['<rootDir>/packages/common/**/*.test.ts'],
		},
		{
			displayName: 'dependency-graph-integrator',
			transform,
			testMatch: [
				'<rootDir>/packages/dependency-graph-integrator/**/*.test.ts',
			],
		},
		{
			displayName: 'repocop',
			transform,
			transformIgnorePatterns: [
				'node_modules/(?!@guardian/private-infrastructure-config)',
			],
			testMatch: ['<rootDir>/packages/repocop/**/*.test.ts'],
		},
		{
			displayName: 'interactive-monitor',
			transform,
			testMatch: ['<rootDir>/packages/interactive-monitor/**/*.test.ts'],
		},
		{
			displayName: 'snyk-integrator',
			transform,
			testMatch: ['<rootDir>/packages/snyk-integrator/**/*.test.ts'],
		},
		{
			displayName: 'reservations-checker',
			transform,
			testMatch: ['<rootDir>/packages/reservations-checker/**/*.test.ts'],
		},
	],
};

import 'source-map-support/register';
import { RiffRaffYamlFile } from '@guardian/cdk/lib/riff-raff-yaml-file';
import { App, Duration } from 'aws-cdk-lib';
import { Schedule } from 'aws-cdk-lib/aws-events';
import { ServiceCatalogue } from '../lib/service-catalogue';

const app = new App();

const stack = 'deploy';
const region = 'eu-west-1';

new ServiceCatalogue(app, 'ServiceCatalogue-PROD', {
	stack,
	stage: 'PROD',
	env: { region },
	cloudFormationStackName: 'deploy-PROD-service-catalogue',
});

new ServiceCatalogue(app, 'ServiceCatalogue-CODE', {
	stack,
	stage: 'CODE',
	env: { region },
	schedule: Schedule.rate(Duration.days(30)),
	rdsDeletionProtection: false,
	cloudFormationStackName: 'deploy-CODE-service-catalogue',
});

// --- Add an additional S3 deployment type and synth riff-raff.yml ---

const riffRaff = new RiffRaffYamlFile(app);

const deployments = riffRaff.riffRaffYaml.deployments;

/**
 * All cfn-based dependencies should be applied before this s3 deployment
 */
const dependencies = [...deployments.entries()]
	.filter(([, { type }]) => type === 'cloud-formation')
	.map(([key]) => key);

deployments.set('upload-prisma-migrations', {
	type: 'aws-s3',
	contentDirectory: 'prisma',
	app: 'prisma-migrate-task',
	dependencies,
	parameters: {
		// TODO: refactor once this is working...
		bucketSsmKeyStageParam: {
			CODE: '/CODE/deploy/prisma-migrate-task-bucket',
			PROD: '/PROD/deploy/prisma-migrate-task-bucket',
		},
		prefixStage: false,
		prefixStack: false,
		publicReadAcl: false,
		cacheControl: 'public, max-age=315360000, immutable',
	},
	regions: new Set([region]),
	stacks: new Set([stack]),
});

riffRaff.synth();

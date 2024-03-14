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

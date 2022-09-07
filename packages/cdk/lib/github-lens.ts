import { GuScheduledLambda } from '@guardian/cdk';
import type { GuStackProps } from '@guardian/cdk/lib/constructs/core';
import { GuStack, GuStringParameter } from '@guardian/cdk/lib/constructs/core';
import { GuS3Bucket } from '@guardian/cdk/lib/constructs/s3';
import type { App } from 'aws-cdk-lib';
import { Duration } from 'aws-cdk-lib';
import { Schedule } from 'aws-cdk-lib/aws-events';
import { Effect, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { Runtime } from 'aws-cdk-lib/aws-lambda';

export class GithubLens extends GuStack {
	constructor(scope: App, id: string, props: GuStackProps) {
		super(scope, id, props);

		const app = 'github-lens';

		const dataBucket = new GuS3Bucket(this, `${app}-data-bucket`, {
			app,
		});

		const dataPutPolicy = new PolicyStatement({
			effect: Effect.ALLOW,
			actions: ['s3:PutObject', 's3:PutObjectAcl'],
			resources: [`${dataBucket.bucketArn}/github/*`],
		});

		const paramPathBase = `/${this.stage}/${this.stack}/${app}`;
		const repoFetcherApp = 'repo-fetcher';

		const githubAppId = new GuStringParameter(this, 'github-app-id', {
			default: `${paramPathBase}/github-app-id`,
			description:
				'(From SSM) The GitHub app ID of the app used to authenticate github-lens',
			fromSSM: true,
		});

		const githubInstallationId = new GuStringParameter(
			this,
			'github-installation-id',
			{
				default: `${paramPathBase}/github-installation-id`,
				description:
					'(From SSM) The GitHub installation ID of the app used to authenticate github-lens in the Guardian org',
				fromSSM: true,
			},
		);

		// TODO: Finalize KMS decryption of this (add permissions, add decryption to lambda(s) etc.)
		const githubPrivateKey = new GuStringParameter(this, 'github-private-key', {
			default: `${paramPathBase}/github-private-key`,
			description:
				'(From SSM) (KMS encrypted) The private key of the app used to authenticate github-lens in the Guardian org',
			fromSSM: true,
		});

		// TODO: Make DATA_KEY_PREFIX configurable
		new GuScheduledLambda(this, `${repoFetcherApp}-lambda`, {
			app: repoFetcherApp,
			runtime: Runtime.NODEJS_16_X,
			memorySize: 512,
			handler: 'cron.handler',
			fileName: `${repoFetcherApp}.zip`,
			monitoringConfiguration: {
				toleratedErrorPercentage: 0,
				snsTopicName: 'devx-alerts',
			},
			rules: [{ schedule: Schedule.expression('cron(0 8 ? * * *)') }],
			timeout: Duration.seconds(300),
			environment: {
				STAGE: this.stage,
				GITHUB_APP_ID: githubAppId.valueAsString,
				GITHUB_APP_PRIVATE_KEY: githubPrivateKey.valueAsString,
				GITHUB_APP_INSTALLATION_ID: githubInstallationId.valueAsString,
				DATA_BUCKET_NAME: dataBucket.bucketName,
			},
			initialPolicy: [dataPutPolicy],
		});
	}
}

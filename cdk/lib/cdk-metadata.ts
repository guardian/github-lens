import type { GuStackProps } from '@guardian/cdk/lib/constructs/core';
import { GuStack } from '@guardian/cdk/lib/constructs/core';
import { GuScheduledLambda } from '@guardian/cdk/lib/patterns/scheduled-lambda';
import type { App } from 'aws-cdk-lib';
import { Duration } from 'aws-cdk-lib';
import { Schedule } from 'aws-cdk-lib/aws-events';
import { Effect, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { Bucket } from 'aws-cdk-lib/aws-s3';

export class CdkMetadata extends GuStack {
	constructor(scope: App, id: string, props: GuStackProps) {
		super(scope, id, props);

		const bucket = new Bucket(this, 'data-bucket');

		const lambda = new GuScheduledLambda(this, 'lambda', {
			app: 'cdk-metadata',
			rules: [
				{
					schedule: Schedule.rate(Duration.days(1)),
					description: 'Run daily.',
				},
			],
			runtime: Runtime.GO_1_X,
			handler: 'main',
			fileName: 'lambda.zip',
			monitoringConfiguration: { noMonitoring: true }, // FIXME
			environment: {
				BUCKET: bucket.bucketName,
			},
		});

		lambda.addToRolePolicy(
			new PolicyStatement({
				effect: Effect.ALLOW,
				actions: ['dynamodb:Query'],
				resources: [
					`arn:aws:dynamodb:eu-west-1:${this.account}:table/config-deploy`,
				],
			}),
		);
	}
}

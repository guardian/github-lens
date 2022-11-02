import { GuApiLambda, GuScheduledLambda } from '@guardian/cdk';
import type { NoMonitoring } from '@guardian/cdk/lib/constructs/cloudwatch';
import { GuStack, GuStringParameter } from '@guardian/cdk/lib/constructs/core';
import type { GuStackProps } from '@guardian/cdk/lib/constructs/core';
import { GuCname } from '@guardian/cdk/lib/constructs/dns';
import { GuS3Bucket } from '@guardian/cdk/lib/constructs/s3';
import type { App } from 'aws-cdk-lib';
import { Duration } from 'aws-cdk-lib';
import {
	AccessLogFormat,
	EndpointType,
	LogGroupLogDestination,
} from 'aws-cdk-lib/aws-apigateway';
import { InterfaceVpcEndpoint } from 'aws-cdk-lib/aws-ec2';
import { Schedule } from 'aws-cdk-lib/aws-events';
import {
	Effect,
	PolicyDocument,
	PolicyStatement,
	StarPrincipal,
} from 'aws-cdk-lib/aws-iam';
import { Key } from 'aws-cdk-lib/aws-kms';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import { LogGroup } from 'aws-cdk-lib/aws-logs';

interface GithubLensProps extends GuStackProps {
	// Domain name to use for the app/stage.
	domainName: string;

	// ID of a virtual private endpoint used to connect to this private API
	// Gateway. For more info, see:
	// https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-private-apis.html#apigateway-private-api-create-interface-vpc-endpoint.
	vpceId: string;
}

export class GithubLens extends GuStack {
	constructor(scope: App, id: string, props: GithubLensProps) {
		super(scope, id, props);

		const app = 'github-lens';

		const dataBucket = new GuS3Bucket(this, `${app}-data-bucket`, {
			bucketName: `github-lens-data-${this.stage.toLowerCase()}`,
			app,
		});

		const kmsKeyAlias = `${this.stage}/${this.stack}/${app}`;
		const kmsKey = new Key(this, kmsKeyAlias, {
			enableKeyRotation: true,
		});

		const kmsDecryptPolicy = new PolicyStatement({
			effect: Effect.ALLOW,
			actions: ['kms:Decrypt'],
			resources: [kmsKey.keyArn],
		});

		const paramPathBase = `/${this.stage}/${this.stack}/${app}`;
		const repoFetcherApp = 'repo-fetcher';
		const apiApp = 'github-lens-api';

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

		const githubPrivateKey = new GuStringParameter(this, 'github-private-key', {
			default: `${paramPathBase}/github-private-key`,
			noEcho: true,
			description:
				'(From SSM) (KMS encrypted) The private key of the app used to authenticate github-lens in the Guardian org',
			fromSSM: true,
		});

		const noMonitoring: NoMonitoring = { noMonitoring: true };

		const prodLogGroup = new LogGroup(this, 'ProdLogs', {
			retention: 14,
		});

		const apiLambda = new GuApiLambda(this, `${apiApp}-lambda`, {
			fileName: `${apiApp}.zip`,
			handler: 'handler.main',
			runtime: Runtime.NODEJS_16_X,
			monitoringConfiguration: noMonitoring,
			app: apiApp,
			api: {
				id: 'github-lens',
				deployOptions: {
					accessLogDestination: new LogGroupLogDestination(prodLogGroup),
					accessLogFormat: AccessLogFormat.jsonWithStandardFields(),
				},
				description: 'API that proxies all requests to Lambda',
				endpointConfiguration: {
					types: [EndpointType.PRIVATE],
					vpcEndpoints: [
						InterfaceVpcEndpoint.fromInterfaceVpcEndpointAttributes(
							this,
							'vpce',
							{ vpcEndpointId: props.vpceId, port: 443 },
						),
					],
				},
				disableExecuteApiEndpoint: false,
				policy: new PolicyDocument({
					statements: [
						new PolicyStatement({
							actions: ['execute-api:Invoke'],
							principals: [new StarPrincipal()],
							resources: ['execute-api:/*/*/*'],
							effect: Effect.ALLOW,
							conditions: {
								StringEquals: {
									'aws:SourceVpce': props.vpceId,
								},
							},
						}),
					],
				}),
			},
		});

		new GuCname(this, 'DNS', {
			app: app,
			ttl: Duration.days(1),
			domainName: props.domainName,
			// See: https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-private-api-test-invoke-url.html#apigateway-private-api-public-dns.
			resourceRecord: `${apiLambda.api.restApiId}-${props.vpceId}.execute-api.${this.region}.amazonaws.com`,
		});

		const scheduledLambda = new GuScheduledLambda(
			this,
			`${repoFetcherApp}-lambda`,
			{
				app: repoFetcherApp,
				runtime: Runtime.NODEJS_16_X,
				memorySize: 512,
				handler: 'handler.main',
				fileName: `${repoFetcherApp}.zip`,
				monitoringConfiguration: {
					toleratedErrorPercentage: 0,
					snsTopicName: 'devx-alerts',
				},
				rules: [{ schedule: Schedule.cron({ minute: '0', hour: '8' }) }],
				timeout: Duration.seconds(300),
				environment: {
					STAGE: this.stage,
					KMS_KEY_ID: kmsKey.keyId,
					GITHUB_APP_ID: githubAppId.valueAsString,
					GITHUB_APP_PRIVATE_KEY: githubPrivateKey.valueAsString,
					GITHUB_APP_INSTALLATION_ID: githubInstallationId.valueAsString,
					DATA_BUCKET_NAME: dataBucket.bucketName,
				},
				initialPolicy: [kmsDecryptPolicy],
			},
		);

		dataBucket.grantRead(apiLambda);
		dataBucket.grantReadWrite(scheduledLambda);
	}
}

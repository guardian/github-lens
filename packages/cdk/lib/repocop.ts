import { GuScheduledLambda, type GuScheduledLambdaProps } from '@guardian/cdk';
import type {
	GuLambdaErrorPercentageMonitoringProps,
	NoMonitoring,
} from '@guardian/cdk/lib/constructs/cloudwatch';
import type { GuStack } from '@guardian/cdk/lib/constructs/core';
import { Duration } from 'aws-cdk-lib';
import type { IVpc, SecurityGroup } from 'aws-cdk-lib/aws-ec2';
import type { Schedule } from 'aws-cdk-lib/aws-events';
import { Runtime } from 'aws-cdk-lib/aws-lambda';
import type { DatabaseInstance } from 'aws-cdk-lib/aws-rds';
import type { Secret } from 'aws-cdk-lib/aws-secretsmanager';
import type { ITopic, Topic } from 'aws-cdk-lib/aws-sns';

export class Repocop {
	constructor(
		guStack: GuStack,
		schedule: Schedule,
		anghammaradTopic: ITopic,
		cloudqueryDB: DatabaseInstance,
		monitoringConfiguration:
			| NoMonitoring
			| GuLambdaErrorPercentageMonitoringProps,
		vpc: IVpc,
		interactiveMonitorTopic: Topic,
		dbSecurityGroup: SecurityGroup,
		githubAppSecret: Secret,
	) {
		const repocopLampdaProps: GuScheduledLambdaProps = {
			app: 'repocop',
			fileName: 'repocop.zip',
			handler: 'index.main',
			memorySize: 1024,
			monitoringConfiguration,
			rules: [{ schedule }],
			runtime: Runtime.NODEJS_20_X,
			environment: {
				ANGHAMMARAD_SNS_ARN: anghammaradTopic.topicArn,
				DATABASE_HOSTNAME: cloudqueryDB.dbInstanceEndpointAddress,
				QUERY_LOGGING: 'false', // Set this to 'true' to enable SQL query logging
				INTERACTIVE_MONITOR_TOPIC_ARN: interactiveMonitorTopic.topicArn,
				GITHUB_APP_SECRET: githubAppSecret.secretArn,
				INTERACTIVES_COUNT: guStack.stage === 'PROD' ? '20' : '3',
			},
			vpc,
			securityGroups: [dbSecurityGroup],
			timeout: Duration.minutes(5),
		};

		const repocopLambda = new GuScheduledLambda(
			guStack,
			'repocop',
			repocopLampdaProps,
		);

		cloudqueryDB.grantConnect(repocopLambda, 'repocop');

		githubAppSecret.grantRead(repocopLambda);
		anghammaradTopic.grantPublish(repocopLambda);
		interactiveMonitorTopic.grantPublish(repocopLambda);
	}
}

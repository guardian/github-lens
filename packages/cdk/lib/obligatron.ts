import type { GuStack } from '@guardian/cdk/lib/constructs/core';
import type { GuSecurityGroup } from '@guardian/cdk/lib/constructs/ec2';
import { GuLambdaFunction } from '@guardian/cdk/lib/constructs/lambda';
import { Duration } from 'aws-cdk-lib';
import type { IVpc } from 'aws-cdk-lib/aws-ec2';
import { Rule, RuleTargetInput, Schedule } from 'aws-cdk-lib/aws-events';
import { LambdaFunction } from 'aws-cdk-lib/aws-events-targets';
import { Architecture, LoggingFormat, Runtime } from 'aws-cdk-lib/aws-lambda';
import type { DatabaseInstance } from 'aws-cdk-lib/aws-rds';
import { Obligations } from '../../obligatron/src/obligations';

type ObligatronProps = {
	vpc: IVpc;
	dbAccess: GuSecurityGroup;
	db: DatabaseInstance;
};

export class Obligatron {
	constructor(stack: GuStack, props: ObligatronProps) {
		const { vpc, dbAccess, db } = props;
		const app = 'obligatron';

		const lambda = new GuLambdaFunction(stack, 'obligatron', {
			app,
			vpc,
			architecture: Architecture.ARM_64,
			runtime: Runtime.NODEJS_20_X,
			securityGroups: [dbAccess],
			fileName: `${app}.zip`,
			handler: 'index.main',
			environment: {
				DATABASE_HOSTNAME: db.dbInstanceEndpointAddress,
				QUERY_LOGGING: 'false', // Set this to 'true' to enable SQL query logging
			},
			timeout: Duration.minutes(5),
			// Unfortunately Prisma doesn't support streaming data from Postgres at the moment https://github.com/prisma/prisma/issues/5055
			// This means that all rows need to be loaded into memory at the same time whenever a query is ran hence the high memory requirement.
			memorySize: 4096,
			errorPercentageMonitoring: {
				toleratedErrorPercentage: 0,
				snsTopicName: 'devx-alerts',
			},

			/*
			Override the default provided by GuCDK for improved compatability with https://github.com/guardian/cloudwatch-logs-management when producing log lines with markers.

			Note: `logFormat` is a deprecated property, replaced with `loggingFormat`.
			However, we can only specify one of `logFormat` or `loggingFormat`, and as GuCDK is setting `logFormat`, we have to do the same.
			TODO - patch GuCDK.

			See also: https://github.com/guardian/cloudwatch-logs-management/issues/326.
			 */
			logFormat: LoggingFormat.TEXT,
		});

		const ObligationsWithIndex = Obligations.map((obligation) => ({
			obligation,
			index: Obligations.indexOf(obligation),
		}));

		for (const obligation of ObligationsWithIndex) {
			const startTime = (9 + obligation.index).toString();
			new Rule(stack, `obligatron-${obligation.obligation}`, {
				description: `Daily execution of Obligatron lambda for '${obligation.obligation}' obligation`,
				schedule: Schedule.cron({ minute: '0', hour: startTime }),
				targets: [
					new LambdaFunction(lambda, {
						event: RuleTargetInput.fromText(obligation.obligation),
					}),
				],
			});
		}

		db.grantConnect(lambda, 'obligatron');
	}
}

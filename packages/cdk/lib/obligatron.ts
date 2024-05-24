import type { GuStack } from '@guardian/cdk/lib/constructs/core';
import type { GuSecurityGroup } from '@guardian/cdk/lib/constructs/ec2';
import { GuLambdaFunction } from '@guardian/cdk/lib/constructs/lambda';
import { Duration } from 'aws-cdk-lib';
import type { IVpc } from 'aws-cdk-lib/aws-ec2';
import { Architecture, Runtime } from 'aws-cdk-lib/aws-lambda';
import type { DatabaseInstance } from 'aws-cdk-lib/aws-rds';

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
		});

		db.grantConnect(lambda, 'obligatron');
	}
}
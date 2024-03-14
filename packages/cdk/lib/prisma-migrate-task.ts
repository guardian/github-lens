import type { GuStack } from '@guardian/cdk/lib/constructs/core';
import { GuS3Bucket } from '@guardian/cdk/lib/constructs/s3';
import type { ICluster } from 'aws-cdk-lib/aws-ecs';
import {
	FargateTaskDefinition,
	FireLensLogDriver,
	FirelensLogRouterType,
	LogDrivers,
} from 'aws-cdk-lib/aws-ecs';
import type { PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';
import { RetentionDays } from 'aws-cdk-lib/aws-logs';
import {
	EcsFargateLaunchTarget,
	EcsRunTask,
} from 'aws-cdk-lib/aws-stepfunctions-tasks';
import { Images } from './cloudquery/images';

// 1. Be able to drop prisma.zip files in a bucket
// 2. Trigger an ECS task when prisma.zip is updated, that runs a hello world ECS task
// 3. Fix up the task so that it performs the DB migrations against the DB

interface PrismaMigrateTaskProps {
	cluster: ICluster;
	loggingStreamName: string;
	logShippingPolicy: PolicyStatement;
}

export function addPrismaMigrateTask(
	scope: GuStack,
	{ cluster, loggingStreamName, logShippingPolicy }: PrismaMigrateTaskProps,
) {
	const app = 'prisma-migrate-task';
	const { stack, stage, region } = scope;

	new GuS3Bucket(scope, `prisma-bucket`, { app });

	const roleName = `${app}-${stage}`;
	const taskRole = new Role(scope, roleName, {
		assumedBy: new ServicePrincipal('ecs-tasks.amazonaws.com'),
		roleName,
	});

	const fireLensLogDriver = new FireLensLogDriver({
		options: {
			Name: `kinesis_streams`,
			region,
			stream: loggingStreamName,
			retry_limit: '2',
		},
	});

	const taskDefinition = new FargateTaskDefinition(
		scope,
		`${app}TaskDefinition`,
		{
			cpu: 512,
			memoryLimitMiB: 1024,
			taskRole,
		},
	);

	taskDefinition.addFirelensLogRouter(`${app}Firelens`, {
		image: Images.devxLogs,
		logging: LogDrivers.awsLogs({
			streamPrefix: [stack, stage, app].join('/'),
			logRetention: RetentionDays.ONE_DAY,
		}),
		environment: {
			STACK: stack,
			STAGE: stage,
			APP: app,
			GU_REPO: 'guardian/service-catalogue',
		},
		firelensConfig: {
			type: FirelensLogRouterType.FLUENTBIT,
		},
	});

	taskDefinition.addContainer(`${app}Container`, {
		image: Images.amazonLinux,
		entryPoint: [''],
		environment: {
			// ...
		},
		secrets: {
			// ...secrets,
			// DB_USERNAME: Secret.fromSecretsManager(db.secret, 'username'),
			// DB_HOST: Secret.fromSecretsManager(db.secret, 'host'),
			// DB_PASSWORD: Secret.fromSecretsManager(db.secret, 'password'),
			// CLOUDQUERY_API_KEY: cloudQueryApiKey,
		},
		dockerLabels: {
			Stack: stack,
			Stage: stage,
			App: app,
		},
		command: [
			'/bin/sh',
			'-c',
			[
				// /*
				// 	Install the CA bundle for all RDS certificates.
				// 	See https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html#UsingWithRDS.SSL.CertificatesAllRegions
				// 	 */
				// 'wget -O /usr/local/share/ca-certificates/global-bundle.crt -q https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem && update-ca-certificates',
				'echo "Hello, World!"',
			].join(';'),
		],
		logging: fireLensLogDriver,
	});

	taskDefinition.addToTaskRolePolicy(logShippingPolicy);

	new EcsRunTask(scope, `${app}RunTask`, {
		cluster,
		taskDefinition,
		launchTarget: new EcsFargateLaunchTarget(),
	});

	return taskDefinition;
}

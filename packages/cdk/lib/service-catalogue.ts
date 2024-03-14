import type {
	GuLambdaErrorPercentageMonitoringProps,
	NoMonitoring,
} from '@guardian/cdk/lib/constructs/cloudwatch';
import type { GuStackProps } from '@guardian/cdk/lib/constructs/core';
import {
	GuAnghammaradTopicParameter,
	GuStack,
} from '@guardian/cdk/lib/constructs/core';
import {
	GuSecurityGroup,
	GuVpc,
	SubnetType,
} from '@guardian/cdk/lib/constructs/ec2';
import { GuardianPrivateNetworks } from '@guardian/private-infrastructure-config';
import type { App } from 'aws-cdk-lib';
import { Duration, Tags } from 'aws-cdk-lib';
import {
	InstanceClass,
	InstanceSize,
	InstanceType,
	Peer,
	Port,
} from 'aws-cdk-lib/aws-ec2';
import { Schedule } from 'aws-cdk-lib/aws-events';
import type { DatabaseInstanceProps } from 'aws-cdk-lib/aws-rds';
import {
	CaCertificate,
	DatabaseInstance,
	DatabaseInstanceEngine,
} from 'aws-cdk-lib/aws-rds';
import { Secret } from 'aws-cdk-lib/aws-secretsmanager';
import { Topic } from 'aws-cdk-lib/aws-sns';
import {
	ParameterDataType,
	ParameterTier,
	StringParameter,
} from 'aws-cdk-lib/aws-ssm';
import { getCentralElkLink } from 'common/src/logs';
import { addCloudqueryEcsCluster } from './cloudquery';
import { addDataAuditLambda } from './data-audit';
import { addGithubActionsUsageLambda } from './github-actions-usage';
import { InteractiveMonitor } from './interactive-monitor';
import { addPrismaMigrateTask } from './prisma-migrate-task';
import { Repocop } from './repocop';

interface ServiceCatalogueProps extends GuStackProps {
	//TODO add fields for every kind of job to make schedule explicit at a glance.
	//For code environments, data accuracy is not the main priority.
	// To keep costs low, we can choose to run all the tasks on the same cadence, less frequently than on prod
	schedule?: Schedule;

	/**
	 * Enable deletion protection for the RDS instance?
	 *
	 * @default true
	 */
	rdsDeletionProtection?: boolean;
}

export class ServiceCatalogue extends GuStack {
	constructor(scope: App, id: string, props: ServiceCatalogueProps) {
		super(scope, id, props);

		const { stage, stack } = this;
		const app = props.app ?? 'service-catalogue';

		const { rdsDeletionProtection = true } = props;

		const nonProdSchedule = props.schedule;

		const privateSubnets = GuVpc.subnetsFromParameter(this, {
			type: SubnetType.PRIVATE,
		});

		const vpc = GuVpc.fromIdParameter(this, 'vpc', {
			/*
			CDK wants privateSubnetIds to be a multiple of availabilityZones.
			We're pulling the subnets from a parameter at runtime.
			We know they evaluate to 3 subnets, but at compile time CDK doesn't.
			Set the number of AZs to 1 to avoid the error:
			  `Error: Number of privateSubnetIds (1) must be a multiple of availability zones (2).`
			 */
			availabilityZones: ['ignored'],
			privateSubnetIds: privateSubnets.map((subnet) => subnet.subnetId),
		});

		const port = 5432;

		const dbSecurityGroup = new GuSecurityGroup(this, 'PostgresSecurityGroup', {
			app,
			vpc,
		});

		const dbProps: DatabaseInstanceProps = {
			engine: DatabaseInstanceEngine.POSTGRES,
			port,
			vpc,
			vpcSubnets: { subnets: privateSubnets },
			iamAuthentication: true, // We're not using IAM auth for ECS tasks, however we do use IAM auth when connecting to RDS locally.
			instanceType: InstanceType.of(InstanceClass.T4G, InstanceSize.SMALL),
			storageEncrypted: true,
			securityGroups: [dbSecurityGroup],
			deletionProtection: rdsDeletionProtection,

			/*
			This certificate supports automatic rotation.
			See https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html#UsingWithRDS.SSL.RegionCertificateAuthorities
			 */
			caCertificate: CaCertificate.RDS_CA_RDS2048_G1,
		};

		const db = new DatabaseInstance(this, 'PostgresInstance1', dbProps);

		Tags.of(db).add('devx-backup-enabled', 'true');

		const applicationToPostgresSecurityGroup = new GuSecurityGroup(
			this,
			'PostgresAccessSecurityGroup',
			{ app, vpc },
		);

		// TODO use a bastion host here instead? https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_ec2.BastionHostLinux.html
		dbSecurityGroup.addIngressRule(
			Peer.ipv4(GuardianPrivateNetworks.Engineering),
			Port.tcp(port),
			'Allow connection to Postgres from the office network.',
		);

		dbSecurityGroup.connections.allowFrom(
			applicationToPostgresSecurityGroup,
			Port.tcp(port),
		);

		// Used by downstream services that read ServiceCatalogue data, namely Grafana.
		new StringParameter(this, 'PostgresAccessSecurityGroupParam', {
			parameterName: `/${stage}/${stack}/${app}/postgres-access-security-group`,
			simpleName: false,
			stringValue: applicationToPostgresSecurityGroup.securityGroupId,
			tier: ParameterTier.STANDARD,
			dataType: ParameterDataType.TEXT,
		});
		new StringParameter(this, 'PostgresInstanceEndpointAddress', {
			parameterName: `/${stage}/${stack}/${app}/postgres-instance-endpoint-address`,
			simpleName: false,
			stringValue: db.dbInstanceEndpointAddress,
			tier: ParameterTier.STANDARD,
			dataType: ParameterDataType.TEXT,
		});

		const snykReadOnlyKey = new Secret(this, 'snyk-credentials', {
			secretName: `/${stage}/${stack}/${app}/snyk-credentials`,
		});

		addCloudqueryEcsCluster(this, {
			nonProdSchedule,
			db,
			vpc,
			dbAccess: applicationToPostgresSecurityGroup,
			snykCredentials: snykReadOnlyKey,
		});

		const anghammaradTopicParameter =
			GuAnghammaradTopicParameter.getInstance(this);

		const repocopProdMonitoring: GuLambdaErrorPercentageMonitoringProps = {
			toleratedErrorPercentage: 50,
			lengthOfEvaluationPeriod: Duration.minutes(1),
			numberOfEvaluationPeriodsAboveThresholdBeforeAlarm: 1,
			snsTopicName: 'devx-alerts',
			alarmDescription: `RepoCop error percentage is too high. Find the logs here ${getCentralElkLink(
				{
					filters: {
						stage,
						app: 'repocop',
					},
				},
			)}`,
		};

		const repocopCodeMonitoring: NoMonitoring = { noMonitoring: true };

		const repocopMonitoringConfiguration =
			stage === 'PROD' ? repocopProdMonitoring : repocopCodeMonitoring;

		const interactiveMonitor = new InteractiveMonitor(this);

		const anghammaradTopic = Topic.fromTopicArn(
			this,
			'anghammarad-arn',
			anghammaradTopicParameter.valueAsString,
		);

		const githubCredentials = new Secret(
			this,
			`branch-protector-github-app-auth`,
			{
				secretName: `/${stage}/${stack}/service-catalogue/branch-protector-github-app-secret`,
			},
		);

		const prodSchedule = Schedule.cron({
			weekDay: 'MON-FRI',
			hour: '10',
			minute: '30',
		});

		new Repocop(
			this,
			nonProdSchedule ?? prodSchedule,
			anghammaradTopic,
			db,
			repocopMonitoringConfiguration,
			vpc,
			interactiveMonitor.topic,
			applicationToPostgresSecurityGroup,
			githubCredentials,
			snykReadOnlyKey,
		);

		addDataAuditLambda(this, {
			vpc,
			db,
			dbAccess: applicationToPostgresSecurityGroup,
		});

		addGithubActionsUsageLambda(this, {
			vpc,
			db,
			dbAccess: applicationToPostgresSecurityGroup,
		});

		addPrismaMigrateTask(this, {});
	}
}

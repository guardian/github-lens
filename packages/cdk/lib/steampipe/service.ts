import type { AppIdentity, GuStack } from '@guardian/cdk/lib/constructs/core';
import { GuCname } from '@guardian/cdk/lib/constructs/dns';
import { GuSecurityGroup } from '@guardian/cdk/lib/constructs/ec2';
import { Duration } from 'aws-cdk-lib';
import { type ISecurityGroup, Port } from 'aws-cdk-lib/aws-ec2';
import {
	FargateService,
	FargateTaskDefinition,
	FireLensLogDriver,
	FirelensLogRouterType,
	LogDrivers,
	Secret,
} from 'aws-cdk-lib/aws-ecs';
import type { FargateServiceProps } from 'aws-cdk-lib/aws-ecs';
import {
	NetworkLoadBalancer,
	Protocol,
} from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import type { IManagedPolicy, PolicyStatement } from 'aws-cdk-lib/aws-iam';
import { RetentionDays } from 'aws-cdk-lib/aws-logs';
import { Secret as SecretsManager } from 'aws-cdk-lib/aws-secretsmanager';
import { Images } from '../cloudquery/images';

export interface SteampipeServiceProps
	extends AppIdentity,
		Omit<FargateServiceProps, 'Cluster' | 'taskDefinition'> {
	/**
	 * Any secrets to pass to the CloudQuery container.
	 *
	 * @see https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_ecs.ContainerDefinitionOptions.html#secrets
	 * @see https://repost.aws/knowledge-center/ecs-data-security-container-task
	 */
	secrets?: Record<string, Secret>;

	/**
	 * Any IAM managed policies to attach to the task.
	 */
	managedPolicies: IManagedPolicy[];

	/**
	 * IAM policies to attach to the task.
	 */
	policies: PolicyStatement[];

	/**
	 * The name of the Kinesis stream to send logs to.
	 */
	loggingStreamName: string;

	/**
	 * Security group allowing access to Network Load Balancer
	 */
	accessSecurityGroup: ISecurityGroup;
}

export class SteampipeService extends FargateService {
	constructor(scope: GuStack, id: string, props: SteampipeServiceProps) {
		const {
			managedPolicies,
			policies,
			loggingStreamName,
			cluster,
			app,
			accessSecurityGroup,
		} = props;
		const { region, stack, stage } = scope;
		const thisRepo = 'guardian/service-catalogue'; // TODO get this from GuStack

		const steampipeCredentials = new SecretsManager(
			scope,
			'steampipe-credentials',
			{
				secretName: `/${stage}/${stack}/${app}/steampipe-credentials`,
			},
		);

		const task = new FargateTaskDefinition(scope, `${id}TaskDefinition`, {
			memoryLimitMiB: 512,
			cpu: 256,
		});

		const fireLensLogDriver = new FireLensLogDriver({
			options: {
				Name: `kinesis_streams`,
				region,
				stream: loggingStreamName,
				retry_limit: '2',
			},
		});

		task.addContainer(`${id}Container`, {
			image: Images.steampipe,
			dockerLabels: {
				Stack: stack,
				Stage: stage,
				App: app,
			},
			secrets: {
				STEAMPIPE_DATABASE_PASSWORD: Secret.fromSecretsManager(
					steampipeCredentials,
					'password',
				),
			},
			command: ['service', 'start', '--foreground'],
			logging: fireLensLogDriver,
			portMappings: [
				{
					containerPort: 9193,
					name: 'steampipe',
				},
			],
		});

		task.addFirelensLogRouter(`${id}Firelens`, {
			image: Images.devxLogs,
			logging: LogDrivers.awsLogs({
				streamPrefix: [stack, stage, app].join('/'),
				logRetention: RetentionDays.ONE_DAY,
			}),
			environment: {
				STACK: stack,
				STAGE: stage,
				APP: app,
				GU_REPO: thisRepo,
			},
			firelensConfig: {
				type: FirelensLogRouterType.FLUENTBIT,
			},
		});

		managedPolicies.forEach((policy) => task.taskRole.addManagedPolicy(policy));
		policies.forEach((policy) => task.addToTaskRolePolicy(policy));

		const steampipeSecurityGroup = new GuSecurityGroup(scope, `steampipe-sg`, {
			app: app,
			vpc: cluster.vpc,
		});

		// Anything with this SG can talk to anything else with this SG
		// In this case the NLB can talk to the ECS Service
		steampipeSecurityGroup.addIngressRule(
			steampipeSecurityGroup,
			Port.tcp(9193),
			'Allow this SG to talk to other applications also using this SG (in this case NLB to ECS)',
		);

		const nlb = new NetworkLoadBalancer(scope, `steampipe-nlb`, {
			vpc: cluster.vpc,
			securityGroups: [accessSecurityGroup, steampipeSecurityGroup],
		});

		const nlbListener = nlb.addListener(`steampipe-nlb-listener`, {
			port: 9193,
			protocol: Protocol.TCP,
		});

		new GuCname(scope, 'SteampipeDNS', {
			app: app,
			ttl: Duration.hours(1),
			domainName: 'steampipe.code.dev-gutools.co.uk',
			resourceRecord: nlb.loadBalancerDnsName,
		});

		super(scope, id, {
			cluster,
			vpcSubnets: { subnets: cluster.vpc.privateSubnets },
			taskDefinition: task,
			securityGroups: [steampipeSecurityGroup],
			assignPublicIp: false,
			desiredCount: 1,
		});

		nlbListener.addTargets(`steampipe-nlb-target`, {
			port: 9193,
			protocol: Protocol.TCP,
			targets: [this],
		});
	}
}

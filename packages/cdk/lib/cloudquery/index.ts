import type { GuStack } from '@guardian/cdk/lib/constructs/core';
import { GuStringParameter } from '@guardian/cdk/lib/constructs/core';
import { GuSecurityGroup } from '@guardian/cdk/lib/constructs/ec2';
import { GuS3Bucket } from '@guardian/cdk/lib/constructs/s3';
import { GuardianAwsAccounts } from '@guardian/private-infrastructure-config';
import { Duration } from 'aws-cdk-lib';
import type { IVpc } from 'aws-cdk-lib/aws-ec2';
import { Secret } from 'aws-cdk-lib/aws-ecs';
import { Schedule } from 'aws-cdk-lib/aws-events';
import type { PolicyStatement } from 'aws-cdk-lib/aws-iam';
import type { DatabaseInstance } from 'aws-cdk-lib/aws-rds';
import { Secret as SecretsManager } from 'aws-cdk-lib/aws-secretsmanager';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import type { CloudquerySource } from './cluster';
import { CloudqueryCluster } from './cluster';
import {
	awsSourceConfigForAccount,
	awsSourceConfigForOrganisation,
	fastlySourceConfig,
	galaxiesSourceConfig,
	githubLanguagesConfig,
	githubSourceConfig,
	ns1SourceConfig,
	riffraffSourcesConfig,
	serviceCatalogueConfigDirectory,
	skipTables,
	snykSourceConfig,
} from './config';
import { Images } from './images';
import { cloudqueryAccess, listOrgsPolicy, readBucketPolicy } from './policies';

interface CloudqueryEcsClusterProps {
	vpc: IVpc;
	db: DatabaseInstance;
	dbAccess: GuSecurityGroup;
	nonProdSchedule?: Schedule;
	snykCredentials: SecretsManager;
	loggingStreamName: string;
	logShippingPolicy: PolicyStatement;
}

export function addCloudqueryEcsCluster(
	scope: GuStack,
	props: CloudqueryEcsClusterProps,
) {
	const { stage, stack, app = 'service-catalogue' } = scope;
	const {
		vpc,
		db,
		dbAccess,
		nonProdSchedule,
		loggingStreamName,
		logShippingPolicy,
	} = props;

	const riffRaffDatabaseAccessSecurityGroupParam =
		StringParameter.valueForStringParameter(
			scope,
			`/${stage}/deploy/riff-raff/external-database-access-security-group`,
		);

	// Provisioned by RiffRaff to specifically allow applications other than RiffRaff to access its DB
	// See https://github.com/guardian/deploy-tools-platform/pull/731
	const applicationToRiffRaffDatabaseSecurityGroup =
		GuSecurityGroup.fromSecurityGroupId(
			scope,
			'RiffRaffDatabaseAccessSecurityGroup',
			riffRaffDatabaseAccessSecurityGroupParam,
		);

	const individualAwsSources: CloudquerySource[] = [
		{
			name: 'AwsListOrgs',
			description:
				'Data about the AWS Organisation, including accounts and OUs. Uses include mapping account IDs to account names.',
			schedule: nonProdSchedule ?? Schedule.rate(Duration.days(1)),
			config: awsSourceConfigForAccount(GuardianAwsAccounts.DeployTools, {
				tables: [
					/*
          Collect all AWS Organisation tables, including account names, and which OU they belong to.
          A wildcard is used, as there are a lot of tables!
          See https://www.cloudquery.io/docs/advanced-topics/performance-tuning#use-wildcard-matching
           */
					'aws_organization*',
				],
			}),
			policies: [
				listOrgsPolicy,
				cloudqueryAccess(GuardianAwsAccounts.DeployTools),
			],
		},
		{
			name: 'AwsDelegatedToSecurityAccount',
			description:
				'Organisation wide security data, from access analyzer and security hub. Uses include identifying lambdas using deprecated runtimes.',
			schedule: nonProdSchedule ?? Schedule.cron({ minute: '0', hour: '22' }),
			config: awsSourceConfigForAccount(
				GuardianAwsAccounts.Security,
				{
					tables: ['aws_accessanalyzer_*', 'aws_securityhub_*'],
					concurrency: 2000,
				},
				{
					table_options: {
						// For more information on how security hub filtering works, see the following links:
						// # https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_AwsSecurityFindingFilters.html
						// # https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_StringFilter.html
						//https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_NumberFilter.html
						aws_securityhub_findings: {
							get_findings: [
								{
									filters: {
										record_state: [
											{
												comparison: 'EQUALS',
												value: 'ACTIVE',
											},
										],
										compliance_status: [
											{
												comparison: 'NOT_EQUALS',
												value: 'PASSED',
											},
										],
										workflow_status: [
											{
												comparison: 'NOT_EQUALS',
												value: 'RESOLVED',
											},
										],
									},
								},
							],
						},
					},
				},
			),
			policies: [cloudqueryAccess(GuardianAwsAccounts.Security)],
			memoryLimitMiB: 2048,
			cpu: 1024,
		},
		{
			name: 'AwsOrgWideCloudFormation',
			description:
				'Collecting CloudFormation data across the organisation. We use CloudFormation stacks as a proxy for a service, so collect the data multiple times a day',
			schedule: nonProdSchedule ?? Schedule.rate(Duration.hours(3)),
			config: awsSourceConfigForOrganisation({
				tables: ['aws_cloudformation_*'],
			}),
			policies: [listOrgsPolicy, cloudqueryAccess('*')],
			memoryLimitMiB: 1024,
		},
		{
			name: 'AwsCostExplorer',
			description:
				'Collecting Aws Cost Explorer Information. This is usefull for reservations',
			schedule: nonProdSchedule ?? Schedule.rate(Duration.days(7)),
			config: awsSourceConfigForOrganisation({
				tables: ['aws_costexplorer_*'],
			}),
			policies: [listOrgsPolicy, cloudqueryAccess('*')],
		},
		{
			name: 'AwsOrgWideLoadBalancers',
			description:
				'Collecting load balancer data across the organisation. Uses include building SLO dashboards.',
			schedule: nonProdSchedule ?? Schedule.rate(Duration.minutes(30)),
			config: awsSourceConfigForOrganisation({
				tables: ['aws_elbv1_*', 'aws_elbv2_*'],
			}),
			policies: [listOrgsPolicy, cloudqueryAccess('*')],
		},
		{
			name: 'AwsOrgWideAutoScalingGroups',
			description:
				'Collecting ASG data across the organisation. Uses include building SLO dashboards.',
			schedule: nonProdSchedule ?? Schedule.cron({ minute: '0', hour: '0' }),
			config: awsSourceConfigForOrganisation({
				tables: ['aws_autoscaling_groups'],
			}),
			policies: [listOrgsPolicy, cloudqueryAccess('*')],
		},
		{
			name: 'AwsOrgWideCertificates',
			description:
				'Collecting certificate data across the organisation. Uses include building SLO dashboards.',
			schedule: nonProdSchedule ?? Schedule.cron({ minute: '0', hour: '1' }),
			config: awsSourceConfigForOrganisation({
				tables: ['aws_acm*'],
			}),
			policies: [listOrgsPolicy, cloudqueryAccess('*')],
		},
		{
			name: 'AwsLambda',
			description: 'Collecting lambda data across the organisation.',
			schedule: nonProdSchedule ?? Schedule.cron({ minute: '10', hour: '1' }),
			config: awsSourceConfigForOrganisation({
				tables: ['aws_lambda_*'],
			}),
			policies: [listOrgsPolicy, cloudqueryAccess('*')],
		},
		{
			name: 'AwsSSMParameters',
			description: 'Collecting ssm parameters across the organisation.',
			schedule: nonProdSchedule ?? Schedule.cron({ minute: '20', hour: '1' }),
			config: awsSourceConfigForOrganisation({
				tables: ['aws_ssm_parameters'],
			}),
			policies: [listOrgsPolicy, cloudqueryAccess('*')],
		},
		{
			name: 'AwsOrgWideCloudwatchAlarms',
			description:
				'Collecting CloudWatch Alarm data across the organisation. Uses include building SLO dashboards.',
			schedule: nonProdSchedule ?? Schedule.cron({ minute: '0', hour: '2' }),
			config: awsSourceConfigForOrganisation({
				tables: ['aws_cloudwatch_alarms'],
			}),
			policies: [listOrgsPolicy, cloudqueryAccess('*')],
		},
		{
			name: 'AwsOrgWideInspector',
			description: 'Collecting Inspector data across the organisation.',
			schedule: nonProdSchedule ?? Schedule.cron({ minute: '0', hour: '3' }),
			config: awsSourceConfigForOrganisation({
				tables: ['aws_inspector_findings', 'aws_inspector2_findings'],
			}),
			policies: [listOrgsPolicy, cloudqueryAccess('*')],
			memoryLimitMiB: 1024,
		},
		{
			name: 'AwsOrgWideS3',
			description:
				'Collecting S3 data across the organisation. Uses include identifying which account a bucket resides.',
			schedule: nonProdSchedule ?? Schedule.cron({ minute: '0', hour: '4' }),
			config: awsSourceConfigForOrganisation({
				tables: ['aws_s3*'],
			}),
			policies: [listOrgsPolicy, cloudqueryAccess('*')],
		},
		{
			name: 'AwsOrgWideDynamoDB',
			description:
				'Collecting DynamoDB data across the organisation. Uses include auditing backup configuration.',
			schedule: nonProdSchedule ?? Schedule.cron({ minute: '0', hour: '5' }),
			config: awsSourceConfigForOrganisation({
				tables: ['aws_dynamodb*'],
			}),
			policies: [listOrgsPolicy, cloudqueryAccess('*')],
		},
		{
			name: 'AwsOrgWideRDS',
			description:
				'Collecting RDS data across the organisation. Uses include auditing backup configuration.',
			schedule: nonProdSchedule ?? Schedule.cron({ minute: '0', hour: '6' }),
			config: awsSourceConfigForOrganisation({
				tables: [
					'aws_rds_instances',
					'aws_rds_clusters',
					'aws_rds_db_snapshots',
					'aws_rds_cluster_snapshots',
				],
			}),
			policies: [listOrgsPolicy, cloudqueryAccess('*')],
		},
		{
			name: 'AwsOrgWideBackup',
			description:
				'Collecting Backup data across the organisation. Uses include auditing backup configuration.',
			schedule: nonProdSchedule ?? Schedule.cron({ minute: '0', hour: '7' }),
			config: awsSourceConfigForOrganisation({
				tables: [
					'aws_backup_protected_resources',
					'aws_backup_vaults',
					'aws_backup_vault_recovery_points',
				],
			}),
			policies: [listOrgsPolicy, cloudqueryAccess('*')],
			memoryLimitMiB: 1024,
		},
		{
			name: 'AwsOrgWideEc2',
			description:
				'Collecting EC2 instance information, and their security groups. Uses include identifying instances failing the "30 day old" SLO, and (eventually) replacing Prism.',
			schedule: nonProdSchedule ?? Schedule.rate(Duration.minutes(30)),
			config: awsSourceConfigForOrganisation({
				tables: [
					'aws_ec2_instances',
					'aws_ec2_security_groups',
					'aws_ec2_images',
				],
			}),
			policies: [listOrgsPolicy, cloudqueryAccess('*')],
			runAsSingleton: true,
			memoryLimitMiB: 1024,
		},
		{
			name: 'AwsOrgWideIamCredentialReports',
			description:
				'Collecting IAM credential reports to surface information about outdated or inactive users and access keys',
			schedule: nonProdSchedule ?? Schedule.rate(Duration.hours(4)),
			config: awsSourceConfigForOrganisation({
				tables: ['aws_iam_credential_reports'],
			}),
			policies: [listOrgsPolicy, cloudqueryAccess('*')],
			memoryLimitMiB: 1024,
		},
	];

	/*
  This is a catch-all task, collecting all other AWS data.
  Although we're not using the data for any particular reason, it is still useful to have.

  It runs once a week because there is a lot of data, and we need to avoid overlapping invocations.
  If we identify a table that needs to be updated more often, we should create a dedicated task for it.
   */
	const remainingAwsSources: CloudquerySource = {
		name: 'AwsRemainingData',
		description: 'Data fetched across all accounts in the organisation.',
		schedule:
			nonProdSchedule ??
			Schedule.cron({ minute: '0', hour: '16', weekDay: 'SAT' }), // Every Saturday, at 4PM UTC
		config: awsSourceConfigForOrganisation({
			tables: ['aws_*'],
			skipTables: [
				...skipTables,

				// casting because `config.spec.tables` could be empty, though in reality it never is
				...(individualAwsSources.flatMap(
					(_) => _.config.spec.tables,
				) as string[]),
			],

			// Defaulted to 500000 by ServiceCatalogue, concurrency controls the maximum number of Go routines to use.
			// The amount of memory used is a function of this value.
			// See https://www.cloudquery.io/docs/reference/source-spec#concurrency.
			concurrency: 2000,
		}),
		policies: [listOrgsPolicy, cloudqueryAccess('*')],

		// This task is quite expensive, and requires more power than the default (500MB memory, 0.25 vCPU).
		memoryLimitMiB: 3072,
		cpu: 1024,
	};

	const cloudqueryGithubCredentials = new SecretsManager(
		scope,
		'github-credentials',
		{
			secretName: `/${stage}/${stack}/${app}/github-credentials`,
		},
	);

	const githubSecrets: Record<string, Secret> = {
		GITHUB_PRIVATE_KEY: Secret.fromSecretsManager(
			cloudqueryGithubCredentials,
			'private-key',
		),
		GITHUB_APP_ID: Secret.fromSecretsManager(
			cloudqueryGithubCredentials,
			'app-id',
		),
		GITHUB_INSTALLATION_ID: Secret.fromSecretsManager(
			cloudqueryGithubCredentials,
			'installation-id',
		),
	};

	const additionalGithubCommands = [
		`echo -n $GITHUB_PRIVATE_KEY | base64 -d > ${serviceCatalogueConfigDirectory}/github-private-key`,
		`echo -n $GITHUB_APP_ID >  ${serviceCatalogueConfigDirectory}/github-app-id`,
		`echo -n $GITHUB_INSTALLATION_ID >  ${serviceCatalogueConfigDirectory}/github-installation-id`,
	];

	const githubSources: CloudquerySource[] = [
		{
			name: 'GitHubRepositories',
			description:
				'Collect GitHub repository data. Uses include RepoCop, which flags repositories that do not meet certain obligations.',
			schedule: nonProdSchedule ?? Schedule.cron({ minute: '0', hour: '0' }),
			config: githubSourceConfig({
				tables: [
					'github_repositories',
					'github_repository_branches',
					'github_repository_collaborators',
					'github_workflows',
					'github_repository_dependabot_alerts',
				],

				// We're not (yet) interested in the following tables, so do not collect them to reduce API quota usage.
				// See https://www.cloudquery.io/docs/advanced-topics/performance-tuning#improve-performance-by-skipping-relations
				skipTables: [
					'github_releases',
					'github_release_assets',
					'github_repository_dependabot_secrets',
				],
			}),
			secrets: githubSecrets,
			additionalCommands: additionalGithubCommands,
			memoryLimitMiB: 4096,
		},
		{
			name: 'GitHubTeams',
			description:
				'Collect GitHub team data. Uses include identifying which repositories a team owns.',
			schedule:
				nonProdSchedule ??
				Schedule.cron({ weekDay: '1', hour: '10', minute: '0' }),
			config: githubSourceConfig({
				tables: [
					'github_organizations',
					'github_organization_members',
					'github_teams',
					'github_team_members',
					'github_team_repositories',
				],
				skipTables: [
					/*
          These tables are children of github_organizations.
          ServiceCatalogue collects child tables automatically.
          We don't use them as they take a long time to collect, so skip them.
          See https://www.cloudquery.io/docs/advanced-topics/performance-tuning#improve-performance-by-skipping-relations
           */
					'github_organization_dependabot_alerts',
					'github_organization_dependabot_secrets',
				],
			}),
			secrets: githubSecrets,
			additionalCommands: additionalGithubCommands,
			memoryLimitMiB: 4096,
			cpu: 2048,
		},
		{
			name: 'GitHubIssues',
			description: 'Collect GitHub issue data (PRs and Issues)',
			schedule: nonProdSchedule ?? Schedule.cron({ minute: '0', hour: '2' }),
			config: githubSourceConfig({
				tables: ['github_issues'],
			}),
			secrets: githubSecrets,
			additionalCommands: additionalGithubCommands,
			memoryLimitMiB: 1024,
		},
	];

	const fastlyCredentials = new SecretsManager(scope, 'fastly-credentials', {
		secretName: `/${stage}/${stack}/${app}/fastly-credentials`,
	});

	const fastlySources: CloudquerySource[] = [
		{
			name: 'FastlyServices',
			description: 'Fastly services data',
			schedule: nonProdSchedule ?? Schedule.rate(Duration.days(1)),
			config: fastlySourceConfig({
				tables: [
					'fastly_services',
					'fastly_service_versions',
					'fastly_service_backends',
					'fastly_service_domains',
					'fastly_service_health_checks',
					'fastly_account_users',
				],
			}),
			secrets: {
				FASTLY_API_KEY: Secret.fromSecretsManager(fastlyCredentials, 'api-key'),
			},
		},
	];

	// The bucket in which the Galaxies data lives.
	const actionsStaticSiteBucketArn = new GuStringParameter(
		scope,
		'ActionsStaticSiteBucketArnParam',
		{
			fromSSM: true,
			default: '/INFRA/deploy/cloudquery/actions-static-site-bucket-arn',
		},
	).valueAsString;

	const actionsStaticSiteBucket = GuS3Bucket.fromBucketArn(
		scope,
		'ActionsStaticSiteBucket',
		actionsStaticSiteBucketArn,
	);

	const galaxiesSources: CloudquerySource[] = [
		{
			name: 'Galaxies',
			description: 'Galaxies data',
			schedule: nonProdSchedule ?? Schedule.rate(Duration.days(1)),
			policies: [
				readBucketPolicy(
					`${actionsStaticSiteBucket.bucketArn}/galaxies.gutools.co.uk/data/*`,
				),
			],
			config: galaxiesSourceConfig(actionsStaticSiteBucket.bucketName),
		},
	];

	const snykSources: CloudquerySource[] = [
		{
			name: 'SnykAll',
			description: 'Collecting all Snyk data, except for projects',
			schedule: nonProdSchedule ?? Schedule.cron({ minute: '0', hour: '6' }),
			config: snykSourceConfig({
				tables: [
					'snyk_issues',
					'snyk_organizations',
					'snyk_projects',
					'snyk_sbom',
				],
				skipTables: [],
			}),
			secrets: {
				SNYK_API_KEY: Secret.fromSecretsManager(
					props.snykCredentials,
					'api-key',
				),
			},
			memoryLimitMiB: 1024,
		},
	];

	const cloudqueryRiffRaffDatabaseCredentials = new SecretsManager(
		scope,
		'RiffRaffDatabaseCredentials',
		{
			secretName: `/${stage}/${stack}/${app}/riffraff-database-credentials`,
		},
	);

	const riffRaffSources: CloudquerySource = {
		name: 'RiffRaffData',
		description: "Source deployment data directly from riff-raff's database",
		schedule: nonProdSchedule ?? Schedule.cron({ minute: '0', hour: '0' }),
		config: riffraffSourcesConfig(),
		additionalSecurityGroups: [applicationToRiffRaffDatabaseSecurityGroup],
		secrets: {
			RIFFRAFF_DB_USERNAME: Secret.fromSecretsManager(
				cloudqueryRiffRaffDatabaseCredentials,
				'username',
			),
			RIFFRAFF_DB_PASSWORD: Secret.fromSecretsManager(
				cloudqueryRiffRaffDatabaseCredentials,
				'password',
			),

			RIFFRAFF_DB_HOST: Secret.fromSecretsManager(
				cloudqueryRiffRaffDatabaseCredentials,
				'host',
			),
		},
	};

	const githubLanguagesSecret = new SecretsManager(scope, 'github-languages', {
		secretName: `/${stage}/${stack}/${app}/github-languages`,
	});

	const githubLanguagesSource: CloudquerySource = {
		name: 'GitHubLanguages',
		description: 'Collect GitHub languages data',
		schedule: nonProdSchedule ?? Schedule.rate(Duration.days(7)),
		config: githubLanguagesConfig(),
		secrets: {
			GITHUB_ACCESS_TOKEN: Secret.fromSecretsManager(githubLanguagesSecret),
		},
		// additionalCommands: additionalGithubCommands,
	};

	const ns1ApiKey = new SecretsManager(scope, 'ns1-credentials', {
		secretName: `/${stage}/${stack}/${app}/ns1-credentials`,
	});

	const ns1Source: CloudquerySource = {
		name: 'NS1',
		description: 'DNS records from NS1',
		schedule: nonProdSchedule ?? Schedule.cron({ minute: '0', hour: '0' }),
		dockerDistributedPluginImage: Images.ns1Source,
		secrets: {
			NS1_API_KEY: Secret.fromSecretsManager(ns1ApiKey, 'api-key'),
		},
		config: ns1SourceConfig(),
	};

	return new CloudqueryCluster(scope, `${app}Cluster`, {
		app,
		vpc,
		db,
		dbAccess,
		loggingStreamName,
		logShippingPolicy,
		sources: [
			...individualAwsSources,
			remainingAwsSources,
			...githubSources,
			...fastlySources,
			...galaxiesSources,
			...snykSources,
			riffRaffSources,
			githubLanguagesSource,
			ns1Source,
		],
	});
}

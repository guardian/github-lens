import { GuardianAwsAccounts } from '@guardian/private-infrastructure-config';
import { dump } from 'js-yaml';
import {
	awsSourceConfigForAccount,
	awsSourceConfigForOrganisation,
	githubSourceConfig,
	postgresDestinationConfig,
} from './config';

describe('Config generation, and converting to YAML', () => {
	it('Should create a destination configuration', () => {
		const config = postgresDestinationConfig();
		expect(dump(config)).toMatchInlineSnapshot(`
		"kind: destination
		spec:
		  name: postgresql
		  registry: github
		  path: cloudquery/postgresql
		  version: v7.2.0
		  migrate_mode: forced
		  spec:
		    connection_string: >-
		      user=\${DB_USERNAME} password=\${DB_PASSWORD} host=\${DB_HOST} port=5432
		      dbname=postgres sslmode=verify-full
		"
	`);
	});

	it('Should create an AWS source configuration for the organisation', () => {
		const config = awsSourceConfigForOrganisation({
			tables: ['aws_s3_buckets'],
		});
		expect(dump(config)).toMatchInlineSnapshot(`
"kind: source
spec:
  name: aws
  path: cloudquery/aws
  version: v27.5.0
  tables:
    - aws_s3_buckets
  destinations:
    - postgresql
  otel_endpoint: 0.0.0.0:4318
  otel_endpoint_insecure: true
  spec:
    org:
      member_role_name: cloudquery-access
      organization_units:
        - ou-123
"
`);
	});

	it('Should create an AWS source configuration with skipped tables for the organisation', () => {
		const config = awsSourceConfigForOrganisation({
			tables: ['*'],
			skipTables: ['aws_s3_buckets'],
		});
		expect(dump(config)).toMatchInlineSnapshot(`
"kind: source
spec:
  name: aws
  path: cloudquery/aws
  version: v27.5.0
  tables:
    - '*'
  skip_tables:
    - aws_s3_buckets
  destinations:
    - postgresql
  otel_endpoint: 0.0.0.0:4318
  otel_endpoint_insecure: true
  spec:
    org:
      member_role_name: cloudquery-access
      organization_units:
        - ou-123
"
`);
	});

	it('Should create an AWS source configuration for a single account', () => {
		const config = awsSourceConfigForAccount(GuardianAwsAccounts.Security, {
			tables: [
				'aws_accessanalyzer_analyzers',
				'aws_accessanalyzer_analyzer_archive_rules',
				'aws_accessanalyzer_analyzer_findings',
			],
		});
		expect(dump(config)).toMatchInlineSnapshot(`
"kind: source
spec:
  name: aws
  path: cloudquery/aws
  version: v27.5.0
  tables:
    - aws_accessanalyzer_analyzers
    - aws_accessanalyzer_analyzer_archive_rules
    - aws_accessanalyzer_analyzer_findings
  destinations:
    - postgresql
  otel_endpoint: 0.0.0.0:4318
  otel_endpoint_insecure: true
  spec:
    accounts:
      - id: cq-for-000000000015
        role_arn: arn:aws:iam::000000000015:role/cloudquery-access
"
`);
	});

	it('Should create an AWS source configuration for a single account with table options', () => {
		const config = awsSourceConfigForAccount(
			GuardianAwsAccounts.Security,
			{
				tables: ['aws_securityhub_findings'],
			},
			{
				table_options: {
					securityhub_findings: {
						record_state: 'ACTIVE',
					},
				},
			},
		);
		expect(dump(config)).toMatchInlineSnapshot(`
"kind: source
spec:
  name: aws
  path: cloudquery/aws
  version: v27.5.0
  tables:
    - aws_securityhub_findings
  destinations:
    - postgresql
  otel_endpoint: 0.0.0.0:4318
  otel_endpoint_insecure: true
  spec:
    accounts:
      - id: cq-for-000000000015
        role_arn: arn:aws:iam::000000000015:role/cloudquery-access
    table_options:
      securityhub_findings:
        record_state: ACTIVE
"
`);
	});

	it('Should create a GitHub source configuration', () => {
		const config = githubSourceConfig({
			tables: ['github_repositories'],
			org: 'guardian',
		});
		expect(dump(config)).toMatchInlineSnapshot(`
		"kind: source
		spec:
		  name: github
		  path: cloudquery/github
		  version: v11.10.0
		  tables:
		    - github_repositories
		  destinations:
		    - postgresql
		  spec:
		    concurrency: 1000
		    orgs:
		      - guardian
		    app_auth:
		      - org: guardian
		        private_key_path: /usr/share/cloudquery/github-private-key
		        app_id: \${file:/usr/share/cloudquery/github-app-id}
		        installation_id: \${file:/usr/share/cloudquery/github-installation-id}
		    include_archived_repos: true
		"
	`);
	});
});

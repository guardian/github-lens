import { ContainerImage } from 'aws-cdk-lib/aws-ecs';
import { Versions } from './versions';

export const Images = {
	cloudquery: ContainerImage.fromRegistry(
		`ghcr.io/cloudquery/cloudquery:${Versions.CloudqueryCli}`,
	),
	devxLogs: ContainerImage.fromRegistry('ghcr.io/guardian/devx-logs:2'),
	amazonLinux: ContainerImage.fromRegistry(
		'public.ecr.aws/amazonlinux/amazonlinux:latest',
	),
	// https://github.com/guardian/cq-source-ns1
	ns1Source: ContainerImage.fromRegistry(
		`ghcr.io/guardian/cq-source-ns1:${Versions.CloudqueryNs1}`,
	),
	postgres: ContainerImage.fromRegistry(
		'public.ecr.aws/docker/library/postgres:16-alpine',
	),
	prismaMigrate: ContainerImage.fromRegistry(
		'ghcr.io/guardian/service-catalogue/prisma-migrate:1',
	),
};

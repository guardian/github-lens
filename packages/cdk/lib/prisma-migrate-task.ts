import type { GuStack } from '@guardian/cdk/lib/constructs/core';
import { GuS3Bucket } from '@guardian/cdk/lib/constructs/s3';

// 1. Be able to drop prisma.zip files in a bucket
// 2. Trigger an ECS task when prisma.zip is updated, that runs a hello world ECS task
// 3. Fix up the task so that it performs the DB migrations against the DB

interface PrismaMigrateTaskProps {}

export function addPrismaMigrateTask(
	scope: GuStack,
	props: PrismaMigrateTaskProps,
) {
	const app = 'prisma-migrate-task';
	// eslint-disable-next-line no-empty-pattern -- TODO
	const {} = props;

	new GuS3Bucket(scope, `prisma-bucket`, { app });
}

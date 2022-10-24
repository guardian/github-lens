import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';

export class S3Ops {
	private readonly s3Client: S3Client;

	constructor(region: string) {
		this.s3Client = new S3Client({
			region,
		});
	}

	async putObject<T>(bucketName: string, key: string, body: T): Promise<void> {
		try {
			const command = new PutObjectCommand({
				Bucket: bucketName,
				Key: key,
				Body: JSON.stringify(body),
				ContentType: 'application/json; charset=utf-8',
				ACL: 'private',
			});

			await this.s3Client.send(command);
			console.log(
				`Item uploaded to s3 successfully to: s3://${bucketName}/${key}`,
			);
		} catch (e) {
			if (e instanceof Error) {
				console.error(`Error uploading item to s3: ${e.message}`);
			} else {
				console.error(e);
			}
		}
	}
}

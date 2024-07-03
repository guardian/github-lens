import type { SNSEvent } from 'aws-lambda';
import {
	anghammaradThreadKey,
	branchProtectionCtas,
	daysLeftToFix,
	getEnvOrThrow,
	getGithubAppSecret,
	parseEvent,
	parseSecretJson,
	partition,
	stringToSeverity,
	toNonEmptyArray,
	topicMonitoringProductionTagCtas,
} from './functions';
import type { NonEmptyArray } from './types';

function isValidUrl(str: string) {
	try {
		new URL(str);
		return true;
	} catch (err) {
		return false;
	}
}

describe('branchProtectionCtas', () => {
	it('should return an array of three valid urls', () => {
		const fullRepoName = 'my-org/my-repo';
		const teamSlug = 'my-team';
		const result = branchProtectionCtas(fullRepoName, teamSlug);
		expect(result).toHaveLength(3);
		expect(result.every((x) => isValidUrl(x.url))).toBe(true);
	});

	it('should return the correct urls in the correct order', () => {
		const fullRepoName = 'my-org/my-repo';
		const teamSlug = 'my-team';
		const result = branchProtectionCtas(fullRepoName, teamSlug);
		expect(result.map((x) => x.url)).toStrictEqual([
			'https://github.com/my-org/my-repo',
			'https://metrics.gutools.co.uk/d/EOPnljWIz/repocop-compliance?var-team=my-team&var-rule=All&orgId=1',
			'https://github.com/my-org/my-repo/settings/branches',
		]);
	});
});

describe('topicMonitoringProductionTagCtas', () => {
	it('should return an array of four valid urls', () => {
		const fullRepoName = 'my-org/my-repo';
		const teamSlug = 'my-team';
		const result = topicMonitoringProductionTagCtas(fullRepoName, teamSlug);
		expect(result).toHaveLength(4);
		expect(result.every((x) => isValidUrl(x.url))).toBe(true);
	});

	it('should return the correct urls in the correct order', () => {
		const fullRepoName = 'my-org/my-repo';
		const teamSlug = 'my-team';
		const result = topicMonitoringProductionTagCtas(fullRepoName, teamSlug);
		expect(result.map((x) => x.url)).toStrictEqual([
			'https://github.com/my-org/my-repo',
			'https://github.com/guardian/service-catalogue/blob/main/packages/best-practices/best-practices.md',
			'https://metrics.gutools.co.uk/d/EOPnljWIz/repocop-compliance?var-team=my-team&var-rule=All&orgId=1',
			'https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/classifying-your-repository-with-topics#adding-topics-to-your-repository',
		]);
	});
});

describe('anghammaradThreadKey', () => {
	it('should return a the expected string, with no slashes', () => {
		const fullRepoName = 'my-org/my-repo';
		const result = anghammaradThreadKey(fullRepoName);
		expect(result).toBe('service-catalogue-my-org-my-repo');
	});
});

describe('parseSecretJson', () => {
	it('should parse a valid JSON string', () => {
		const secretString =
			'{"installationId":"installation1","clientSecret":"secret1","appId":"app1","base64PrivateKey":"aGVsbG8K"}';
		const result = parseSecretJson(secretString);
		expect(result.installationId).toBe('installation1');
		expect(result.strategyOptions.clientSecret).toBe('secret1');
		expect(result.strategyOptions.appId).toBe('app1');
		expect(result.strategyOptions.privateKey).toBe('hello\n');
	});

	it('should throw an error for an invalid JSON string', () => {
		const secretString = 'not a JSON string';
		expect(() => parseSecretJson(secretString)).toThrow();
	});
});

describe('getEnvOrThrow', () => {
	it('should return the value of an existing environment variable', () => {
		process.env.TEST_VAR = 'test value';
		expect(getEnvOrThrow('TEST_VAR')).toBe('test value');
	});

	it('should throw an error for a non-existing environment variable', () => {
		const err = 'Environment variable NON_EXISTING_VAR is not set.';
		expect(() => getEnvOrThrow('NON_EXISTING_VAR')).toThrow(err);
	});
});

describe('getGitHubAppSecret', () => {
	it('should throw if the GITHUB_APP_SECRET environment variable is not set', async () => {
		const err = 'Environment variable GITHUB_APP_SECRET is not set.';
		const secret = process.env.GITHUB_APP_SECRET;
		delete process.env.GITHUB_APP_SECRET;
		await expect(getGithubAppSecret()).rejects.toThrow(err);
		process.env.GITHUB_APP_SECRET = secret;
	});
});

describe('parseSecretJson', () => {
	it('put the right values in the right fields, if the JSON string has the correct fields', () => {
		const actual = parseSecretJson(
			'{"appId": "myAppId", "base64PrivateKey": "aGVsbG8=", "clientId": "myClientId", "clientSecret": "myClientSecret", "installationId": "myInstallationId"}',
		);
		//check that the correct fields are in the correct values, and that base64PrivateKey has been decoded
		expect(actual.installationId).toEqual('myInstallationId');
		expect(actual.strategyOptions.appId).toEqual('myAppId');
		expect(actual.strategyOptions.clientId).toEqual('myClientId');
		expect(actual.strategyOptions.clientSecret).toEqual('myClientSecret');
		expect(actual.strategyOptions.installationId).toEqual('myInstallationId');
		expect(actual.strategyOptions.privateKey).toEqual('hello');
	});
	it('should throw an error if the input string is not valid JSON', () => {
		const input = 'not valid JSON';
		expect(() => parseSecretJson(input)).toThrow();
	});
	it('should throw an error if the input string is not a valid GithubAppSecret', () => {
		const input = '{"not": "a valid GithubAppSecret"}';
		expect(() => parseSecretJson(input)).toThrow();
	});
});

describe('partitioning an array', () => {
	it('should split it into two arrays based on a predicate', () => {
		const input = [1, 2, 1, 3, 1, 4];
		const predicate = (x: number) => x === 1;
		const [truthy, falsy] = partition(input, predicate);
		expect(truthy).toEqual([1, 1, 1]);
		expect(falsy).toEqual([2, 3, 4]);
	});
});

describe('Unwrapping an SNS message', () => {
	function eventWithMessage(msg: string): SNSEvent {
		return {
			Records: [
				{
					EventSource: 'aws:sns',
					EventVersion: '1.0',
					EventSubscriptionArn: '',
					Sns: {
						Message: msg,
						SignatureVersion: '',
						Timestamp: '',
						Signature: '',
						SigningCertUrl: '',
						MessageId: '',
						MessageAttributes: {},
						Type: '',
						UnsubscribeUrl: '',
						TopicArn: '',
					},
				},
			],
		};
	}

	interface MyEvent {
		myString: string;
		myArray: string[];
	}

	it('should generate a result of the expected type', () => {
		const outputEvent: MyEvent = {
			myString: 'hello',
			myArray: ['how', 'are', 'you', '?'],
		};

		const inputMsg = '{"myString":"hello","myArray":["how","are","you","?"]}';
		const inputEvent = eventWithMessage(inputMsg);
		expect(parseEvent<MyEvent>(inputEvent)).toEqual([outputEvent]);
	});
	it('should throw an error if the input message is not valid JSON', () => {
		const inputMsg = '{"myString":"goodbye","myArray":["how","are","you","?]}';
		const inputEvent = eventWithMessage(inputMsg);
		expect(() => parseEvent<MyEvent>(inputEvent)).toThrow();
	});
});

describe('stringToSeverity', () => {
	test('should return unknown if it is passed an unexpected string', () => {
		expect(stringToSeverity('foo')).toBe('unknown');
	});
	test('should return the correct severity for valid inputs', () => {
		expect(stringToSeverity('low')).toBe('low');
		expect(stringToSeverity('medium')).toBe('medium');
		expect(stringToSeverity('high')).toBe('high');
		expect(stringToSeverity('critical')).toBe('critical');
	});
});

describe('daysLeftToFix', () => {
	test('should return 0 if we exceed the SLA', () => {
		expect(daysLeftToFix('high', new Date('2021-01-01'))).toBe(0);
	});
	test('should return 30 if a high vuln was raised in the last 24 hours', () => {
		function hoursAgo(hours: number): Date {
			const date = new Date();
			date.setHours(date.getHours() - hours);
			return date;
		}

		expect(daysLeftToFix('high', hoursAgo(1))).toBe(30);
		expect(daysLeftToFix('high', hoursAgo(23))).toBe(30);
		expect(daysLeftToFix('high', hoursAgo(25))).toBe(29);
	});
	test('should return 2 if a critical vuln was raised today', () => {
		expect(daysLeftToFix('critical', new Date())).toBe(2);
	});
});

describe('Failure on empty arrays', () => {
	test('throw an error if input is an empty array', () => {
		const emptyArray: string[] = [];
		const nonEmptyArray: string[] = ['a', 'b'];
		const typedNonEmptyArray: NonEmptyArray<string> = ['a', 'b'];

		expect(() => toNonEmptyArray(emptyArray)).toThrow();
		expect(() => toNonEmptyArray(nonEmptyArray)).not.toThrow();
		expect(toNonEmptyArray(nonEmptyArray)).toEqual(nonEmptyArray);
		expect(toNonEmptyArray(nonEmptyArray)).toEqual(typedNonEmptyArray);
	});
});

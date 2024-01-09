import type { Octokit } from 'octokit';
import { h2, p, tsMarkdown } from 'ts-markdown';
import { stringify } from 'yaml';
import { createPullRequest } from './create-pull-request';

interface SnykInputs {
	ORG: string;
	SKIP_SBT?: boolean;
	SKIP_NODE?: boolean;
	SKIP_PYTHON?: boolean;
	PYTHON_VERSION?: string;
	PIP_REQUIREMENTS_FILES?: string;
	PIPFILES?: string;
	SKIP_GO?: boolean;
}

interface SnykSchema {
	name: string;
	on: {
		push: {
			branches: string[];
		};
		workflow_dispatch: object;
	};
	jobs: {
		security: {
			uses: string;
			with: SnykInputs;
			secrets: {
				SNYK_TOKEN: string;
			};
		};
	};
}

export function createYaml(languages: string[], prBranch: string): string {
	const inputs: SnykInputs = {
		ORG: '<SNYK_ORG_ID>',
		SKIP_SBT: languages.includes('Scala') ? undefined : true,
		SKIP_NODE:
			languages.includes('TypeScript') || languages.includes('JavaScript')
				? undefined
				: true,
		SKIP_PYTHON: languages.includes('Python') ? false : undefined,
		PYTHON_VERSION: languages.includes('Python') ? '<MAJOR.MINOR>' : undefined,
		PIP_REQUIREMENTS_FILES: languages.includes('Python')
			? '<PATH_TO_REQUIREMENTS> # Space separated list of requirements files. Only use one of this or PIPFILES'
			: undefined,
		PIPFILES: languages.includes('Python')
			? '<PATH_TO_PIPFILES> # Space separated list of pipfiles. Only use one of this or PIP_REQUIREMENTS_FILES'
			: undefined,
		SKIP_GO: languages.includes('Go') ? false : undefined,
	};

	const snykWorkflowJson: SnykSchema = {
		name: 'Snyk',
		on: {
			push: {
				branches: ['main', prBranch],
			},
			workflow_dispatch: {}, //There isn't an elegant way to do this in TypeScript, so we'll remove the {} at the end
		},
		jobs: {
			security: {
				uses: 'guardian/.github/.github/workflows/sbt-node-snyk.yml@main',
				with: inputs,
				secrets: {
					SNYK_TOKEN: '${{ secrets.SNYK_TOKEN }}',
				},
			},
		},
	};

	return stringify(snykWorkflowJson, { lineWidth: 120 })
		.replace('{}', '')
		.replaceAll(`"`, '');
}

function generatePrHeader(languages: string[]): string {
	return `Integrate ${languages.join(', ')} projects with Snyk`;
}

function checklist(items: string[]): string {
	return items.map((item) => `- [ ] ${item}`).join('\n');
}

function generatePrBody(branchName: string, repoName: string): string {
	const body = [
		h2('What does this change?'),
		p(
			'This PR integrates your repository with Snyk, to track its dependencies, in line with our recommendations.',
		),
		h2('Why?'),
		p(
			'If a repository is in production, we need to track its third party dependencies for vulnerabilities. ' +
				'DevX have detected that your repo contains at least one language that is not supported by Dependabot. ' +
				'As a result, we have raised this PR on your behalf to add it to Snyk.',
		),
		h2('How has it been verified?'),
		p(
			'We have tested this action against a combination of TypeScript, Scala, Go, and Python repositories. ' +
				'If your repository contains other languages not included here, integration may not work the way you expect it to.',
		),
		h2('What do I need to do?'),
		checklist([
			'Replace the SNYK_ORG variable with one that your team already uses (you should have other repos integrated with Snyk. ' +
				'If you can’t find any, reach out to DevX)',
			'Replace the python version with the version your repo uses',
		]),
		h2('How do I check this works?'),
		checklist([
			`Run the action via the GitHub CLI \`gh workflow run snyk.yml --ref ${branchName} --repo guardian/${repoName}\``,
			`View the action output, verify it has generated one project per dependency manifest.`,
		]),
	];
	return tsMarkdown(body);
}

export function generatePr(
	repoLanguages: string[],
	branch: string,
	repoName: string,
): [string, string] {
	const workflowLanguages = [
		'Scala',
		'TypeScript',
		'JavaScript',
		'Python',
		'Go',
	];

	//intersection of repo languages and workflow-supported languages
	const workflowSupportedLanguages = repoLanguages.filter((lang) =>
		workflowLanguages.includes(lang),
	);

	if (workflowSupportedLanguages.length === 0) {
		throw new Error('No supported languages provided, cannot generate PR');
	}

	const header = generatePrHeader(workflowSupportedLanguages);
	const body = generatePrBody(branch, repoName);

	return [header, body];
}

export async function createSnykPullRequest(
	octokit: Octokit,
	repoName: string,
	branchName: string,
	repoLanguages: string[],
) {
	const snykFileContents = createYaml(repoLanguages);
	const [title, body] = generatePr(repoLanguages, branchName, repoName);
	return await createPullRequest(octokit, {
		repoName,
		title,
		body,
		branchName,
		changes: [
			{
				commitMessage: 'Add Snyk.yml',
				files: {
					'.github/workflows/snyk.yml': snykFileContents,
				},
			},
		],
	});
}

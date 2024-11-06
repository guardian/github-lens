import { PublishCommand, SNSClient } from '@aws-sdk/client-sns';
import { awsClientConfig } from 'common/src/aws';
import { shuffle } from 'common/src/functions';
import type {
	AugmentedRepository,
	DependencyGraphIntegratorEvent,
	DepGraphLanguage,
	RepositoryWithDepGraphLanguage,
} from 'common/src/types';
import type { Config } from '../../config';
import { removeRepoOwner } from '../shared-utilities';

export function checkRepoForLanguage(
	augmentedRepository: AugmentedRepository,
	targetLanguage: string,
): boolean {
	return augmentedRepository.languages.includes(targetLanguage);
}

export function doesRepoHaveDepSubmissionWorkflowForLanguage(
	augmentedRepository: AugmentedRepository,
	targetLanguage: DepGraphLanguage,
): boolean {
	const dependencySubmissionWorkflows: Record<DepGraphLanguage, string> = {
		Scala: 'scalacenter/sbt-dependency-submission',
		Kotlin: 'gradle/actions/dependency-submission',
	};

	return augmentedRepository.workflow_usages.includes(
		dependencySubmissionWorkflows[`${targetLanguage}`],
	);
}

export function createSnsEventsForDependencyGraphIntegration(
	reposWithoutWorkflows: RepositoryWithDepGraphLanguage[],
): DependencyGraphIntegratorEvent[] {
	const eventsForAllLanguages: DependencyGraphIntegratorEvent[] =
		reposWithoutWorkflows.map((repo) => ({
			name: removeRepoOwner(repo.full_name),
			language: repo.dependency_graph_language,
			admins: repo.gh_admin_team_slugs,
		}));

	console.log(`Found ${eventsForAllLanguages.length} events to send to SNS`);

	return eventsForAllLanguages;
}

async function sendOneRepoToDepGraphIntegrator(
	config: Config,
	eventToSend: DependencyGraphIntegratorEvent,
) {
	if (config.stage === 'PROD') {
		const publishRequestEntry = new PublishCommand({
			Message: JSON.stringify(eventToSend),
			TopicArn: config.dependencyGraphIntegratorTopic,
		});
		console.log(`Sending ${eventToSend.name} to Dependency Graph Integrator`);
		await new SNSClient(awsClientConfig(config.stage)).send(
			publishRequestEntry,
		);
	} else {
		console.log(
			`Would have sent ${eventToSend.name} to Dependency Graph Integrator`,
		);
	}
}

export function getReposWithoutDepSubmissionWorkflows(
	augmentedRepositories: AugmentedRepository[],
): RepositoryWithDepGraphLanguage[] {
	const depGraphLanguages: DepGraphLanguage[] = ['Scala', 'Kotlin'];

	const allReposWithoutWorkflows: RepositoryWithDepGraphLanguage[] =
		depGraphLanguages.flatMap((depGraphLanguage) => {
			const reposWithDepGraphLanguages: AugmentedRepository[] =
				augmentedRepositories.filter((repo) =>
					checkRepoForLanguage(repo, depGraphLanguage),
				);
			console.log(
				`Found ${reposWithDepGraphLanguages.length} ${depGraphLanguage} repos in production`,
			);

			return reposWithDepGraphLanguages
				.filter((repo) => {
					return !doesRepoHaveDepSubmissionWorkflowForLanguage(
						repo,
						depGraphLanguage,
					);
				})
				.map((repo) => ({
					...repo,
					dependency_graph_language: depGraphLanguage,
				}));
		});

	console.log(
		`Found ${allReposWithoutWorkflows.length} production repos without dependency submission workflows`,
	);
	return allReposWithoutWorkflows;
}

export async function sendReposToDependencyGraphIntegrator(
	config: Config,
	augmentedRepositories: AugmentedRepository[],
	repoCount: number,
): Promise<void> {
	const reposRequiringDepGraphIntegration: RepositoryWithDepGraphLanguage[] =
		getReposWithoutDepSubmissionWorkflows(augmentedRepositories);

	if (reposRequiringDepGraphIntegration.length !== 0) {
		console.log(
			`Found ${reposRequiringDepGraphIntegration.length} repos requiring dependency graph integration`,
		);

		const selectedRepos = shuffle(reposRequiringDepGraphIntegration).slice(
			0,
			repoCount,
		);

		const eventsToSend: DependencyGraphIntegratorEvent[] =
			createSnsEventsForDependencyGraphIntegration(selectedRepos);

		for (const event of eventsToSend) {
			await sendOneRepoToDepGraphIntegrator(config, event);
		}
	} else {
		console.log('No suitable repos found to create events for.');
	}
}

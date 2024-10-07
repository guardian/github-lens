import { createYaml } from './file-generator';

describe('createYaml for sbt', () => {
	it('should generate the following yaml file', () => {
		const yaml = createYaml('branch', 'Scala', 'repo1');
		const result =
			String.raw`name: Update Dependency Graph for sbt
on:
  push:
    branches:
      - main
      - branch
  workflow_dispatch: 
jobs:
  dependency-graph:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout branch
        id: checkout
        uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7
      - name: Submit dependencies
        id: submit
        uses: scalacenter/sbt-dependency-submission@64084844d2b0a9b6c3765f33acde2fbe3f5ae7d3 # v3.1.0
      - name: Log snapshot for user validation
        id: validate
        run: cat` +
			' ${{ steps.submit.outputs.snapshot-json-path }} | jq' + // Need to split this line to avoid syntax errors due to the template string
			String.raw`
    permissions:
      contents: write
`;
		expect(yaml).toEqual(result);
	});
});

describe('createYaml for Kotlin', () => {
	it('should generate the following yaml file', () => {
		const yaml = createYaml('branch', 'Kotlin', 'repo2');
		const result =
			String.raw`name: Update Dependency Graph for Gradle
on:
  push:
    branches:
      - main
      - branch
  workflow_dispatch: 
jobs:
  dependency-graph:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout branch
        id: checkout
        uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7
      - name: Set up Java
        id: setup
        uses: actions/setup-java@99b8673ff64fbf99d8d325f52d9a5bdedb8483e9 # v4.2.1
        with:
          distribution: temurin
          java-version: 17
      - name: Submit dependencies
        id: submit
        uses: gradle/actions/dependency-submission@d156388eb19639ec20ade50009f3d199ce1e2808 # v4.1.0
      - name: Log snapshot for user validation
        id: validate
        run: cat ` + // Need to split this line to avoid errors due to new line produced in yaml
			'/home/runner/work/repo2/repo2/dependency-graph-reports/update_dependency_graph_for_gradle-dependency-graph.json\n          | jq' +
			String.raw`
    permissions:
      contents: write
`;
		expect(yaml).toEqual(result);
	});
});

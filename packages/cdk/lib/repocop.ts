import {GuStack, GuStackProps} from "@guardian/cdk/lib/constructs/core/index.js";
import {App, Duration} from "aws-cdk-lib";
import {GuScheduledLambda} from "@guardian/cdk/lib/patterns/scheduled-lambda.js";
import {Runtime} from "aws-cdk-lib/aws-lambda";
import {Schedule} from "aws-cdk-lib/aws-events";

export class Repocop extends GuStack{

    constructor(scope: App, id: string, props: GuStackProps) {
        super(scope, id, props);
        const repoCopApp = "repocop"
        new GuScheduledLambda(
            this,
            `${repoCopApp}-lambda`,
            {
                app: repoCopApp,
                runtime: Runtime.JAVA_11,
                memorySize: 512,
                handler: 'com.gu.repocop.main.main',
                fileName: `${repoCopApp}.jar`,
                monitoringConfiguration: {
                    toleratedErrorPercentage: 0,
                    snsTopicName: 'devx-alerts',
                },
                rules: [{ schedule: Schedule.cron({ minute: '0', hour: '8' }) }],
                timeout: Duration.seconds(300),
            },
        );


    }


}
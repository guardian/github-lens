import { json as jsonBodyParser } from 'body-parser';
import type { RetrievedObject } from 'common/aws/s3';
import type { Repository } from 'common/github/github';
import cors from 'cors';
import type { Express } from 'express';
import express, { Router } from 'express';
import asyncHandler from 'express-async-handler';
import { getDescribeRouterHandler } from '../../common/src/expressRoutes';

export function buildApp(
	repoData: Promise<RetrievedObject<Repository[]>>,
): Express {
	const app = express();
	const router = Router();

	router.use(jsonBodyParser());

	router.use(
		cors({
			origin: /\.(dev-)?gutools.co.uk$/,
			credentials: true,
		}),
	);

	router.get('/healthcheck', (req: express.Request, res: express.Response) => {
		res.status(200).json({ status: 'OK', stage: 'INFRA' });
	});

	router.get(
		'/repos',
		asyncHandler(async (req: express.Request, res: express.Response) => {
			res.status(200).json(await repoData);
		}),
	);

	//handle all invalid routes by showing all available routes
	router.get('*', getDescribeRouterHandler(router));

	app.use('/', router);

	return app;
}

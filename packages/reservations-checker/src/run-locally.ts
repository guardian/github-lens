import { homedir } from 'os';
import { config } from 'dotenv';
import { main } from './index';

config({ path: `../../.env` }); // Load `.env` file at the root of the repository
config({ path: `${homedir()}/.gu/service_catalogue/.env.local` });

if (require.main === module) {
	void main();
}

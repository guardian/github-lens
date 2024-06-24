import { QueryVariable } from '@grafana/scenes';
import { DATASOURCE_SERVICE_CATALOGUE } from '../../constants';

export class AccountVariable extends QueryVariable {
  constructor() {
    super({
      name: 'Account',
      datasource: DATASOURCE_SERVICE_CATALOGUE,
      query: 'SELECT name AS __text, id AS __value FROM aws_accounts',
    });
  }
}

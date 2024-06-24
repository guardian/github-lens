import type { SceneComponentProps, SceneObjectState } from '@grafana/scenes';
import { sceneGraph, SceneObjectBase, SceneQueryRunner } from '@grafana/scenes';
import React from 'react';
import { DATASOURCE_SERVICE_CATALOGUE } from '../../constants';

interface HeaderState extends SceneObjectState {}

export class Header extends SceneObjectBase<HeaderState> {
  static Component = HeaderRenderer;

  public constructor(state?: Partial<HeaderState>) {
    super({
      $data: new SceneQueryRunner({
        datasource: DATASOURCE_SERVICE_CATALOGUE,
        queries: [
          {
            refId: 'TotalInstances',
            rawSql: `
              SELECT COUNT(*) FROM aws_ec2_instances WHERE
            `,
            format: 'table',
          },
        ],
      }),
      ...state,
    });
  }
}

function HeaderRenderer({ model }: SceneComponentProps<Header>) {
  const data = sceneGraph.getData(model).useState();

  return <div>${JSON.stringify(data.data)}</div>;
}

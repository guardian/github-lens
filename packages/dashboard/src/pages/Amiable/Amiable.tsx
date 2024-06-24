import {
  EmbeddedScene,
  PanelBuilders,
  QueryVariable,
  SceneApp,
  SceneAppPage,
  SceneControlsSpacer,
  SceneDataTransformer,
  SceneFlexItem,
  SceneFlexLayout,
  SceneQueryRunner,
  SceneVariableSet,
  TextBoxVariable,
  VariableValueSelectors,
} from '@grafana/scenes';
import React from 'react';
import { Header } from '../../components/Amiable/Header';
import { AccountVariable } from '../../components/Variables/AccountVariable';
import { DATASOURCE_SERVICE_CATALOGUE, ROUTES } from '../../constants';
import { prefixRoute } from '../../utils/utils.routing';

const getEmbeddedScene = () => {
  const amiIdVariable = new TextBoxVariable({
    name: 'AMI ID',
  });

  const instances = new SceneQueryRunner({
    datasource: DATASOURCE_SERVICE_CATALOGUE,
    queries: [
      {
        refId: 'A',
        rawSql: `
          SELECT
            instance.account_id, 
            instance.instance_id, 
            instance.image_id, 
            instance.tags
          FROM aws_ec2_instances instance
          LEFT JOIN aws_ec2_images image ON instance.image_id = image.image_id
        `,
        format: 'table',
      },
    ],
  });

  return new EmbeddedScene({
    $data: instances,
    controls: [
      new VariableValueSelectors({
        $variables: new SceneVariableSet({
          variables: [new AccountVariable()],
        }),
      }),
      new SceneControlsSpacer(),
      new VariableValueSelectors({
        $variables: new SceneVariableSet({
          variables: [amiIdVariable],
        }),
      }),
    ],
    body: new SceneFlexLayout({
      children: [
        new SceneFlexItem({
          width: '100%',
          height: 300,
          body: new Header({
            $data: instances,
          }),
        }),
      ],
    }),
  });
};

const getScene = () => {
  return new SceneApp({
    pages: [
      new SceneAppPage({
        title: 'Amiable V2',
        url: prefixRoute(ROUTES.Amiable),
        getScene: () => {
          return getEmbeddedScene();
        },
      }),
    ],
  });
};

export const AmiablePage = () => {
  const scene = getScene();

  return <scene.Component model={scene} />;
};

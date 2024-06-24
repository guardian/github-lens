import React from 'react';
import { Redirect, Route, Switch } from 'react-router-dom';
import { ROUTES } from '../../constants';
import { AmiablePage } from '../../pages/Amiable/Amiable';
import { HelloWorldPluginPage } from '../../pages/HelloWorld';
import { HomePage } from '../../pages/Home';
import { WithDrilldown } from '../../pages/WithDrilldown';
import { PageWithTabs } from '../../pages/WithTabs';
import { prefixRoute } from '../../utils/utils.routing';

export const Routes = () => {
  return (
    <Switch>
      <Route path={prefixRoute(`${ROUTES.WithTabs}`)} component={PageWithTabs} />
      <Route path={prefixRoute(`${ROUTES.WithDrilldown}`)} component={WithDrilldown} />
      <Route path={prefixRoute(`${ROUTES.Home}`)} component={HomePage} />
      <Route path={prefixRoute(`${ROUTES.HelloWorld}`)} component={HelloWorldPluginPage} />
      <Route path={prefixRoute(`${ROUTES.Amiable}`)} component={AmiablePage} />
      <Redirect to={prefixRoute(ROUTES.Home)} />
    </Switch>
  );
};

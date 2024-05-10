import { type SceneComponentProps, SceneObjectBase, type SceneObjectState } from '@grafana/scenes';
import { Input } from '@grafana/ui';
import React from 'react';

export interface CustomSceneObjectState extends SceneObjectState {
  counter: number;
}

export class CustomSceneObject extends SceneObjectBase<CustomSceneObjectState> {
  static Component = CustomSceneObjectRenderer;

  onValueChange = (value: number) => {
    this.setState({ counter: value });
  };
}

function CustomSceneObjectRenderer({ model }: SceneComponentProps<CustomSceneObject>) {
  const state = model.useState();

  return (
    <Input
      prefix="Series count"
      defaultValue={state.counter}
      width={20}
      type="number"
      onBlur={(evt) => {
        model.onValueChange(parseInt(evt.currentTarget.value, 10));
      }}
    />
  );
}

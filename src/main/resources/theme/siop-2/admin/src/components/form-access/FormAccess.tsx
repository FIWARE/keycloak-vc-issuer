import {
  Children,
  cloneElement,
  FunctionComponent,
  isValidElement,
  ReactElement,
  ReactNode,
} from "react";
import { Controller } from "react-hook-form";
import {
  ActionGroup,
  ClipboardCopy,
  Form,
  FormGroup,
  FormProps,
  Grid,
  GridItem,
  Stack,
  StackItem,
  TextArea,
} from "@patternfly/react-core";
import type { AccessType } from "@keycloak/keycloak-admin-client/lib/defs/whoAmIRepresentation";

import { useAccess } from "../../context/access/Access";

export type FormAccessProps = FormProps & {
  /**
   * One of the AccessType's that the user needs to have to view this form. Also see {@link useAccess}.
   * @type {AccessType}
   */
  role: AccessType;

  /**
   * An override property if fine grained access has been setup for this form.
   * @type {boolean}
   */
  fineGrainedAccess?: boolean;

  /**
   * Set unWrap when you don't want this component to wrap your "children" in a {@link Form} component.
   * @type {boolean}
   */
  unWrap?: boolean;

  /**
   * Overwrite the fineGrainedAccess and make form regardless of access rights.
   */
  isReadOnly?: boolean;
};

/**
 * Use this in place of a patternfly Form component and add the `role` and `fineGrainedAccess` properties.
 * @param {FormAccessProps} param0 - all properties of Form + role and fineGrainedAccess
 */
export const FormAccess: FunctionComponent<FormAccessProps> = ({
  children,
  role,
  fineGrainedAccess = false,
  isReadOnly = false,
  unWrap = false,
  ...rest
}) => {
  const { hasAccess } = useAccess();

  const recursiveCloneChildren = (
    children: ReactNode,
    newProps: any
  ): ReactNode => {
    return Children.map(children, (child) => {
      if (!isValidElement(child)) {
        return child;
      }

      if (child.props) {
        const element = child as ReactElement;
        if (child.type === Controller) {
          return cloneElement(child, {
            ...element.props,
            render: (props: any) => {
              const renderElement = element.props.render(props);
              return cloneElement(renderElement, {
                ...renderElement.props,
                ...newProps,
              });
            },
          });
        }
        const children = recursiveCloneChildren(
          element.props.children,
          newProps
        );
        if (child.type === TextArea) {
          return cloneElement(child, {
            readOnly: newProps.isDisabled,
            children,
          } as any);
        }

        return cloneElement(
          child,
          child.type === FormGroup ||
            child.type === GridItem ||
            child.type === Grid ||
            child.type === ActionGroup ||
            child.type === ClipboardCopy ||
            child.type === Stack ||
            child.type === StackItem
            ? { children }
            : { ...newProps, children }
        );
      }
      return child;
    });
  };

  const isDisabled = isReadOnly || (!hasAccess(role) && !fineGrainedAccess);

  return (
    <>
      {!unWrap && (
        <Form {...rest} className={"keycloak__form " + (rest.className || "")}>
          {recursiveCloneChildren(children, isDisabled ? { isDisabled } : {})}
        </Form>
      )}
      {unWrap &&
        recursiveCloneChildren(children, isDisabled ? { isDisabled } : {})}
    </>
  );
};

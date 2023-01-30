import { lazy } from "react";
import type { Path } from "react-router-dom-v5-compat";
import { generatePath } from "react-router-dom-v5-compat";
import type { RouteDef } from "../../route-config";

export type NewClientScopeParams = { realm: string };

export const NewClientScopeRoute: RouteDef = {
  path: "/:realm/client-scopes/new",
  component: lazy(() => import("../form/ClientScopeForm")),
  breadcrumb: (t) => t("client-scopes:createClientScope"),
  access: "manage-clients",
};

export const toNewClientScope = (
  params: NewClientScopeParams
): Partial<Path> => ({
  pathname: generatePath(NewClientScopeRoute.path, params),
});

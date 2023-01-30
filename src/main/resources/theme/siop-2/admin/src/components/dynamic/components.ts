import type { FunctionComponent } from "react";

import type { ConfigPropertyRepresentation } from "@keycloak/keycloak-admin-client/lib/defs/authenticatorConfigInfoRepresentation";
import { StringComponent } from "./StringComponent";
import { TextComponent } from "./TextComponent";
import { BooleanComponent } from "./BooleanComponent";
import { ListComponent } from "./ListComponent";
import { RoleComponent } from "./RoleComponent";
import { MapComponent } from "./MapComponent";
import { ScriptComponent } from "./ScriptComponent";
import { ClientSelectComponent } from "./ClientSelectComponent";
import { MultiValuedStringComponent } from "./MultivaluedStringComponent";
import { MultiValuedListComponent } from "./MultivaluedListComponent";
import { GroupComponent } from "./GroupComponent";
import { FileComponent } from "./FileComponent";
import { PasswordComponent } from "./PasswordComponent";

export type ComponentProps = Omit<ConfigPropertyRepresentation, "type"> & {
  isDisabled?: boolean;
};

const ComponentTypes = [
  "String",
  "Text",
  "boolean",
  "List",
  "Role",
  "Script",
  "Map",
  "Group",
  "MultivaluedList",
  "ClientList",
  "MultivaluedString",
  "File",
  "Password",
] as const;

export type Components = typeof ComponentTypes[number];

export const COMPONENTS: {
  [index in Components]: FunctionComponent<ComponentProps>;
} = {
  String: StringComponent,
  Text: TextComponent,
  boolean: BooleanComponent,
  List: ListComponent,
  Role: RoleComponent,
  Script: ScriptComponent,
  Map: MapComponent,
  Group: GroupComponent,
  ClientList: ClientSelectComponent,
  MultivaluedList: MultiValuedListComponent,
  MultivaluedString: MultiValuedStringComponent,
  File: FileComponent,
  Password: PasswordComponent,
} as const;

export const isValidComponentType = (value: string): value is Components =>
  value in COMPONENTS;

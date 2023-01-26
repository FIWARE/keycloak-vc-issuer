function _defineProperty(obj, key, value) { key = _toPropertyKey(key); if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }
function _toPropertyKey(arg) { var key = _toPrimitive(arg, "string"); return typeof key === "symbol" ? key : String(key); }
function _toPrimitive(input, hint) { if (typeof input !== "object" || input === null) return input; var prim = input[Symbol.toPrimitive]; if (prim !== undefined) { var res = prim.call(input, hint || "default"); if (typeof res !== "object") return res; throw new TypeError("@@toPrimitive must return a primitive value."); } return (hint === "string" ? String : Number)(input); }
/*
 * Copyright 2020 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as React from "../../../../common/keycloak/web_modules/react.js";
import { Select, SelectOption, Button, Text, PageSectionVariants, PageSection, ActionList, ActionListItem, TextVariants, List, ListItem } from "../../../../common/keycloak/web_modules/@patternfly/react-core.js";
import { QRCodeSVG } from "./QRCode.js";
import { ContentPage } from "../ContentPage.js";
import { AccountServiceContext } from "../../account-service/AccountServiceContext.js";
export class VC extends React.Component {
  constructor(props, context) {
    console.log("Received context");
    console.log(context);
    super(props, context);
    this.state = {
      dropdownItems: [],
      credential: "",
      vcUrl: "",
      isOpen: false,
      isDisabled: true,
      vcQRVisible: false,
      urlQRVisible: false,
      selected: ""
    };
    this.fetchAvailableTypes();
  }
  fetchAvailableTypes() {
    const accountURL = new URL(this.context.accountUrl);
    const keycloakContext = this.context.kcSvc.keycloakAuth;
    const vcTypes = accountURL.protocol + "//" + accountURL.host + "/realms/" + keycloakContext.realm + "/verifiable-credential/types";
    const token = keycloakContext.token;
    var options = {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + token
      }
    };
    fetch(vcTypes, options).then(response => response.json()).then(data => this.setState({
      ...{
        dropdownItems: data
      }
    }));
  }
  generateVCUrl() {
    const accountURL = new URL(this.context.accountUrl);
    const keycloakContext = this.context.kcSvc.keycloakAuth;
    const vcIssue = accountURL.protocol + "//" + accountURL.host + "/realms/" + keycloakContext.realm + "/verifiable-credential?type=" + this.state.selected + "&token=" + keycloakContext.token;
    this.setState({
      ...{
        vcUrl: vcIssue,
        vcQRVisible: false,
        urlQRVisible: true
      }
    });
  }
  requestVC() {
    const accountURL = new URL(this.context.accountUrl);
    const keycloakContext = this.context.kcSvc.keycloakAuth;
    const vcIssue = accountURL.protocol + "//" + accountURL.host + "/realms/" + keycloakContext.realm + "/verifiable-credential?type=" + this.state.selected;
    const token = keycloakContext.token;
    var options = {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + token
      }
    };
    fetch(vcIssue, options).then(response => response.text()).then(data => this.setState({
      ...{
        credential: data,
        vcQRVisible: true,
        urlQRVisible: false
      }
    }));
  }
  render() {
    const {
      isOpen,
      selected,
      dropdownItems,
      isDisabled,
      credential,
      vcQRVisible,
      urlQRVisible,
      vcUrl
    } = this.state;
    return /*#__PURE__*/React.createElement(ContentPage, {
      title: "Issue VCs",
      introMessage: "Request a VC of the selected type or generate the request for importing it into your wallet."
    }, /*#__PURE__*/React.createElement(PageSection, {
      isFilled: true,
      variant: PageSectionVariants.light
    }, /*#__PURE__*/React.createElement(List, {
      isPlain: true
    }, /*#__PURE__*/React.createElement(ListItem, null, /*#__PURE__*/React.createElement(Select, {
      placeholderText: "Select an option",
      "aria-label": "Select Input with descriptions",
      onToggle: isOpen => {
        this.setState({
          isOpen
        });
      },
      onSelect: (e, s) => this.setState({
        ...{
          selected: s,
          isOpen: false,
          isDisabled: false
        }
      }),
      selections: selected,
      isOpen: isOpen
    }, dropdownItems.map((option, index) => /*#__PURE__*/React.createElement(SelectOption, {
      key: index,
      value: option
    })))), /*#__PURE__*/React.createElement(ListItem, null, /*#__PURE__*/React.createElement(ActionList, null, /*#__PURE__*/React.createElement(ActionListItem, null, /*#__PURE__*/React.createElement(Button, {
      onClick: () => this.requestVC(),
      isDisabled: isDisabled
    }, "Request VerifiableCredential")), /*#__PURE__*/React.createElement(ActionListItem, null, /*#__PURE__*/React.createElement(Button, {
      onClick: () => this.generateVCUrl(),
      isDisabled: isDisabled
    }, "Generate VerifiableCredential-Request")))), /*#__PURE__*/React.createElement(ListItem, null, /*#__PURE__*/React.createElement(ActionList, null, vcQRVisible && /*#__PURE__*/React.createElement(ActionListItem, null, /*#__PURE__*/React.createElement(QRCodeSVG, {
      value: credential,
      bgColor: "#ffffff",
      fgColor: "#000000",
      level: "L",
      includeMargin: false,
      size: 512
    })), urlQRVisible && /*#__PURE__*/React.createElement(ActionListItem, null, /*#__PURE__*/React.createElement(QRCodeSVG, {
      value: vcUrl,
      bgColor: "#ffffff",
      fgColor: "#000000",
      level: "L",
      includeMargin: false,
      size: 512
    })))), /*#__PURE__*/React.createElement(ListItem, null, vcQRVisible && /*#__PURE__*/React.createElement(Text, {
      component: TextVariants.h5
    }, credential), urlQRVisible && /*#__PURE__*/React.createElement(Text, {
      component: TextVariants.h5
    }, vcUrl)))));
  }
}
_defineProperty(VC, "contextType", AccountServiceContext);
;
//# sourceMappingURL=VC.js.map
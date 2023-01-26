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

import * as React from 'react';

import {
    Select,
    SelectOption,
    Button,
    Text,
    PageSectionVariants,
    PageSection,
    ActionList,
    ActionListItem,
    TextVariants,
    List,
    ListItem,
    SelectOptionObject
} from '@patternfly/react-core';
import { QRCodeSVG, QRCodeCanvas } from './QRCode';

 
import { ContentPage } from "../ContentPage"
import { ContentAlert } from "../ContentAlter"
import { AccountServiceContext } from "../../account-service/AccountServiceContext"

interface VCProps {
}

interface VCState {
  dropdownItems: string[],
  credential: string,
  vcUrl: string,
  isOpen: boolean,
  isDisabled: boolean,
  vcQRVisible: boolean,
  urlQRVisible: boolean,
  selected: string | SelectOptionObject
}

export class VC extends React.Component<VCProps, VCState> {
  static contextType = AccountServiceContext;

  constructor(props: VCProps, context:  React.ContextType<typeof AccountServiceContext>){

    console.log("Received context")
    console.log(context)
    super(props, context)
    this.state = {
      dropdownItems: [],
      credential: "",
      vcUrl: "",
      isOpen: false,
      isDisabled: true,
      vcQRVisible: false,
      urlQRVisible: false,
      selected:""
    }
    this.fetchAvailableTypes()
  }


  private fetchAvailableTypes() {
      const accountURL = new URL(this.context.accountUrl)
      const keycloakContext = this.context.kcSvc.keycloakAuth;
      const vcTypes = accountURL.protocol + "//" + accountURL.host + "/realms/" + keycloakContext.realm + "/verifiable-credential/types";
      const token = keycloakContext.token

      var options = {  
          method: 'GET',
          headers: {
          'Authorization': 'Bearer ' + token
          }
      }
      fetch(vcTypes, options)
          .then(response => response.json())
          .then(data =>  this.setState({ ...{dropdownItems: data}}));
    }
  
  
  private generateVCUrl() {
    const accountURL = new URL(this.context.accountUrl)
    const keycloakContext = this.context.kcSvc.keycloakAuth;
    const vcIssue = accountURL.protocol + "//" + accountURL.host + "/realms/" + keycloakContext.realm + "/verifiable-credential?type="+ this.state.selected + "&token=" + keycloakContext.token;

    this.setState({ ...{
      vcUrl: vcIssue,
      vcQRVisible: false,
      urlQRVisible: true}});
  }

  private requestVC() {
      const accountURL = new URL(this.context.accountUrl)
      const keycloakContext = this.context.kcSvc.keycloakAuth;
      const vcIssue = accountURL.protocol + "//" + accountURL.host + "/realms/" + keycloakContext.realm + "/verifiable-credential?type="+ this.state.selected;
      const token = keycloakContext.token
  
      var options = {  
        method: 'GET',
        headers: {
          'Authorization': 'Bearer ' + token
        }
      }
      fetch(vcIssue, options)
        .then(response => response.text())
        .then(data => this.setState({ ...{
            credential: data,
            vcQRVisible: true,
            urlQRVisible: false}})
        );
    }

    public render(): React.ReactNode {
          
    const { isOpen, selected, dropdownItems, isDisabled, credential, vcQRVisible, urlQRVisible, vcUrl} = this.state;

    return (
      <ContentPage title='Issue VCs' introMessage='Request a VC of the selected type or generate the request for importing it into your wallet.'>
        <PageSection isFilled variant={PageSectionVariants.light}>     
          <List isPlain>    
            <ListItem>   
              <Select
                placeholderText="Select an option"
                aria-label="Select Input with descriptions"
                onToggle={isOpen => {
                  this.setState({
                    isOpen
                  });
                }}
                onSelect={(e,s) => this.setState({ ...{
                  selected: s,
                  isOpen: false,
                  isDisabled: false
                }})}
                selections={selected}
                isOpen={isOpen}
              >
                {dropdownItems.map((option, index) => (
                  <SelectOption
                    key={index}
                    value={option}
                  />
                ))}
              </Select>     
            </ListItem>     
            <ListItem>         
              <ActionList>
                <ActionListItem>
                  <Button 
                    onClick={() => this.requestVC()} 
                    isDisabled={isDisabled}>
                    Request VerifiableCredential
                  </Button>
                </ActionListItem>
                <ActionListItem>
                  <Button 
                    onClick={() => this.generateVCUrl()} 
                    isDisabled={isDisabled}>
                    Generate VerifiableCredential-Request
                  </Button>
                </ActionListItem>
              </ActionList>
            </ListItem>           
            
              <ListItem>
            <ActionList>  
            { vcQRVisible &&
                <ActionListItem>
              <QRCodeSVG 
                value={credential}
                bgColor={"#ffffff"}
                fgColor={"#000000"}
                level={"L"}
                includeMargin={false}
                size={512}/> 
                </ActionListItem>
            }
            { urlQRVisible &&
                <ActionListItem>
              <QRCodeSVG 
                value={vcUrl}
                bgColor={"#ffffff"}
                fgColor={"#000000"}
                level={"L"}
                includeMargin={false}
                size={512}/> 
                </ActionListItem>
            }   
              </ActionList>
            </ListItem>

            <ListItem>         
              { vcQRVisible &&
              <Text component={TextVariants.h5}>
              {credential}
              </Text> 
              }
              { urlQRVisible &&
              <Text component={TextVariants.h5}>
              {vcUrl}
              </Text>           
              }
            </ListItem>      
          </List>       
        </PageSection>   
      </ContentPage>
      );
    }
};
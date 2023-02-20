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
    PageSectionVariants,
    PageSection,
    ActionList,
    ActionListItem,
    List,
    ListItem,
    SelectOptionObject
} from '@patternfly/react-core';
import { QRCodeSVG, QRCodeCanvas } from './QRCode';

 
import { ContentPage } from "../ContentPage"
import { ContentAlert } from "../ContentAlert"
import { AccountServiceContext } from "../../account-service/AccountServiceContext"

interface VCProps {
}

interface SupportedCredential {
  type: string,
  format: string
}

interface VCState {
  dropdownItems: string[],
  selectOptions: Map<string, SupportedCredential>,
  credential: string,
  vcUrl: string,
  offerUrl: string,
  isOpen: boolean,
  isDisabled: boolean,
  vcQRVisible: boolean,
  offerQRVisible: boolean,
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
      selectOptions: new Map<string, SupportedCredential>(),
      credential: "",
      vcUrl: "",
      offerUrl: "",
      isOpen: false,
      isDisabled: true,
      vcQRVisible: false,
      urlQRVisible: false,
      selected:"",
      offerQRVisible: false
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
          .then(data => {
            const  itemsList: string[] = [];
            const options = new Map<string, SupportedCredential>();
            data.forEach((element: SupportedCredential) => {
              const key = element.type + " " + element.format;
              itemsList.push(key);
              options.set(key, element);
            });
            this.setState({ ...{dropdownItems: itemsList, selectOptions: options}});
          });
    }
  
  
  private generateVCUrl() {
 
    const supportedCredential: SupportedCredential = this.getSelectedCredential()

    const accountURL = new URL(this.context.accountUrl);
    const keycloakContext = this.context.kcSvc.keycloakAuth;
    const vcIssue = accountURL.protocol + "//" + accountURL.host + "/realms/" + keycloakContext.realm + "/verifiable-credential?type="+  supportedCredential.type + "&token=" + keycloakContext.token;

    this.setState({ ...{
      vcUrl: vcIssue,
      vcQRVisible: false,
      offerQRVisible: false,
      urlQRVisible: true}});
  }

  private requestOID4VCI() {

 
    const supportedCredential: SupportedCredential = this.getSelectedCredential()

    const accountURL = new URL(this.context.accountUrl)
    const keycloakContext = this.context.kcSvc.keycloakAuth;
    const vcIssue = accountURL.protocol + "//" + accountURL.host + "/realms/" + keycloakContext.realm + "/verifiable-credential/credential";
    const token = keycloakContext.token
  
    var options = {  
      method: 'POST',
      headers: {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        'format': supportedCredential.format,
        'types': [supportedCredential.type]
      })
    }
    fetch(vcIssue, options)
      .then(response => this.handleResponse(response))
  }

  private getSelectedCredential(): SupportedCredential {
    const selectedOption = this.state.selectOptions.get(this.state.selected.toString());
    if(selectedOption === undefined) {
      throw new Error("Selection failed.")
    }
  
    return selectedOption

  }

  private buildOIDCConfigDiscovery() : string{

    const accountURL = new URL(this.context.accountUrl)
    const keycloakContext = this.context.kcSvc.keycloakAuth;
    const discoveryUrl =  accountURL.protocol + "//" + accountURL.host + "/realms/" + keycloakContext.realm + "/verifiable-credential";
    return "openid://discovery?issuer="+discoveryUrl


  }

  private requestVCOffer() {

 
    const supportedCredential: SupportedCredential = this.getSelectedCredential()

    const accountURL = new URL(this.context.accountUrl)
    const keycloakContext = this.context.kcSvc.keycloakAuth;
    const vcIssue = accountURL.protocol + "//" + accountURL.host + "/realms/" + keycloakContext.realm + "/verifiable-credential/credential-offer?type="+ supportedCredential.type+"&format="+supportedCredential.format;
    const token = keycloakContext.token

    var options = {  
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + token
      }
    }
    fetch(vcIssue, options)
      .then(response => this.handleOfferResponse(response))
  }
  
  private handleOfferResponse(response: Response) {
    response.text()
      .then(textData => {
        if (response.status !== 200) {
          console.log("Did not receive an offer.");
          ContentAlert.warning(textData);
        } else {
          this.setState({ ...{
            credential: textData,
            vcQRVisible: true,
            offerQRVisible: false,
            urlQRVisible: false}});
        }
      })    
  }

  private handleResponse(response: Response) {
    response.text()
    .then(textData => {
      if (response.status !== 200) {
        console.log("Did not receive a vc.");
        ContentAlert.warning(textData);
      } else {
        this.setState({ ...{
          offerUrl: textData,
          vcQRVisible: false,
          offerQRVisible: true,
          urlQRVisible: false}});
      }
    })      
  }

  public render(): React.ReactNode {
        
  const { isOpen, selected, dropdownItems, isDisabled, credential, vcQRVisible, urlQRVisible, vcUrl, offerQRVisible, offerUrl} = this.state;

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
                  onClick={() => this.requestOID4VCI()} 
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
              <ActionListItem>
                <Button 
                  onClick={() => this.requestVCOffer()} 
                  isDisabled={isDisabled}>
                  Initiate VerifiableCredential-Issuance
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
          { offerQRVisible &&
              <ActionListItem>
            <QRCodeSVG 
              value={offerUrl}
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
          <ActionList>  
              <ActionListItem>
            <QRCodeSVG 
              value={this.buildOIDCConfigDiscovery()}
              bgColor={"#ffffff"}
              fgColor={"#000000"}
              level={"L"}
              includeMargin={false}
              size={512}/> 
              </ActionListItem>
          
              </ActionList>
          </ListItem>
        </List>       
      </PageSection>   
    </ContentPage>
    );
  }
};
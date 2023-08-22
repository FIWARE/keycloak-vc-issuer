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
import { QRCodeSVG } from './QRCode';

 
import { ContentPage } from "../ContentPage"
import { ContentAlert } from "../ContentAlert"
import { AccountServiceContext } from "../../account-service/AccountServiceContext"

interface VCProps {
}

interface CredentialOfferURI {
  issuer: string;
  nonce: string;
}

interface SupportedCredential {
  type: string,
  format: string
}

interface VCState {
  dropdownItems: string[],
  selectOptions: Map<string, SupportedCredential>,
  credential: string,
  issuerDid: string,
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

    super(props, context)
    this.state = {
      dropdownItems: [],
      selectOptions: new Map<string, SupportedCredential>(),
      credential: "",
      issuerDid: "",
      vcUrl: "",
      offerUrl: "",
      isOpen: false,
      isDisabled: true,
      vcQRVisible: false,
      urlQRVisible: false,
      selected:"",
      offerQRVisible: false
    }
    this.fetchIssuer()
    .then(data => {
      console.log(data)
      this.setState({ ...{issuerDid: data}});
      this.fetchAvailableTypes()
    })
  }

  private fetchIssuer(): Promise<string> {

    const accountURL = new URL(this.context.accountUrl);
    const keycloakContext = this.context.kcSvc.keycloakAuth;
    const path = accountURL.protocol + "//" + accountURL.host + "/realms/" + keycloakContext.realm + "/verifiable-credential/issuer"
    var options = {  
      method: 'GET'
      }
    return fetch(path, options)
      .then(response => response.text());
      
  }

  private fetchAvailableTypes() {
      const accountURL = new URL(this.context.accountUrl)
      const keycloakContext = this.context.kcSvc.keycloakAuth;
      const vcTypes = accountURL.protocol + "//" + accountURL.host + "/realms/" + keycloakContext.realm + "/verifiable-credential/" + this.state.issuerDid + "/types";
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
  
  private getSelectedCredential(): SupportedCredential {
    const selectedOption = this.state.selectOptions.get(this.state.selected.toString());
    if(selectedOption === undefined) {
      throw new Error("Selection failed.")
    }
  
    return selectedOption

  }


  private requestVCOffer(path: String) {

 
    const supportedCredential: SupportedCredential = this.getSelectedCredential()

    const accountURL = new URL(this.context.accountUrl)
    const keycloakContext = this.context.kcSvc.keycloakAuth;
    const vcIssue = accountURL.protocol + "//" + accountURL.host + "/realms/" + keycloakContext.realm + "/verifiable-credential/" +  this.state.issuerDid + "/credential-offer-uri?type="+ supportedCredential.type+"&format="+supportedCredential.format;
    const token = keycloakContext.token

    var options = {  
      method: 'GET',
      headers: {
        'Authorization': 'Bearer ' + token
      }
    }
    fetch(vcIssue, options)
      .then(response => this.handleOfferResponse(response, path))
  }
  
  private handleOfferResponse(response: Response, _: String) {
    response.json()
      .then((offerURI: CredentialOfferURI) => {
        if (response.status !== 200) {
          console.log("Did not receive an offer.");
          ContentAlert.warning(response.status + ":" + response.statusText);
        } else {
          const credUrl = offerURI.issuer + "/credential-offer?credential_offer_uri="
              + encodeURIComponent(offerURI.issuer + "/credential-offer/" + offerURI.nonce)
          console.log(credUrl)
          this.setState({ ...{
            offerUrl: credUrl,
            vcQRVisible: false,
            offerQRVisible: true,
            urlQRVisible: false}});
        }
      })    
  }

  public render(): React.ReactNode {
        
  const { isOpen, selected, dropdownItems, isDisabled, offerQRVisible, offerUrl} = this.state;

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
                  onClick={() => this.requestVCOffer("")}
                  isDisabled={isDisabled}>
                  Initiate Credential-Issuance(OIDC4CI)
                </Button>
              </ActionListItem>
              <ActionListItem>
                <Button
                  onClick={() => this.requestVCOffer("/alt")}
                  isDisabled={isDisabled}>
                  Initiate Credential-Issuance(OIDC4CI) - Alternative Meta-Data
                </Button>
              </ActionListItem>
            </ActionList>
          </ListItem>           
          
          <ListItem>
          <ActionList>
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
        </List>       
      </PageSection>   
    </ContentPage>
    );
  }
}
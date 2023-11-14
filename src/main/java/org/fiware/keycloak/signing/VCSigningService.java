package org.fiware.keycloak.signing;

import com.danubetech.verifiablecredentials.VerifiableCredential;

public interface VCSigningService<T> {

	T signCredential(VerifiableCredential verifiableCredential);
}

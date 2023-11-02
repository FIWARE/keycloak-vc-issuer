package org.fiware.keycloak;

import com.danubetech.verifiablecredentials.VerifiableCredential;

public interface VCSigningService<T> {

	T signCredential(VerifiableCredential verifiableCredential);
}

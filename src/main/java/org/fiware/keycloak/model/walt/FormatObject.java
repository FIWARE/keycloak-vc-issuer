package org.fiware.keycloak.model.walt;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Setter
public class FormatObject {
	private List<String> types;
}

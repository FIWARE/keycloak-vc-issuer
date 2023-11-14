package org.fiware.keycloak.mappers;

import org.keycloak.models.ProtocolMapperModel;

public class SIOP2MapperFactory {

	private SIOP2MapperFactory() {
		// prevent instantiation
	}

	public static SIOP2Mapper createSiop2Mapper(ProtocolMapperModel mapperModel) {
		return switch (mapperModel.getProtocolMapper()) {
			case SIOP2TargetRoleMapper.MAPPER_ID -> new SIOP2TargetRoleMapper(mapperModel);
			case SIOP2SubjectIdMapper.MAPPER_ID -> new SIOP2SubjectIdMapper(mapperModel);
			case SIOP2UserAttributeMapper.MAPPER_ID -> new SIOP2UserAttributeMapper(mapperModel);
			case SIOP2StaticClaimMapper.MAPPER_ID -> new SIOP2StaticClaimMapper(mapperModel);
			default -> throw new SIOP2MapperException(
					String.format("No mapper with id %s exists.", mapperModel.getProtocolMapper()));
		};
	}
}

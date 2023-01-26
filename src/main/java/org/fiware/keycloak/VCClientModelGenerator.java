package org.fiware.keycloak;

import lombok.RequiredArgsConstructor;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.protocol.ProtocolMapper;

import java.beans.Introspector;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class VCClientModelGenerator {

	VCClientModel createVCModel(RealmModel realm, Map<String, String> clientData) {
		return createVCModel(realm, modelAttributes -> {
			modelAttributes.put("publicClient", false);
			modelAttributes.put("directAccessGrantsEnabled", false);
			modelAttributes.put("standardFlowEnabled", false);
			modelAttributes.put("supportedVCType", clientData.get("supportedVCType"));
			modelAttributes.put("expiryInMin", clientData.get("expiryInMin"));

			modelAttributes.putAll(clientData);

		});
	}

	VCClientModel createVCModel(RealmModel realm, Consumer<Map<String, Object>> adjuster) {

		Map<String, Object> modelAttributes = new HashMap<>();

		modelAttributes.put("realmName", realm.getName());
		modelAttributes.put("realm", realm);
		modelAttributes.put("protocol", "SIOP-2");
		modelAttributes.put("protocolMappers", Collections.<String>emptySet());
		modelAttributes.put("attributes", new HashMap<String, String>());
		modelAttributes.put("authFlowBindings", new HashMap<String, String>());
		modelAttributes.put("authenticationFlowBindingOverrides", new HashMap<>());
		modelAttributes.put("clientAuthenticatorType", "verifiable-credentials");
		modelAttributes.put("redirectUris", Collections.<String>emptySet());
		modelAttributes.put("webOrigins", Collections.<String>emptySet());
		modelAttributes.put("scopeMappings", Collections.<RoleModel>emptySet());
		modelAttributes.put("defaultRoles", Collections.emptyList());
		modelAttributes.put("serviceAccountsEnabled", true);

		adjuster.accept(modelAttributes);

		ClassLoader cl = VCClientModel.class.getClassLoader();
		Class[] ifaces = { VCClientModel.class };
		VirtualClientModelStorageHandler handler = new VirtualClientModelStorageHandler(realm, modelAttributes);

		return VCClientModel.class.cast(Proxy.newProxyInstance(cl, ifaces, handler));
	}

	@RequiredArgsConstructor
	static class VirtualClientModelStorageHandler implements InvocationHandler {

		private final RealmModel realm;

		private final Map<String, Object> modelAttributes;

		private static final Method OBJECT_EQUALS =
				getObjectMethod("equals", Object.class);

		private static final Method OBJECT_HASHCODE =
				getObjectMethod("hashCode");

		private static final Method OBJECT_TOSTRING =
				getObjectMethod("toString");

		/**
		 * Filter client scope to the set of explicitly allowed client
		 *
		 * @param defaultScope
		 * @param filterByProtocol
		 * @return
		 */
		public Map<String, ClientScopeModel> getClientScopes(boolean defaultScope, boolean filterByProtocol) {

			List<String> defaultScopeNames = (List<String>) modelAttributes.get("defaultScopes");
			List<String> optionalScopeNames = (List<String>) modelAttributes.get("optionalScopes");

			Stream<ClientScopeModel> allClientScopes = Stream.concat(realm.getDefaultClientScopesStream(defaultScope),
					realm.getDefaultClientScopesStream(!defaultScope));

			List<ClientScopeModel> scopeModels = allClientScopes.filter(
					scope -> (defaultScope ? defaultScopeNames : optionalScopeNames).contains(scope.getName())).collect(
					Collectors.toList());
			Map<String, ClientScopeModel> scopes = new HashMap<>();
			for (ClientScopeModel scopeModel : scopeModels) {
				scopes.put(scopeModel.getName(), scopeModel);
			}

			return scopes;
		}

		public ClientScopeModel getDynamicClientScope(String scope) {
			return null;
		}

		@Override
		public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {

			String methodName = method.getName();

			if (OBJECT_EQUALS.equals(method)) {
				return equalsInternal(proxy, args[0]);
			}

			if (OBJECT_HASHCODE.equals(method)) {
				return modelAttributes.hashCode();
			}

			if (OBJECT_TOSTRING.equals(method)) {
				return "VCClientModel(clientId=" + modelAttributes.get("clientId") + ")";
			}

			if (methodName.equals("getClientScopes") && method.getParameterCount() == 2) {
				return getClientScopes((Boolean) args[0], (Boolean) args[1]);
			}

			if (methodName.equals("getDynamicClientScope") && method.getParameterCount() == 1) {
				return getDynamicClientScope((String) args[0]);
			}

			if (methodName.equals("getProtocolMapperByName") && method.getParameterCount() == 2) {
				return getProtocolMapperByName((String) args[0], (String) args[1]);
			}

			if (methodName.equals("getScopeMappingsStream") && method.getParameterCount() == 0) {
				return Stream.empty();
			}

			if (methodName.equals("getProtocolMappersStream") && method.getParameterCount() == 0) {
				return Stream.empty();
			}

			if (methodName.equals("getDefaultRolesStream") && method.getParameterCount() == 0) {
				return Stream.empty();
			}

			if (methodName.equals("getRegisteredNodes") && method.getParameterCount() == 0) {
				return Collections.emptyMap();
			}

			if (methodName.startsWith("get") && method.getParameterCount() == 0) {
				String attribute = Introspector.decapitalize(methodName.substring(3));
				if (modelAttributes.containsKey(attribute)) {
					return modelAttributes.get(attribute);
				}
			}

			if (methodName.startsWith("is") && method.getParameterCount() == 0) {
				String attribute = Introspector.decapitalize(methodName.substring(2));
				if (modelAttributes.containsKey(attribute)) {
					return modelAttributes.get(attribute);
				}
			}

			if (methodName.startsWith("set") && method.getParameterCount() == 1) {
				return modelAttributes.put(Introspector.decapitalize(methodName.substring(3)), args[0]);
			}

			if (Boolean.class.equals(method.getReturnType()) || boolean.class.equals(method.getReturnType())) {
				return false;
			}

			if (Integer.class.equals(method.getReturnType()) || int.class.equals(method.getReturnType())) {
				return 0;
			}

			return null;
		}

		private ProtocolMapper getProtocolMapperByName(String protocol, String name) {
			return null;
		}

		private boolean equalsInternal(Object me, Object other) {
			if (other == null) {
				return false;
			}
			if (other.getClass() != me.getClass()) {
				return false;
			}
			InvocationHandler handler = Proxy.getInvocationHandler(other);
			if (!(handler instanceof VirtualClientModelStorageHandler)) {
				return false;
			}
			return ((VirtualClientModelStorageHandler) handler).modelAttributes.equals(modelAttributes);
		}

		private static Method getObjectMethod(String name, Class... types) {
			try {
				return Object.class.getMethod(name, types);
			} catch (NoSuchMethodException e) {
				throw new IllegalArgumentException(e);
			}
		}
	}
}


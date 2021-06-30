/*
 * Copyright 2020-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.server.authorization.web.authentication;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2EndpointUtils.throwError;

/**
 * Attempts to extract an Access Token Request from {@link HttpServletRequest} for the OAuth 2.0 Authorization Code Grant
 * and then converts it to an {@link OAuth2AuthorizationCodeAuthenticationToken} used for authenticating the authorization grant.
 *
 * @author Joe Grandja
 * @since 0.1.2
 * @see AuthenticationConverter
 * @see OAuth2AuthorizationCodeAuthenticationToken
 * @see OAuth2TokenEndpointFilter
 */
public final class OAuth2DeviceCodeAuthenticationConverter implements AuthenticationConverter {

	public static final AuthorizationGrantType DEVICE_CODE = new AuthorizationGrantType("urn:ietf:params:oauth:grant-type:device_code");

	@Nullable
	@Override
	public Authentication convert(HttpServletRequest request) {
		// grant_type (REQUIRED)
		String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
		// TODO add to enum object
		if (!DEVICE_CODE.getValue().equals(grantType)) {
			return null;
		}

		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

		// device_code (REQUIRED)
		String deviceCode = parameters.getFirst("device_code");// TODO proper num class
		if (!StringUtils.hasText(deviceCode) ||
				parameters.get("device_code").size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, "device_code");
		}

		// @formatter:off
		Map<String, Object> additionalParameters = parameters
				.entrySet()
				.stream()
				.filter(e -> !e.getKey().equals(OAuth2ParameterNames.GRANT_TYPE) &&
						!e.getKey().equals(OAuth2ParameterNames.CLIENT_ID) &&
						!e.getKey().equals("device_code")) // TODO
				.collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().get(0)));
        // @formatter:on

		return new OAuth2DeviceCodeAuthenticationToken(deviceCode, clientPrincipal,  additionalParameters);
	}

}

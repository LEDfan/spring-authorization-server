/*
 * Copyright 2020 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.web;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2PublicClientWithoutPKCEAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;

import static org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2DeviceCodeAuthenticationConverter.DEVICE_CODE;

/**
 * Attempts to extract the parameters from {@link HttpServletRequest}
 * used for authenticating public clients without using Proof Key for Code Exchange (PKCE).
 * Used in the Device Code flow.
 *
 * @author Joe Grandja
 * @since 0.0.2
 * @see AuthenticationConverter
 * @see OAuth2ClientAuthenticationToken
 * @see OAuth2ClientAuthenticationFilter
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7636">Proof Key for Code Exchange by OAuth Public Clients</a>
 */
public class PublicClientAuthenticationConverterWithoutPKCE implements AuthenticationConverter {

	private final RequestMatcher deviceCodeRequestMatcher;


	public PublicClientAuthenticationConverterWithoutPKCE(RequestMatcher deviceCodeRequestMatcher) {
		this.deviceCodeRequestMatcher = deviceCodeRequestMatcher;
	}

	public PublicClientAuthenticationConverterWithoutPKCE() {
		this.deviceCodeRequestMatcher = null;
	}

	@Override
	public Authentication convert(HttpServletRequest request) {
		if (!isDeviceCodeRequest(request) && !isDeviceCodeTokenRequest(request)) {
			// not a device_code request
			return null;
		}

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

		// client_id (REQUIRED for public clients)
		String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
		if (!StringUtils.hasText(clientId) ||
				parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
		}

		parameters.remove(OAuth2ParameterNames.CLIENT_ID);

		return new OAuth2PublicClientWithoutPKCEAuthenticationToken(clientId,
				new HashMap<>(parameters.toSingleValueMap()));
	}

	private boolean isDeviceCodeTokenRequest(HttpServletRequest request) {
		return DEVICE_CODE.getValue().equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE)) &&
				request.getParameter("device_code") != null;
	}

	private boolean isDeviceCodeRequest(HttpServletRequest request) {
		return deviceCodeRequestMatcher != null && deviceCodeRequestMatcher.matches(request);
	}
}

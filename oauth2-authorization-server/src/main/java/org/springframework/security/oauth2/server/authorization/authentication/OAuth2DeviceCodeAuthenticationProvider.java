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
package org.springframework.security.oauth2.server.authorization.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2DeviceCode;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import static org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationProviderUtils.getAuthenticatedClientElseThrowInvalidClient;
import static org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2DeviceCodeAuthenticationConverter.DEVICE_CODE;


/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Authorization Code Grant.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @since 0.0.1
 * @see OAuth2AuthorizationCodeAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see OAuth2AuthorizationService
 * @see JwtEncoder
 * @see OAuth2TokenCustomizer
 * @see JwtEncodingContext
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request</a>
 */
public class OAuth2DeviceCodeAuthenticationProvider extends BaseAuthorizationCodeAuthenticationProvider {
	private static final OAuth2TokenType DEVICE_CODE_TOKEN_TYPE = new OAuth2TokenType("device_code"); // TODO

	/**
	 * Constructs an {@code OAuth2DeviceCodeAuthenticationProvider} using the provided parameters.
	 *
	 * @param authorizationService the authorization service
	 * @param jwtEncoder the jwt encoder
	 */
	public OAuth2DeviceCodeAuthenticationProvider(OAuth2AuthorizationService authorizationService, JwtEncoder jwtEncoder) {
		super(authorizationService, jwtEncoder);
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2DeviceCodeAuthenticationToken deviceCodeAuthentication = (OAuth2DeviceCodeAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(deviceCodeAuthentication);

		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		OAuth2Authorization authorization = this.authorizationService.findByToken(deviceCodeAuthentication.getDeviceCode(), DEVICE_CODE_TOKEN_TYPE);
		if (authorization == null) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT));
		}
		OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode = authorization.getToken(OAuth2DeviceCode.class);

		return authenticate(authentication, authorization, registeredClient, clientPrincipal, DEVICE_CODE, deviceCode);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2DeviceCodeAuthenticationToken.class.isAssignableFrom(authentication);
	}

}

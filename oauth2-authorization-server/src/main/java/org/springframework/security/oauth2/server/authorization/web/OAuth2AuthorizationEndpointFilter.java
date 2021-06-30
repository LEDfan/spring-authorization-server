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
package org.springframework.security.oauth2.server.authorization.web;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@code Filter} for the OAuth 2.0 Authorization Code Grant,
 * which handles the processing of the OAuth 2.0 Authorization Request.
 *
 * @author Joe Grandja
 * @author Paurav Munshi
 * @author Daniel Garnier-Moiroux
 * @author Anoop Garlapati
 * @since 0.0.1
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2AuthorizationConsentService
 * @see OAuth2Authorization
 * @see OAuth2AuthorizationConsent
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Request</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.2">Section 4.1.2 Authorization Response</a>
 */
public class OAuth2AuthorizationEndpointFilter extends BaseAuthorizationEndpointFilter {
	/**
	 * The default endpoint {@code URI} for authorization requests.
	 */
	public static final String DEFAULT_AUTHORIZATION_ENDPOINT_URI = "/oauth2/authorize";

	protected static final Pattern LOOPBACK_ADDRESS_PATTERN =
			Pattern.compile("^127(?:\\.[0-9]+){0,2}\\.[0-9]+$|^\\[(?:0*:)*?:?0*1]$");

	/**
	 * Constructs an {@code OAuth2AuthorizationEndpointFilter} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @deprecated use
	 * {@link #OAuth2AuthorizationEndpointFilter(RegisteredClientRepository, OAuth2AuthorizationService, OAuth2AuthorizationConsentService)}
	 * instead.
	 */
	@Deprecated
	public OAuth2AuthorizationEndpointFilter(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService) {
		this(registeredClientRepository, authorizationService, new InMemoryOAuth2AuthorizationConsentService());
	}

	/**
	 * Constructs an {@code OAuth2AuthorizationEndpointFilter} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param authorizationEndpointUri the endpoint {@code URI} for authorization requests
	 * @deprecated use
	 * {@link #OAuth2AuthorizationEndpointFilter(RegisteredClientRepository, OAuth2AuthorizationService, OAuth2AuthorizationConsentService, String)}
	 * instead.
	 */
	@Deprecated
	public OAuth2AuthorizationEndpointFilter(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService, String authorizationEndpointUri) {
		super(registeredClientRepository, authorizationService, new InMemoryOAuth2AuthorizationConsentService(), authorizationEndpointUri);
	}

	/**
	 * Constructs an {@code OAuth2AuthorizationEndpointFilter} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param authorizationConsentService the authorization consent service
	 */
	public OAuth2AuthorizationEndpointFilter(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationService authorizationService, OAuth2AuthorizationConsentService authorizationConsentService) {
		super(registeredClientRepository, authorizationService, authorizationConsentService, DEFAULT_AUTHORIZATION_ENDPOINT_URI);
	}

	/**
	 * Constructs an {@code OAuth2AuthorizationEndpointFilter} using the provided parameters.
	 *
	 * @param registeredClientRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 * @param authorizationConsentService the authorization consent service
	 * @param authorizationEndpointUri the endpoint {@code URI} for authorization requests
	 */
	public OAuth2AuthorizationEndpointFilter(RegisteredClientRepository registeredClientRepository, OAuth2AuthorizationService authorizationService, OAuth2AuthorizationConsentService authorizationConsentService, String authorizationEndpointUri) {
		super(registeredClientRepository, authorizationService, authorizationConsentService, authorizationEndpointUri);
	}

	@Override
	protected AbstractOAuth2Token createAuthorizationCode(MultiValueMap<String, String> authorizationRequestContext) {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(5, ChronoUnit.MINUTES);		// TODO Allow configuration for authorization code time-to-live
		return new OAuth2AuthorizationCode(this.codeGenerator.generateKey(), issuedAt, expiresAt);
	}

	private static Set<String> extractScopes(MultiValueMap<String, String> parameters) {
		String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
		return StringUtils.hasText(scope) ?
				new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " "))) :
				Collections.emptySet();
	}

	@Override
	protected OAuth2AuthorizationRequestContext createAndValidateAuthorizationRequest(HttpServletRequest request) {
		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

		OAuth2AuthorizationRequestContext authorizationRequestContext =
				new OAuth2AuthorizationRequestContext(
						request.getRequestURL().toString(),
						parameters.getFirst(OAuth2ParameterNames.CLIENT_ID),
						extractScopes(parameters),
						parameters
						);

		// ---------------
		// Validate the request to ensure all required parameters are present and valid
		// ---------------

		// client_id (REQUIRED)
		if (!StringUtils.hasText(authorizationRequestContext.getClientId()) ||
				authorizationRequestContext.getParameters().get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
			authorizationRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID));
			return authorizationRequestContext;
		}

		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(
				authorizationRequestContext.getClientId());
		if (registeredClient == null) {
			authorizationRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID));
			return authorizationRequestContext;
		} else if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
			authorizationRequestContext.setError(
					createError(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, OAuth2ParameterNames.CLIENT_ID));
			return authorizationRequestContext;
		}
		authorizationRequestContext.setRegisteredClient(registeredClient);

		// redirect_uri (OPTIONAL)
		if (StringUtils.hasText(authorizationRequestContext.getRedirectUri())) {
			if (!isValidRedirectUri(authorizationRequestContext.getRedirectUri(), registeredClient) ||
					authorizationRequestContext.getParameters().get(OAuth2ParameterNames.REDIRECT_URI).size() != 1) {
				authorizationRequestContext.setError(
						createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI));
				return authorizationRequestContext;
			}
		} else if (authorizationRequestContext.isAuthenticationRequest() ||		// redirect_uri is REQUIRED for OpenID Connect
				registeredClient.getRedirectUris().size() != 1) {
			authorizationRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI));
			return authorizationRequestContext;
		}
		authorizationRequestContext.setRedirectOnError(true);

		// response_type (REQUIRED)
		if (!StringUtils.hasText(authorizationRequestContext.getResponseType()) ||
				authorizationRequestContext.getParameters().get(OAuth2ParameterNames.RESPONSE_TYPE).size() != 1) {
			authorizationRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.RESPONSE_TYPE));
			return authorizationRequestContext;
		} else if (!authorizationRequestContext.getResponseType().equals(OAuth2AuthorizationResponseType.CODE.getValue())) {
			authorizationRequestContext.setError(
					createError(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, OAuth2ParameterNames.RESPONSE_TYPE));
			return authorizationRequestContext;
		}

		// scope (OPTIONAL)
		Set<String> requestedScopes = authorizationRequestContext.getScopes();
		Set<String> allowedScopes = registeredClient.getScopes();
		if (!requestedScopes.isEmpty() && !allowedScopes.containsAll(requestedScopes)) {
			authorizationRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE));
			return authorizationRequestContext;
		}

		// code_challenge (REQUIRED for public clients) - RFC 7636 (PKCE)
		String codeChallenge = authorizationRequestContext.getParameters().getFirst(PkceParameterNames.CODE_CHALLENGE);
		if (StringUtils.hasText(codeChallenge)) {
			if (authorizationRequestContext.getParameters().get(PkceParameterNames.CODE_CHALLENGE).size() != 1) {
				authorizationRequestContext.setError(
						createError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE, PKCE_ERROR_URI));
				return authorizationRequestContext;
			}

			String codeChallengeMethod = authorizationRequestContext.getParameters().getFirst(PkceParameterNames.CODE_CHALLENGE_METHOD);
			if (StringUtils.hasText(codeChallengeMethod)) {
				if (authorizationRequestContext.getParameters().get(PkceParameterNames.CODE_CHALLENGE_METHOD).size() != 1 ||
						(!"S256".equals(codeChallengeMethod) && !"plain".equals(codeChallengeMethod))) {
					authorizationRequestContext.setError(
							createError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE_METHOD, PKCE_ERROR_URI));
					return authorizationRequestContext;
				}
			}
		} else if (registeredClient.getClientSettings().requireProofKey()) {
			authorizationRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE, PKCE_ERROR_URI));
			return authorizationRequestContext;
		}
		return authorizationRequestContext;
	}

	@Override
	protected void sendAuthorizationResponse(HttpServletRequest request, HttpServletResponse response, String redirectUri, AbstractOAuth2Token authorizationCode, String state) throws IOException {

		UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUriString(redirectUri)
				.queryParam(OAuth2ParameterNames.CODE, authorizationCode.getTokenValue());
		if (StringUtils.hasText(state)) {
			uriBuilder.queryParam(OAuth2ParameterNames.STATE, state);
		}
		this.redirectStrategy.sendRedirect(request, response, uriBuilder.toUriString());
	}

	@Override
	protected void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
			String redirectUri, OAuth2Error error, String state) throws IOException {

		UriComponentsBuilder uriBuilder = UriComponentsBuilder
				.fromUriString(redirectUri)
				.queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());
		if (StringUtils.hasText(error.getDescription())) {
			uriBuilder.queryParam(OAuth2ParameterNames.ERROR_DESCRIPTION, error.getDescription());
		}
		if (StringUtils.hasText(error.getUri())) {
			uriBuilder.queryParam(OAuth2ParameterNames.ERROR_URI, error.getUri());
		}
		if (StringUtils.hasText(state)) {
			uriBuilder.queryParam(OAuth2ParameterNames.STATE, state);
		}
		this.redirectStrategy.sendRedirect(request, response, uriBuilder.toUriString());
	}

	@Override
	protected void sendErrorResponse(HttpServletResponse response, OAuth2Error error) throws IOException {
		// TODO Send default html error response
		response.sendError(HttpStatus.BAD_REQUEST.value(), error.toString());
	}

	private static boolean isValidRedirectUri(String requestedRedirectUri, RegisteredClient registeredClient) {
		UriComponents requestedRedirect;
		try {
			requestedRedirect = UriComponentsBuilder.fromUriString(requestedRedirectUri).build();
			if (requestedRedirect.getFragment() != null) {
				return false;
			}
		} catch (Exception ex) {
			return false;
		}

		String requestedRedirectHost = requestedRedirect.getHost();
		if (requestedRedirectHost == null || requestedRedirectHost.equals("localhost")) {
			// As per https://tools.ietf.org/html/draft-ietf-oauth-v2-1-01#section-9.7.1
			// While redirect URIs using localhost (i.e.,
			// "http://localhost:{port}/{path}") function similarly to loopback IP
			// redirects described in Section 10.3.3, the use of "localhost" is NOT RECOMMENDED.
			return false;
		}
		if (!LOOPBACK_ADDRESS_PATTERN.matcher(requestedRedirectHost).matches()) {
			// As per https://tools.ietf.org/html/draft-ietf-oauth-v2-1-01#section-9.7
			// When comparing client redirect URIs against pre-registered URIs,
			// authorization servers MUST utilize exact string matching.
			return registeredClient.getRedirectUris().contains(requestedRedirectUri);
		}

		// As per https://tools.ietf.org/html/draft-ietf-oauth-v2-1-01#section-10.3.3
		// The authorization server MUST allow any port to be specified at the
		// time of the request for loopback IP redirect URIs, to accommodate
		// clients that obtain an available ephemeral port from the operating
		// system at the time of the request.
		for (String registeredRedirectUri : registeredClient.getRedirectUris()) {
			UriComponentsBuilder registeredRedirect = UriComponentsBuilder.fromUriString(registeredRedirectUri);
			registeredRedirect.port(requestedRedirect.getPort());
			if (registeredRedirect.build().toString().equals(requestedRedirect.toString())) {
				return true;
			}
		}
		return false;
	}

}

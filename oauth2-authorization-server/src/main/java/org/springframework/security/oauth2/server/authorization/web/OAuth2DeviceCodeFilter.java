package org.springframework.security.oauth2.server.authorization.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2DeviceCode;
import org.springframework.security.oauth2.server.authorization.OAuth2DeviceCodeService;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class OAuth2DeviceCodeFilter extends OncePerRequestFilter {

	private final RequestMatcher requestMatcher;

	private final AuthenticationManager authenticationManager;

	private final AuthenticationConverter authenticationConverter;

	private final OAuth2DeviceCodeService deviceCodeService;

	private final StringKeyGenerator deviceCodeGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

	public OAuth2DeviceCodeFilter(AuthenticationManager authenticationManager, OAuth2DeviceCodeService deviceCodeService, RequestMatcher requestMatcher) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		Assert.notNull(deviceCodeService, "deviceCodeService cannot be null");
		this.authenticationManager = authenticationManager;
		this.deviceCodeService = deviceCodeService;
		this.requestMatcher = requestMatcher;
		this.authenticationConverter = new PublicClientAuthenticationConverterWithoutPKCE(requestMatcher);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		if (this.requestMatcher.matches(request)) {
			// validate client_id
			Authentication authenticationRequest = this.authenticationConverter.convert(request);
			if (authenticationRequest != null) {
				Authentication authenticationResult = this.authenticationManager.authenticate(authenticationRequest);

				if (authenticationResult != null && authenticationResult.isAuthenticated()) {

					Instant issuedAt = Instant.now();
					Instant expiresAt = issuedAt.plus(5, ChronoUnit.MINUTES); // TODO Allow configuration for authorization code time-to-live

					String scope = request.getParameter(OAuth2ParameterNames.SCOPE);
					Set<String> scopes = StringUtils.hasText(scope) ? new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " "))) : Collections.emptySet();

					OAuth2DeviceCode deviceCode = new OAuth2DeviceCode(
							authenticationResult.getPrincipal().toString(),
							generateUserCode(),
							deviceCodeGenerator.generateKey(),
							issuedAt,
							expiresAt,
							scopes);

					deviceCodeService.save(deviceCode);

					DeviceCodeResponse deviceCodeResponse = new DeviceCodeResponse(
							deviceCode.getTokenValue(),
							"http://auth-server:9000/device",
							deviceCode.getUserCode(),
							(long) (5 * 60),
							5);

					ObjectMapper objectMapper = new ObjectMapper();
					objectMapper.setPropertyNamingStrategy(PropertyNamingStrategy.SNAKE_CASE);

					response.setContentType("application/json");

					objectMapper.writeValue(response.getWriter(), deviceCodeResponse);
					return;
				}
			}
		}
		filterChain.doFilter(request, response);
	}

	private String generateUserCode() {
		int leftLimit = 65; // letter 'a'
		int rightLimit = 90; // letter 'z'
		int targetStringLength = 10;
		SecureRandom random = new SecureRandom();

		return random.ints(leftLimit, rightLimit + 1)
				.limit(targetStringLength)
				.collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
				.toString();
	}

	public static class DeviceCodeResponse {

		private final String deviceCode;
		private final String verificationUri;
		private final String userCode;
		private final Long expiresIN;
		private final Integer interval;


		public DeviceCodeResponse(String deviceCode, String verificationUri, String userCode, Long expiresIn, Integer interval) {
			this.deviceCode = deviceCode;
			this.verificationUri = verificationUri;
			this.userCode = userCode;
			this.expiresIN = expiresIn;
			this.interval = interval;
		}

		public String getDeviceCode() {
			return deviceCode;
		}

		public String getUserCode() {
			return userCode;
		}

		public String getVerificationUri() {
			return verificationUri;
		}

		public Integer getInterval() {
			return interval;
		}

		public Long getExpiresIN() {
			return expiresIN;
		}
	}

}

package org.springframework.security.oauth2.server.authorization.web;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2DeviceCode;
import org.springframework.security.oauth2.server.authorization.OAuth2DeviceCodeService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashSet;
import java.util.Objects;


public class OAuth2DeviceAuthorizationFilter extends BaseAuthorizationEndpointFilter {

	private final OAuth2DeviceCodeService deviceCodeService;

	private final RequestMatcher userCodeFormMatcher;

	public OAuth2DeviceAuthorizationFilter(RegisteredClientRepository registeredClientRepository,
			OAuth2AuthorizationConsentService authorizationConsentService,
			OAuth2AuthorizationService authorizationService,
			OAuth2DeviceCodeService deviceCodeService,
			String authorizationEndpointUri
	) {
		super(registeredClientRepository, authorizationService, authorizationConsentService, authorizationEndpointUri);
		this.deviceCodeService = deviceCodeService;

		this.userCodeFormMatcher = new AntPathRequestMatcher(authorizationEndpointUri, HttpMethod.GET.name());

		this.authorizationRequestMatcher = new AndRequestMatcher(
				new AntPathRequestMatcher(authorizationEndpointUri, "POST"),
				request -> Objects.equals(request.getParameter("user_code_action"), "submit"));
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (this.userCodeFormMatcher.matches(request)) {
			processUserCodeFormRequest(request, response, filterChain);
		} else {
			super.doFilterInternal(request, response, filterChain);
		}
	}

	private void processUserCodeFormRequest(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
		Authentication principal = SecurityContextHolder.getContext().getAuthentication();
		if (!isPrincipalAuthenticated(principal)) {
			// Pass through the chain with the expectation that the authentication process
			// will commence via AuthenticationEntryPoint
			filterChain.doFilter(request, response);
			return;
		}

		// TODO support custom page
		UserCodeFormPage.displayPage(request, response);
	}

	@Override
	protected AbstractOAuth2Token createAuthorizationCode(MultiValueMap<String, String> parameters) {
		String userCode = parameters.getFirst("user_code");
		OAuth2DeviceCode deviceCode = deviceCodeService.findByUserCode(userCode);

		deviceCodeService.remove(deviceCode);

		return deviceCode;
	}

	@Override
	protected void sendAuthorizationResponse(HttpServletRequest request, HttpServletResponse response, String redirectUri, AbstractOAuth2Token authorizationCode, String state) throws IOException {
		// TODO support custom page
		SuccessPage.displayPage(request, response);
	}

	@Override
	protected void sendErrorResponse(HttpServletRequest request, HttpServletResponse response, String redirectUri, OAuth2Error error, String state) throws IOException {
		// Device Code flow never redirects back on error
		sendErrorResponse(response, error);
	}

	@Override
	protected void sendErrorResponse(HttpServletResponse response, OAuth2Error error) throws IOException {
		response.sendError(HttpStatus.BAD_REQUEST.value(), error.toString());
	}

	@Override
	protected OAuth2AuthorizationRequestContext createAndValidateAuthorizationRequest(HttpServletRequest request) {
		// ---------------
		// Validate the request to ensure all required parameters are present and valid
		// ---------------

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

		// user_code (REQUIRED)
		if (!StringUtils.hasText(parameters.getFirst("user_code")) || parameters.get("user_code").size() != 1) {
			OAuth2AuthorizationRequestContext authorizationRequestContext =
					new OAuth2AuthorizationRequestContext(
							request.getRequestURL().toString(),
							null,
							new HashSet<>(),
							parameters
					);

			authorizationRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_REQUEST, "user_code"));

			return authorizationRequestContext;
		}

		String userCode = parameters.getFirst("user_code");
		OAuth2DeviceCode deviceCode = deviceCodeService.findByUserCode(userCode);

		if (deviceCode == null || deviceCode.getExpiresAt() == null && !Instant.now().isAfter(deviceCode.getExpiresAt())) {
			if (deviceCode != null) {
				deviceCodeService.remove(deviceCode);
			}
			OAuth2AuthorizationRequestContext authorizationRequestContext =
					new OAuth2AuthorizationRequestContext(
							request.getRequestURL().toString(),
							null,
							new HashSet<>(),
							parameters
					);

			authorizationRequestContext.setError(
					createError(OAuth2ErrorCodes.INVALID_REQUEST, "user_code"));

			return authorizationRequestContext;
		}

		// set scopes from the original (device) request
		OAuth2AuthorizationRequestContext authorizationRequestContext =
				new OAuth2AuthorizationRequestContext(
						request.getRequestURL().toString(),
						deviceCode.getClientId(),
						deviceCode.getRequestedScopes(),
						parameters
				);

		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(
				deviceCode.getClientId());
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

		return authorizationRequestContext;
	}

	private static class UserCodeFormPage {
		private static final MediaType TEXT_HTML_UTF8 = new MediaType("text", "html", StandardCharsets.UTF_8);

		private static void displayPage(HttpServletRequest request, HttpServletResponse response) throws IOException {
			String consentPage = generatePage(request);
			response.setContentType(TEXT_HTML_UTF8.toString());
			response.setContentLength(consentPage.getBytes(StandardCharsets.UTF_8).length);
			response.getWriter().write(consentPage);
		}

		private static String generatePage(HttpServletRequest request) {
			StringBuilder builder = new StringBuilder();

			CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());

			builder.append("<!DOCTYPE html>");
			builder.append("<html lang=\"en\">");
			builder.append("<head>");
			builder.append("    <meta charset=\"utf-8\">");
			builder.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">");
			builder.append("    <link rel=\"stylesheet\" href=\"https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css\" integrity=\"sha384-JcKb8q3iqJ61gNV9KGb8thSsNjpSL0n8PARn9HuZOnIxN0hoP+VmmDGMN5t9UJ0Z\" crossorigin=\"anonymous\">");
			builder.append("    <title>Consent required</title>");
			builder.append("</head>");
			builder.append("<body>");
			builder.append("<div class=\"container\">");
			builder.append("    <div class=\"py-5\">");
			builder.append("        <h1 class=\"text-center\">User code required</h1>");
			builder.append("    </div>");
			builder.append("    <div class=\"row\">");
			builder.append("        <div class=\"col text-center\">");
			builder.append("            <form method=\"post\" action=\"" + request.getRequestURI() + "\">");
			builder.append("				<input type=\"hidden\" name=\"" + csrfToken.getParameterName() + "\" value=\"" + csrfToken.getToken() + "\"/>");
			builder.append("                <div class=\"form-group form-check py-1\">");
			builder.append("                    <input class=\"form-check-input\" type=\"text\" name=\"user_code\" id=\"user_code\">");
			builder.append("                    <label class=\"form-check-label\" for=\"user_code\">User Code</label>");
			builder.append("                </div>");
			builder.append("                <div class=\"form-group pt-3\">");
			builder.append("                    <button class=\"btn btn-primary btn-lg\" type=\"submit\" name=\"user_code_action\" value=\"submit\" >Submit User Code</button>");
			builder.append("                </div>");
			builder.append("            </form>");
			builder.append("        </div>");
			builder.append("    </div>");
			builder.append("</div>");
			builder.append("</body>");
			builder.append("</html>");

			return builder.toString();
		}
	}

	private static class SuccessPage {
		private static final MediaType TEXT_HTML_UTF8 = new MediaType("text", "html", StandardCharsets.UTF_8);

		private static void displayPage(HttpServletRequest request, HttpServletResponse response) throws IOException {
			String consentPage = generatePage(request);
			response.setContentType(TEXT_HTML_UTF8.toString());
			response.setContentLength(consentPage.getBytes(StandardCharsets.UTF_8).length);
			response.getWriter().write(consentPage);
		}

		private static String generatePage(HttpServletRequest request) {
			StringBuilder builder = new StringBuilder();

			CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());

			builder.append("<!DOCTYPE html>");
			builder.append("<html lang=\"en\">");
			builder.append("<head>");
			builder.append("    <meta charset=\"utf-8\">");
			builder.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">");
			builder.append("    <link rel=\"stylesheet\" href=\"https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css\" integrity=\"sha384-JcKb8q3iqJ61gNV9KGb8thSsNjpSL0n8PARn9HuZOnIxN0hoP+VmmDGMN5t9UJ0Z\" crossorigin=\"anonymous\">");
			builder.append("    <title>Consent required</title>");
			builder.append("</head>");
			builder.append("<body>");
			builder.append("<div class=\"container\">");
			builder.append("    <div class=\"py-5\">");
			builder.append("        <h1 class=\"text-center\">Device activated!</h1>");
			builder.append("    </div>");
			builder.append("</div>");
			builder.append("</body>");
			builder.append("</html>");

			return builder.toString();
		}
	}

}

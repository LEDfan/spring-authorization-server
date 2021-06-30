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

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2DeviceCodeAuthenticationConverter;
import org.springframework.util.Assert;

import java.util.Map;


public class OAuth2DeviceCodeAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
	private final String deviceCode;

	/**
	 * Constructs an {@code OAuth2AuthorizationCodeAuthenticationToken} using the provided parameters.
	 *
	 * @param deviceCode the device code
	 * @param clientPrincipal the authenticated client principal
	 * @param additionalParameters the additional parameters
	 */
	public OAuth2DeviceCodeAuthenticationToken(String deviceCode, Authentication clientPrincipal, @Nullable Map<String, Object> additionalParameters) {
		super(OAuth2DeviceCodeAuthenticationConverter.DEVICE_CODE, clientPrincipal, additionalParameters);
		Assert.hasText(deviceCode, "device_code cannot be empty");
		this.deviceCode = deviceCode;
	}

	/**
	 * Returns the device code.
	 *
	 * @return the device code
	 */
	public String getDeviceCode() {
		return deviceCode;
	}

}

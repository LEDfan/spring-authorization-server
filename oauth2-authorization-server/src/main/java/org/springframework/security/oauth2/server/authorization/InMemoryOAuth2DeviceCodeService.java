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
package org.springframework.security.oauth2.server.authorization;

import org.springframework.util.Assert;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An {@link OAuth2AuthorizationService} that stores {@link OAuth2Authorization}'s in-memory.
 *
 * <p>
 * <b>NOTE:</b> This implementation should ONLY be used during development/testing.
 *
 * @author Krisztian Toth
 * @author Joe Grandja
 * @since 0.0.1
 * @see OAuth2AuthorizationService
 */
public final class InMemoryOAuth2DeviceCodeService implements OAuth2DeviceCodeService {
	private final Map<String, OAuth2DeviceCode> deviceCodes = new ConcurrentHashMap<>();

	@Override
	public void save(OAuth2DeviceCode deviceCode) {
		Assert.notNull(deviceCode, "deviceCode cannot be null");
		this.deviceCodes.put(deviceCode.getUserCode(), deviceCode);
	}

	@Override
	public void remove(OAuth2DeviceCode deviceCode) {
		Assert.notNull(deviceCode, "deviceCode cannot be null");
		this.deviceCodes.remove(deviceCode.getUserCode(), deviceCode);
	}

	@Override
	public OAuth2DeviceCode findByUserCode(String userCode) {
		Assert.hasText(userCode, "userCode cannot be empty");
		return this.deviceCodes.get(userCode);
	}

}

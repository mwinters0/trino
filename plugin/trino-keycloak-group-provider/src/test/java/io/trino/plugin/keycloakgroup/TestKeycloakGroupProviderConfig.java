/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.plugin.keycloakgroup;

import com.google.common.collect.ImmutableMap;
import io.airlift.units.Duration;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotEmpty;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Map;

import static io.airlift.configuration.testing.ConfigAssertions.assertFullMapping;
import static io.airlift.configuration.testing.ConfigAssertions.assertRecordedDefaults;
import static io.airlift.configuration.testing.ConfigAssertions.recordDefaults;
import static io.airlift.testing.ValidationAssertions.assertFailsValidation;
import static io.trino.plugin.keycloakgroup.KeycloakGroupProviderConfig.KeycloakGroupLookupErrorMode.FAIL;
import static io.trino.plugin.keycloakgroup.KeycloakGroupProviderConfig.KeycloakGroupLookupErrorMode.RETURN_EMPTY;
import static io.trino.plugin.keycloakgroup.KeycloakGroupProviderConfig.KeycloakGroupLookupErrorMode.RETURN_STALE;
import static io.trino.plugin.keycloakgroup.KeycloakGroupProviderConfig.KeycloakGroupNameField.NAME;
import static io.trino.plugin.keycloakgroup.KeycloakGroupProviderConfig.KeycloakGroupNameField.PATH;
import static io.trino.plugin.keycloakgroup.KeycloakGroupProviderConfig.KeycloakGroupSearchMode.ANCESTORS;
import static io.trino.plugin.keycloakgroup.KeycloakGroupProviderConfig.KeycloakGroupSearchMode.DIRECT;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

final class TestKeycloakGroupProviderConfig
{
    @Test
    void testDefaults()
    {
        assertRecordedDefaults(recordDefaults(KeycloakGroupProviderConfig.class)
                .setUrl(null)
                .setRealm(null)
                .setClientRealm(null)
                .setClientId(null)
                .setClientSecret(null)
                .setGroupNameField(NAME)
                .setGroupSearchMode(DIRECT)
                .setGroupLookupErrorMode(RETURN_EMPTY)
                .setCacheEnabled(true)
                .setCacheTtl(new Duration(5, SECONDS))
                .setCacheMaximumSize(1000));
    }

    @Test
    void testExplicitPropertyMappings()
    {
        Map<String, String> properties = ImmutableMap.<String, String>builder()
                .put("keycloak.url", "https://keycloak.example.com")
                .put("keycloak.realm", "trino")
                .put("keycloak.client-realm", "master")
                .put("keycloak.client-id", "trino-group-provider")
                .put("keycloak.client-secret", "secret")
                .put("keycloak.group-name-field", "PATH")
                .put("keycloak.group-search-mode", "ANCESTORS")
                .put("keycloak.group-lookup-error-mode", "FAIL")
                .put("keycloak.cache.enabled", "false")
                .put("keycloak.cache.ttl", "5m")
                .put("keycloak.cache.maximum-size", "500")
                .buildOrThrow();

        KeycloakGroupProviderConfig expected = new KeycloakGroupProviderConfig()
                .setUrl(URI.create("https://keycloak.example.com"))
                .setRealm("trino")
                .setClientRealm("master")
                .setClientId("trino-group-provider")
                .setClientSecret("secret")
                .setGroupNameField(PATH)
                .setGroupSearchMode(ANCESTORS)
                .setGroupLookupErrorMode(FAIL)
                .setCacheEnabled(false)
                .setCacheTtl(new Duration(5, MINUTES))
                .setCacheMaximumSize(500);

        assertFullMapping(properties, expected);
    }

    @Test
    void testValidation()
    {
        // A host name with no scheme parses as a URI with neither a scheme nor a host, so it
        // reaches the client as a relative reference rather than failing here.
        assertFailsValidation(
                validConfig().setUrl(URI.create("keycloak.example.com")),
                "urlValid",
                "keycloak.url must be an absolute URL including a scheme and a host, for example https://keycloak.example.com",
                AssertTrue.class);

        // An empty value is a misconfiguration rather than an unset property, and reaches Keycloak
        // as a URL with an empty path segment, which it answers with a 404 naming nothing useful.
        assertFailsValidation(validConfig().setRealm(""), "realm", "must not be empty", NotEmpty.class);
        assertFailsValidation(validConfig().setClientId(""), "clientId", "must not be empty", NotEmpty.class);
        assertFailsValidation(validConfig().setClientSecret(""), "clientSecret", "must not be empty", NotEmpty.class);

        assertFailsValidation(
                validConfig().setGroupSearchMode(ANCESTORS).setGroupNameField(NAME),
                "groupSearchModeValid",
                "keycloak.group-search-mode=ANCESTORS requires keycloak.group-name-field=PATH, because ancestor groups cannot be distinguished by name alone",
                AssertTrue.class);

        assertFailsValidation(
                validConfig().setGroupLookupErrorMode(RETURN_STALE).setCacheTtl(new Duration(0, SECONDS)),
                "groupLookupErrorModeValid",
                "keycloak.group-lookup-error-mode=RETURN_STALE requires keycloak.cache.enabled=true and a non-zero keycloak.cache.ttl, because there is nothing to report when the cache is disabled",
                AssertTrue.class);
        assertFailsValidation(
                validConfig().setGroupLookupErrorMode(RETURN_STALE).setCacheEnabled(false),
                "groupLookupErrorModeValid",
                "keycloak.group-lookup-error-mode=RETURN_STALE requires keycloak.cache.enabled=true and a non-zero keycloak.cache.ttl, because there is nothing to report when the cache is disabled",
                AssertTrue.class);
    }

    private static KeycloakGroupProviderConfig validConfig()
    {
        return new KeycloakGroupProviderConfig()
                .setUrl(URI.create("https://keycloak.example.com"))
                .setRealm("trino")
                .setClientId("trino-group-provider")
                .setClientSecret("secret");
    }
}

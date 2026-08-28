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

import io.airlift.configuration.Config;
import io.airlift.configuration.ConfigDescription;
import io.airlift.configuration.ConfigSecuritySensitive;
import io.airlift.units.Duration;
import io.airlift.units.MinDuration;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.net.URI;
import java.util.Optional;

import static io.trino.plugin.keycloakgroup.KeycloakGroupProviderConfig.KeycloakGroupLookupErrorMode.RETURN_EMPTY;
import static io.trino.plugin.keycloakgroup.KeycloakGroupProviderConfig.KeycloakGroupLookupErrorMode.RETURN_STALE;
import static io.trino.plugin.keycloakgroup.KeycloakGroupProviderConfig.KeycloakGroupNameField.NAME;
import static io.trino.plugin.keycloakgroup.KeycloakGroupProviderConfig.KeycloakGroupSearchMode.ANCESTORS;
import static io.trino.plugin.keycloakgroup.KeycloakGroupProviderConfig.KeycloakGroupSearchMode.DIRECT;
import static java.util.concurrent.TimeUnit.SECONDS;

public class KeycloakGroupProviderConfig
{
    public enum KeycloakGroupNameField
    {
        /**
         * The group's own name, without its ancestors. A member of {@code /engineering/backend}
         * is reported as {@code backend}.
         */
        NAME,
        /**
         * The group's full path. A member of {@code /engineering/backend} is reported as
         * {@code /engineering/backend}.
         */
        PATH,
    }

    public enum KeycloakGroupSearchMode
    {
        /**
         * Report only the groups a user is directly a member of. This is what Keycloak returns:
         * a member of {@code /engineering/backend} is not a member of {@code /engineering}.
         */
        DIRECT,
        /**
         * Additionally report every ancestor of each directly assigned group, so a member of
         * {@code /engineering/backend} is also reported as a member of {@code /engineering}.
         */
        ANCESTORS,
    }

    public enum KeycloakGroupLookupErrorMode
    {
        /**
         * Report no groups for the user.
         */
        RETURN_EMPTY,
        /**
         * Report the groups from the last successful lookup for the user, if there is one, and
         * no groups otherwise.
         */
        RETURN_STALE,
        /**
         * Fail the operation that requested the groups.
         */
        FAIL,
    }

    private URI url;
    private String realm;
    private String clientRealm;
    private String clientId;
    private String clientSecret;
    private KeycloakGroupNameField groupNameField = NAME;
    private KeycloakGroupSearchMode groupSearchMode = DIRECT;
    private KeycloakGroupLookupErrorMode groupLookupErrorMode = RETURN_EMPTY;
    private boolean cacheEnabled = true;
    private Duration cacheTtl = new Duration(5, SECONDS);
    private long cacheMaximumSize = 1000;

    @NotNull
    public URI getUrl()
    {
        return url;
    }

    @Config("keycloak.url")
    @ConfigDescription("Base URL of the Keycloak server, with or without a trailing slash. Example: https://keycloak.example.com")
    public KeycloakGroupProviderConfig setUrl(URI url)
    {
        this.url = url;
        return this;
    }

    @NotEmpty
    public String getRealm()
    {
        return realm;
    }

    @Config("keycloak.realm")
    @ConfigDescription("Realm whose users are looked up")
    public KeycloakGroupProviderConfig setRealm(String realm)
    {
        this.realm = realm;
        return this;
    }

    @NotNull
    public Optional<String> getClientRealm()
    {
        return Optional.ofNullable(clientRealm);
    }

    @Config("keycloak.client-realm")
    @ConfigDescription("Realm the service account client authenticates against. Defaults to keycloak.realm")
    public KeycloakGroupProviderConfig setClientRealm(String clientRealm)
    {
        this.clientRealm = clientRealm;
        return this;
    }

    @NotEmpty
    public String getClientId()
    {
        return clientId;
    }

    @Config("keycloak.client-id")
    @ConfigDescription("Client ID of the service account client used to call the Admin REST API")
    public KeycloakGroupProviderConfig setClientId(String clientId)
    {
        this.clientId = clientId;
        return this;
    }

    @NotEmpty
    public String getClientSecret()
    {
        return clientSecret;
    }

    @Config("keycloak.client-secret")
    @ConfigDescription("Client secret of the service account client")
    @ConfigSecuritySensitive
    public KeycloakGroupProviderConfig setClientSecret(String clientSecret)
    {
        this.clientSecret = clientSecret;
        return this;
    }

    @NotNull
    public KeycloakGroupNameField getGroupNameField()
    {
        return groupNameField;
    }

    @Config("keycloak.group-name-field")
    @ConfigDescription("Field of the Keycloak group to report as the group name")
    public KeycloakGroupProviderConfig setGroupNameField(KeycloakGroupNameField groupNameField)
    {
        this.groupNameField = groupNameField;
        return this;
    }

    @NotNull
    public KeycloakGroupSearchMode getGroupSearchMode()
    {
        return groupSearchMode;
    }

    @Config("keycloak.group-search-mode")
    @ConfigDescription("Whether to report only directly assigned groups, or their ancestors as well")
    public KeycloakGroupProviderConfig setGroupSearchMode(KeycloakGroupSearchMode groupSearchMode)
    {
        this.groupSearchMode = groupSearchMode;
        return this;
    }

    @NotNull
    public KeycloakGroupLookupErrorMode getGroupLookupErrorMode()
    {
        return groupLookupErrorMode;
    }

    @Config("keycloak.group-lookup-error-mode")
    @ConfigDescription("What to report when Keycloak cannot be reached")
    public KeycloakGroupProviderConfig setGroupLookupErrorMode(KeycloakGroupLookupErrorMode groupLookupErrorMode)
    {
        this.groupLookupErrorMode = groupLookupErrorMode;
        return this;
    }

    public boolean isCacheEnabled()
    {
        return cacheEnabled;
    }

    @Config("keycloak.cache.enabled")
    @ConfigDescription("Cache the groups of each user")
    public KeycloakGroupProviderConfig setCacheEnabled(boolean cacheEnabled)
    {
        this.cacheEnabled = cacheEnabled;
        return this;
    }

    @NotNull
    @MinDuration("0ms")
    public Duration getCacheTtl()
    {
        return cacheTtl;
    }

    @Config("keycloak.cache.ttl")
    @ConfigDescription("How long to cache a user's groups. Zero disables caching")
    public KeycloakGroupProviderConfig setCacheTtl(Duration cacheTtl)
    {
        this.cacheTtl = cacheTtl;
        return this;
    }

    @Min(1)
    public long getCacheMaximumSize()
    {
        return cacheMaximumSize;
    }

    @Config("keycloak.cache.maximum-size")
    @ConfigDescription("Maximum number of users to remember groups for")
    public KeycloakGroupProviderConfig setCacheMaximumSize(long cacheMaximumSize)
    {
        this.cacheMaximumSize = cacheMaximumSize;
        return this;
    }

    @AssertTrue(message = "keycloak.url must be an absolute URL including a scheme and a host, for example https://keycloak.example.com")
    public boolean isUrlValid()
    {
        return url == null || (url.getScheme() != null && url.getHost() != null);
    }

    @AssertTrue(message = "keycloak.group-search-mode=ANCESTORS requires keycloak.group-name-field=PATH, because ancestor groups cannot be distinguished by name alone")
    public boolean isGroupSearchModeValid()
    {
        return groupSearchMode != ANCESTORS || groupNameField != NAME;
    }

    @AssertTrue(message = "keycloak.group-lookup-error-mode=RETURN_STALE requires keycloak.cache.enabled=true and a non-zero keycloak.cache.ttl, because there is nothing to report when the cache is disabled")
    public boolean isGroupLookupErrorModeValid()
    {
        return groupLookupErrorMode != RETURN_STALE || (cacheEnabled && cacheTtl.toMillis() > 0);
    }
}

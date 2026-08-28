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
import io.airlift.http.client.testing.TestingHttpClient;
import io.trino.spi.TrinoException;
import io.trino.spi.security.GroupProvider;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static io.trino.plugin.keycloakgroup.TestingKeycloak.REALM;
import static io.trino.plugin.keycloakgroup.TestingKeycloak.userJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

final class TestKeycloakGroupProvider
{
    @Test
    void testDirectMembershipByName()
    {
        TestingKeycloak keycloak = new TestingKeycloak()
                .withUser("alice", "user-alice", "/engineering/backend", "/on-call");

        assertThat(createGroupProvider(keycloak).getGroups("alice"))
                .containsExactlyInAnyOrder("backend", "on-call");
    }

    @Test
    void testDirectMembershipByPath()
    {
        TestingKeycloak keycloak = new TestingKeycloak()
                .withUser("alice", "user-alice", "/engineering/backend", "/on-call");

        assertThat(createGroupProvider(keycloak, ImmutableMap.of("keycloak.group-name-field", "PATH")).getGroups("alice"))
                .containsExactlyInAnyOrder("engineering/backend", "on-call");
    }

    @Test
    void testAncestorsAreReportedOnlyWhenAskedFor()
    {
        TestingKeycloak keycloak = new TestingKeycloak()
                .withUser("alice", "user-alice", "/engineering/backend/storage");

        // Keycloak reports direct membership only: a member of /engineering/backend/storage is not
        // reported as a member of /engineering.
        assertThat(createGroupProvider(keycloak, ImmutableMap.of("keycloak.group-name-field", "PATH")).getGroups("alice"))
                .containsExactly("engineering/backend/storage");

        assertThat(createGroupProvider(keycloak, ImmutableMap.of(
                "keycloak.group-name-field", "PATH",
                "keycloak.group-search-mode", "ANCESTORS"))
                .getGroups("alice"))
                .containsExactlyInAnyOrder("engineering", "engineering/backend", "engineering/backend/storage");
    }

    @Test
    void testTopLevelGroupHasNoAncestors()
    {
        TestingKeycloak keycloak = new TestingKeycloak()
                .withUser("alice", "user-alice", "/on-call");

        assertThat(createGroupProvider(keycloak, ImmutableMap.of(
                "keycloak.group-name-field", "PATH",
                "keycloak.group-search-mode", "ANCESTORS"))
                .getGroups("alice"))
                .containsExactly("on-call");
    }

    @Test
    void testGetGroupsForMissingUserReturnsEmpty()
    {
        TestingKeycloak keycloak = new TestingKeycloak().withUser("alice", "user-alice", "/on-call");

        assertThat(createGroupProvider(keycloak).getGroups("bob")).isEmpty();
    }

    @Test
    void testUserWithNoGroupsReturnsEmpty()
    {
        TestingKeycloak keycloak = new TestingKeycloak().withUser("alice", "user-alice");

        assertThat(createGroupProvider(keycloak).getGroups("alice")).isEmpty();
    }

    @Test
    void testUsernameMatchIsCaseInsensitive()
    {
        TestingKeycloak keycloak = new TestingKeycloak().withUser("alice", "user-alice", "/on-call");

        assertThat(createGroupProvider(keycloak).getGroups("Alice")).containsExactly("on-call");
    }

    @Test
    void testMatchedUserIsVerifiedRatherThanTrusted()
    {
        TestingKeycloak keycloak = new TestingKeycloak()
                .withUsersResponse("alice", userJson("user-bob", "bob"));

        assertThatThrownBy(() -> createGroupProvider(keycloak).getGroups("alice"))
                .isInstanceOf(TrinoException.class)
                .hasMessageContaining("answered an exact lookup of username [alice]")
                .hasMessageContaining("with the user [bob]");
    }

    @Test
    void testMoreThanOneMatchingUserFailsRegardlessOfErrorMode()
    {
        TestingKeycloak keycloak = new TestingKeycloak().withUsersResponse(
                "alice",
                "[{\"id\":\"user-alice\",\"username\":\"alice\"},{\"id\":\"user-alice-2\",\"username\":\"Alice\"}]");

        // The default error mode reports no groups when Keycloak cannot be reached, but this is a
        // broken assumption rather than an unreachable Keycloak, so the query fails either way.
        for (String errorMode : new String[] {"RETURN_EMPTY", "FAIL"}) {
            assertThatThrownBy(() -> createGroupProvider(keycloak, ImmutableMap.of("keycloak.group-lookup-error-mode", errorMode)).getGroups("alice"))
                    .isInstanceOf(TrinoException.class)
                    .isNotInstanceOf(KeycloakLookupException.class)
                    .hasMessageContaining("Keycloak matched 2 users in realm %s for the exact username [alice]".formatted(REALM));
        }
    }

    @Test
    void testFieldsKeycloakSendsAndThisPluginIgnoresAreNotAnError()
    {
        // Every response the fake Keycloak gives carries the fields a real one sends, so this only
        // has to prove that the plugin reads one of them at all.
        TestingKeycloak keycloak = new TestingKeycloak().withUser("alice", "user-alice", "/on-call");

        assertThat(createGroupProvider(keycloak).getGroups("alice")).containsExactly("on-call");
        // One lookup for the startup check and one for alice.
        assertThat(keycloak.userLookups()).isEqualTo(2);
        assertThat(keycloak.groupLookups()).isEqualTo(1);
    }

    @Test
    void testResultsAreCached()
    {
        TestingKeycloak keycloak = new TestingKeycloak().withUser("alice", "user-alice", "/on-call");
        GroupProvider groupProvider = createGroupProvider(keycloak);

        assertThat(groupProvider.getGroups("alice")).containsExactly("on-call");
        assertThat(groupProvider.getGroups("alice")).containsExactly("on-call");

        // One lookup for the startup check and one for alice; the second call is served from the cache.
        assertThat(keycloak.userLookups()).isEqualTo(2);
        assertThat(keycloak.groupLookups()).isEqualTo(1);
    }

    @Test
    void testMissingUserIsCached()
    {
        TestingKeycloak keycloak = new TestingKeycloak().withUser("alice", "user-alice", "/on-call");
        GroupProvider groupProvider = createGroupProvider(keycloak);

        assertThat(groupProvider.getGroups("bob")).isEmpty();
        assertThat(groupProvider.getGroups("bob")).isEmpty();

        // One lookup for the startup check and one for bob; a second lookup of bob would mean
        // every unknown username reaches Keycloak on every query.
        assertThat(keycloak.userLookups()).isEqualTo(2);
    }

    @Test
    void testNothingIsCachedWhenTheCacheIsDisabled()
    {
        TestingKeycloak keycloak = new TestingKeycloak().withUser("alice", "user-alice", "/on-call");
        GroupProvider groupProvider = createGroupProvider(keycloak, ImmutableMap.of("keycloak.cache.enabled", "false"));

        assertThat(groupProvider.getGroups("alice")).containsExactly("on-call");
        assertThat(groupProvider.getGroups("alice")).containsExactly("on-call");

        assertThat(keycloak.groupLookups()).isEqualTo(2);
    }

    @Test
    void testNothingIsCachedWithAZeroTtl()
    {
        TestingKeycloak keycloak = new TestingKeycloak().withUser("alice", "user-alice", "/on-call");
        GroupProvider groupProvider = createGroupProvider(keycloak, ImmutableMap.of("keycloak.cache.ttl", "0s"));

        assertThat(groupProvider.getGroups("alice")).containsExactly("on-call");
        assertThat(groupProvider.getGroups("alice")).containsExactly("on-call");

        assertThat(keycloak.groupLookups()).isEqualTo(2);
    }

    @Test
    void testUnreachableKeycloakReportsNoGroupsByDefault()
    {
        TestingKeycloak keycloak = new TestingKeycloak().withUser("alice", "user-alice", "/on-call");
        GroupProvider groupProvider = createGroupProvider(keycloak);
        keycloak.setReachable(false);

        assertThat(groupProvider.getGroups("alice")).isEmpty();
    }

    @Test
    void testUnreachableKeycloakFailsTheQueryUnderFail()
    {
        TestingKeycloak keycloak = new TestingKeycloak().withUser("alice", "user-alice", "/on-call");
        GroupProvider groupProvider = createGroupProvider(keycloak, ImmutableMap.of("keycloak.group-lookup-error-mode", "FAIL"));
        keycloak.setReachable(false);

        assertThatThrownBy(() -> groupProvider.getGroups("alice"))
                .isInstanceOf(KeycloakLookupException.class)
                .hasMessageContaining("Keycloak did not answer");
    }

    @Test
    void testUnreachableKeycloakServesTheLastResultUnderReturnStale()
    {
        TestingKeycloak keycloak = new TestingKeycloak().withUser("alice", "user-alice", "/on-call");
        GroupProvider groupProvider = createGroupProvider(keycloak, ImmutableMap.of(
                "keycloak.group-lookup-error-mode", "RETURN_STALE",
                "keycloak.cache.ttl", "1ms"));

        assertThat(groupProvider.getGroups("alice")).containsExactly("on-call");
        keycloak.setReachable(false);

        assertThat(groupProvider.getGroups("alice")).containsExactly("on-call");
    }

    @Test
    void testReturnStaleReportsNoGroupsForAUserItHasNeverSeen()
    {
        TestingKeycloak keycloak = new TestingKeycloak().withUser("alice", "user-alice", "/on-call");
        GroupProvider groupProvider = createGroupProvider(keycloak, ImmutableMap.of(
                "keycloak.group-lookup-error-mode", "RETURN_STALE",
                "keycloak.cache.ttl", "1ms"));
        keycloak.setReachable(false);

        assertThat(groupProvider.getGroups("alice")).isEmpty();
    }

    @Test
    void testAccessTokenIsReusedUntilItExpires()
    {
        TestingKeycloak keycloak = new TestingKeycloak().withUser("alice", "user-alice", "/on-call");
        GroupProvider groupProvider = createGroupProvider(keycloak, ImmutableMap.of("keycloak.cache.enabled", "false"));

        groupProvider.getGroups("alice");
        groupProvider.getGroups("alice");

        assertThat(keycloak.tokenRequests()).isEqualTo(1);
    }

    @Test
    void testShortLivedAccessTokenDoesNotCauseATokenRequestPerLookup()
    {
        // A realm whose tokens live for less than the margin the plugin subtracts would leave the
        // token expired the moment it is issued, and every lookup would fetch another one.
        TestingKeycloak keycloak = new TestingKeycloak()
                .withAccessTokenLifetimeSeconds(5)
                .withUser("alice", "user-alice", "/on-call");
        GroupProvider groupProvider = createGroupProvider(keycloak, ImmutableMap.of("keycloak.cache.enabled", "false"));

        groupProvider.getGroups("alice");
        groupProvider.getGroups("alice");

        assertThat(keycloak.tokenRequests()).isEqualTo(1);
    }

    @Test
    void testRevokedAccessTokenIsDiscardedSoTheNextLookupSucceeds()
    {
        TestingKeycloak keycloak = new TestingKeycloak().withUser("alice", "user-alice", "/on-call");
        GroupProvider groupProvider = createGroupProvider(keycloak, ImmutableMap.of("keycloak.cache.enabled", "false"));
        assertThat(keycloak.tokenRequests()).isEqualTo(1);

        keycloak.revokeIssuedTokens();

        // Keycloak refuses a revoked token in a way this client cannot tell apart from being
        // unreachable, so the lookup that meets the refusal fails under the configured error mode.
        assertThat(groupProvider.getGroups("alice")).isEmpty();
        // The token is dropped with it, so the next lookup authenticates again rather than
        // repeating the failure until the revoked token reaches its stated expiry.
        assertThat(groupProvider.getGroups("alice")).containsExactly("on-call");
        assertThat(keycloak.tokenRequests()).isEqualTo(2);
    }

    @Test
    void testStartupFailsWhenTheClientCredentialsAreRejected()
    {
        TestingKeycloak keycloak = new TestingKeycloak().setCredentialsAccepted(false);

        assertThatThrownBy(() -> createGroupProvider(keycloak))
                .isInstanceOf(KeycloakLookupException.class)
                .hasMessageContaining("Keycloak did not issue a token to client %s in realm master".formatted(TestingKeycloak.CLIENT_ID))
                .hasMessageContaining("keycloak.client-secret");
    }

    @Test
    void testStartupFailsWhenTheClientCannotListUsers()
    {
        TestingKeycloak keycloak = new TestingKeycloak().setAllowedToListUsers(false);

        assertThatThrownBy(() -> createGroupProvider(keycloak))
                .isInstanceOf(KeycloakLookupException.class)
                .hasMessageContaining("is not allowed to list the users of realm %s".formatted(REALM))
                .hasMessageContaining("Grant it the view-users role");
    }

    @Test
    void testStartupFailsWhenTheRealmDoesNotExist()
    {
        TestingKeycloak keycloak = new TestingKeycloak().setRealmExists(false);

        assertThatThrownBy(() -> createGroupProvider(keycloak))
                .isInstanceOf(KeycloakLookupException.class)
                .hasMessageContaining("Keycloak has no realm %s".formatted(REALM));
    }

    @Test
    void testStartupFailsWhenKeycloakIsUnreachable()
    {
        TestingKeycloak keycloak = new TestingKeycloak().setReachable(false);

        // Deliberately the same message as a rejected client secret: Keycloak's 401 carries no
        // WWW-Authenticate header, so the HTTP client fails the request rather than returning it,
        // and the two are indistinguishable here. Naming one of them would be a guess.
        assertThatThrownBy(() -> createGroupProvider(keycloak))
                .isInstanceOf(KeycloakLookupException.class)
                .hasMessageContaining("Keycloak did not issue a token to client %s in realm master".formatted(TestingKeycloak.CLIENT_ID))
                .hasMessageContaining("keycloak.url");
    }

    @Test
    void testStartupCheckDoesNotLookUpAPlausibleUsername()
    {
        TestingKeycloak keycloak = new TestingKeycloak().withUser("alice", "user-alice", "/on-call");
        createGroupProvider(keycloak);

        // The check has to reach the users endpoint - a token alone does not prove view-users -
        // and it must not match anybody while doing so.
        assertThat(keycloak.userLookups()).isEqualTo(1);
        assertThat(keycloak.groupLookups()).isEqualTo(0);
    }

    private static GroupProvider createGroupProvider(TestingKeycloak keycloak, Map<String, String> extraProperties)
    {
        Map<String, String> configuration = ImmutableMap.<String, String>builder()
                .putAll(TestingKeycloak.configuration())
                .putAll(extraProperties)
                .buildKeepingLast();
        return KeycloakGroupProviderFactory.create(configuration, Optional.of(new TestingHttpClient(keycloak)));
    }

    private static GroupProvider createGroupProvider(TestingKeycloak keycloak)
    {
        return createGroupProvider(keycloak, ImmutableMap.of());
    }
}

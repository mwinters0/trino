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

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import io.trino.plugin.keycloakgroup.TestingKeycloakAdminApi.ServiceAccountClient;
import io.trino.spi.security.GroupProvider;
import io.trino.testing.containers.KeycloakContainer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.net.URI;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import static io.trino.plugin.keycloakgroup.TestingKeycloakAdminApi.ADMIN_REALM;
import static io.trino.testing.containers.KeycloakContainer.DEFAULT_PASSWORD;
import static io.trino.testing.containers.KeycloakContainer.DEFAULT_USER_NAME;
import static java.util.concurrent.Executors.newFixedThreadPool;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.TestInstance.Lifecycle.PER_CLASS;

/**
 * Exercises the provider against a real Keycloak, which is the only thing that can establish that
 * the group semantics this plugin is built on are Keycloak's own: that a member of a nested group
 * is not a member of its parent, and that the paths and the {@code client_credentials} flow are
 * what the plugin expects. Everything that runs downstream of a parsed Keycloak response - the
 * cache, the error modes, the token lifecycle - is pinned in {@link TestKeycloakGroupProvider}
 * against a Keycloak written by hand, where a test controls the failures and the request counts.
 */
@TestInstance(PER_CLASS)
final class TestKeycloakGroupProviderIntegration
{
    /**
     * The Keycloak to test against. Overriding it runs the whole class against another version,
     * which is how the range of supported Keycloak versions is checked.
     */
    private static final String IMAGE_NAME = System.getProperty("testing.keycloak-image-name", KeycloakContainer.DEFAULT_IMAGE);

    private static final String REALM = "employees";
    private static final String CLIENT_ID = "trino-group-provider";
    private static final String CROSS_REALM_CLIENT_ID = "trino-group-provider-cross-realm";
    private static final String UNGRANTED_CLIENT_ID = "trino-group-provider-ungranted";

    /**
     * The role that lets a service account read a realm's users. Inside the realm itself it
     * belongs to the {@code realm-management} client; inside {@code master} it belongs to the
     * client named after the realm.
     */
    private static final String VIEW_USERS = "view-users";

    private KeycloakContainer keycloak;
    private URI serverUrl;
    private String clientSecret;
    private String crossRealmClientSecret;
    private String ungrantedClientSecret;

    @BeforeAll
    void setUp()
    {
        keycloak = KeycloakContainer.builder()
                .withImage(IMAGE_NAME)
                .build();
        keycloak.start();
        serverUrl = URI.create(keycloak.getUrl());

        try (TestingKeycloakAdminApi admin = new TestingKeycloakAdminApi(serverUrl, DEFAULT_USER_NAME, DEFAULT_PASSWORD)) {
            admin.awaitReady();
            admin.createRealm(REALM);

            String engineering = admin.createGroup(REALM, "engineering");
            String backend = admin.createChildGroup(REALM, engineering, "backend");
            String onCall = admin.createGroup(REALM, "on-call");

            String alice = admin.createUser(REALM, "alice");
            admin.addUserToGroup(REALM, alice, backend);
            admin.addUserToGroup(REALM, alice, onCall);
            String bob = admin.createUser(REALM, "bob");
            admin.addUserToGroup(REALM, bob, onCall);
            admin.createUser(REALM, "carol");

            // The client lives in the realm it reads, and is granted view-users there.
            ServiceAccountClient client = admin.createServiceAccountClient(REALM, CLIENT_ID);
            admin.grantClientRole(REALM, client.serviceAccountUserId(), "realm-management", VIEW_USERS);
            clientSecret = client.secret();

            // The client lives in master, and is granted view-users over the realm it reads
            // through the client master holds for that realm.
            ServiceAccountClient crossRealmClient = admin.createServiceAccountClient(ADMIN_REALM, CROSS_REALM_CLIENT_ID);
            admin.grantClientRole(ADMIN_REALM, crossRealmClient.serviceAccountUserId(), REALM + "-realm", VIEW_USERS);
            crossRealmClientSecret = crossRealmClient.secret();

            // The same client again, granted nothing at all.
            ungrantedClientSecret = admin.createServiceAccountClient(ADMIN_REALM, UNGRANTED_CLIENT_ID).secret();
        }
    }

    @AfterAll
    void tearDown()
    {
        if (keycloak != null) {
            keycloak.close();
            keycloak = null;
        }
    }

    @Test
    void testDirectMembershipReportsLeafGroupsOnly()
    {
        GroupProvider groupProvider = createGroupProvider(ImmutableMap.of());

        // alice is a member of /engineering/backend, and Keycloak reports the groups a user is
        // directly a member of: /engineering is not among them.
        assertThat(groupProvider.getGroups("alice")).containsExactlyInAnyOrder("backend", "on-call");
        assertThat(groupProvider.getGroups("bob")).containsExactly("on-call");
        assertThat(groupProvider.getGroups("carol")).isEmpty();
    }

    @Test
    void testGroupPathsComeFromKeycloak()
    {
        GroupProvider groupProvider = createGroupProvider(ImmutableMap.of("keycloak.group-name-field", "PATH"));

        assertThat(groupProvider.getGroups("alice")).containsExactlyInAnyOrder("engineering/backend", "on-call");
        assertThat(groupProvider.getGroups("bob")).containsExactly("on-call");
    }

    @Test
    void testAncestorsAreDerivedFromRealGroupPaths()
    {
        GroupProvider groupProvider = createGroupProvider(ImmutableMap.of(
                "keycloak.group-name-field", "PATH",
                "keycloak.group-search-mode", "ANCESTORS"));

        assertThat(groupProvider.getGroups("alice")).containsExactlyInAnyOrder("engineering", "engineering/backend", "on-call");
        assertThat(groupProvider.getGroups("bob")).containsExactly("on-call");
    }

    @Test
    void testUserMissingFromTheRealmHasNoGroups()
    {
        assertThat(createGroupProvider(ImmutableMap.of()).getGroups("nobody")).isEmpty();
    }

    @Test
    void testGroupsAreResolvedConcurrently()
            throws Exception
    {
        assertGroupsAreResolvedConcurrently(createGroupProvider(ImmutableMap.of()));
        // With the cache disabled every lookup reaches Keycloak, so the token is shared across
        // threads doing real work rather than across threads waiting on one cache entry.
        assertGroupsAreResolvedConcurrently(createGroupProvider(ImmutableMap.of("keycloak.cache.enabled", "false")));
    }

    private static void assertGroupsAreResolvedConcurrently(GroupProvider groupProvider)
            throws Exception
    {
        ImmutableList.Builder<Callable<Void>> lookups = ImmutableList.builder();
        for (int i = 0; i < 8; i++) {
            lookups.add(() -> {
                assertThat(groupProvider.getGroups("alice")).containsExactlyInAnyOrder("backend", "on-call");
                return null;
            });
            lookups.add(() -> {
                assertThat(groupProvider.getGroups("bob")).containsExactly("on-call");
                return null;
            });
            lookups.add(() -> {
                assertThat(groupProvider.getGroups("carol")).isEmpty();
                return null;
            });
        }

        try (ExecutorService executor = newFixedThreadPool(8)) {
            for (Future<Void> result : executor.invokeAll(lookups.build())) {
                // Rethrows whatever the lookup threw, so that a failed assertion fails the test
                // rather than being lost with the thread that made it.
                result.get();
            }
        }
    }

    @Test
    void testClientInAnotherRealmResolvesGroups()
    {
        GroupProvider groupProvider = createGroupProvider(ImmutableMap.of(
                "keycloak.client-realm", ADMIN_REALM,
                "keycloak.client-id", CROSS_REALM_CLIENT_ID,
                "keycloak.client-secret", crossRealmClientSecret));

        assertThat(groupProvider.getGroups("alice")).containsExactlyInAnyOrder("backend", "on-call");
    }

    @Test
    void testWrongClientSecretFailsStartup()
    {
        // Against a real Keycloak this is the only test that sees a 401 at all, and it sees it as
        // a failed request rather than as a response: Keycloak sends no WWW-Authenticate header
        // with it, so Jetty fails the request as a protocol violation. The message therefore names
        // both an unreachable server and rejected credentials, and this test pins that the
        // properties an operator has to check are in it.
        assertThatThrownBy(() -> createGroupProvider(ImmutableMap.of("keycloak.client-secret", "not-the-secret")))
                .isInstanceOf(KeycloakLookupException.class)
                .hasMessageContaining("Keycloak did not issue a token to client %s in realm %s".formatted(CLIENT_ID, REALM))
                .hasMessageContaining("keycloak.client-secret");
    }

    @Test
    void testClientInAnotherRealmWithoutTheRoleFailsStartup()
    {
        // Keycloak issues this client a token, because its credentials are valid in its own realm.
        // Only the startup check establishes that the token cannot read the realm being searched,
        // which is otherwise indistinguishable from every user having no groups.
        assertThatThrownBy(() -> createGroupProvider(ImmutableMap.of(
                "keycloak.client-realm", ADMIN_REALM,
                "keycloak.client-id", UNGRANTED_CLIENT_ID,
                "keycloak.client-secret", ungrantedClientSecret)))
                .isInstanceOf(KeycloakLookupException.class)
                .hasMessageContaining("is not allowed to list the users of realm %s".formatted(REALM))
                .hasMessageContaining(VIEW_USERS);
    }

    private GroupProvider createGroupProvider(Map<String, String> extraProperties)
    {
        Map<String, String> configuration = ImmutableMap.<String, String>builder()
                .put("keycloak.url", serverUrl.toString())
                .put("keycloak.realm", REALM)
                .put("keycloak.client-id", CLIENT_ID)
                .put("keycloak.client-secret", clientSecret)
                .putAll(extraProperties)
                .buildKeepingLast();
        return new KeycloakGroupProviderFactory().create(configuration);
    }
}

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
import io.airlift.http.client.HttpClient;
import io.airlift.http.client.HttpClientConfig;
import io.airlift.http.client.HttpUriBuilder;
import io.airlift.http.client.Request;
import io.airlift.http.client.StringResponseHandler.StringResponse;
import io.airlift.http.client.jetty.JettyHttpClient;
import io.airlift.json.JsonCodec;
import io.airlift.units.Duration;

import java.io.Closeable;
import java.net.URI;
import java.util.List;

import static com.google.common.base.Preconditions.checkState;
import static com.google.common.net.MediaType.FORM_DATA;
import static com.google.common.net.MediaType.JSON_UTF_8;
import static com.google.common.util.concurrent.Uninterruptibles.sleepUninterruptibly;
import static io.airlift.http.client.HeaderNames.ACCEPT;
import static io.airlift.http.client.HeaderNames.AUTHORIZATION;
import static io.airlift.http.client.HeaderNames.CONTENT_TYPE;
import static io.airlift.http.client.HeaderNames.LOCATION;
import static io.airlift.http.client.HttpStatus.Family.SUCCESSFUL;
import static io.airlift.http.client.HttpStatus.familyForStatusCode;
import static io.airlift.http.client.HttpUriBuilder.uriBuilderFrom;
import static io.airlift.http.client.JsonResponseHandler.createJsonResponseHandler;
import static io.airlift.http.client.Request.Builder.prepareGet;
import static io.airlift.http.client.Request.Builder.preparePost;
import static io.airlift.http.client.Request.Builder.preparePut;
import static io.airlift.http.client.StaticBodyGenerator.createStaticBodyGenerator;
import static io.airlift.http.client.StringResponseHandler.createStringResponseHandler;
import static io.airlift.json.JsonCodec.jsonCodec;
import static io.airlift.json.JsonCodec.listJsonCodec;
import static java.lang.System.nanoTime;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.NANOSECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Builds a fixture realm through Keycloak's Admin REST API, as the administrator of the
 * {@code master} realm.
 * <p>
 * The requests are written out by hand rather than made through Keycloak's admin client library,
 * so that this module needs no dependency on Keycloak itself and so that the test runs unchanged
 * against every Keycloak version the plugin supports. Only the fields each request actually sets
 * are sent, so a representation that gained a field in a later Keycloak version cannot break the
 * fixture on an earlier one.
 */
final class TestingKeycloakAdminApi
        implements Closeable
{
    /**
     * The realm Keycloak's own administrator lives in, and the realm a client must live in to be
     * granted a role over another realm.
     */
    public static final String ADMIN_REALM = "master";

    /**
     * Keycloak's client for the administrative user interface, which is the one that accepts a
     * username and password rather than a client secret.
     */
    private static final String ADMIN_CLIENT_ID = "admin-cli";

    /**
     * How long an administrator's token is used for. Keycloak issues these with a lifetime of a
     * minute, and a fixture takes long enough to build that one token may not cover it.
     */
    private static final long ADMIN_TOKEN_LIFETIME_SECONDS = 30;

    /**
     * How long to wait for Keycloak to start answering.
     */
    private static final Duration READINESS_TIMEOUT = new Duration(2, MINUTES);

    private static final JsonCodec<KeycloakTokenResponse> TOKEN_CODEC = jsonCodec(KeycloakTokenResponse.class);
    private static final JsonCodec<KeycloakUser> USER_CODEC = jsonCodec(KeycloakUser.class);
    private static final JsonCodec<ClientSecret> CLIENT_SECRET_CODEC = jsonCodec(ClientSecret.class);
    private static final JsonCodec<List<Client>> CLIENT_LIST_CODEC = listJsonCodec(Client.class);
    private static final JsonCodec<Role> ROLE_CODEC = jsonCodec(Role.class);
    private static final JsonCodec<List<Role>> ROLE_LIST_CODEC = listJsonCodec(Role.class);

    private final HttpClient httpClient = new JettyHttpClient(new HttpClientConfig());
    private final URI serverUrl;
    private final String username;
    private final String password;

    private String adminToken;
    private long adminTokenExpiresAt;

    public TestingKeycloakAdminApi(URI serverUrl, String username, String password)
    {
        this.serverUrl = requireNonNull(serverUrl, "serverUrl is null");
        this.username = requireNonNull(username, "username is null");
        this.password = requireNonNull(password, "password is null");
    }

    /**
     * Waits until Keycloak answers requests. The container reports itself started as soon as its
     * port accepts connections, which is earlier than the point at which Keycloak serves anything
     * over it.
     */
    public void awaitReady()
    {
        long deadline = nanoTime() + READINESS_TIMEOUT.roundTo(NANOSECONDS);
        while (true) {
            try {
                bearer();
                return;
            }
            catch (RuntimeException e) {
                if (nanoTime() - deadline >= 0) {
                    throw new IllegalStateException("Keycloak at %s did not start answering within %s".formatted(serverUrl, READINESS_TIMEOUT), e);
                }
                sleepUninterruptibly(100, MILLISECONDS);
            }
        }
    }

    public void createRealm(String realm)
    {
        post(uriBuilderFrom(serverUrl).appendPath("admin/realms").build(),
                """
                {"realm": "%s", "enabled": true}""".formatted(realm));
    }

    /**
     * Creates a group at the top level of the realm and returns its identifier.
     */
    public String createGroup(String realm, String name)
    {
        return create(realmUri(realm).appendPath("groups").build(),
                """
                {"name": "%s"}""".formatted(name));
    }

    /**
     * Creates a group below another group and returns its identifier. A group named
     * {@code backend} below {@code engineering} has the path {@code /engineering/backend}.
     */
    public String createChildGroup(String realm, String parentGroupId, String name)
    {
        return create(realmUri(realm).appendPath("groups").appendPath(parentGroupId).appendPath("children").build(),
                """
                {"name": "%s"}""".formatted(name));
    }

    public String createUser(String realm, String username)
    {
        return create(realmUri(realm).appendPath("users").build(),
                """
                {"username": "%s", "enabled": true}""".formatted(username));
    }

    public void addUserToGroup(String realm, String userId, String groupId)
    {
        Request request = preparePut()
                .setUri(realmUri(realm).appendPath("users").appendPath(userId).appendPath("groups").appendPath(groupId).build())
                .setHeader(AUTHORIZATION, bearer())
                .build();
        StringResponse response = httpClient.execute(request, createStringResponseHandler());
        checkSuccessful(response, request);
    }

    /**
     * Creates a confidential client with a service account, which is what the
     * {@code client_credentials} grant needs, and returns the secret and the service account to
     * grant roles to.
     */
    public ServiceAccountClient createServiceAccountClient(String realm, String clientId)
    {
        String id = create(realmUri(realm).appendPath("clients").build(),
                """
                {
                  "clientId": "%s",
                  "enabled": true,
                  "protocol": "openid-connect",
                  "publicClient": false,
                  "serviceAccountsEnabled": true,
                  "standardFlowEnabled": false,
                  "directAccessGrantsEnabled": false,
                  "implicitFlowEnabled": false
                }""".formatted(clientId));
        String secret = fetchJson(realmUri(realm).appendPath("clients").appendPath(id).appendPath("client-secret").build(), CLIENT_SECRET_CODEC)
                .value();
        String serviceAccountUserId = fetchJson(realmUri(realm).appendPath("clients").appendPath(id).appendPath("service-account-user").build(), USER_CODEC)
                .id();
        return new ServiceAccountClient(clientId, secret, serviceAccountUserId);
    }

    /**
     * Grants one of another client's roles to a service account. Keycloak's own permissions are
     * modelled this way: {@code view-users} on a realm's users is a role of the
     * {@code realm-management} client inside that realm, and of the {@code <realm>-realm} client
     * inside {@code master}.
     */
    public void grantClientRole(String realm, String serviceAccountUserId, String roleContainerClientId, String roleName)
    {
        List<Client> containers = fetchJson(realmUri(realm).appendPath("clients").addParameter("clientId", roleContainerClientId).build(), CLIENT_LIST_CODEC);
        checkState(containers.size() == 1, "Expected exactly one client %s in realm %s, found %s", roleContainerClientId, realm, containers.size());
        String containerId = containers.getFirst().id();

        Role role = fetchJson(realmUri(realm).appendPath("clients").appendPath(containerId).appendPath("roles").appendPath(roleName).build(), ROLE_CODEC);
        post(realmUri(realm).appendPath("users").appendPath(serviceAccountUserId).appendPath("role-mappings/clients").appendPath(containerId).build(),
                ROLE_LIST_CODEC.toJson(ImmutableList.of(role)));
    }

    @Override
    public void close()
    {
        httpClient.close();
    }

    private HttpUriBuilder realmUri(String realm)
    {
        return uriBuilderFrom(serverUrl).appendPath("admin/realms").appendPath(realm);
    }

    /**
     * Sends a request that creates something, and returns the identifier Keycloak reports in the
     * location of the created resource.
     */
    private String create(URI uri, String json)
    {
        StringResponse response = post(uri, json);
        String location = response.getHeader(LOCATION)
                .orElseThrow(() -> new IllegalStateException("Keycloak did not report the location of the resource created by %s".formatted(uri)));
        return location.substring(location.lastIndexOf('/') + 1);
    }

    private StringResponse post(URI uri, String json)
    {
        Request request = preparePost()
                .setUri(uri)
                .setHeader(AUTHORIZATION, bearer())
                .setHeader(CONTENT_TYPE, JSON_UTF_8.toString())
                .setBodyGenerator(createStaticBodyGenerator(json, UTF_8))
                .build();
        StringResponse response = httpClient.execute(request, createStringResponseHandler());
        checkSuccessful(response, request);
        return response;
    }

    private <T> T fetchJson(URI uri, JsonCodec<T> codec)
    {
        Request request = prepareGet()
                .setUri(uri)
                .setHeader(AUTHORIZATION, bearer())
                .setHeader(ACCEPT, JSON_UTF_8.toString())
                .build();
        return httpClient.execute(request, createJsonResponseHandler(codec));
    }

    private static void checkSuccessful(StringResponse response, Request request)
    {
        checkState(
                familyForStatusCode(response.getStatusCode()) == SUCCESSFUL,
                "%s %s failed with HTTP %s: %s",
                request.getMethod(),
                request.getUri(),
                response.getStatusCode(),
                response.getBody());
    }

    private String bearer()
    {
        if (adminToken == null || nanoTime() - adminTokenExpiresAt >= 0) {
            String body = "grant_type=password&client_id=%s&username=%s&password=%s".formatted(ADMIN_CLIENT_ID, username, password);
            Request request = preparePost()
                    .setUri(uriBuilderFrom(serverUrl).appendPath("realms").appendPath(ADMIN_REALM).appendPath("protocol/openid-connect/token").build())
                    .setHeader(CONTENT_TYPE, FORM_DATA.toString())
                    .setHeader(ACCEPT, JSON_UTF_8.toString())
                    .setBodyGenerator(createStaticBodyGenerator(body, UTF_8))
                    .build();
            long requestedAt = nanoTime();
            adminToken = httpClient.execute(request, createJsonResponseHandler(TOKEN_CODEC)).accessToken();
            adminTokenExpiresAt = requestedAt + SECONDS.toNanos(ADMIN_TOKEN_LIFETIME_SECONDS);
        }
        return "Bearer " + adminToken;
    }

    public record ServiceAccountClient(String clientId, String secret, String serviceAccountUserId) {}

    record ClientSecret(String value) {}

    record Client(String id) {}

    record Role(String id, String name) {}
}

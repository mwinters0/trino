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

import com.google.common.base.CharMatcher;
import com.google.common.collect.ImmutableList;
import com.google.inject.Inject;
import io.airlift.http.client.FullJsonResponseHandler.JsonResponse;
import io.airlift.http.client.HttpClient;
import io.airlift.http.client.Request;
import io.airlift.json.JsonCodec;
import io.airlift.log.Logger;
import io.trino.spi.TrinoException;

import java.net.URI;
import java.net.URLEncoder;
import java.util.List;
import java.util.Optional;

import static com.google.common.net.MediaType.FORM_DATA;
import static com.google.common.net.MediaType.JSON_UTF_8;
import static io.airlift.http.client.FullJsonResponseHandler.createFullJsonResponseHandler;
import static io.airlift.http.client.HeaderNames.ACCEPT;
import static io.airlift.http.client.HeaderNames.AUTHORIZATION;
import static io.airlift.http.client.HeaderNames.CONTENT_TYPE;
import static io.airlift.http.client.HttpStatus.FORBIDDEN;
import static io.airlift.http.client.HttpStatus.Family.SUCCESSFUL;
import static io.airlift.http.client.HttpStatus.NOT_FOUND;
import static io.airlift.http.client.HttpStatus.familyForStatusCode;
import static io.airlift.http.client.HttpUriBuilder.uriBuilderFrom;
import static io.airlift.http.client.Request.Builder.prepareGet;
import static io.airlift.http.client.Request.Builder.preparePost;
import static io.airlift.http.client.StaticBodyGenerator.createStaticBodyGenerator;
import static io.airlift.json.JsonCodec.jsonCodec;
import static io.airlift.json.JsonCodec.listJsonCodec;
import static io.trino.spi.StandardErrorCode.GENERIC_INTERNAL_ERROR;
import static java.lang.Math.max;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Calls the Keycloak Admin REST API as a service account client, authenticating with the
 * {@code client_credentials} grant.
 * <p>
 * <b>A 401 from Keycloak never reaches this class as a response.</b> Keycloak answers both a
 * rejected {@code client_credentials} request and a request carrying a token it no longer accepts
 * with a 401 that carries no {@code WWW-Authenticate} header - on the token endpoint and on the
 * Admin API alike, measured on Keycloak 22 through 26.7. Jetty treats a challenge without that
 * header as a protocol violation and fails the request instead of returning the response, so an
 * unauthorized request and an unreachable server arrive here in the same way: as a thrown
 * exception. Hence a message about a failed request names both causes rather than picking one, and
 * a failed admin request drops the access token rather than waiting for a 401 that cannot arrive.
 * A 403 is unaffected and still arrives as a response, which is what a client without the
 * {@code view-users} role produces.
 */
public class KeycloakClient
{
    private static final Logger log = Logger.get(KeycloakClient.class);

    private static final JsonCodec<KeycloakTokenResponse> TOKEN_CODEC = jsonCodec(KeycloakTokenResponse.class);
    private static final JsonCodec<List<KeycloakUser>> USER_LIST_CODEC = listJsonCodec(KeycloakUser.class);
    private static final JsonCodec<List<KeycloakGroup>> GROUP_LIST_CODEC = listJsonCodec(KeycloakGroup.class);

    /**
     * The username the startup check looks up. A fixed random identifier rather than a plausible
     * name, so that the check cannot match a real user however the realm is configured, and so
     * that no real username reaches Keycloak's admin event log once per node start.
     */
    private static final String STARTUP_CHECK_USERNAME = "b2d4c3fe-9a55-4f0a-9a3e-6f2c8d1e7b40";

    /**
     * How long before Keycloak's stated expiry a token is treated as expired. Without a margin a
     * token can expire between the check and Keycloak reading it.
     */
    private static final long TOKEN_EXPIRY_MARGIN_SECONDS = 30;

    private final HttpClient httpClient;
    private final String realm;
    private final String clientRealm;
    private final String clientId;
    private final String clientSecret;
    private final URI tokenUri;
    private final URI usersUri;

    // Read without the lock on the common path; only replaced while holding it.
    private final Object tokenLock = new Object();
    private volatile Token token;

    @Inject
    public KeycloakClient(@ForKeycloak HttpClient httpClient, KeycloakGroupProviderConfig config)
    {
        this.httpClient = requireNonNull(httpClient, "httpClient is null");
        this.realm = config.getRealm();
        // The client authenticates in its own realm, which defaults to the realm being searched.
        this.clientRealm = config.getClientRealm().orElse(config.getRealm());
        this.clientId = config.getClientId();
        this.clientSecret = config.getClientSecret();

        // The scheme and host are guaranteed by KeycloakGroupProviderConfig.isUrlValid().
        URI serverUrl = config.getUrl();
        // Absorb a trailing slash, so that "https://keycloak.example.com/" does not produce
        // "https://keycloak.example.com//admin/realms/...", which Keycloak answers with a 404.
        String basePath = CharMatcher.is('/').trimTrailingFrom(serverUrl.getPath());
        this.tokenUri = uriBuilderFrom(serverUrl)
                .replacePath(basePath)
                .appendPath("realms")
                .appendPath(clientRealm)
                .appendPath("protocol/openid-connect/token")
                .build();
        this.usersUri = uriBuilderFrom(serverUrl)
                .replacePath(basePath)
                .appendPath("admin/realms")
                .appendPath(realm)
                .appendPath("users")
                .build();
    }

    /**
     * Returns the groups the user is directly a member of, or an empty list when the realm has no
     * such user.
     */
    public List<KeycloakGroup> fetchGroups(String user)
    {
        Optional<String> userId = findUserId(user);
        if (userId.isEmpty()) {
            return ImmutableList.of();
        }
        URI uri = uriBuilderFrom(usersUri)
                .appendPath(userId.get())
                .appendPath("groups")
                .addParameter("briefRepresentation", "true")
                .build();
        return executeAdminRequest(uri, GROUP_LIST_CODEC);
    }

    /**
     * Verifies that this plugin can do its job at all: that the client credentials are accepted in
     * {@code keycloak.client-realm}, and that the resulting token is allowed to list users of
     * {@code keycloak.realm}. Called once when the plugin is created, so that a misconfiguration
     * fails the node's startup rather than silently reporting no groups for every user.
     */
    public void verifyConfiguration()
    {
        String accessToken = accessToken();
        URI uri = uriBuilderFrom(usersUri)
                .addParameter("exact", "true")
                .addParameter("username", STARTUP_CHECK_USERNAME)
                .build();
        JsonResponse<List<KeycloakUser>> response = execute(uri, USER_LIST_CODEC, accessToken);
        int statusCode = response.getStatusCode();
        if (statusCode == FORBIDDEN.code()) {
            throw new KeycloakLookupException(
                    "Keycloak accepted the credentials of client %s in realm %s, but that client is not allowed to list the users of realm %s (HTTP %s). Grant it the view-users role."
                            .formatted(clientId, clientRealm, realm, statusCode));
        }
        if (statusCode == NOT_FOUND.code()) {
            throw new KeycloakLookupException(
                    "Keycloak has no realm %s, or keycloak.url does not point at the root of a Keycloak server: %s returned HTTP 404"
                            .formatted(realm, uri));
        }
        if (familyForStatusCode(statusCode) != SUCCESSFUL) {
            throw new KeycloakLookupException("Keycloak answered HTTP %s for %s".formatted(statusCode, uri));
        }
    }

    private Optional<String> findUserId(String user)
    {
        URI uri = uriBuilderFrom(usersUri)
                .addParameter("exact", "true")
                .addParameter("username", user)
                .build();
        List<KeycloakUser> users = executeAdminRequest(uri, USER_LIST_CODEC);
        if (users.isEmpty()) {
            // The user exists in Trino but not in this realm. Not an error; they have no groups.
            log.debug("Realm %s has no user with the exact username [%s]; reporting no groups", realm, user);
            return Optional.empty();
        }
        if (users.size() > 1) {
            throw new TrinoException(GENERIC_INTERNAL_ERROR, "Keycloak matched %s users in realm %s for the exact username [%s]. Usernames are unique within a realm, so authorizing against any one of them would be a guess."
                    .formatted(users.size(), realm, user));
        }
        KeycloakUser match = users.getFirst();
        // Keycloak matches a username without regard to case, so the match is verified rather than
        // trusted: the realm's user [alice] answers a lookup of [Alice], but nothing else may.
        if (!user.equalsIgnoreCase(match.username())) {
            throw new TrinoException(GENERIC_INTERNAL_ERROR, "Keycloak answered an exact lookup of username [%s] in realm %s with the user [%s]"
                    .formatted(user, realm, match.username()));
        }
        return Optional.of(match.id());
    }

    private <T> T executeAdminRequest(URI uri, JsonCodec<T> codec)
    {
        String accessToken = accessToken();
        JsonResponse<T> response;
        try {
            response = execute(uri, codec, accessToken);
        }
        catch (KeycloakLookupException e) {
            // A token Keycloak has stopped accepting is one of the things this can be, so it is
            // dropped rather than reused: the next lookup authenticates again instead of failing
            // the same way until the token reaches its stated expiry. The request is not retried
            // here, so that an unreachable Keycloak costs one timeout per lookup and not two.
            discardToken(accessToken);
            throw e;
        }
        if (familyForStatusCode(response.getStatusCode()) != SUCCESSFUL) {
            throw new KeycloakLookupException("Keycloak answered HTTP %s for %s".formatted(response.getStatusCode(), uri));
        }
        if (!response.hasValue()) {
            throw new KeycloakLookupException("Cannot read the Keycloak response to %s".formatted(uri), response.getException());
        }
        return response.getValue();
    }

    private <T> JsonResponse<T> execute(URI uri, JsonCodec<T> codec, String accessToken)
    {
        Request request = prepareGet()
                .setUri(uri)
                .setHeader(AUTHORIZATION, "Bearer " + accessToken)
                .setHeader(ACCEPT, JSON_UTF_8.toString())
                .build();
        try {
            return httpClient.execute(request, createFullJsonResponseHandler(codec));
        }
        catch (RuntimeException e) {
            throw new KeycloakLookupException("Keycloak did not answer %s: the server could not be reached, or it refused the request".formatted(uri), e);
        }
    }

    private String accessToken()
    {
        Token current = token;
        if (current != null && !current.isExpired()) {
            return current.accessToken();
        }
        synchronized (tokenLock) {
            current = token;
            if (current != null && !current.isExpired()) {
                return current.accessToken();
            }
            Token refreshed = requestToken();
            token = refreshed;
            return refreshed.accessToken();
        }
    }

    private void discardToken(String accessToken)
    {
        synchronized (tokenLock) {
            // Another thread may already have replaced it; only drop the one that was refused.
            if (token != null && token.accessToken().equals(accessToken)) {
                token = null;
            }
        }
    }

    private Token requestToken()
    {
        String body = "grant_type=client_credentials&client_id=%s&client_secret=%s"
                .formatted(urlEncode(clientId), urlEncode(clientSecret));
        Request request = preparePost()
                .setUri(tokenUri)
                .setHeader(CONTENT_TYPE, FORM_DATA.toString())
                .setHeader(ACCEPT, JSON_UTF_8.toString())
                .setBodyGenerator(createStaticBodyGenerator(body, UTF_8))
                .build();
        long issuedAt = System.nanoTime();
        JsonResponse<KeycloakTokenResponse> response;
        try {
            response = httpClient.execute(request, createFullJsonResponseHandler(TOKEN_CODEC));
        }
        catch (RuntimeException e) {
            throw new KeycloakLookupException(("Keycloak did not issue a token to client %s in realm %s at %s: the server could not be reached, " +
                    "or it rejected the credentials. Check keycloak.url, keycloak.client-realm, keycloak.client-id and " +
                    "keycloak.client-secret, and that the client has its service account enabled.")
                    .formatted(clientId, clientRealm, tokenUri), e);
        }
        if (familyForStatusCode(response.getStatusCode()) != SUCCESSFUL) {
            throw new KeycloakLookupException("Keycloak refused the credentials of client %s in realm %s with HTTP %s. Check keycloak.client-id, keycloak.client-secret and keycloak.client-realm, and that the client has its service account enabled."
                    .formatted(clientId, clientRealm, response.getStatusCode()));
        }
        if (!response.hasValue()) {
            throw new KeycloakLookupException("Cannot read the Keycloak token response from %s".formatted(tokenUri), response.getException());
        }
        KeycloakTokenResponse token = response.getValue();
        long lifetimeSeconds = max(1, token.expiresIn() - TOKEN_EXPIRY_MARGIN_SECONDS);
        return new Token(token.accessToken(), issuedAt + SECONDS.toNanos(lifetimeSeconds));
    }

    private static String urlEncode(String value)
    {
        return URLEncoder.encode(value, UTF_8);
    }

    private record Token(String accessToken, long expiresAt)
    {
        private Token
        {
            requireNonNull(accessToken, "accessToken is null");
        }

        public boolean isExpired()
        {
            return System.nanoTime() - expiresAt >= 0;
        }
    }
}

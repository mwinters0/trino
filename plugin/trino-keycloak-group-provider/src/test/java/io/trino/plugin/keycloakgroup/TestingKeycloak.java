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
import io.airlift.http.client.HttpStatus;
import io.airlift.http.client.Request;
import io.airlift.http.client.Response;
import io.airlift.http.client.StaticBodyGenerator;
import io.airlift.http.client.testing.TestingHttpClient;

import java.net.ConnectException;
import java.net.URI;
import java.net.URLDecoder;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.net.MediaType.JSON_UTF_8;
import static io.airlift.http.client.HeaderNames.AUTHORIZATION;
import static io.airlift.http.client.HttpStatus.FORBIDDEN;
import static io.airlift.http.client.HttpStatus.NOT_FOUND;
import static io.airlift.http.client.HttpStatus.OK;
import static io.airlift.http.client.testing.TestingResponse.mockResponse;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Locale.ENGLISH;
import static java.util.Objects.requireNonNull;

/**
 * A Keycloak that answers the three requests this plugin makes, written by hand so that the
 * responses, the failures and the number of requests are all under a test's control. Usernames are
 * matched without regard to case, as Keycloak matches them.
 */
public final class TestingKeycloak
        implements TestingHttpClient.Processor
{
    public static final URI SERVER_URL = URI.create("https://keycloak.example.com");
    public static final String REALM = "employees";
    public static final String CLIENT_REALM = "master";
    public static final String CLIENT_ID = "trino-group-provider";
    public static final String CLIENT_SECRET = "topsecret";

    private static final String TOKEN_PATH = "/realms/%s/protocol/openid-connect/token".formatted(CLIENT_REALM);
    private static final String USERS_PATH = "/admin/realms/%s/users".formatted(REALM);
    private static final Pattern USER_GROUPS_PATH = Pattern.compile("/admin/realms/([^/]+)/users/([^/]+)/groups");

    private final Map<String, String> userIdsByUsername = new ConcurrentHashMap<>();
    private final Map<String, String> usernamesByUserId = new ConcurrentHashMap<>();
    private final Map<String, String> groupsJsonByUserId = new ConcurrentHashMap<>();
    private final Map<String, String> usersJsonByUsername = new ConcurrentHashMap<>();

    private final AtomicInteger tokenRequests = new AtomicInteger();
    private final AtomicInteger userLookups = new AtomicInteger();
    private final AtomicInteger groupLookups = new AtomicInteger();
    private final AtomicInteger issuedTokens = new AtomicInteger();

    private volatile boolean reachable = true;
    private volatile boolean credentialsAccepted = true;
    private volatile boolean allowedToListUsers = true;
    private volatile boolean realmExists = true;
    private volatile int accessTokenLifetimeSeconds = 300;
    private volatile int firstValidToken = 1;

    public static Map<String, String> configuration()
    {
        return ImmutableMap.<String, String>builder()
                .put("keycloak.url", SERVER_URL.toString())
                .put("keycloak.realm", REALM)
                .put("keycloak.client-realm", CLIENT_REALM)
                .put("keycloak.client-id", CLIENT_ID)
                .put("keycloak.client-secret", CLIENT_SECRET)
                .buildOrThrow();
    }

    /**
     * Adds a user, together with the groups Keycloak reports them as a direct member of. Every
     * group is described the way Keycloak describes it, including the fields this plugin ignores.
     */
    public TestingKeycloak withUser(String username, String userId, String... groupPaths)
    {
        userIdsByUsername.put(username.toLowerCase(ENGLISH), userId);
        usernamesByUserId.put(userId, username);
        groupsJsonByUserId.put(userId, groupsJson(ImmutableList.copyOf(groupPaths)));
        return this;
    }

    /**
     * Answers a lookup of this username with a response written out in full, for the responses a
     * real Keycloak is not supposed to give.
     */
    public TestingKeycloak withUsersResponse(String username, String json)
    {
        usersJsonByUsername.put(username.toLowerCase(ENGLISH), json);
        return this;
    }

    public TestingKeycloak withAccessTokenLifetimeSeconds(int seconds)
    {
        this.accessTokenLifetimeSeconds = seconds;
        return this;
    }

    public TestingKeycloak setReachable(boolean reachable)
    {
        this.reachable = reachable;
        return this;
    }

    public TestingKeycloak setCredentialsAccepted(boolean credentialsAccepted)
    {
        this.credentialsAccepted = credentialsAccepted;
        return this;
    }

    public TestingKeycloak setAllowedToListUsers(boolean allowedToListUsers)
    {
        this.allowedToListUsers = allowedToListUsers;
        return this;
    }

    public TestingKeycloak setRealmExists(boolean realmExists)
    {
        this.realmExists = realmExists;
        return this;
    }

    /**
     * Revokes every access token issued so far, as an administrator would.
     */
    public void revokeIssuedTokens()
    {
        firstValidToken = issuedTokens.get() + 1;
    }

    public int tokenRequests()
    {
        return tokenRequests.get();
    }

    public int userLookups()
    {
        return userLookups.get();
    }

    public int groupLookups()
    {
        return groupLookups.get();
    }

    @Override
    public Response handle(Request request)
            throws Exception
    {
        if (!reachable) {
            throw new ConnectException("Connection refused: " + request.getUri());
        }
        URI uri = request.getUri();
        checkArgument(uri.getHost().equals(SERVER_URL.getHost()), "unexpected host: %s", uri);
        if (uri.getPath().equals(TOKEN_PATH)) {
            return handleTokenRequest(request);
        }
        if (!isTokenValid(request)) {
            throw unauthorized();
        }
        if (!realmExists) {
            return jsonResponse(NOT_FOUND, "{\"error\":\"Realm does not exist\"}");
        }
        if (!allowedToListUsers) {
            return jsonResponse(FORBIDDEN, "{\"error\":\"unknown_error\"}");
        }
        if (uri.getPath().equals(USERS_PATH)) {
            return handleUserLookup(uri);
        }
        Matcher groups = USER_GROUPS_PATH.matcher(uri.getPath());
        if (groups.matches() && groups.group(1).equals(REALM)) {
            groupLookups.incrementAndGet();
            return jsonResponse(OK, requireNonNull(groupsJsonByUserId.get(groups.group(2)), "no such user id"));
        }
        throw new IllegalArgumentException("Unexpected request: " + uri);
    }

    /**
     * Answers the way the plugin's HTTP client presents a Keycloak 401, which is not as a
     * response: Keycloak sends no {@code WWW-Authenticate} header with it, and Jetty fails such a
     * request as a protocol violation. A fake that returned a 401 status instead would let the
     * plugin be written against a status code it can never observe.
     */
    private static RuntimeException unauthorized()
    {
        return new RuntimeException("HTTP protocol violation: Authentication challenge without WWW-Authenticate header");
    }

    private Response handleTokenRequest(Request request)
    {
        tokenRequests.incrementAndGet();
        Map<String, String> form = parseForm(new String(((StaticBodyGenerator) request.getBodyGenerator()).getBody(), UTF_8));
        checkArgument(form.get("grant_type").equals("client_credentials"), "unexpected grant type: %s", form);
        if (!credentialsAccepted || !CLIENT_ID.equals(form.get("client_id")) || !CLIENT_SECRET.equals(form.get("client_secret"))) {
            throw unauthorized();
        }
        return jsonResponse(OK,
                """
                {"access_token":"%s","expires_in":%s,"token_type":"Bearer","not-before-policy":0,"scope":"profile email"}"""
                        .formatted(accessToken(issuedTokens.incrementAndGet()), accessTokenLifetimeSeconds));
    }

    private Response handleUserLookup(URI uri)
    {
        userLookups.incrementAndGet();
        Map<String, String> query = parseForm(uri.getRawQuery());
        checkArgument("true".equals(query.get("exact")), "expected an exact match: %s", uri);
        String username = requireNonNull(query.get("username"), "username is missing").toLowerCase(ENGLISH);
        String canned = usersJsonByUsername.get(username);
        if (canned != null) {
            return jsonResponse(OK, canned);
        }
        String userId = userIdsByUsername.get(username);
        if (userId == null) {
            return jsonResponse(OK, "[]");
        }
        return jsonResponse(OK, userJson(userId, usernamesByUserId.get(userId)));
    }

    private boolean isTokenValid(Request request)
    {
        String authorization = request.getHeader(AUTHORIZATION);
        for (int token = firstValidToken; token <= issuedTokens.get(); token++) {
            if (("Bearer " + accessToken(token)).equals(authorization)) {
                return true;
            }
        }
        return false;
    }

    private static String accessToken(int number)
    {
        return "access-token-" + number;
    }

    /**
     * A user as Keycloak describes one, so that a test proves the response is read despite the
     * fields this plugin does not declare.
     */
    public static String userJson(String userId, String username)
    {
        return """
               [{"id":"%s","username":"%s","firstName":"Given","lastName":"Family","email":"%s@example.com",
                 "emailVerified":true,"enabled":true,"totp":false,"createdTimestamp":1700000000000,
                 "disableableCredentialTypes":[],"requiredActions":[],"notBefore":0,
                 "access":{"manageGroupMembership":true,"view":true,"mapRoles":true,"impersonate":true,"manage":true}}]"""
                .formatted(userId, username, username);
    }

    private static String groupsJson(List<String> paths)
    {
        return paths.stream()
                .map(path -> """
                             {"id":"%s","name":"%s","path":"%s","parentId":"00000000-0000-0000-0000-000000000000","subGroupCount":0,"subGroups":[],"attributes":{}}"""
                        .formatted("group-id" + path.replace('/', '-'), path.substring(path.lastIndexOf('/') + 1), path))
                .reduce((left, right) -> left + "," + right)
                .map("[%s]"::formatted)
                .orElse("[]");
    }

    private static Response jsonResponse(HttpStatus status, String body)
    {
        return mockResponse(status, JSON_UTF_8, body);
    }

    private static Map<String, String> parseForm(String body)
    {
        ImmutableMap.Builder<String, String> parsed = ImmutableMap.builder();
        for (String pair : body.split("&")) {
            int separator = pair.indexOf('=');
            parsed.put(
                    URLDecoder.decode(pair.substring(0, separator), UTF_8),
                    URLDecoder.decode(pair.substring(separator + 1), UTF_8));
        }
        return parsed.buildOrThrow();
    }
}

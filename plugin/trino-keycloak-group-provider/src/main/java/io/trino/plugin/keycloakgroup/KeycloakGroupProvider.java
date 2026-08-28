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

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.util.concurrent.UncheckedExecutionException;
import com.google.inject.Inject;
import io.airlift.log.Logger;
import io.trino.cache.EvictableCacheBuilder;
import io.trino.plugin.keycloakgroup.KeycloakGroupProviderConfig.KeycloakGroupLookupErrorMode;
import io.trino.plugin.keycloakgroup.KeycloakGroupProviderConfig.KeycloakGroupNameField;
import io.trino.plugin.keycloakgroup.KeycloakGroupProviderConfig.KeycloakGroupSearchMode;
import io.trino.spi.security.GroupProvider;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;

import static com.google.common.base.Throwables.throwIfUnchecked;
import static com.google.common.collect.ImmutableSet.toImmutableSet;
import static io.trino.cache.CacheUtils.uncheckedCacheGet;
import static io.trino.cache.SafeCaches.buildNonEvictableCache;
import static io.trino.plugin.keycloakgroup.KeycloakGroupProviderConfig.KeycloakGroupLookupErrorMode.RETURN_STALE;
import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.MILLISECONDS;

public class KeycloakGroupProvider
        implements GroupProvider
{
    private static final Logger log = Logger.get(KeycloakGroupProvider.class);

    private final KeycloakClient client;
    private final KeycloakGroupLookupErrorMode errorMode;
    private final Function<KeycloakGroup, Stream<String>> groupNames;
    private final Cache<String, Set<String>> groups;
    /**
     * The result of the last successful lookup for a user, served when {@code RETURN_STALE} is
     * configured and Keycloak cannot be reached. Kept apart from the cache above because an
     * expiring cache does not retain an entry past its time to live, which is exactly when the
     * stale value is wanted.
     */
    private final Optional<Cache<String, Set<String>>> lastKnownGoodGroups;

    @Inject
    public KeycloakGroupProvider(KeycloakClient client, KeycloakGroupProviderConfig config)
    {
        this.client = requireNonNull(client, "client is null");
        this.errorMode = config.getGroupLookupErrorMode();
        this.groupNames = groupNames(config.getGroupSearchMode(), config.getGroupNameField());
        // A zero time to live is what disables an EvictableCache, so keycloak.cache.enabled=false
        // and keycloak.cache.ttl=0 are the same cache.
        long cacheTtlMillis = config.isCacheEnabled() ? config.getCacheTtl().toMillis() : 0;
        this.groups = EvictableCacheBuilder.newBuilder()
                .expireAfterWrite(cacheTtlMillis, MILLISECONDS)
                .maximumSize(config.getCacheMaximumSize())
                // EvictableCacheBuilder requires one of the two disabled-cache behaviours to be
                // chosen explicitly. Sharing nothing is what makes a disabled cache mean what it is
                // documented to mean - a lookup per request - rather than collapsing concurrent
                // lookups of one user into a single one.
                .shareNothingWhenDisabled()
                .recordStats()
                .build();
        this.lastKnownGoodGroups = errorMode == RETURN_STALE
                ? Optional.of(buildNonEvictableCache(CacheBuilder.newBuilder().maximumSize(config.getCacheMaximumSize())))
                : Optional.empty();
    }

    @Override
    public Set<String> getGroups(String user)
    {
        try {
            return uncheckedCacheGet(groups, user, () -> fetchGroups(user));
        }
        catch (UncheckedExecutionException e) {
            // Anything the loader throws arrives wrapped. Only an unreachable or misbehaving
            // Keycloak is subject to keycloak.group-lookup-error-mode; a broken assumption of this
            // plugin fails the query whatever that property says.
            if (e.getCause() instanceof KeycloakLookupException failure) {
                return onLookupFailure(user, failure);
            }
            throwIfUnchecked(e.getCause());
            throw e;
        }
    }

    private Set<String> fetchGroups(String user)
    {
        List<KeycloakGroup> keycloakGroups = client.fetchGroups(user);
        Set<String> names = keycloakGroups.stream()
                .flatMap(groupNames)
                .collect(toImmutableSet());
        lastKnownGoodGroups.ifPresent(cache -> cache.put(user, names));
        return names;
    }

    private Set<String> onLookupFailure(String user, KeycloakLookupException failure)
    {
        return switch (errorMode) {
            case RETURN_EMPTY -> {
                log.error(failure, "Keycloak group lookup failed for user [%s]; reporting no groups", user);
                yield ImmutableSet.of();
            }
            case RETURN_STALE -> {
                Set<String> stale = lastKnownGoodGroups.orElseThrow().getIfPresent(user);
                if (stale == null) {
                    log.error(failure, "Keycloak group lookup failed for user [%s] and no earlier result is held; reporting no groups", user);
                    yield ImmutableSet.of();
                }
                log.warn(failure, "Keycloak group lookup failed for user [%s]; reporting the groups from the last successful lookup", user);
                yield stale;
            }
            case FAIL -> throw failure;
        };
    }

    private static Function<KeycloakGroup, Stream<String>> groupNames(KeycloakGroupSearchMode searchMode, KeycloakGroupNameField nameField)
    {
        return switch (searchMode) {
            case DIRECT -> switch (nameField) {
                case NAME -> group -> Stream.of(group.name());
                case PATH -> group -> Stream.of(relativePath(group));
            };
            // Ancestors are only distinguishable by path, which keycloak.group-name-field enforces.
            case ANCESTORS -> group -> pathWithAncestors(relativePath(group));
        };
    }

    /**
     * Keycloak reports a path with a leading slash. It is dropped so that {@code PATH} reads as
     * {@code engineering/backend}, and so that a rules file does not need a leading empty segment
     * in every pattern.
     */
    private static String relativePath(KeycloakGroup group)
    {
        String path = group.path();
        return path.startsWith("/") ? path.substring(1) : path;
    }

    private static Stream<String> pathWithAncestors(String path)
    {
        ImmutableList.Builder<String> paths = ImmutableList.builder();
        for (int separator = path.indexOf('/'); separator >= 0; separator = path.indexOf('/', separator + 1)) {
            paths.add(path.substring(0, separator));
        }
        return paths.add(path).build().stream();
    }
}

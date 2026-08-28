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

import com.google.common.annotations.VisibleForTesting;
import com.google.inject.Injector;
import com.google.inject.Key;
import io.airlift.bootstrap.Bootstrap;
import io.airlift.http.client.HttpClient;
import io.airlift.units.Duration;
import io.trino.spi.security.GroupProvider;
import io.trino.spi.security.GroupProviderFactory;

import java.util.Map;
import java.util.Optional;

import static io.airlift.http.client.HttpClientBinder.httpClientBinder;
import static java.util.Objects.requireNonNull;
import static java.util.concurrent.TimeUnit.SECONDS;

public class KeycloakGroupProviderFactory
        implements GroupProviderFactory
{
    @Override
    public String getName()
    {
        return "keycloak";
    }

    @Override
    public GroupProvider create(Map<String, String> config)
    {
        return create(config, Optional.empty());
    }

    @VisibleForTesting
    static GroupProvider create(Map<String, String> config, Optional<HttpClient> httpClient)
    {
        requireNonNull(config, "config is null");
        requireNonNull(httpClient, "httpClient is null");

        Bootstrap app = new Bootstrap(
                "io.trino.bootstrap.groups.keycloak",
                binder -> httpClient.ifPresentOrElse(
                        client -> binder.bind(Key.get(HttpClient.class, ForKeycloak.class)).toInstance(client),
                        () -> httpClientBinder(binder)
                                .bindHttpClient("keycloak", ForKeycloak.class)
                                // Group lookups happen while a query is being analyzed, so a
                                // Keycloak that accepts a connection and then stops answering must
                                // not hold up the query for the five minutes Airlift allows by
                                // default. Two requests at a time is the whole workload.
                                .withConfigDefaults(clientConfig -> clientConfig
                                        .setRequestTimeout(new Duration(10, SECONDS))
                                        .setSelectorCount(1)
                                        .setMinThreads(1))),
                new KeycloakGroupProviderModule());

        Injector injector = app
                .doNotInitializeLogging()
                .disableSystemProperties()
                .setRequiredConfigurationProperties(config)
                .initialize();

        // Fail the node's startup rather than reporting no groups for every user, forever, because
        // of a typo in a client secret.
        injector.getInstance(KeycloakClient.class).verifyConfiguration();

        return injector.getInstance(GroupProvider.class);
    }
}

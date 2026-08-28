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

import io.trino.spi.TrinoException;

import static io.trino.spi.StandardErrorCode.GENERIC_INTERNAL_ERROR;

/**
 * Keycloak could not be reached, or answered with something other than the expected response.
 * <p>
 * This is the failure that {@code keycloak.group-lookup-error-mode} governs. Conditions that mean
 * an assumption of this plugin is broken rather than that Keycloak is unavailable - more than one
 * user matching an exact username, for instance - are thrown as a plain {@link TrinoException} and
 * always fail the query, whatever that property says.
 */
public class KeycloakLookupException
        extends TrinoException
{
    public KeycloakLookupException(String message)
    {
        super(GENERIC_INTERNAL_ERROR, message);
    }

    public KeycloakLookupException(String message, Throwable cause)
    {
        super(GENERIC_INTERNAL_ERROR, message, cause);
    }
}

# Group mapping

Group providers in Trino map usernames onto groups for easier access control
and resource group management.

Configure a group provider by creating an `etc/group-provider.properties` file
on the coordinator:

```properties
group-provider.name=file
```
The value for `group-provider.name` must be `file`, `keycloak`, or `ldap` and
the configuration of the chosen group provider must be included in the same
file.

:::{list-table} Group provider configuration
:widths: 40, 60
:header-rows: 1

* - Property name
  - Description

* - `group-provider.name`
  - Name of the group provider to use.
    Supported values are:

      * `file`: [See configuration](file-group-provider)
      * `keycloak`: [See configuration](keycloak-group-provider)
      * `ldap`: [See configuration](ldap-group-provider)
* - `group-provider.group-case`
  - Optional transformation of the case of the group name.
    Supported values are:

    * `keep`: default, no conversion
    * `upper`: convert group name to _UPPERCASE_
    * `lower`: converts the group name to _lowercase_

    Defaults to `keep`.
:::

## Integration with access control

Groups resolved by the group provider are passed to Trino’s system access
control engine. Access control rules can reference these group names to grant
or restrict permissions.

(file-group-provider)=
## File group provider

The file group provider resolves group memberships with the configuration in
the group-provider.properties file on the coordinator.

### Configuration

Enable the file group provider by creating an `etc/group-provider.properties`
file on the coordinator:

```properties
group-provider.name=file
file.group-file=/path/to/group.txt
```

The following configuration properties are available:

:::{list-table} File group provider configuration
:widths: 40, 60
:header-rows: 1

* - Property name
  - Description
* - `file.group-file`
  - Path of the group file.
* - `file.refresh-period`
  - [Duration](prop-type-duration) between refreshing the group mapping
    configuration from the file. Defaults to `5s`.
:::

### Group file format

The group file contains a list of groups and members, one per line,
separated by a colon. Users are separated by a comma.

```text
group_name:user_1,user_2,user_3
```

(keycloak-group-provider)=
## Keycloak group provider

The Keycloak group provider resolves user group memberships from a Keycloak
realm, so that access control rules can be written against the groups that
already exist in Keycloak instead of individual users.

Trino reads the memberships from Keycloak's Admin REST API as a service account
client, rather than from the tokens of users who sign in. Group memberships are
therefore available for every username Trino needs to authorize, including the
owner of a view and the users named in row filters and column masks, none of
whom have necessarily signed in.

### Configuration

Enable the Keycloak group provider by creating an `etc/group-provider.properties`
file on the coordinator:

```properties
group-provider.name=keycloak
keycloak.url=https://keycloak.example.com
keycloak.realm=employees
keycloak.client-id=trino-group-provider
keycloak.client-secret=secret
```

The following configuration properties are available:

:::{list-table} Keycloak group provider configuration
:widths: 40, 60
:header-rows: 1

* - Property name
  - Description
* - `keycloak.url`
  - Base URL of the Keycloak server, for example
    `https://keycloak.example.com`. This is the root of the server, not the URL
    of a realm. Required.
* - `keycloak.realm`
  - Name of the realm whose users and groups are looked up. Required.
* - `keycloak.client-realm`
  - Name of the realm that the service account client itself belongs to.
    Defaults to the value of `keycloak.realm`.
* - `keycloak.client-id`
  - Client ID of the Keycloak client Trino authenticates as. Required.
* - `keycloak.client-secret`
  - Client secret of the Keycloak client Trino authenticates as. Required.
* - `keycloak.group-name-field`
  - Field of the Keycloak group to use as the group name in Trino.
    Supported values are:

    * `NAME`: default, the name of the group alone, for example `backend`
    * `PATH`: the full path of the group, for example `engineering/backend`
* - `keycloak.group-search-mode`
  - Whether to report the ancestors of a group in addition to the group itself.
    Supported values are:

    * `DIRECT`: default, report only the groups a user is assigned to
    * `ANCESTORS`: additionally report every ancestor of those groups, so that a
      member of `engineering/backend` is also a member of `engineering`.
      Requires `keycloak.group-name-field=PATH`.
* - `keycloak.group-lookup-error-mode`
  - What to report when Keycloak cannot be reached or answers with an error.
    Supported values are:

    * `RETURN_EMPTY`: default, report no groups for the user
    * `RETURN_STALE`: report the groups from the last successful lookup for that
      user, or no groups if there has not been one. Requires the cache to be
      enabled with a non-zero `keycloak.cache.ttl`.
    * `FAIL`: fail the operation that requested the groups
* - `keycloak.cache.enabled`
  - Cache the groups of each user. Set to `false` to look them up on every
    request. Defaults to `true`.
* - `keycloak.cache.ttl`
  - [Duration](prop-type-duration) for which a user's groups are cached.
    `0s` disables the cache like `keycloak.cache.enabled=false`. Defaults to
    `5s`.
* - `keycloak.cache.maximum-size`
  - Maximum number of users to cache groups for. Defaults to `1000`.
* - `keycloak.http-client.*`
  - Optional HTTP client configuration for the connection from Trino to Keycloak,
    for example `keycloak.http-client.http-proxy` for configuring the HTTP proxy.
    Find more details in [](/admin/properties-http-client).
:::

### Keycloak configuration

Trino needs a Keycloak client that authenticates with the `client_credentials`
grant and is allowed to read the users of the realm:

1. Create a client in Keycloak with **Client authentication** enabled, and with
   **Service accounts roles** as its only enabled authentication flow.
2. Copy the client secret into `keycloak.client-secret`.
3. Grant the `view-users` role to the client's service account. This is the only
   permission Trino needs; it never writes to Keycloak.

The client can live in the realm it reads, or in another realm. Where the
`view-users` role comes from depends on which:

* When the client is in the same realm, `view-users` is a role of that realm's
  `realm-management` client. Leave `keycloak.client-realm` unset.
* When the client is in the `master` realm, `view-users` is a role of the
  `<realm>-realm` client inside `master`, where `<realm>` is the value of
  `keycloak.realm`. Set `keycloak.client-realm=master`. This is the arrangement
  to use when one client resolves groups for several realms.

Trino verifies both the credentials and the `view-users` role at startup, and
refuses to start if either is missing. A client that authenticates but cannot
list users is otherwise indistinguishable from every user belonging to no
groups.

:::{warning}
This check runs on every node that has an `etc/group-provider.properties` file,
not only on the coordinator, because that is where Trino loads a group provider.
While Keycloak is unreachable, no such node starts, so a rolling restart leaves
every node that cycles down until Keycloak answers again. Groups are only ever
resolved on the coordinator, so keep `etc/group-provider.properties` on the
coordinator alone, as described above.
:::

### Group membership semantics

Keycloak reports the groups a user is **directly** assigned to. A user assigned
to `/engineering/backend` is not a member of `/engineering`, and Trino reports
what Keycloak reports. Set `keycloak.group-search-mode=ANCESTORS` to have Trino
add the ancestors of each assigned group.

Group names are not necessarily unique in Keycloak, because two groups in
different parts of the hierarchy can have the same name. Use
`keycloak.group-name-field=PATH` where that matters, so that
`engineering/backend` and `sales/backend` remain distinct.

Keycloak matches usernames without regard to case, so a Trino user named `ALICE`
resolves to the groups of the Keycloak user `alice`.

### Failure behavior

By default, a Keycloak that cannot be reached results in the user being reported
as a member of no groups, and the failure is logged.

:::{warning}
Reporting no groups is not the same as denying access. Access control rules that
grant permissions to a group stop matching, but rules that deny permissions to a
group stop matching as well. Use `keycloak.group-lookup-error-mode=FAIL` if a
Keycloak outage must fail queries instead.
:::

`keycloak.group-lookup-error-mode` covers failures to reach or read Keycloak. It
does not cover a response that contradicts what this group provider assumes -
more than one user matching an exact username, for example. Those always fail
the operation, whatever the property is set to.

### Supported Keycloak versions

The group provider is verified against Keycloak 22 through 26.7. It uses only
the Admin REST API endpoints for user lookup and group membership, which have
been stable across those releases.

### Example configuration

The following configuration resolves groups for the `employees` realm with a
client in the `master` realm, reports full group paths with their ancestors, and
keeps serving the last known groups of a user while Keycloak is unavailable:

```properties
group-provider.name=keycloak
group-provider.group-case=lower

keycloak.url=https://keycloak.example.com
keycloak.realm=employees
keycloak.client-realm=master
keycloak.client-id=trino-group-provider
keycloak.client-secret=your_client_secret

keycloak.group-name-field=PATH
keycloak.group-search-mode=ANCESTORS
keycloak.group-lookup-error-mode=RETURN_STALE
keycloak.cache.ttl=5m
```

(ldap-group-provider)=
## LDAP group provider

The LDAP group provider resolves user group memberships from configuration
retrieved from an LDAP server. This allows access rules to be defined based on
LDAP groups instead of individual users.

### Configuration

Enable LDAP group provider by creating an `etc/group-provider.properties` file
on the coordinator and add further configuration for the LDAP server
connections and other information as detailed in the following sections.

```properties
group-provider.name=ldap
```

:::{list-table} Generic LDAP properties
:widths: 40, 60
:header-rows: 1
* - Property name
  - Description
* - `ldap.url`
  - LDAP server URI.  For example, `ldap://host:389` or `ldaps://host:636`.
* - `ldap.allow-insecure`
  - Allow insecure connection to the LDAP server. Defaults to `false`.
* - `ldap.ssl.keystore.path`
  - Path to the PEM or JKS key store.
* - `ldap.ssl.keystore.password`
  - Password for the key store.
* - `ldap.ssl.truststore.path`
  - Path to the PEM or JKS trust store.
* - `ldap.ssl.truststore.password`
  - Password for the trust store.
* - `ldap.ignore-referrals`
  - Referrals allow finding entries across multiple LDAP servers. Ignore them
    to only search within one LDAP server. Defaults to `false`.
* - `ldap.timeout.connect`
  - Timeout [duration](prop-type-duration) for establishing a connection.
    Defaults to `1m`.
* - `ldap.timeout.read`
  - Timeout [duration](prop-type-duration) for reading data from LDAP.
    Defaults to `1m`.
* - `ldap.admin-user`
  - Bind distinguished name for admin user. For example,
    `CN=UserName,OU=City,OU=State,DC=domain,DC=domain_root`
* - `ldap.admin-password`
  - Bind password used for the admin user.
* - `ldap.user-base-dn`
  - Base distinguished name for users. For example, `dc=example,dc=com`.
* - `ldap.user-search-filter`
  - LDAP filter to find user entries; `{0}` is replaced with the Trino username.
    For example, `(cn={0})`
* - `ldap.group-name-attribute`
  - Attribute to extract group name from group entry. For example, `cn`.
* - `ldap.use-group-filter`
  - Whether to use search-based group resolution. Defaults to `true`.
    When `false`, Trino uses the attribute-based method.
:::

Group resolution behavior is controlled by the `ldap.use-group-filter` property.
With search-based group resolution, Trino searches for group entries that
include the user DN. This requires the following properties:

:::{list-table} Search-based group resolution
:widths: 40, 60
:header-rows: 1
* - Property name
  - Description
* - `ldap.group-base-dn`
  - Base distinguished name for groups. For example, `dc=example,dc=com`.
* - `ldap.group-search-filter`
  - Search filter for group documents. For example, `(cn=trino_*)`.
* - `ldap.group-search-member-attribute`
  - Attribute from group documents used for filtering by member. For example,
    `cn`.
:::

In case of attribute-based group resolution, Trino reads the group list
directly from a user attribute. This requires the following property:

:::{list-table} Attribute-based (single query) group resolution
:widths: 40, 60
:header-rows: 1

* - Property name
  - Description
* - `ldap.user-member-of-attribute`
  - Group membership attribute in user documents. For example, `memberOf`.
:::

### Example configurations

The following configuration is an example for an OpenLDAP (search-based)
group provider:

```properties
group-provider.name=ldap
group-provider.group-case=lower

ldap.url=ldap://ldap.example.com:389
ldap.admin-user=cn=admin,dc=example,dc=com
ldap.admin-password=your_password
ldap.group-name-attribute=cn
ldap.user-base-dn=ou=users,dc=example,dc=com
ldap.user-search-filter=(uid={0})
ldap.use-group-filter=true

ldap.group-base-dn=ou=groups,dc=example,dc=com
ldap.group-search-filter=(cn=trino_*)
ldap.group-search-member-attribute=member
```

The following configuration is an example for an Active Directory
(single query, attribute-based) group provider:

```properties
group-provider.name=ldap
group-provider.group-case=lower

ldap.url=ldaps://ad.example.com:636
ldap.admin-user=cn=admin,dc=example,dc=com
ldap.admin-password=your_password
ldap.group-name-attribute=cn
ldap.user-base-dn=ou=users,dc=example,dc=com
ldap.user-search-filter=(sAMAccountName={0})
ldap.use-group-filter=false

ldap.user-member-of-attribute=memberOf
```

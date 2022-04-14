# Grindery Nexus Credential Manager Specification

This document specifies the Grindery Nexus Credential Manager API methods.


## cm_putConnectorSecrets

Stores connector secrets i.e environment variables.

**Parameters:**

Index | Type | Description
------|------|------------
1 | `string` | id of the connector.
2 | `object` | key, value map where the key is the name of the secret and the value is the value of the secret.

**Returns:**

none.

**NOTE:** Stored secrets can be referenced with the `{{secrets.<key>}}` syntax in the parameters of other methods.


## cm_putAuthCredentials

Retrieves and stores user authentication credentials e.g username and password for basic and digest auth or access token and refresh token for OAuth.
 
**Parameters:**

Index | Type | Description
------|------|------------
1 | `string` | id of the connector.
2 | `string` | DID of the user.
3 | oneOf([RequestSchema](https://github.com/grindery-io/grindery-nexus-schema/tree/master/connectors#requestschema), object)  | the request to make to retrieve the user’s authentication credentials (e.g the `getAccessToken` call from the [OAuth2](https://github.com/grindery-io/grindery-nexus-schema/tree/master/connectors#authenticationoauth2configschema) and [OAuth1](https://github.com/grindery-io/grindery-nexus-schema/tree/master/connectors#authenticationoauth1configschema) config of the connector) or a key, value map where the key is the name of the auth secret and the value is the value of the auth secret e.g (the username and password for `basic` and `digest` authentication).
4 | `string` | Display name for the credentials.

**Returns:**

`string` | the id of the auth credential.

**Processing:**

In the case of a request (e.g OAuth2), all response data should be stored, not just the access token and refresh token.

Along with the display name passed in with the request, some additional metadata about credentials should be stored for use by the [cm_getAuthCredentialsDisplayInfo](#cm_getauthcredentialsdisplayinfo) method e.g a creation date/time.

**NOTE:** Stored auth credentials can be referenced with the `{{auth.<key>}}` syntax in the parameters of other methods


## cm_getAuthCredentialsDisplayInfo

Returns metadata about existing auth credentials.

**Parameters:**

Index | Type | Description
------|------|------------
1 | `string` | id of the connector.
2 | `string` | DID of the user.

**Returns:**

`Array<object>` | an array of object each representing one auth credential item.

Each auth credential item should have the following properties.

Key | Type | Description
----|------|------------
`id` | `string` | the id of the auth credentials.
`name` | `string` |  the display name of the auth credentials, See `cm_putAuthCredentials`.
`createdAt` | `string` | the creation date/time of the auth credentials.



## cm_makeRequest

Makes an authenticated request and returns the response

**Parameters:**

Index | Type | Description
------|------|------------
1 | `string` | id of the connector.
2 | `string` | id of the auth credentials.
3 | [RequestSchema](https://github.com/grindery-io/grindery-nexus-schema/tree/master/connectors#requestschema)  | the request to make.

**Returns:**

`object` | an object that represents the response received for the request.

The response object should have the following properties.

Key | Type | Description
----|------|------------
`data` | oneOf(`object`, `string`) | the response data.
`headers` | `object` | the response headers.

**Processing:**

The connector id should be used to retrieve the [authentication config](https://github.com/grindery-io/grindery-nexus-schema/tree/master/connectors#authenticationschema), 
whose `type` and other definitions then determines which headers and/or parameters to add to the request.
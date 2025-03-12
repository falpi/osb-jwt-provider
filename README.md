<p align="center"><img src="https://github.com/user-attachments/assets/acfcac92-b4c7-46a6-a85a-c597c6f02ac0" /></p>

<h1 align="center">WebLogic Identity Assertion Provider<br/>for OAUTH2/JWT authentication on<br/>Oracle Service Bus</h1>
An highly configurable WebLogic Custom Identity Assertion Provider with support for inbound OAUTH2/JWT authentication for Oracle Service Bus Proxy Services.<br/>

## Overview
<p align="justify">Up to and including version 12.1.3 the Oracle Service Bus does not support OAUTH2/JWT inbound and outbound authentication out of the box. Starting with version 12.2.1, the Bus supports it through the use of OWSM policies but without the certification and flexibility needed to use a third-party IDP such as Azure Entra ID.<br/><br/>
Furthermore, the use of OWSM policies may not be a proper solution for those who are used to managing authentication and authorization through the simple management of users and groups of the integrated authentication provider of WebLogic. As if that wasn't enough, OAUTH2 introduces the need to adopt identities defined by very long and opaque strings (client_id), impossible to re-associate to a given consumer without appropriate mechanisms of credential mappings and in this OWSM is of no help.<br/><br/>
Fortunately, since the old versions of WebLogic there is the possibility to extend the product to support custom authentication schemes. The proposed library is based in particular on a Custom Identity Assertion Provider that supports OAUTH2 authentication based on signed JWT tokens and offer also an optional identity mappings mechanism to translate client_ids to weblogic realm users.<br/><br/>
In addition to the JWT-based authentication scheme, the provider also offers support for the legacy Basic Auth to simplify the progressive adoption of JWT authentication by different consumers on the same Proxy Service, without the need to create different Proxies for each authentication scheme.</p>

## Token Types
<p align="justify">In WebLogic Identity Asserter terminology, Token Types are a way to declare which authentication schemes a given provider supports and which are active at a given time, i.e. which can be selected for authentication of a Proxy Service. The provider proposed in this project supports the JWT and BASIC schemes and allows to select them individually or in a combined way through the "JWT+BASIC" type.<br/><br/>
The "JWT+BASIC" typology is useful because on a given Proxy Service it is possible to select only one type of token at a time and the combined token allows to keep both authentication schemes active at the same time on a single Proxy Service. This allows to implement a progressive migration of consumers from the BASIC scheme to the JWT scheme in a progressive way, without having to create different Proxy Services for each scheme.</p>
<p align="center"><img src="https://github.com/user-attachments/assets/a94a2dd0-2c46-45eb-aab2-d28b82ed1493" /></p>
<p align="justify">
As you can see from the image the provider offers similar types but with a different suffix (#1 and #2). This makes it possible to create multiple instances of the same provider and differentiate their configuration to support different IDPs.</p>

## How to configure Proxy Services
<p align="justify">To enable custom authentication, you need to act on the configuration of the transport details of a proxy service, as highlighted in the following screenshot. The selected token must be one of those selected as active for the provider (with the prefix "CIA." which stands for "Custom Identity Asserter").</p>
<p align="center"><img src="https://github.com/user-attachments/assets/29391a49-5547-48e4-a05d-3ff937863811" /></p>
<p align="justify">In the "Authentication Header" field, the http header must be specified, whose presence activates the use of the custom authentication provider. It can be any valid identifier, however if you want to support the BASIC authentication scheme together with the JWT scheme, the header must necessarily be the standard "Authorization" one as shown in the image.</p>

## Provider Parameters
<p align="justify">The provider is highly configurable and can be adapted to be used with different types of identity providers. It has currently been tested on an Oracle Service Bus 12.1.3 and with Azure Entra ID as the IDP. Below is a detailed description of each parameters and a screenshot of the available parameters populated with sample values is provided further down.</p>

Parameter                     | Description                                                     
----------------------------- | --------------------------------------------------------------- 
`LOGGING_LEVEL`               | Minimum level of log messages that end up in the logging file.
`BASIC_AUTH_STATUS`           | Allows to control Basic authentication if it is among those actives.
`JWT_AUTH_STATUS`             | Allows to control JWT authentication if it is among those actives.
`JWT_KEYS_URL`                | Download URL for public keys used for JWT signature validation.
`JWT_KEYS_FORMAT`             | Payload format for public keys. Could be JSON or XML.
`JWT_KEYS_MODULUS_XPATH`      | XPath expression for public key modulus. If payload is in JSON format it's translated to XML before. The default value is suitable for standard JWKS (JSON Web Key Set).
`JWT_KEYS_EXPONENT_XPATH`     | XPath expression for public key exponent. If payload is in JSON format it's translated to XML before. The default value is suitable for standard JWKS (JSON Web Key Set).
`JWT_KEYS_CACHE_TTL`          | Public keys caching duration (Seconds).
`JWT_KEYS_CONN_TIMEOUT`       | Public keys server connection timeout (Seconds).
`JWT_KEYS_READ_TIMEOUT`       | Public keys server response timeout (Seconds)-
`JWT_KEYS_SSL_VERIFY`         | Public keys request SSL enforcement. Use only in non-production environement to test endpoints.
`JWT_KEYS_HOST_AUTH_MODE`     | Public keys server require authentication. The following choices are supported : ANONYMOUS, BASIC, NTLM, KERBEROS (NEGOTIATE).
`JWT_KEYS_HOST_ACCOUNT_PATH`  | OSB resource path (\*) of the "Service Account" used to get public keys credentials.
`JWT_KEYS_PROXY_SERVER_MODE`  | Public keys server require proxy mediation.  The following choices are supported : DIRECT (no proxy), ANONYMOUS, BASIC, NTLM, KERBEROS (NEGOTIATE).
`JWT_KEYS_PROXY_SERVER_PATH`  | OSB resource path (\*) for the "Proxy Server" used to extract proxy host and credentials.
`JWT_IDENTITY_MAPPING_MODE`   | Specifies whether the token identity is translated into the WebLogic realm username using an OSB "Service Account" resource.
`JWT_IDENTITY_MAPPING_PATH`   | OSB resource path (\*) of the "Service Account" used for mapping user identity to realm username.
`JWT_IDENTITY_ASSERTION`      | Must contain a javascript text that returns the identity of the jwt token according to the specifications of the IDP used. It must return a String object.
`VALIDATION_ASSERTION`        | May contain a javascript text that must validate or reject the authentication request according to arbitrary criteria defined by the user. If present, it must return a Boolean object.
`DEBUGGING_ASSERTION`         | May contain a javascript text that is used to filter log messages with TRACE or DEBUG level according to arbitrary criteria defined by the user. This can be useful to reduce log messages and analyze specific requests. If present, it must return a Boolean object.
`KERBEROS_CONFIGURATION`      | May contain text that defines the configuration for outgoing Kerberos calls. Must follow the standard "krb5.conf" file format (https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/krb5_conf.html). Note that at least under the Windows operating system, often no configuration is necessary.                                                                                                                      

<p align="center"><img src="https://github.com/user-attachments/assets/fb5b2ba8-d923-49af-916b-0126d80ad10a" /></p>

## Substitution Variables
<p align="justify">All string configuration parameters support the use of substitution variables to create configurations that can dynamically adapt to the runtime state. The following is a list of supported variables.</p>

Variable                      | Replaced by                                                    
----------------------------- | ------------------------------------------------------------------------------------
`${osb.server}`               | The name of the WebLogic Managed Server that took charge of the request 
`${osb.project}`              | The name of the Osb Project that the endpoint that received the request is part of
`${osb.service}`              | The name of the Osb Proxy Service that took charge of the request
`${http.client.host}`         | The remote/client hostname of the http request
`${http.client.addr}`         | The remote/client address of the http request
`${http.server.host}`         | The local/server hostname of the machine that took charge of the request
`${http.server.addr}`         | The local/server address of the machine that took charge of the request
`${http.server.name}`         | The hostname declared in the http request by the client
`${http.content.type}`        | The content mime/type declared in http request by the client
`${http.content.body}`        | The body sent in http request by the client
`${http.content.length}`      | The content length of body 
`${http.request.url}`         | The original url of http request
`${http.request.proto}`       | The protocol version of http request
`${http.request.scheme}`      | The scheme of http request
`${http.header.<name>}`       | The value of the http header \<name\> in the http request
`${http.header.*}`            | A string with the key/value list of all http headers of the request
`${token.header.<attr>}`      | The value of the header \<attr\> element in the JWT token
`${token.payload.<attr>}`     | The value of the payload \<attr\> element in the JWT token
`${identity}`                 | The jwt token identity constructed from the assertion
`${username}`                 | The name of the user that must be present in the WebLogic realm. In the case of Basic Auth it coincides with the authenticated user while in the case of JWT Auth, if mapping is not required it coincides with the token identity otherwise it is the user mapped by the OSB mapping service account.<br/>

## Build instructions
<p align="justify">
The sources can be compiled with any Java IDE with Ant support but you need to prepare the necessary dependencies for WebLogic and Oracle Service Bus libraries. The repository contains a project already prepared for a JDeveloper 12.1.3 installed as part of the Oracle SOA Suite Quick Start for Developers (see references).<br/>

Ant compilation can be triggered from JDeveloper by right-clicking on the "Build.xml" file and selecting the "all" target or from the command line by running the "Build.cmd" batch.
In both cases, at the end of the compilation, two jar archives are produced and automatically copied to the ```<WEBLOGIC_HOME>/wlserver/server/lib/mbeantypes``` folder from which WebLogic loads the security providers at startup. At the end of the compilation, you can directly launch the WebLogic environment integrated into JDeveloper to test the provider's operation.</p>

## Credits
- **JSON-java** (https://github.com/stleary/JSON-java)<br/>
- **Apache HttpClient** (https://hc.apache.org/httpcomponents-client-4.5.x/index.html)<br/>
- **Nimbus JOSE + JWT** (https://connect2id.com/products/nimbus-jose-jwt)<br/>

## References
- Installing Oracle SOA Suite Quick Start for Developers 12.1.3:<br/> https://docs.oracle.com/middleware/1213/soasuite/index.html
- WebLogic 12.1.3 Identity Assertion Providers:<br/> https://docs.oracle.com/middleware/1213/wls/DEVSP/ia.htm
- WebLogic 12.1.3 Security Providers Developer Guide:<br/> https://docs.oracle.com/middleware/1213/wls/DEVSP/DEVSP.pdf
- Generate an MBean Type Using the WebLogic MBeanMaker:<br/> https://docs.oracle.com/middleware/1213/wls/DEVSP/generate_mbeantype.htm
- Sample Custom Identity Asserter for Weblogic Server:<br/> https://weblogic-wonders.com/simple-sample-custom-identity-asserter-weblogic-server-12c/
- Sample Custom SSO using Weblogic IdentityAsserter:<br/> https://virtual7.de/en/blog/custom-sso-using-weblogic-identityasserter

<p align="center"><img src="https://github.com/user-attachments/assets/acfcac92-b4c7-46a6-a85a-c597c6f02ac0" /></p>
<div id="user-content-toc" align="center"><ul><summary><h1 align="center">WebLogic Identity Assertion Provider<br/>for OAUTH2/JWT authentication on<br/>Oracle Service Bus</h1></summary></ul></div>

## Overview
<p align="justify">Up to and including version 12.1.3 the Oracle Service Bus does not support OAUTH2/JWT inbound and outbound authentication out of the box. Starting with version 12.2.1, the Bus supports it through the use of OWSM policies but without the certification and flexibility needed to use a third-party IDP such as Azure Entra ID.<br/><br/>
Furthermore, the use of OWSM policies may not be a proper solution for those who are used to managing authentication and authorization through the simple management of users and groups of the integrated authentication provider of WebLogic. As if that wasn't enough, OAUTH2 introduces the need to adopt identities defined by very long and opaque strings (client_id), that are difficult to re-associate to a given consumer without appropriate mechanisms of credential mappings and in this OWSM is of no help.<br/><br/>
Fortunately, since the old versions of WebLogic there is the possibility to extend the product to support custom authentication schemes. The proposed library is based in particular on a Custom Identity Assertion Provider that supports OAUTH2 authentication based on signed JWT tokens and offer also an optional identity mappings mechanism to translate client_ids to weblogic realm users.<br/><br/>
In addition to the JWT-based authentication scheme, the provider also offers support for the legacy Basic Auth to simplify the progressive adoption of JWT authentication by different consumers on the same Proxy Service, without the need to create different Proxies for each authentication scheme.<br/><br/>
It has currently been tested on an Oracle Service Bus 12.1.3 and 12.2.1.4 and with Azure Entra ID as the IDP</p>

## Installation
<p align="justify">For in-depth information on Custom Providers, please refer to the product documentation (see references). In short, first you need to stop WebLogic and copy the provider packages into the folder:</p>

```<WEBLOGIC_HOME>/wlserver/server/lib/mbeantypes```

<p align="justify">Once you have restarted WebLogic, as shown in the following screenshots, you just need to create a new provider using the "Provider" tab of the Realm settings in WebLogic Console, selecting the "CustomIdentityAsserter" (CIA) item which is the identifier of this provider. We then need to reorder the providers to move ours to the top.</p>
<p align="center"><img src="https://github.com/user-attachments/assets/75512bac-005a-447e-8d12-9b999fab4c7f" /></p>
<p align="center"><img src="https://github.com/user-attachments/assets/59a05b5c-1565-4bf7-99fb-8233e2da9e1f" /></p>

## Token Types
<p align="justify">Installing the provider registers in the system the presence of new types of "Tokens" that can be used to secure the Proxy Services. In WebLogic Identity Asserter terminology, Token Types are a declarative way to show which authentication schemes a given provider supports and which are active at a given time, i.e. which can be selected for authentication of a Proxy Service. The provider proposed in this project supports the JWT and BASIC schemes and allows to select them individually or in a combined way through the "JWT+BASIC" type.<br/><br/>
The "JWT+BASIC" typology is useful because on a given Proxy Service it is possible to select only one type of token at a time and the combined token allows to keep both authentication schemes active at the same time on a single Proxy Service. This allows to implement a progressive migration of consumers from the BASIC scheme to the JWT scheme in a progressive way, without having to create different Proxy Services for each scheme.<br/><br/> 
As you can see from the image below the provider offers similar types but with a different suffix (#1 and #2). This makes it possible to create multiple instances of the same provider and differentiate their configuration to support different IDPs.</p>

<p align="center"><img src="https://github.com/user-attachments/assets/a94a2dd0-2c46-45eb-aab2-d28b82ed1493" /></p>

## How to configure Proxy Services
<p align="justify">To enable the use of our provider on Proxy Services, you need to act from the JDeveloper IDE or from the Service Bus console on the configuration of the Proxy transport details as shown in the following screenshot.</br></br>
In the "Authentication Header" field the http header must be specified, whose presence activates the use of the custom authentication provider. It can be any valid identifier, however if you want to support the BASIC authentication scheme together with the JWT scheme, the header must necessarily be the standard "Authorization".</br></br>
In the "Authentication Token Type" field you need to select one of the token types selected as active in the Provider configuration.</p>

<p align="center"><img src="https://github.com/user-attachments/assets/29391a49-5547-48e4-a05d-3ff937863811" /></p>

## Provider Parameters
<p align="justify">The provider is highly configurable and can be adapted to be used with different types of identity providers.<br/>Below is a detailed description of each parameter.</p>

Parameter                     | Description                                                      
----------------------------- | --------------------------------------------------------------- 
`LOGGING_LEVEL`               | Minimum level of log messages printed.
`LOGGING_LINES`               | Maximum number of stacktrace lines logged.
`BASIC_AUTH`                  | Allows to control Basic authentication if it is among those actives.
`JWT_AUTH`                    | Allows to control JWT authentication if it is among those actives.
`JWT_KEYS_URL`                | Download URL for public keys used for JWT signature validation.
`JWT_KEYS_FORMAT`             | Payload format for public keys. Could be JSON or XML.
`JWT_KEYS_MODULUS_XPATH`      | XPath expression for public key modulus. If payload is in JSON format it's translated to XML before. The default value is suitable for standard JWKS (JSON Web Key Set).
`JWT_KEYS_EXPONENT_XPATH`     | XPath expression for public key exponent. If payload is in JSON format it's translated to XML before. The default value is suitable for standard JWKS (JSON Web Key Set).
`JWT_KEYS_CACHE_TTL`          | Public keys caching duration (Seconds).
`JWT_KEYS_CONN_TIMEOUT`       | Public keys server connection timeout (Seconds).
`JWT_KEYS_READ_TIMEOUT`       | Public keys server response timeout (Seconds).
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
`DEBUGGING_PROPERTIES`        | Allows you to send one or more string expressions to the log file. They are printed as log messages with DEBUG level. Any template variables are resolved allowing you to analyze the runtime context. 
`KERBEROS_CONFIGURATION`      | May contain text that defines the configuration for outgoing Kerberos calls. Must follow the standard "krb5.conf" file format (https://web.mit.edu/kerberos/krb5-1.12/doc/admin/conf_files/krb5_conf.html). Note that at least under the Windows operating system, often no configuration is necessary.<br/>                                                                                                                     

(*) OSB resources path are constructed as follows: `<project-name>/<root-folder>/.../<parent-folder>/<resource-name>`.<br/>
If a resource is located directly under a project, the path is constructed as follows: `<project-name>/<resource-name>`.<br/>
Please note that resources of type "Proxy Server" can only be created in the fixed path `System/Proxy Servers/<resource-name>`.<br/>

For more information on OSB resources follow this [link](https://docs.oracle.com/cd/E23943_01/admin.1111/e15867/project_explorer.htm#OSBAG822)<br/>
 
Below is a screenshot of the available parameters populated with sample values suitable for Azure Entra ID.<br/>
<p align="center"><img src="https://github.com/user-attachments/assets/956c93e2-30b1-4e31-a71d-2f497996ce0f" /></p>

## Template Variables
<p align="justify">All string configuration parameters support the use of substitution variables to create configurations that can dynamically adapt to the runtime state. The following is a list of supported variables.</p>

Variable                      | Replaced by                                                    
----------------------------- | ------------------------------------------------------------------------------------
`${osb.server}`               | The name of the WebLogic Managed Server that took charge of the request. 
`${osb.project}`              | The name of the Osb Project that the endpoint that received the request is part of.
`${osb.service}`              | The name of the Osb Proxy Service that took charge of the request.
`${http.client.host}`         | The remote/client hostname of the http request.
`${http.client.addr}`         | The remote/client address of the http request.
`${http.server.host}`         | The local/server hostname of the machine that took charge of the request.
`${http.server.addr}`         | The local/server address of the machine that took charge of the request.
`${http.server.name}`         | The hostname declared in the http request by the client.
`${http.content.type}`        | The content mime/type declared in http request by the client.
`${http.content.body}`        | The body sent in http request by the client.
`${http.content.length}`      | The content length of body.
`${http.request.url}`         | The original url of http request.
`${http.request.proto}`       | The protocol version of http request.
`${http.request.scheme}`      | The scheme of http request.
`${http.header.<name>}`       | The value of the http header \<name\> in the http request.
`${http.header.*}`            | A string with the key/value list of all http headers of the request.
`${token.header.<attr>}`      | The value of the header \<attr\> element in the JWT token.
`${token.payload.<attr>}`     | The value of the payload \<attr\> element in the JWT token.
`${identity}`                 | The jwt token identity constructed from the assertion.
`${username}`                 | The name of the user that must be present in the WebLogic realm. In the case of Basic Auth it coincides with the authenticated user while in the case of JWT Auth, if mapping is not required it coincides with the token identity otherwise it is the user mapped by the OSB mapping service account.<br/>

## Identity mapping strategies
<p align="justify">It is possible to implement different strategies to establish the identities of the JWT token and eventually map this identity to the users of the weblogic realm. Let's see some possible scenarios below.</p>

#### 1. Direct identity
<p align="justify">The simplest scenario is to use one of the attributes of the JWT token that uniquely defines its identity (typically a "client_id"), ensuring that in the weblogic realm there is a user with the same username as the identity. This scenario does not require any identity mapping and does not necessarily require the use of special JWT claims. The problem is that in the WebLogic realm we observe the proliferation of esoteric users that are not immediately attributable to consumers. Furthermore, if a consumer already authenticates with a Basic Auth on an existing weblogic user, it cannot be reused and the profiling of users must be reproduced from scratch.</p>

#### 2. Claim identity
<p align="justify">If you can fully trust the identity provisioning process on the IDP and it is possible to request the configuration of the claims on the JWT token it is possible to implement a form of identity mapping by delegating it to the IDP. For example, you could use the standard claim "sub" (Subject) making sure that it is populated with one of the users of the weblogic realm that at this point can be created according to the format that you like, possibly reusing existing users for the Basic Auth and therefore without the need to re-profile them.</p>

In this case the `JWT_IDENTITY_ASSERTION` parameter would be valued with: `'${token.payload.sub}'`.<br/>

#### 3. Mapped identity
<p align="justify">If you prefer not to delegate the identity mapping to the IDP, you can use any of the JWT token attributes to extrapolate its identity and then map it to a realm username using a OSB "Service Account" resource. For example, if you use the Azure Entra ID as IDP, you can typically use the "appid" attribute as the token identity, which typically contains the "client_id".</p>

In this case the `JWT_IDENTITY_ASSERTION` parameter would be valued with: `'${token.payload.appid}'`.<br/>

#### 4. Combined identity
<p align="justify">It is possible to combine scenarios 2 and 3 to strengthen security, maintaining the management of the mapping on the OSB and at the same time forcing the use of a claim by verifying that it corresponds to the mapped user. In this way, you also get the benefit of forcing OAUTH2 app-registrations dedicated to use with the OSB, avoiding that identities already used in other contexts are recycled. This scenario can be implemented by leveraging the VALIDATION_ASSERTION parameter to force this verification.</p>

For example, you can configure the `VALIDATION_ASSERTION` parameter with a simple script like this:  `'${token.payload.sub}'=='${username}'`.<br/>

## How to configure Mapping Service Account
<p align="justify">The OSB resource used for translating the JWT token identity into the weblogic realm username must be a "Service Account" of type "mapping" and must be handled as highlighted in the following screenshot. Please note that it is not necessary to fill in the "Remote Password" field, which can be filled with arbitrary text.</p>

<p align="center"><img src="https://github.com/user-attachments/assets/45f6af65-3cb5-4cc3-8062-a3f8a13d7b0a" /></p>

## Build instructions
<p align="justify">The sources can be compiled with any Java IDE with Ant support but you need to prepare the necessary dependencies for WebLogic and Oracle Service Bus libraries. You only need to modify the "Build.xml" file to suit your environment. The file supports multiple configurations already prepared for WebLogic 12.1.3 and 12.2.1. Here is an excerpt of the section that needs to be customized.</p>

```xml
    <!-- weblogic version selector (only one must be true) -->
    <property name="weblogic-12.1.3" value="true"/>
    <property name="weblogic-12.2.1" value="false"/>
    
    <!-- weblogic version specific properties -->
    <property if:true="${weblogic-12.1.3}" name="javaHomeDir" value="C:/Programmi/Java/jdk1.7"/>
    <property if:true="${weblogic-12.1.3}" name="weblogicDir" value="C:/Oracle/Middleware/12.1.3"/>   
    ...    
    <property if:true="${weblogic-12.2.1}" name="javaHomeDir" value="C:/Programmi/Java/jdk1.8"/>
    <property if:true="${weblogic-12.2.1}" name="weblogicDir" value="C:/Oracle/Middleware/12.2.1"/>    
```
<p align="justify">The repository contains a project already prepared for a JDeveloper 12.1.3 installed as part of the Oracle SOA Suite Quick Start for Developers under Windows operating system (see references). Ant compilation can be triggered from JDeveloper by right-clicking on the "Build.xml" file and selecting the "all" target or from the command line by running the "Build.cmd" Windows batch.</p>

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

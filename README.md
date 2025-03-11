# Oracle Service Bus Identity Assertion Provider for OAUTH2/JWT authentication
An highly configurable WebLogic Custom Identity Assertion Provider with support for inbound OAUTH2/JWT authentication for Oracle Service Bus Proxy Services

# Overview
<p align="justify">
Up to and including versions 12.1.3 the Oracle Service Bus does not support OAUTH2/JWT inbound and outbound authentication out of the box. Starting with version 12.2.1, the Bus supports it through the use of OWSM policies but without the certification and flexibility needed to use a third-party IDP such as Azure Entra ID.<br/><br/>
Furthermore, the use of OWSM policies may not be a familiar solution for those who are used to managing authentication and authorization through the simple management of users and groups of the integrated authentication provider of WebLogic. Furthermore, OAUTH2 introduces the need to adopt identities defined by very long and opaque strings (client_id), impossible to re-associate to a given consumer without appropriate mechanisms of credential mappings.<br/><br/>
Fortunately, since the old versions of WebLogic there is the possibility to extend the product to support custom authentication schemes. The proposed library is based in particular on a Custom Identity Assertion Provider that supports OAUTH2 authentication based on signed JWT tokens and offer also an optional identity mappings mechanism to translate client_ids to weblogic realm users.<br/><br/>
In addition to the JWT-based authentication scheme, the provider also offers support for the legacy Basic Auth to simplify the progressive adoption of JWT authentication by different consumers on the same Proxy Service, without the need to create different Proxies for each authentication scheme.
</p>

# Build instructions
<p align="justify">
The sources can be compiled with any Java IDE with Ant support but it is necessary to prepare the necessary dependencies of WebLogic and Oracle Service Bus. The repository contains a project already prepared for a JDeveloper 12.1.3 installed as part of the Oracle SOA Suite Quick Start for Developers (see references).<br/>

Ant compilation can be triggered from JDeveloper by right-clicking on the "Build.xml" file and selecting the "all" target in the root or from the command line by running the "Build.cmd" batch.
In both cases, at the end of the compilation, two jar archives are produced and automatically copied to the ```<WEBLOGIC_HOME>/wlserver/server/lib/mbeantypes``` folder from which WebLogic loads the security providers at startup. At the end of the compilation, you can directly launch the WebLogic environment integrated into JDeveloper to test the provider's operation.
</p>

# Credits
- **JSON-java** (https://github.com/stleary/JSON-java)<br/>
- **Apache HttpClient** (https://hc.apache.org/httpcomponents-client-4.5.x/index.html)<br/>
- **Nimbus JOSE + JWT** (https://connect2id.com/products/nimbus-jose-jwt)<br/>

# References
- Installing Oracle SOA Suite Quick Start for Developers 12.1.3:<br/> https://docs.oracle.com/middleware/1213/soasuite/index.html
- WebLogic 12.1.3 Identity Assertion Providers:<br/> https://docs.oracle.com/middleware/1213/wls/DEVSP/ia.htm
- WebLogic 12.1.3 Security Providers Developer Guide:<br/> https://docs.oracle.com/middleware/1213/wls/DEVSP/DEVSP.pdf
- Generate an MBean Type Using the WebLogic MBeanMaker:<br/> https://docs.oracle.com/middleware/1213/wls/DEVSP/generate_mbeantype.htm
- Custom Identity Asserter for Weblogic Server:<br/> https://weblogic-wonders.com/simple-sample-custom-identity-asserter-weblogic-server-12c/
- Custom SSO using Weblogic IdentityAsserter:<br/> https://virtual7.de/en/blog/custom-sso-using-weblogic-identityasserter

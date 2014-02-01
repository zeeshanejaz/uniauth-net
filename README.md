# Uniauth for .Net

Uniauth is a .NET portable library for handling various types of Web/API authorization on the client end.

This library uses code from various open-source projects. See the acknowledgements section for further details.

## Installing
Use nuget package manager to install the pre-release version of Uniauth.

```C#
Install-Package Uniauth-API -pre
```

## Supported Authorization Types
Currently, Uniauth supports Basic authentication and a few OAuth1a and OAuth2 authorization flows. Each authorization is implemented in a separate class and provides appropriate methods to implementing the respective authorization.

### Basic Authentication
Basic authentication is the simplest method of authenticating Web/API request. Any authorized request must carry a username and password in base64 encoding. Uniauth makes this process even simpler by providing the BasicAuthHandler class. You can use this class as follows.

```C#
//create authentication handler
BasicAuthHandler authHandler = new BasicAuthHandler(username, password);

//create http client and request message
HttpClient client = new HttpClient();
HttpRequestMessage msg = new HttpRequestMessage(HttpMethod.Get, new Uri(serverUri));

//append the required authentication headers to the outgoing message
authHandler.AppendCredentials(msg);

//get the response against the authenticated request
HttpResponseMessage response = await client.SendAsync(msg);
```

### OAuth 1.0a
Currently, Uniauth supports three different OAuth1.0a authorization flows namely, Two Legged, Three Legged with embedded WebView control, and Three Legged browser-based. For complete detail on various types of OAuth1.0a authorization flows, please visit http://oauthbible.com/
In order to use a particular type of OAuth1.0a authorization, instantiate the respective flow handler class with corresponding parameters.

####Two Legged
The two legged OAuth1.0a
## Authorization Filters
All authorizations are implemented
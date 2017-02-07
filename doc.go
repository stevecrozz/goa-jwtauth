/*
Package jwtauth provides a middleware for the Goa framework that parses and
validates JSON Web Tokens (JWTs) that appear in requests, then adds them
to the request context. It supports any JWT algorithm that uses RSA, ECDSA
or HMAC.

When you setup your goa.Service, install the jwtauth middleware:

    // Assuming your API DSL created a JWT security scheme named "JWT"
		scheme := app.NewJWTSecurity()
    secret := []byte("This is my HMAC key")
    store = jwtauth.SimpleKeystore{secret}
		middleware := jwtauth.New(scheme, store)

In this example, jwtauth uses a single, static HMAC key and relies
on the default authentication and authorization behavior. Your users can now
include an authorization token with every request:

    GET /foo
    Authorization: Bearer <JWT goes here>

When someone makes a request containing a JWT, jwauth verifies that the token
contains all of the scopes that are required by your action, as determined by
goa.ContextRequiredScopes(). If anything is missing, jwtauth returns 4xx or 5xx
error with a detailed message.


Multiple Issuers

For real-world applications, it is advisable to register several trusted keys
so you can perform key rotation on the fly and compartmentalize trust. If you
initialize the middleware with a NamedKeystore, it uses the value of the
JWT "iss" (Issuer) claim to select a verification key for each token.

		import jwtgo "github.com/dgrijalva/jwt-go"
		usKey := jwtgo.ParseRSAPublicFromPEM(ioutil.ReadFile("us.pem))
		euKey := jwtgo.ParseRSAPublicKeyFromPEM(ioutil.ReadFile("eu.pem))

		store := jwt.NamedKeystore{}
		store.Trust("us.acme.com", usKey))
		store.Trust("eu.acme.com", euKey))

		middleware := jwt.New(app.NewJWTSecurity(), store)

Using a NamedKeystore, you can grant or revoke trust at any time, even while
the application is running, and your changes will take effect on the next
request.


Custom Authorization

To change how jwtauth performs auth, write your own function that matches the
signature of type AuthorizationFunc, then pass your function to the
constructor using jwtauth's options DSL:

    func myAuthzFunc(ctx context.Context) error {
			return fmt.Errorf("nobody may do anything!")
	  }

    store := jwt.SimpleKeystore{[]byte("This is my HMAC key")}
		middleware := jwtauth.New(scheme, store,
			jwtauth.Authorization(myAuthzFunc)
		)

When overriding authorization behavior, you can always delegate some work to
the default behavior. To additionally check with a central authorization server
to ensure that the user is alive and well:

		func myAuthzFunc(ctx context.Context) error {
			tokenAuth := jwtauth.Authorize(ctx)
			if err != nil {
				return tokenAuth
			}

			claims := jwtauth.ContextClaims(ctx)
			http.Get(fmt.Sprintf("http://auth-server?%s", claims.Subject()))
		}


Custom Extraction

You can specialize the logic used to extract a JWT from the request
by providing the Extraction() option:

    func myExtraction(*goa.JWTSecurity, *http.Request) (string, error) {
      return "", fmt.Errorf("I hate token1!")
    }

    store := jwt.SimpleKeystore{[]byte("This is my HMAC key")}
    middleware := jwtauth.New(scheme, store,
      jwtauth.Extraction(myExtraction)
    )

The default extraction behavior, described below, should be sufficient for
almost any use case.

DefaultExtraction supports only security schemes that use goa.LocHeader;
JWTs in the query string, or in other locations, are not supported.

Although jwtauth uses the header name specified by the goa.JWTSecurity definition
that is used to initialize it, some assumptions are made about the format of
the header value. It must contain a base64-encoded JWT, which may be prefixed
by a single-word qualifier. Assuming the security scheme uses the Authorization
header, any of the following would be acceptable:

		Authorization: <base64_token>
		Authorization: Bearer <base64_token>
		Authorization: JWT <base64_token>
		Authorization: AnyOtherWordHere <base64_token>


Token Management

If you need to create tokens, jwtauth contains a simplistic helper that helps
to shadow the dependency on dgrijalva/jwt:

		claims := jwtauth.NewClaims()
		token, err := NewToken("my HMAC key", claims)
		fmt.Println("the magic token is", token)


Error Handling

Common errors are returned as instances of a goa error class, which have
the effect of responding with a specific HTTP status:

ErrUnsupported (500): the token or configuration uses an unsupported feature.

ErrInvalidToken (401): the token is malformed or its signature is bad.

ErrAuthenticationFailed (403): the token is well-formed but the issuer is not
trusted, it has expired, or is not yet valid.

ErrAuthorizationFailed (403): the token is well-formed and valid, but the
authentication principal did not satisfy all of the scopes required to call
the requested goa action.


Testing

Call TestMiddleware() to create a middleware initialized to trust a static key,
e.g. for unit tests.

Call TestToken() to create a valid token signed by the same key.

NEVER USE THESE FUNCTIONS in production; they are intended only for testing!

*/
package jwtauth

Authorization
-------------

1) How do middlewares return a specific response e.g. 403? without having access
   to a type-specific responder method?

2) Should we decompose Adapter into AuthenticationAdapter and AuthorizationAdapter
   so they can be used independently? Or, should we eliminate AuthenticationAdapter
   and assume that "sub" always contains the principal?

3) Should we add Context getters and setters for AuthenticationPrincipal, AuthorizedScopes,
   etc so that the adapter (and others) can just get them from the context?

Customized Behavior
-------------------

1) How will users customize the token that extracts the serialized JWT from the request header?
  - "Authorization: JWT" vs "Authorization: Bearer" vs ...

2) How will users customize the behavior for finding an issuer?
  - Without repetitively calling jwt.Parse?

3) Should Authentication support issuers with multiple keys?
  - Seems 100% necessary to repetitively call jwt.Parse in this case...

4) Should Authentication support customized error handling when the token is expired, malformed, etc?
  - Maybe require people to wrap the middleware in order to do this....

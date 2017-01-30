
Customized Behavior
-------------------

1) How will users customize the token that extracts the serialized JWT from the request header?
  - "Authorization: JWT" vs "Authorization: Bearer" vs ...

2) How will users customize the behavior for finding an issuer?
  - Without repetitively calling jwt.Parse?

3) Should the middleware support issuers with multiple keys?
  - Seems 100% necessary to repetitively call jwt.Parse in this case...

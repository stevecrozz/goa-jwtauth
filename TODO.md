Authorization
-------------

- Helper functions for loading & parsing key(s)

Customized Behavior
-------------------

1) Option to customize the token-extract-from-header logic?
  - e.g. discriminate "Authorization: JWT" vs "Authorization: Bearer" vs ...

2) Should Authentication support issuers with multiple keys?
  - Seems 100% necessary to repetitively call jwt.Parse in this case...

3) Option for customized error handling when the token is expired, malformed, etc?
  - Seems unnecessary

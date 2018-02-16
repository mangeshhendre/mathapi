# jwtcookie 

jwtcookie is an http handler for golang that implements the safeguard standard JWT handling via cookies and refresh tokens.

The standard is that:

1.  Check to see if the required cookie exists
 1. redirect to authentication if not.
2. Check to see if the token within the cookie is valid
 1. redirect to authentication if not.
3. Attempt to refresh token if cookie life is too short.
 1.  Failure here should not interrupt the user.




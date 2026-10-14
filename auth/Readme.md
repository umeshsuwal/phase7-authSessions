# Explanations

## Sessions vs JWT

When someone logs in, the app has to remember them, because the web doesn't remember anything between requests.

**Sessions:** the server keeps the memory. After login it saves a record ("user 5 is logged in") in its database or Redis and gives the browser a random ID, like a cloakroom ticket. On every request the browser shows the ticket and the server looks it up. Because the server holds the record, it can delete it at any time and the user is logged out instantly.

**JWT:** the token itself holds the memory. After login the server creates a signed token that says who the user is and when it expires, and gives it to the client. On each request the client sends the token back, and the server only checks the signature. It doesn't look anything up, so any server can verify it. The catch is that the server can't easily cancel a token before it expires.

**When I would pick each:**

- **Sessions:** an admin dashboard or banking app, where I must be able to log a user out immediately if their account is hacked or they are fired.
- **JWT:** a mobile app talking to several small backend services. Each service can verify the token on its own without sharing a session database.

## Hashing vs Encryption

Encryption locks data so you can unlock it later with a key. Hashing turns data into a scrambled string that can never be turned back.

For passwords, hashing is the right choice. The app never needs to know your real password. It only needs to check whether the one you typed matches. So at login it hashes what you typed and compares the result with the stored hash. If the database leaks, attackers get only hashes, not passwords. With encryption, anyone who steals the key can unlock every password at once.

bcrypt makes hashing safer in two ways:

- It adds a random **salt** to each password, so two users with the same password get different hashes, which stops precomputed lookup tables.
- It is deliberately **slow** (the work factor), so guessing millions of passwords against a stolen hash takes far too long.

## Task 2: RBAC and secure session cookies

The `GET /admin/users` route is protected on the server by
`requireRole('admin')`. The middleware uses the user loaded from the
server-side session, so a client cannot grant itself admin access by changing
request data.

The session cookie is configured with these protections:

- **HttpOnly:** JavaScript cannot read the session cookie, which limits the
  ability of an injected XSS script to steal the session token.
- **Secure:** The browser sends the session cookie only over HTTPS, preventing
  it from travelling over an insecure connection.
- **SameSite=Strict:** The browser does not send the session cookie on
  cross-site requests, reducing CSRF risk.

For local HTTP development, `.env` sets `COOKIE_SECURE=false`. For an HTTPS
deployment, set `COOKIE_SECURE=true`.

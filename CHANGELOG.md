# Changelog

## 3.5.0 (2026-09-28)

* Security: Introduced new exception for 'unknown client_id' that does not set the error_url to prevent open redirect attacks - see #64
* Update tox configuration
* Fix handling of id_token claims when exchanging the code in auth-code flow
* Return error_description instead of error_message
* example: example/requirements.txt to reduce vulnerabilities

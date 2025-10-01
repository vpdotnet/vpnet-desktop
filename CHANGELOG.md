# Changelog

### v3.7.3
* Fix WireGuard connections using incorrect port for authentication when server specifies custom port
* Fix Ubuntu 25+ compatibility by resolving LD_LIBRARY_PATH conflicts
* Fix iptables chain name length error on Linux
* Add port override support for individual servers in regions configuration
* Add metadata information to Daemon service for Windows.

### v3.7.2
* Remove unused x509 verification code from server connections

### v3.7.1
* Split-tunnel routing removed to cut high CPU overhead on some platforms and simplify the network path, removing unnecessary complexity and a self described imperfect implementation.
* Geo-located virtual endpoint system removed; each location label now represents a real physical server in that jurisdiction.
* Intel SGX–attested connection path added: during handshake the client and server perform remote attestation, letting both sides cryptographically verify the endpoint's code integrity before keys are exchanged—delivering Verified Privacy™.
* User-usage telemetry eliminated; the app now collects and sends no session statistics, feature-usage data, or performance metrics.
* Branding refreshed with new name and icon set.

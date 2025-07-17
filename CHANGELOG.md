# Changelog

### v3.7.1
* Split-tunnel routing removed to cut high CPU overhead on some platforms and simplify the network path, removing unnecessary complexity and a self described imperfect implementation.
* Geo-located virtual endpoint system removed; each location label now represents a real physical server in that jurisdiction.
* Intel SGX–attested connection path added: during handshake the client and server perform remote attestation, letting both sides cryptographically verify the endpoint's code integrity before keys are exchanged—delivering Verified Privacy™.
* User-usage telemetry eliminated; the app now collects and sends no session statistics, feature-usage data, or performance metrics.
* Branding refreshed with new name and icon set.

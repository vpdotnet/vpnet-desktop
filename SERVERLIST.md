# VPNet Server List Implementation Guide

This document details how the VPNet client fetches server information and the expected response format for server-side implementation.

## Response Format

The server response should be a JSON document with the following structure:

```json
{
  "groups": {
    "ovpntcp": [
      {
        "name": "openvpn_tcp",
        "ports": [80, 443, 853, 8443]
      }
    ],
    "ovpnudp": [
      {
        "name": "openvpn_udp",
        "ports": [8080, 853, 123, 53]
      }
    ],
    "wg": [
      {
        "name": "wireguard",
        "ports": [1337]
      }
    ],
    "ikev2": [
      {
        "name": "ikev2",
        "ports": [500, 4500]
      }
    ],
    "proxysocks": [
      {
        "name": "socks",
        "ports": [1080]
      }
    ],
    "proxyss": [
      {
        "name": "shadowsocks",
        "ports": [443]
      }
    ],
    "meta": [
      {
        "name": "meta",
        "ports": [443, 8080]
      }
    ]
  },
  "regions": [
    {
      "id": "region_code",
      "name": "Region Name",
      "country": "Country Code",
      "auto_region": true,
      "dns": "region.privacy.network",
      "port_forward": true,
      "geo": true,
      "offline": false,
      "servers": {
        "ovpnudp": [
          {
            "ip": "server_ip",
            "cn": "server_name",
            "van": false
          }
        ],
        "ovpntcp": [
          {
            "ip": "server_ip",
            "cn": "server_name",
            "van": false
          }
        ],
        "ikev2": [
          {
            "ip": "server_ip",
            "cn": "server_name"
          }
        ],
        "wg": [
          {
            "ip": "server_ip",
            "cn": "server_name"
          }
        ],
        "meta": [
          {
            "ip": "server_ip",
            "cn": "server_name"
          }
        ]
      }
    }
  ]
}
```

## Metadata API

The client also fetches region metadata from:
```
https://vp.net/_rest/Network/VPN:apiV2?resource=regions/v2
```

This provides additional information like:
- Translated region names in multiple languages
- Country groupings
- Geographic coordinates for map display

## Security and Implementation Details

1. **Cryptographic Signature**: The server response should be cryptographically signed. The client verifies this signature using the public key stored in `Environment::defaultRegionsListPublicKey`.

2. **Refresh Intervals**: 
   - Server list: Every 10 minutes after initial loading
   - Metadata: Every 48 hours

3. **Region Properties**:
   - `id`: Unique identifier for the region
   - `name`: Display name for the region
   - `country`: Two-letter country code
   - `auto_region`: Whether this region can be automatically selected
   - `port_forward`: Whether port forwarding is supported
   - `geo`: Whether geo data is available
   - `servers`: Dictionary of servers grouped by protocol

4. **Server Properties**:
   - `ip`: Server IP address
   - `cn`: Server certificate/common name
   - `van`: Whether this is a special server type (e.g., for streaming)

## Implementation Steps

1. Create a JSON file with your server list following the format above.
2. Set up an endpoint at `https://vp.net/_rest/Network/VPN:apiV2?resource=servers/v6` that returns this JSON.
3. Sign the response using the private key corresponding to the public key in the client.
4. Create a metadata file and serve it at `https://vp.net/_rest/Network/VPN:apiV2?resource=regions/v2`.
5. Ensure your servers support the protocols specified in the groups section.

The client will periodically fetch this data to update its server list, and users will be able to select from the regions you've provided when connecting to your VPN service.

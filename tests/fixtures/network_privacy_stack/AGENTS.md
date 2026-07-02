# Test Privacy Stack (fixture)

Synthetic fixture for the `network/privacy_stack` parser test harness.
This is not a real deployment — every value here is a placeholder.

The project runs Pi-hole for DNS ad blocking and WireGuard for the VPN
tunnel, with Unbound as a DNS-over-TLS resolver and a small Flask control
dashboard.

Services: pihole-FTL, unbound, wg-mullvad, wg0, picontrol, gitea.

Router gateway: 10.0.0.1
Node address:   10.0.0.8

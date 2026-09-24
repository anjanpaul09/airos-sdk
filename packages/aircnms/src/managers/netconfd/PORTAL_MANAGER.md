# Captive Portal Manager

`netconfd` keeps wireless interface configuration separate from captive portal
ownership. Wireless code calls:

```c
portal_manager_assign(&vif_params, vif_params.network, sizeof(vif_params.network));
```

For ordinary SSIDs this returns `lan`, a VLAN network, or `nat_network`.
For authenticated SSIDs with `portalId`, it returns `cp_<hash>` and owns:

- OpenWrt network/firewall sections
- per-portal bridge naming
- CoovaChilli process lifecycle
- template rendering
- `/etc/airpro/captive_portals/instances/<portalId>/metadata.json`
- in-memory portal and VIF reference tracking

On startup, `portal_manager_init()` refreshes default templates, scans existing
instance metadata, restores networks/processes, and rebuilds VIF references from
`wireless.*.network`. Captive portal IP/netmask values come from cloud
`natConfig.netSegmentIp` and `natConfig.netMaskIp`.

Two SSIDs with the same `portalId` share the same `cp_<hash>` network and
CoovaChilli instance. Disabling a VIF releases its reference; the portal
instance is removed only when the reference count reaches zero.

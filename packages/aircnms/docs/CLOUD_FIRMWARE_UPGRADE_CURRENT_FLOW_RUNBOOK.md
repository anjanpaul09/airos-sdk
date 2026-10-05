# Cloud firmware upgrade current-flow runbook

Scope: validate and fix the existing firmware upgrade path only. Do not redesign the protocol, add new cloud states, add signing, or change UI behavior during this pass.

## Current path

```text
Cloud UI
  -> device-management /firmware-upgrade-device/
  -> firmware_updatedevice row = In Process
  -> mqtt-services publish {cmd: "upgrade", id: <UpdateDevice id>, type: "firmware_upgrade"}
  -> AP cgwd receives cloud/to/device/<device_id>/<serial>/cmd
  -> AP cmdexecd downloads /file/download with device_firmware_id=<UpdateDevice id>
  -> AP extracts tar.gz, checks md5sum, runs sysupgrade
  -> AP publishes event statuses: Downloaded, Upgrading, Failed, Success
  -> Telegraf/Kafka/Kafka Connect updates firmware_updatedevice.status
  -> UI grid/websocket shows status
```

## Test artifact

Use the cloud package, not the raw image:

```text
releases/cloud/airos-mt76-<version>-<timestamp>.tar.gz
```

Package must contain:

```text
<image-name>/
  <image-name>.bin
  md5sum
  manifest.json
```

## Preflight checks

On cloud VM:

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}' | egrep 'device-management|device-registration|mqtt-services|mqtt-broker|telegraf|kafka-connect|postgres'
docker exec airpro-kafka-connect curl -fsS http://localhost:8083/connectors/firmware-upgrade-sink-connector/status
```

On AP:

```sh
uci get aircnms.@aircnms[0].device_id
uci get aircnms.@aircnms[0].topics
/etc/init.d/aircgwd status
/etc/init.d/aircmdexecd status
```

## End-to-end test steps

1. Upload firmware tar.gz in cloud UI.
2. Select exactly one test AP.
3. Start firmware upgrade.
4. Capture the created `firmware_updatedevice.id` from cloud DB/UI.
5. Watch cloud command publish:

```bash
docker logs -f airpro-mqtt-services | egrep 'publish|upgrade|firmware|error'
```

6. Watch AP logs:

```sh
logread -f | egrep 'CGWD|CMDEXEC|upgrade|firmware|sysupgrade|md5|download|FAILED|UPGRADING'
```

7. Expected status sequence:

```text
In Process -> Downloaded -> Upgrading -> Success
```

`Success` happens after AP reboots, reconnects, and `cmdexecd` reports the persisted upgrade status.

## Fix-current-only checklist

Fix only failures in this current path:

| Failure | Fix area |
|---|---|
| Cloud command not published | `device_management/firmware/views.py`, `mqttui/utility.py`, `mqtt-services /publish/` |
| AP does not receive command | MQTT topic list, cgwd topic routing, broker ACL/client credentials |
| Download fails | `device-registration /file/download`, `device-management FileDownloadAPIView`, firmware file path/storage |
| Extract fails | AP package format or cmdexec extraction path |
| MD5 mismatch | build cloud package md5sum generation |
| sysupgrade not called | `cmdexec_upgrade.c` current logic |
| Status not updated in UI | AP event payload, Telegraf `kafka-processor.star`, Kafka Connect firmware connector |
| Success not reported after reboot | AP `fw_upgrading_status`, `fw_id`, cmdexecd startup, AP online status |

## Do not add in this pass

- Signature verification
- New firmware job table
- New cloud states
- A/B rollback
- New protocol schema
- New UI flow
- New AP command names

Those are Phase 2 hardening items. This pass only makes the existing flow work reliably.

## Evidence to collect

- Uploaded tar.gz filename
- `Firmware.id`
- `UpdateDevice.id`
- MQTT command topic and payload
- AP log lines: download, md5 OK, sysupgrade
- AP reboot timestamp
- Post-boot AP firmware version
- Final `firmware_updatedevice.status=Success`

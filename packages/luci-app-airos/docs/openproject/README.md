# AirUI OpenProject Backlog

This directory contains a tab-wise delivery backlog for the AirUI access-point UI and its `airuid` backend.

## Files

- `AIRUI_WORK_PACKAGES.csv`: work-package ledger with parent IDs, UI routes, frontend views, UBUS methods, backend source files, acceptance criteria, and current status.
- Parent rows represent sidebar areas. Child rows are independently testable features or backend gaps.

## Recommended OpenProject Setup

Create one project named **AirUI AP Management** and use the CSV `External ID` values as stable references. Create these custom fields before importing or creating work packages through the API:

- `External ID`
- `Tab`
- `UI Route`
- `Frontend View`
- `UBUS Object`
- `UBUS Method`
- `Backend Source`
- `Verification Target`

Use `Task` for child work packages. Parent rows can use `Phase` when that type is enabled. Set each child's parent from `Parent ID`; OpenProject displays these parent-child relations as a hierarchy.

## Status Mapping

- `Closed`: UI and backend mapping exist; normal-path behavior is implemented.
- `In progress`: implemented but edge cases, destructive-device verification, or platform coverage remain.
- `New`: backend capability is missing or the page is still a placeholder.

Do not close destructive operations from UI review alone. Firmware upgrade, reboot, factory reset, and network apply require target-device evidence attached to the work package. The current verification target is `192.168.1.2` unless the board address changes.

## Suggested Views

1. **Tab backlog**: group by `Tab`, then show the hierarchy.
2. **Backend gaps**: filter status `New` and non-empty `UBUS Object`.
3. **Board verification**: filter status `In progress` and verification target `192.168.1.2`.
4. **Release readiness**: show Priority, Status, Assignee, and Due date with all parent rows expanded.

## Definition of Done

A feature is done when its LuCI route renders, the declared RPC matches the registered UBUS method, ACL permissions are present, success and error responses are handled, configuration survives reload/reboot where applicable, and the acceptance criterion passes on the target AP.

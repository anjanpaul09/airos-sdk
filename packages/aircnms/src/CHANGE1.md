## CHANGE 1: Unified libunixcomm IPC and removal of legacy *conn layers

### Overview

- All managers (QM, SM, DM, CM) now communicate via `libunixcomm` for IPC.
- Removed legacy per-manager connection shims: `qm_conn`, `sm_conn`, `dm_conn`, `cm_conn` from build dependencies and code paths.
- Introduced shared IPC direction enum in `include/ipc_dir.h` for clarity when referencing flows.

### Code changes

- QM
  - Already provides a unix domain server at `/tmp/aircnms/qm.sock` via `qm_unixcomm_server.c`.

- SM
  - `src/sm_qm.c`: replaced `qm_conn` usage with `libunixcomm` send to `UNIXCOMM_PROCESS_QM`.
  - `src/sm_unixcomm.c`: client helper retained and used for sending stats.
  - `Makefile`: removed `sm_conn` and `qm_conn` sources/includes; added `-I../../libs/unixcomm/inc`.

- DM
  - `src/dm_qm.c`: replaced `qm_conn` usage with `libunixcomm` send to `UNIXCOMM_PROCESS_QM`.
  - `Makefile`: removed `dm_conn` and `qm_conn` sources/includes; added `-I../../libs/unixcomm/inc`.

- CM
  - `src/cm_qm.c`: replaced `qm_conn` usage with `libunixcomm` send to `UNIXCOMM_PROCESS_QM`.
  - `Makefile`: removed `cm_conn` and `qm_conn` sources/includes; added `-I../../libs/unixcomm/inc`.

- Shared
  - `include/ipc_dir.h`: new header defining `ipc_direction_t` with values like `IPC_DIR_SM_TO_QM`, `IPC_DIR_QM_TO_SM`, etc.

### Build system

- Removed `*_conn` sources and include paths from `managers/*/Makefile`.
- All managers link against `-lunixcomm` (already configured) and include `../../libs/unixcomm/inc`.

### IPC direction flag

- Added `include/ipc_dir.h` with enum values for flows:
  - `IPC_DIR_SM_TO_QM`, `IPC_DIR_QM_TO_SM`
  - `IPC_DIR_CM_TO_QM`, `IPC_DIR_QM_TO_CM`
  - `IPC_DIR_DM_TO_QM`, `IPC_DIR_QM_TO_DM`
- Use these constants for readability when describing/reporting IPC flows.

### Notes

- Tools/test Makefiles still reference legacy `*_conn` for test scaffolding; migrate tests later if needed.
- If you need peer-to-peer sockets among non-QM managers, add corresponding unixcomm endpoints or route via QM as a hub.



#ifndef IPC_DIR_H_INCLUDED
#define IPC_DIR_H_INCLUDED

// IPC direction flags across managers
typedef enum ipc_direction
{
    IPC_DIR_SM_TO_QM = 1,
    IPC_DIR_QM_TO_SM = 2,
    IPC_DIR_CM_TO_QM = 3,
    IPC_DIR_QM_TO_CM = 4,
    IPC_DIR_DM_TO_QM = 5,
    IPC_DIR_QM_TO_DM = 6,
} ipc_direction_t;

#endif /* IPC_DIR_H_INCLUDED */


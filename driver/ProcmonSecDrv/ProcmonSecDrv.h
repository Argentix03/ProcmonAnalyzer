#pragma once
#include <ntifs.h>
#include <wdm.h>

#define PROCMONSEC_DEVICE_NAME      L"\\Device\\ProcmonSecDrv"
#define PROCMONSEC_DOS_DEVICE_NAME  L"\\DosDevices\\ProcmonSecDrv"
#define PROCMONSEC_POOL_TAG         'cmrP' // 'Prmc'

// IOCTL Codes (FILE_DEVICE_UNKNOWN = 0x22, METHOD_BUFFERED = 0, FILE_ANY_ACCESS = 0)
// Access control is enforced in IRP_MJ_CREATE (requires SeDebugPrivilege / Admin).
#define IOCTL_PROCMONSEC_PING                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROCMONSEC_QUERY_OBJECT_SD      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROCMONSEC_QUERY_DRIVER_DEVICES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROCMONSEC_READ_PPL_MEM         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROCMONSEC_DRAIN_HANDLE_EVENTS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef enum _PROCMONSEC_OBJ_KIND {
    ProcmonSecObjFileOrDevice = 0,
    ProcmonSecObjRegistryKey  = 1,
    ProcmonSecObjProcessPid   = 2
} PROCMONSEC_OBJ_KIND;

#pragma pack(push, 1)

typedef struct _PROCMONSEC_PING_RESPONSE {
    ULONG VersionMajor;
    ULONG VersionMinor;
    ULONG ObCallbacksActive;
    ULONG BufferedHandleEvents;
} PROCMONSEC_PING_RESPONSE, *PPROCMONSEC_PING_RESPONSE;

typedef struct _PROCMONSEC_SD_REQUEST {
    ULONG ObjectKind;      // PROCMONSEC_OBJ_KIND
    ULONG TargetPid;       // Used when ObjectKind == ProcmonSecObjProcessPid
    WCHAR ObjectPath[512]; // NT path, e.g. \??\C:\path or \Registry\Machine\... or \Device\...
} PROCMONSEC_SD_REQUEST, *PPROCMONSEC_SD_REQUEST;

typedef struct _PROCMONSEC_SD_RESPONSE {
    ULONG Status;
    ULONG SdLength;
    UCHAR SdBytes[4096];
} PROCMONSEC_SD_RESPONSE, *PPROCMONSEC_SD_RESPONSE;

typedef struct _PROCMONSEC_DRIVER_QUERY_REQUEST {
    WCHAR DriverObjectPath[256]; // e.g. \Driver\HTTP or \Driver\AFD
} PROCMONSEC_DRIVER_QUERY_REQUEST, *PPROCMONSEC_DRIVER_QUERY_REQUEST;

typedef struct _PROCMONSEC_DEVICE_ENTRY {
    WCHAR   DeviceName[128];
    ULONG   DeviceType;
    ULONG   Characteristics;
    BOOLEAN HasSecureOpen; // (Characteristics & FILE_DEVICE_SECURE_OPEN) != 0
    UCHAR   Reserved[3];
    ULONG64 IrpMjCreateAddr;
    ULONG64 IrpMjCloseAddr;
    ULONG64 IrpMjDeviceControlAddr;
    ULONG64 IrpMjInternalDeviceControlAddr;
    ULONG   SdLength;
    UCHAR   SdBytes[512];
} PROCMONSEC_DEVICE_ENTRY, *PPROCMONSEC_DEVICE_ENTRY;

typedef struct _PROCMONSEC_DRIVER_QUERY_RESPONSE {
    ULONG Status;
    ULONG DeviceCount;
    PROCMONSEC_DEVICE_ENTRY Devices[16];
} PROCMONSEC_DRIVER_QUERY_RESPONSE, *PPROCMONSEC_DRIVER_QUERY_RESPONSE;

typedef struct _PROCMONSEC_READ_MEM_REQUEST {
    ULONG   TargetPid;
    ULONG   Size; // Max 65536
    ULONG64 VirtualAddress;
} PROCMONSEC_READ_MEM_REQUEST, *PPROCMONSEC_READ_MEM_REQUEST;

typedef struct _PROCMONSEC_READ_MEM_RESPONSE {
    ULONG Status;
    ULONG BytesRead;
    UCHAR Data[1]; // Variable length up to requested Size
} PROCMONSEC_READ_MEM_RESPONSE, *PPROCMONSEC_READ_MEM_RESPONSE;

typedef struct _PROCMONSEC_HANDLE_EVENT {
    ULONG   CallerPid;
    ULONG   CallerTid;
    ULONG   TargetPid;
    ULONG   Operation;      // 1 =OB_OPERATION_HANDLE_CREATE, 2 = OB_OPERATION_HANDLE_DUPLICATE
    ULONG   DesiredAccess;
    BOOLEAN IsKernelHandle;
    UCHAR   Reserved[3];
    LARGE_INTEGER Timestamp;
} PROCMONSEC_HANDLE_EVENT, *PPROCMONSEC_HANDLE_EVENT;

#define PROCMONSEC_RING_CAPACITY 256
#define PROCMONSEC_DRAIN_BATCH   64

typedef struct _PROCMONSEC_DRAIN_EVENTS_RESPONSE {
    ULONG EventCount;
    PROCMONSEC_HANDLE_EVENT Events[PROCMONSEC_DRAIN_BATCH];
} PROCMONSEC_DRAIN_EVENTS_RESPONSE, *PPROCMONSEC_DRAIN_EVENTS_RESPONSE;

#pragma pack(pop)

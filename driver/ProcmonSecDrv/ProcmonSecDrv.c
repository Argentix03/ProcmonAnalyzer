#include "ProcmonSecDrv.h"

// Exported ntoskrnl.exe routines not always in public headers
NTKERNELAPI NTSTATUS NTAPI ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG Attributes,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID ParseContext,
    PVOID *Object
);

NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize
);

extern POBJECT_TYPE *IoDriverObjectType;

// Global State
static PDEVICE_OBJECT g_DeviceObject = NULL;
static PVOID          g_ObRegHandle  = NULL;
static KSPIN_LOCK     g_RingLock;
static PROCMONSEC_HANDLE_EVENT g_EventRing[PROCMONSEC_RING_CAPACITY];
static ULONG          g_RingWriteIdx = 0;
static ULONG          g_RingReadIdx  = 0;
static ULONG          g_RingCount    = 0;

// ═══════════════════════════════════════════════════════════════════════════════
//  MODULE 4: ObRegisterCallbacks Passive Cross-Process Handle Monitor
// ═══════════════════════════════════════════════════════════════════════════════
static OB_PREOP_CALLBACK_STATUS
ProcmonSecPreProcessHandleCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OpInfo
)
{
    PEPROCESS targetProc;
    PEPROCESS callerProc;
    ULONG callerPid;
    ULONG targetPid;
    ACCESS_MASK desiredAccess = 0;
    ULONG dangerousMask = 0x000C00EA; // CREATE_THREAD | VM_OP | VM_WRITE | DUP_HANDLE | CREATE_PROCESS | WRITE_DAC | WRITE_OWNER
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OpInfo == NULL || OpInfo->Object == NULL) {
        return OB_PREOP_SUCCESS;
    }

    // Only log user-mode cross-process handle requests (100% passive observer, never blocks)
    if (OpInfo->KernelHandle || ExGetPreviousMode() == KernelMode) {
        return OB_PREOP_SUCCESS;
    }

    targetProc = (PEPROCESS)OpInfo->Object;
    callerProc = PsGetCurrentProcess();
    if (targetProc == callerProc) {
        return OB_PREOP_SUCCESS;
    }

    if (OpInfo->Operation == OB_OPERATION_HANDLE_CREATE && OpInfo->Parameters != NULL) {
        desiredAccess = OpInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess;
    } else if (OpInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE && OpInfo->Parameters != NULL) {
        desiredAccess = OpInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
    }

    if ((desiredAccess & dangerousMask) == 0) {
        return OB_PREOP_SUCCESS;
    }

    callerPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    targetPid = (ULONG)(ULONG_PTR)PsGetProcessId(targetProc);
    if (callerPid == targetPid || targetPid <= 4) {
        return OB_PREOP_SUCCESS;
    }

    KeAcquireSpinLock(&g_RingLock, &oldIrql);
    {
        PPROCMONSEC_HANDLE_EVENT ev = &g_EventRing[g_RingWriteIdx];
        ev->CallerPid      = callerPid;
        ev->CallerTid      = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
        ev->TargetPid      = targetPid;
        ev->Operation      = (ULONG)OpInfo->Operation;
        ev->DesiredAccess  = (ULONG)desiredAccess;
        ev->IsKernelHandle = OpInfo->KernelHandle;
        KeQuerySystemTimePrecise(&ev->Timestamp);

        g_RingWriteIdx = (g_RingWriteIdx + 1) % PROCMONSEC_RING_CAPACITY;
        if (g_RingCount < PROCMONSEC_RING_CAPACITY) {
            g_RingCount++;
        } else {
            g_RingReadIdx = (g_RingReadIdx + 1) % PROCMONSEC_RING_CAPACITY;
        }
    }
    KeReleaseSpinLock(&g_RingLock, oldIrql);

    return OB_PREOP_SUCCESS;
}

static VOID RegisterHandleCallbacks(VOID)
{
    OB_CALLBACK_REGISTRATION cbReg;
    OB_OPERATION_REGISTRATION opReg[1];
    UNICODE_STRING altitude;
    NTSTATUS status;

    RtlZeroMemory(&cbReg, sizeof(cbReg));
    RtlZeroMemory(&opReg, sizeof(opReg));

    RtlInitUnicodeString(&altitude, L"385210"); // Research filter altitude

    opReg[0].ObjectType = PsProcessType;
    opReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg[0].PreOperation = ProcmonSecPreProcessHandleCallback;
    opReg[0].PostOperation = NULL;

    cbReg.Version = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 1;
    cbReg.Altitude = altitude;
    cbReg.RegistrationContext = NULL;
    cbReg.OperationRegistration = opReg;

    status = ObRegisterCallbacks(&cbReg, &g_ObRegHandle);
    if (!NT_SUCCESS(status)) {
        g_ObRegHandle = NULL;
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HELPER: Copy Self-Relative Security Descriptor from Kernel Object Pointer
// ═══════════════════════════════════════════════════════════════════════════════
static NTSTATUS CopyObjectSecurityBytes(
    PVOID ObjectPtr,
    PUCHAR OutBuf,
    ULONG MaxBufLen,
    PULONG OutLen
)
{
    PSECURITY_DESCRIPTOR pSd = NULL;
    BOOLEAN memAllocated = FALSE;
    NTSTATUS status;
    ULONG sdLen = 0;

    *OutLen = 0;
    if (ObjectPtr == NULL || OutBuf == NULL || MaxBufLen == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    status = ObGetObjectSecurity(ObjectPtr, &pSd, &memAllocated);
    if (!NT_SUCCESS(status) || pSd == NULL) {
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }

    sdLen = RtlLengthSecurityDescriptor(pSd);
    if (sdLen > 0 && sdLen <= MaxBufLen) {
        RtlCopyMemory(OutBuf, pSd, sdLen);
        *OutLen = sdLen;
        status = STATUS_SUCCESS;
    } else {
        *OutLen = sdLen;
        status = STATUS_BUFFER_TOO_SMALL;
    }

    ObReleaseObjectSecurity(pSd, memAllocated);
    return status;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MODULE 1: Universal SD & Label Reader (Bypasses READ_CONTROL Denials)
// ═══════════════════════════════════════════════════════════════════════════════
static NTSTATUS HandleQueryObjectSd(
    PPROCMONSEC_SD_REQUEST Req,
    PPROCMONSEC_SD_RESPONSE Resp
)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    UNICODE_STRING uPath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    HANDLE hObj = NULL;
    PVOID pObj = NULL;

    RtlZeroMemory(Resp, sizeof(*Resp));
    Req->ObjectPath[511] = L'\0';

    if (Req->ObjectKind == ProcmonSecObjProcessPid) {
        PEPROCESS eproc = NULL;
        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Req->TargetPid, &eproc);
        if (NT_SUCCESS(status) && eproc != NULL) {
            status = CopyObjectSecurityBytes(eproc, Resp->SdBytes, sizeof(Resp->SdBytes), &Resp->SdLength);
            ObDereferenceObject(eproc);
        }
        Resp->Status = (ULONG)status;
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&uPath, Req->ObjectPath);
    InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    if (Req->ObjectKind == ProcmonSecObjRegistryKey) {
        status = ZwOpenKey(&hObj, 0, &oa);
    } else {
        // Open File / Device / Pipe with DesiredAccess = 0 in KernelMode (bypasses DACL READ_CONTROL denials)
        status = ZwOpenFile(
            &hObj,
            0,
            &oa,
            &iosb,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN_REPARSE_POINT
        );
    }

    if (NT_SUCCESS(status) && hObj != NULL) {
        status = ObReferenceObjectByHandle(hObj, 0, NULL, KernelMode, &pObj, NULL);
        if (NT_SUCCESS(status) && pObj != NULL) {
            status = CopyObjectSecurityBytes(pObj, Resp->SdBytes, sizeof(Resp->SdBytes), &Resp->SdLength);
            ObDereferenceObject(pObj);
        }
        ZwClose(hObj);
    }

    Resp->Status = (ULONG)status;
    return STATUS_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MODULE 2: Live \Driver\* & \Device\* Security & Dispatch Auditor
// ═══════════════════════════════════════════════════════════════════════════════
static NTSTATUS HandleQueryDriverDevices(
    PPROCMONSEC_DRIVER_QUERY_REQUEST Req,
    PPROCMONSEC_DRIVER_QUERY_RESPONSE Resp
)
{
    NTSTATUS status;
    UNICODE_STRING uDrvName;
    PDRIVER_OBJECT pDrvObj = NULL;
    PDEVICE_OBJECT pCurDev = NULL;
    ULONG count = 0;

    RtlZeroMemory(Resp, sizeof(*Resp));
    Req->DriverObjectPath[255] = L'\0';
    RtlInitUnicodeString(&uDrvName, Req->DriverObjectPath);

    status = ObReferenceObjectByName(
        &uDrvName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0,
        *IoDriverObjectType,
        KernelMode,
        NULL,
        (PVOID*)&pDrvObj
    );

    if (!NT_SUCCESS(status) || pDrvObj == NULL) {
        Resp->Status = (ULONG)status;
        return STATUS_SUCCESS;
    }

    pCurDev = pDrvObj->DeviceObject;
    while (pCurDev != NULL && count < 16) {
        PPROCMONSEC_DEVICE_ENTRY entry = &Resp->Devices[count];
        UCHAR nameBuf[512];
        POBJECT_NAME_INFORMATION pNameInfo = (POBJECT_NAME_INFORMATION)nameBuf;
        ULONG retLen = 0;

        entry->DeviceType      = pCurDev->DeviceType;
        entry->Characteristics = pCurDev->Characteristics;
        entry->HasSecureOpen   = ((pCurDev->Characteristics & FILE_DEVICE_SECURE_OPEN) != 0) ? TRUE : FALSE;

        entry->IrpMjCreateAddr                = (ULONG64)(ULONG_PTR)pDrvObj->MajorFunction[IRP_MJ_CREATE];
        entry->IrpMjCloseAddr                 = (ULONG64)(ULONG_PTR)pDrvObj->MajorFunction[IRP_MJ_CLOSE];
        entry->IrpMjDeviceControlAddr         = (ULONG64)(ULONG_PTR)pDrvObj->MajorFunction[IRP_MJ_DEVICE_CONTROL];
        entry->IrpMjInternalDeviceControlAddr = (ULONG64)(ULONG_PTR)pDrvObj->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL];

        RtlZeroMemory(nameBuf, sizeof(nameBuf));
        if (NT_SUCCESS(ObQueryNameString(pCurDev, pNameInfo, sizeof(nameBuf), &retLen)) &&
            pNameInfo->Name.Buffer != NULL && pNameInfo->Name.Length > 0) {
            ULONG copyBytes = min((ULONG)pNameInfo->Name.Length, (ULONG)(sizeof(entry->DeviceName) - sizeof(WCHAR)));
            RtlCopyMemory(entry->DeviceName, pNameInfo->Name.Buffer, copyBytes);
            entry->DeviceName[copyBytes / sizeof(WCHAR)] = L'\0';
        }

        CopyObjectSecurityBytes(pCurDev, entry->SdBytes, sizeof(entry->SdBytes), &entry->SdLength);

        count++;
        pCurDev = pCurDev->NextDevice;
    }

    Resp->DeviceCount = count;
    Resp->Status = (ULONG)STATUS_SUCCESS;
    ObDereferenceObject(pDrvObj);
    return STATUS_SUCCESS;
}

// ═══════════════════════════════════════════════════════════════════════════════
//  DISPATCH ROUTINES (Create, Close, DeviceControl, Unload)
// ═══════════════════════════════════════════════════════════════════════════════
static NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (irpSp->MajorFunction == IRP_MJ_CREATE) {
        // Gate device access to callers holding SeDebugPrivilege (Administrators / SYSTEM)
        LUID debugPriv = RtlConvertLongToLuid(SE_DEBUG_PRIVILEGE);
        if (!SeSinglePrivilegeCheck(debugPriv, Irp->RequestorMode)) {
            status = STATUS_PRIVILEGE_NOT_HELD;
        }
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID sysBuf = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR bytesReturned = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (sysBuf == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    switch (ioctl) {
        case IOCTL_PROCMONSEC_PING:
        {
            if (outLen < sizeof(PROCMONSEC_PING_RESPONSE)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PPROCMONSEC_PING_RESPONSE pPing = (PPROCMONSEC_PING_RESPONSE)sysBuf;
            pPing->VersionMajor         = 4;
            pPing->VersionMinor         = 0;
            pPing->ObCallbacksActive    = (g_ObRegHandle != NULL) ? 1 : 0;
            pPing->BufferedHandleEvents = g_RingCount;
            bytesReturned = sizeof(PROCMONSEC_PING_RESPONSE);
            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_PROCMONSEC_QUERY_OBJECT_SD:
        {
            if (inLen < sizeof(PROCMONSEC_SD_REQUEST) || outLen < sizeof(PROCMONSEC_SD_RESPONSE)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PROCMONSEC_SD_REQUEST reqCopy;
            RtlCopyMemory(&reqCopy, sysBuf, sizeof(PROCMONSEC_SD_REQUEST));
            status = HandleQueryObjectSd(&reqCopy, (PPROCMONSEC_SD_RESPONSE)sysBuf);
            bytesReturned = sizeof(PROCMONSEC_SD_RESPONSE);
            break;
        }

        case IOCTL_PROCMONSEC_QUERY_DRIVER_DEVICES:
        {
            if (inLen < sizeof(PROCMONSEC_DRIVER_QUERY_REQUEST) || outLen < sizeof(PROCMONSEC_DRIVER_QUERY_RESPONSE)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PROCMONSEC_DRIVER_QUERY_REQUEST drvReq;
            RtlCopyMemory(&drvReq, sysBuf, sizeof(PROCMONSEC_DRIVER_QUERY_REQUEST));
            status = HandleQueryDriverDevices(&drvReq, (PPROCMONSEC_DRIVER_QUERY_RESPONSE)sysBuf);
            bytesReturned = sizeof(PROCMONSEC_DRIVER_QUERY_RESPONSE);
            break;
        }

        case IOCTL_PROCMONSEC_READ_PPL_MEM:
        {
            if (inLen < sizeof(PROCMONSEC_READ_MEM_REQUEST)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PROCMONSEC_READ_MEM_REQUEST memReq;
            RtlCopyMemory(&memReq, sysBuf, sizeof(PROCMONSEC_READ_MEM_REQUEST));
            if (memReq.Size == 0 || memReq.Size > 65536 || outLen < (FIELD_OFFSET(PROCMONSEC_READ_MEM_RESPONSE, Data) + memReq.Size)) {
                status = STATUS_INVALID_BUFFER_SIZE;
                break;
            }
            PPROCMONSEC_READ_MEM_RESPONSE memResp = (PPROCMONSEC_READ_MEM_RESPONSE)sysBuf;
            PEPROCESS targetProc = NULL;
            SIZE_T copied = 0;
            NTSTATUS lookupSt = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)memReq.TargetPid, &targetProc);
            if (NT_SUCCESS(lookupSt) && targetProc != NULL) {
                lookupSt = MmCopyVirtualMemory(
                    targetProc,
                    (PVOID)(ULONG_PTR)memReq.VirtualAddress,
                    PsGetCurrentProcess(),
                    memResp->Data,
                    memReq.Size,
                    KernelMode,
                    &copied
                );
                ObDereferenceObject(targetProc);
            }
            memResp->Status = (ULONG)lookupSt;
            memResp->BytesRead = (ULONG)copied;
            bytesReturned = FIELD_OFFSET(PROCMONSEC_READ_MEM_RESPONSE, Data) + (ULONG)copied;
            status = STATUS_SUCCESS;
            break;
        }

        case IOCTL_PROCMONSEC_DRAIN_HANDLE_EVENTS:
        {
            if (outLen < sizeof(PROCMONSEC_DRAIN_EVENTS_RESPONSE)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            PPROCMONSEC_DRAIN_EVENTS_RESPONSE drainResp = (PPROCMONSEC_DRAIN_EVENTS_RESPONSE)sysBuf;
            KIRQL oldIrql;
            ULONG drained = 0;

            RtlZeroMemory(drainResp, sizeof(*drainResp));
            KeAcquireSpinLock(&g_RingLock, &oldIrql);
            while (g_RingCount > 0 && drained < PROCMONSEC_DRAIN_BATCH) {
                drainResp->Events[drained] = g_EventRing[g_RingReadIdx];
                g_RingReadIdx = (g_RingReadIdx + 1) % PROCMONSEC_RING_CAPACITY;
                g_RingCount--;
                drained++;
            }
            KeReleaseSpinLock(&g_RingLock, oldIrql);

            drainResp->EventCount = drained;
            bytesReturned = sizeof(PROCMONSEC_DRAIN_EVENTS_RESPONSE);
            status = STATUS_SUCCESS;
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

Exit:
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING uDosName;

    UNREFERENCED_PARAMETER(DriverObject);

    if (g_ObRegHandle != NULL) {
        ObUnRegisterCallbacks(g_ObRegHandle);
        g_ObRegHandle = NULL;
    }

    RtlInitUnicodeString(&uDosName, PROCMONSEC_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&uDosName);

    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING uDevName;
    UNICODE_STRING uDosName;

    UNREFERENCED_PARAMETER(RegistryPath);

    KeInitializeSpinLock(&g_RingLock);

    RtlInitUnicodeString(&uDevName, PROCMONSEC_DEVICE_NAME);
    RtlInitUnicodeString(&uDosName, PROCMONSEC_DOS_DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &uDevName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&uDosName, &uDevName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
    DriverObject->DriverUnload                         = DriverUnload;

    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    RegisterHandleCallbacks();

    return STATUS_SUCCESS;
}

#include "kdns_tdi.h"
#include <tdi.h>
#include <tdikrnl.h>

// =============================================================
// PORT MANAGEMENT
// =============================================================

static volatile LONG g_LastDnsPort = KDNS_MIN_LOCAL_PORT;

USHORT KdnsTdiGetUniquePort(VOID)
{
    LONG Port = InterlockedIncrement(&g_LastDnsPort);
    
    if (Port > KDNS_MAX_LOCAL_PORT) {
        InterlockedExchange(&g_LastDnsPort, KDNS_MIN_LOCAL_PORT);
        Port = KDNS_MIN_LOCAL_PORT;
    }
    
    return (USHORT)Port;
}

// =============================================================
// TDI HELPERS
// =============================================================

#define UDP_DEVICE_NAME L"\\Device\\Udp"

typedef struct _TDI_CONTEXT {
    HANDLE AddressHandle;
    PFILE_OBJECT AddressObject;
    PDEVICE_OBJECT DeviceObject;
    BOOLEAN Valid;
} TDI_CONTEXT, *PTDI_CONTEXT;

static VOID TdiCleanupContext(PTDI_CONTEXT Context)
{
    if (!Context) return;
    
    if (Context->AddressObject) {
        ObDereferenceObject(Context->AddressObject);
        Context->AddressObject = NULL;
    }
    
    if (Context->AddressHandle) {
        ZwClose(Context->AddressHandle);
        Context->AddressHandle = NULL;
    }
    
    Context->Valid = FALSE;
}

static NTSTATUS TdiCreateAddress(
    _In_ USHORT LocalPort,
    _Out_ PTDI_CONTEXT Context
)
{
    if (!Context) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Context, sizeof(TDI_CONTEXT));

    // Build EA buffer for TDI address
    CHAR EaBuffer[sizeof(FILE_FULL_EA_INFORMATION) +
                  TDI_TRANSPORT_ADDRESS_LENGTH +
                  sizeof(TA_IP_ADDRESS)] = { 0 };

    PFILE_FULL_EA_INFORMATION Ea = (PFILE_FULL_EA_INFORMATION)EaBuffer;
    Ea->NextEntryOffset = 0;
    Ea->Flags = 0;
    Ea->EaNameLength = TDI_TRANSPORT_ADDRESS_LENGTH;
    Ea->EaValueLength = sizeof(TA_IP_ADDRESS);

    RtlCopyMemory(Ea->EaName, TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH + 1);

    // Setup TA_IP_ADDRESS
    PTA_IP_ADDRESS TaIp = (PTA_IP_ADDRESS)(Ea->EaName + TDI_TRANSPORT_ADDRESS_LENGTH + 1);
    TaIp->TAAddressCount = 1;
    TaIp->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    TaIp->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    TaIp->Address[0].Address[0].sin_port = HTONS(LocalPort);
    TaIp->Address[0].Address[0].in_addr = 0; // INADDR_ANY

    // Open UDP device
    UNICODE_STRING DeviceName;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK IoStatus;

    RtlInitUnicodeString(&DeviceName, UDP_DEVICE_NAME);
    InitializeObjectAttributes(&Attributes, &DeviceName, 
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS Status = ZwCreateFile(
        &Context->AddressHandle,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        &Attributes,
        &IoStatus,
        NULL,
        0,
        0,
        FILE_CREATE,
        0,
        Ea,
        sizeof(EaBuffer)
    );

    if (!NT_SUCCESS(Status)) {
        DbgPrint("KDNS: TDI CreateFile failed: 0x%08X (port %u)\n", Status, LocalPort);
        return Status;
    }

    // Get file object and device object
    Status = ObReferenceObjectByHandle(
        Context->AddressHandle,
        FILE_ANY_ACCESS,
        NULL,
        KernelMode,
        (PVOID*)&Context->AddressObject,
        NULL
    );

    if (!NT_SUCCESS(Status)) {
        DbgPrint("KDNS: ObReferenceObjectByHandle failed: 0x%08X\n", Status);
        ZwClose(Context->AddressHandle);
        Context->AddressHandle = NULL;
        return Status;
    }

    Context->DeviceObject = IoGetRelatedDeviceObject(Context->AddressObject);
    Context->Valid = TRUE;

    DbgPrint("KDNS: TDI bound to port %u\n", LocalPort);
    return STATUS_SUCCESS;
}

static NTSTATUS TdiSendDatagram(
    _In_ PTDI_CONTEXT Context,
    _In_ ULONG RemoteIp,
    _In_ USHORT RemotePort,
    _In_reads_bytes_(DataLength) PVOID Data,
    _In_ ULONG DataLength
)
{
    if (!Context || !Context->Valid || !Data) {
        return STATUS_INVALID_PARAMETER;
    }

    KEVENT Event;
    IO_STATUS_BLOCK IoStatus;
    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    // Build IRP
    PIRP Irp = TdiBuildInternalDeviceControlIrp(
        TDI_SEND_DATAGRAM,
        Context->DeviceObject,
        Context->AddressObject,
        &Event,
        &IoStatus
    );

    if (!Irp) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Allocate MDL
    PMDL Mdl = IoAllocateMdl(Data, DataLength, FALSE, FALSE, NULL);
    if (!Mdl) {
        IoFreeIrp(Irp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    MmBuildMdlForNonPagedPool(Mdl);

    // Build connection info
    ULONG ConnInfoSize = sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS);
    PTDI_CONNECTION_INFORMATION ConnInfo = KdnsAlloc(ConnInfoSize);
    if (!ConnInfo) {
        IoFreeMdl(Mdl);
        IoFreeIrp(Irp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PTA_IP_ADDRESS RemoteAddr = (PTA_IP_ADDRESS)(ConnInfo + 1);
    RemoteAddr->TAAddressCount = 1;
    RemoteAddr->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    RemoteAddr->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    RemoteAddr->Address[0].Address[0].sin_port = HTONS(RemotePort);
    RemoteAddr->Address[0].Address[0].in_addr = RemoteIp;

    ConnInfo->RemoteAddressLength = sizeof(TA_IP_ADDRESS);
    ConnInfo->RemoteAddress = RemoteAddr;

    // Setup IRP
    TdiBuildSendDatagram(
        Irp,
        Context->DeviceObject,
        Context->AddressObject,
        NULL,
        NULL,
        Mdl,
        DataLength,
        ConnInfo
    );

    // Send
    NTSTATUS Status = IoCallDriver(Context->DeviceObject, Irp);

    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
    }

    KdnsFree(ConnInfo);

    if (NT_SUCCESS(Status)) {
        DbgPrint("KDNS: Sent %lu bytes\n", DataLength);
    }
    else {
        DbgPrint("KDNS: Send failed: 0x%08X\n", Status);
    }

    return Status;
}

static NTSTATUS TdiReceiveDatagram(
    _In_ PTDI_CONTEXT Context,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesReceived,
    _In_ ULONG TimeoutMs
)
{
    if (!Context || !Context->Valid || !Buffer || !BytesReceived) {
        return STATUS_INVALID_PARAMETER;
    }

    KEVENT Event;
    IO_STATUS_BLOCK IoStatus;
    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    // Build IRP
    PIRP Irp = TdiBuildInternalDeviceControlIrp(
        TDI_RECEIVE_DATAGRAM,
        Context->DeviceObject,
        Context->AddressObject,
        &Event,
        &IoStatus
    );

    if (!Irp) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Allocate MDL
    PMDL Mdl = IoAllocateMdl(Buffer, BufferSize, FALSE, FALSE, NULL);
    if (!Mdl) {
        IoFreeIrp(Irp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    MmBuildMdlForNonPagedPool(Mdl);

    // Setup IRP
    TdiBuildReceiveDatagram(
        Irp,
        Context->DeviceObject,
        Context->AddressObject,
        NULL,
        NULL,
        Mdl,
        BufferSize,
        NULL,
        NULL,
        NULL
    );

    // Receive with timeout
    NTSTATUS Status = IoCallDriver(Context->DeviceObject, Irp);

    if (Status == STATUS_PENDING) {
        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -(LONGLONG)TimeoutMs * 10000;

        Status = KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, &Timeout);

        if (Status == STATUS_TIMEOUT) {
            DbgPrint("KDNS: Receive timeout\n");
            IoCancelIrp(Irp);
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            return STATUS_IO_TIMEOUT;
        }

        Status = IoStatus.Status;
    }

    if (NT_SUCCESS(Status)) {
        *BytesReceived = (ULONG)IoStatus.Information;
        DbgPrint("KDNS: Received %lu bytes\n", *BytesReceived);
    }
    else {
        *BytesReceived = 0;
        DbgPrint("KDNS: Receive failed: 0x%08X\n", Status);
    }

    return Status;
}

// =============================================================
// PUBLIC API
// =============================================================

NTSTATUS KdnsTdiSendAndReceive(
    _In_ ULONG DnsServerIp,
    _In_reads_bytes_(RequestLength) PVOID RequestData,
    _In_ ULONG RequestLength,
    _Out_writes_bytes_(ResponseBufferSize) PVOID ResponseBuffer,
    _In_ ULONG ResponseBufferSize,
    _Out_ PULONG ResponseLength,
    _In_ ULONG TimeoutMs,
    _In_ USHORT LocalPort
)
{
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        DbgPrint("KDNS: Cannot call at IRQL > PASSIVE_LEVEL\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    TDI_CONTEXT TdiCtx;
    NTSTATUS Status;

    // Create TDI address
    Status = TdiCreateAddress(LocalPort, &TdiCtx);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    // Send query
    Status = TdiSendDatagram(
        &TdiCtx,
        DnsServerIp,
        KDNS_DEFAULT_DNS_PORT,
        RequestData,
        RequestLength
    );

    if (!NT_SUCCESS(Status)) {
        TdiCleanupContext(&TdiCtx);
        return Status;
    }

    // Receive response
    Status = TdiReceiveDatagram(
        &TdiCtx,
        ResponseBuffer,
        ResponseBufferSize,
        ResponseLength,
        TimeoutMs
    );

    // Cleanup
    TdiCleanupContext(&TdiCtx);

    // Small delay to allow port release
    LARGE_INTEGER Delay;
    Delay.QuadPart = -10000LL * 100; // 100ms
    KeDelayExecutionThread(KernelMode, FALSE, &Delay);

    return Status;
}

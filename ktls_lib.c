#include "ktls_lib.h"
#include <tdi.h>
#include <tdikrnl.h>
#include <ntstrsafe.h>

// mbedTLS Includes
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/timing.h" 
#include "mbedtls/debug.h"
#include "mbedtls/platform.h"

// =============================================================
// CONSTANTS & MACROS
// =============================================================

#define DRIVER_TAG 'KTLS'
#define TCP_DEVICE_NAME L"\\Device\\Tcp"
#define UDP_DEVICE_NAME L"\\Device\\Udp"

#define HTONS(a) (((0xFF&(a))<<8) + ((0xFF00&(a))>>8))

// Timeout Constants
#define HANDSHAKE_TIMEOUT_MS 15000
#define UDP_DEFAULT_TIMEOUT_MS 2000
#define TCP_DEFAULT_TIMEOUT_MS 6000
#define SSL_READ_TIMEOUT_MS 10000

// Entropy & Crypto Constants
#define ENTROPY_SOURCE_LENGTH 32
#define PERSONALIZATION_STRING "KTLS"
#define PERSONALIZATION_LENGTH 4

// mbedTLS Error Codes
#define MBEDTLS_X509_CERT_VERIFY_FAILED (-0x3b00)

// Tick to Millisecond Conversion
#define TICKS_TO_MS_DIVISOR 10000

// =============================================================
// LOGGING
// =============================================================

#if DBG
#define KTLS_LOG_ERROR(fmt, ...) DbgPrint("KTLS [ERROR]: " fmt "\n", ##__VA_ARGS__)
#define KTLS_LOG_WARN(fmt, ...)  DbgPrint("KTLS [WARN]:  " fmt "\n", ##__VA_ARGS__)
#define KTLS_LOG_INFO(fmt, ...)  DbgPrint("KTLS [INFO]:  " fmt "\n", ##__VA_ARGS__)
#define KTLS_LOG_DEBUG(fmt, ...) DbgPrint("KTLS [DEBUG]: " fmt "\n", ##__VA_ARGS__)
#else
#define KTLS_LOG_ERROR(fmt, ...)
#define KTLS_LOG_WARN(fmt, ...)
#define KTLS_LOG_INFO(fmt, ...)
#define KTLS_LOG_DEBUG(fmt, ...)
#endif

// =============================================================
// STRUCTURES
// =============================================================

// Protocol Configuration
typedef struct _PROTOCOL_CONFIG {
    ULONG DefaultTimeout;
    BOOLEAN RequiresTdiConnection;
    BOOLEAN SupportsTls;
    const WCHAR* DeviceName;
} PROTOCOL_CONFIG;

// Timing Context
typedef struct _KTLS_TIMING_CONTEXT {
    LARGE_INTEGER StartTick;
    ULONG DurationMs;
    BOOLEAN Active;
} KTLS_TIMING_CONTEXT;

// Session Structure
typedef struct _KTLS_SESSION {
    // mbedTLS Contexts
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    // Custom Timing Contexts
    KTLS_TIMING_CONTEXT TimerInt;
    KTLS_TIMING_CONTEXT TimerFin;

    // Stored timeout in milliseconds
    ULONG TimeoutMs;

    // Connection Info
    KTLS_PROTOCOL Protocol;
    ULONG RemoteIp;
    USHORT RemotePort;

    // Flag to indicate if TLS is active
    BOOLEAN UseTls;

    // TDI Handles & Objects
    HANDLE AddressHandle;
    PFILE_OBJECT AddressFileObj;
    HANDLE ConnectionHandle;
    PFILE_OBJECT ConnFileObj;

    // Active I/O Object
    PFILE_OBJECT ActiveFileObj;
    PDEVICE_OBJECT DeviceObject;

} KTLS_SESSION;

// =============================================================
// PROTOCOL CONFIGURATION TABLE
// =============================================================

static const PROTOCOL_CONFIG g_ProtocolConfigs[] = {
    [KTLS_PROTO_TCP]       = { TCP_DEFAULT_TIMEOUT_MS, TRUE,  TRUE,  TCP_DEVICE_NAME },
    [KTLS_PROTO_UDP]       = { UDP_DEFAULT_TIMEOUT_MS, FALSE, TRUE,  UDP_DEVICE_NAME },
    [KTLS_PROTO_TCP_PLAIN] = { TCP_DEFAULT_TIMEOUT_MS, TRUE,  FALSE, TCP_DEVICE_NAME }
};

// =============================================================
// FORWARD DECLARATIONS
// =============================================================

static NTSTATUS ValidateSessionParams(ULONG Ip, USHORT Port, KTLS_PROTOCOL Protocol, PKTLS_SESSION* SessionOut);
static NTSTATUS InitializeTlsContext(PKTLS_SESSION s, PCHAR Hostname);
static NTSTATUS EstablishTransportConnection(PKTLS_SESSION s);
static NTSTATUS PerformTlsHandshake(PKTLS_SESSION s);
static ULONG GetElapsedMs(LARGE_INTEGER Start);
static NTSTATUS SafeBufferCopy(PVOID Dest, SIZE_T DestSize, PVOID Src, SIZE_T SrcSize);

// =============================================================
// MEMORY MANAGEMENT
// =============================================================

static void* KernelCalloc(size_t n, size_t size) {
    size_t total = n * size;
    
    // Check for multiplication overflow
    if (n != 0 && total / n != size) {
        KTLS_LOG_ERROR("Calloc overflow: n=%zu, size=%zu", n, size);
        return NULL;
    }
    
    void* p = ExAllocatePoolWithTag(NonPagedPool, total, DRIVER_TAG);
    if (p) {
        RtlZeroMemory(p, total);
    } else {
        KTLS_LOG_ERROR("Failed to allocate %zu bytes", total);
    }
    
    return p;
}

static void KernelFree(void* ptr) {
    if (ptr) {
        ExFreePoolWithTag(ptr, DRIVER_TAG);
    }
}

// =============================================================
// UTILITY FUNCTIONS
// =============================================================

static NTSTATUS ValidateSessionParams(
    ULONG Ip,
    USHORT Port,
    KTLS_PROTOCOL Protocol,
    PKTLS_SESSION* SessionOut
) {
    if (!SessionOut) {
        KTLS_LOG_ERROR("SessionOut is NULL");
        return STATUS_INVALID_PARAMETER;
    }
    
    if (Ip == 0) {
        KTLS_LOG_ERROR("Invalid IP address: 0");
        return STATUS_INVALID_PARAMETER;
    }
    
    if (Port == 0) {
        KTLS_LOG_ERROR("Invalid port: 0");
        return STATUS_INVALID_PARAMETER;
    }
    
    if (Protocol >= 3) { // Max protocol value
        KTLS_LOG_ERROR("Invalid protocol: %d", Protocol);
        return STATUS_INVALID_PARAMETER;
    }
    
    return STATUS_SUCCESS;
}

static NTSTATUS SafeBufferCopy(
    PVOID Dest,
    SIZE_T DestSize,
    PVOID Src,
    SIZE_T SrcSize
) {
    if (!Dest || !Src) {
        KTLS_LOG_ERROR("SafeBufferCopy: NULL pointer");
        return STATUS_INVALID_PARAMETER;
    }
    
    if (SrcSize > DestSize) {
        KTLS_LOG_ERROR("SafeBufferCopy: Buffer overflow (src=%zu, dest=%zu)", SrcSize, DestSize);
        return STATUS_BUFFER_OVERFLOW;
    }
    
    RtlCopyMemory(Dest, Src, SrcSize);
    return STATUS_SUCCESS;
}

static ULONG GetElapsedMs(LARGE_INTEGER Start) {
    LARGE_INTEGER Now;
    ULONG Inc;
    ULONGLONG Elapsed;
    
    KeQueryTickCount(&Now);
    Inc = KeQueryTimeIncrement();
    
    // Calculate elapsed ticks
    Elapsed = (ULONGLONG)(Now.QuadPart - Start.QuadPart);
    
    // Check for overflow: (Elapsed * Inc) / TICKS_TO_MS_DIVISOR
    if (Elapsed > (ULONGLONG)ULONG_MAX * TICKS_TO_MS_DIVISOR / Inc) {
        KTLS_LOG_WARN("Elapsed time overflow, returning max value");
        return ULONG_MAX;
    }
    
    return (ULONG)(Elapsed * Inc / TICKS_TO_MS_DIVISOR);
}

// =============================================================
// TDI NETWORK LAYER
// =============================================================

static NTSTATUS TdiOpenAddress(PKTLS_SESSION s) {
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attr;
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;

    UCHAR EaBuffer[sizeof(FILE_FULL_EA_INFORMATION) + sizeof(TdiTransportAddress) + sizeof(TA_IP_ADDRESS)];
    PFILE_FULL_EA_INFORMATION Ea = (PFILE_FULL_EA_INFORMATION)EaBuffer;
    PTA_IP_ADDRESS TaIp;

    const PROTOCOL_CONFIG* cfg = &g_ProtocolConfigs[s->Protocol];
    RtlInitUnicodeString(&Name, cfg->DeviceName);

    InitializeObjectAttributes(&Attr, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    RtlZeroMemory(EaBuffer, sizeof(EaBuffer));
    Ea->EaNameLength = sizeof(TdiTransportAddress) - 1;
    RtlCopyMemory(Ea->EaName, TdiTransportAddress, Ea->EaNameLength + 1);
    Ea->EaValueLength = sizeof(TA_IP_ADDRESS);

    TaIp = (PTA_IP_ADDRESS)(Ea->EaName + Ea->EaNameLength + 1);
    TaIp->TAAddressCount = 1;
    TaIp->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    TaIp->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    TaIp->Address[0].Address[0].sin_port = 0;
    TaIp->Address[0].Address[0].in_addr = 0;

    Status = ZwCreateFile(
        &s->AddressHandle,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        &Attr,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        0,
        Ea,
        sizeof(EaBuffer)
    );

    if (NT_SUCCESS(Status)) {
        Status = ObReferenceObjectByHandle(
            s->AddressHandle,
            FILE_ANY_ACCESS,
            NULL,
            KernelMode,
            (PVOID*)&s->AddressFileObj,
            NULL
        );
        
        if (NT_SUCCESS(Status)) {
            s->DeviceObject = IoGetRelatedDeviceObject(s->AddressFileObj);
            KTLS_LOG_INFO("Address opened successfully (Device: %S)", cfg->DeviceName);
        } else {
            KTLS_LOG_ERROR("ObReferenceObjectByHandle failed: 0x%x", Status);
            ZwClose(s->AddressHandle);
            s->AddressHandle = NULL;
        }
    } else {
        KTLS_LOG_ERROR("ZwCreateFile failed for %S: 0x%x", cfg->DeviceName, Status);
    }

    return Status;
}

static NTSTATUS TdiOpenConnection(PKTLS_SESSION s) {
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attr;
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;

    UCHAR EaBuffer[sizeof(FILE_FULL_EA_INFORMATION) + sizeof(TdiConnectionContext) + sizeof(PVOID)];
    PFILE_FULL_EA_INFORMATION Ea = (PFILE_FULL_EA_INFORMATION)EaBuffer;

    RtlInitUnicodeString(&Name, TCP_DEVICE_NAME);
    InitializeObjectAttributes(&Attr, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    RtlZeroMemory(EaBuffer, sizeof(EaBuffer));
    Ea->EaNameLength = sizeof(TdiConnectionContext) - 1;
    RtlCopyMemory(Ea->EaName, TdiConnectionContext, Ea->EaNameLength + 1);
    Ea->EaValueLength = sizeof(PVOID);
    *(PVOID*)(Ea->EaName + Ea->EaNameLength + 1) = NULL;

    Status = ZwCreateFile(
        &s->ConnectionHandle,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE,
        &Attr,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        0,
        Ea,
        sizeof(EaBuffer)
    );

    if (NT_SUCCESS(Status)) {
        Status = ObReferenceObjectByHandle(
            s->ConnectionHandle,
            FILE_ANY_ACCESS,
            NULL,
            KernelMode,
            (PVOID*)&s->ConnFileObj,
            NULL
        );
        
        if (!NT_SUCCESS(Status)) {
            KTLS_LOG_ERROR("ObReferenceObjectByHandle failed for connection: 0x%x", Status);
            ZwClose(s->ConnectionHandle);
            s->ConnectionHandle = NULL;
        }
    } else {
        KTLS_LOG_ERROR("TdiOpenConnection failed: 0x%x", Status);
    }
    
    return Status;
}

static NTSTATUS TdiAssociate(PKTLS_SESSION s) {
    PIRP Irp;
    KEVENT Event;
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;
    
    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    
    Irp = TdiBuildInternalDeviceControlIrp(
        TDI_ASSOCIATE_ADDRESS,
        s->DeviceObject,
        s->ConnFileObj,
        &Event,
        &IoStatus
    );
    
    if (!Irp) {
        KTLS_LOG_ERROR("TdiBuildInternalDeviceControlIrp failed for ASSOCIATE");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    TdiBuildAssociateAddress(Irp, s->DeviceObject, s->ConnFileObj, NULL, NULL, s->AddressHandle);

    Status = IoCallDriver(s->DeviceObject, Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
    }
    
    if (!NT_SUCCESS(Status)) {
        KTLS_LOG_ERROR("TdiAssociate failed: 0x%x", Status);
    }
    
    return Status;
}

static NTSTATUS TdiConnect(PKTLS_SESSION s) {
    PIRP Irp;
    KEVENT Event;
    IO_STATUS_BLOCK IoStatus;
    TA_IP_ADDRESS RemoteAddr;
    TDI_CONNECTION_INFORMATION ConnInfo;
    NTSTATUS Status;

    RemoteAddr.TAAddressCount = 1;
    RemoteAddr.Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    RemoteAddr.Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    RemoteAddr.Address[0].Address[0].sin_port = HTONS(s->RemotePort);
    RemoteAddr.Address[0].Address[0].in_addr = s->RemoteIp;

    RtlZeroMemory(&ConnInfo, sizeof(ConnInfo));
    ConnInfo.RemoteAddressLength = sizeof(RemoteAddr);
    ConnInfo.RemoteAddress = &RemoteAddr;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    
    Irp = TdiBuildInternalDeviceControlIrp(
        TDI_CONNECT,
        s->DeviceObject,
        s->ConnFileObj,
        &Event,
        &IoStatus
    );
    
    if (!Irp) {
        KTLS_LOG_ERROR("TdiBuildInternalDeviceControlIrp failed for CONNECT");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    TdiBuildConnect(Irp, s->DeviceObject, s->ConnFileObj, NULL, NULL, NULL, &ConnInfo, NULL);

    Status = IoCallDriver(s->DeviceObject, Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
    }
    
    if (!NT_SUCCESS(Status)) {
        KTLS_LOG_ERROR("TdiConnect failed: 0x%x", Status);
    }
    
    return Status;
}

static NTSTATUS TdiSendGeneric(PKTLS_SESSION s, PVOID Data, ULONG Len) {
    PIRP Irp;
    PMDL Mdl;
    KEVENT Event;
    IO_STATUS_BLOCK IoStatus;
    PVOID Buffer;
    NTSTATUS Status;
    PVOID ConnInfoToFree = NULL;
    BOOLEAN IsTcp;

    // Allocate NonPagedPool buffer (required for MDL)
    Buffer = ExAllocatePoolWithTag(NonPagedPool, Len, DRIVER_TAG);
    if (!Buffer) {
        KTLS_LOG_ERROR("Failed to allocate send buffer (%u bytes)", Len);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlCopyMemory(Buffer, Data, Len);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    IsTcp = (s->Protocol == KTLS_PROTO_TCP || s->Protocol == KTLS_PROTO_TCP_PLAIN);
    UCHAR MajorFunction = IsTcp ? TDI_SEND : TDI_SEND_DATAGRAM;

    Irp = TdiBuildInternalDeviceControlIrp(
        MajorFunction,
        s->DeviceObject,
        s->ActiveFileObj,
        &Event,
        &IoStatus
    );
    
    if (!Irp) {
        KTLS_LOG_ERROR("TdiBuildInternalDeviceControlIrp failed for SEND");
        ExFreePoolWithTag(Buffer, DRIVER_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Mdl = IoAllocateMdl(Buffer, Len, FALSE, FALSE, NULL);
    if (!Mdl) {
        KTLS_LOG_ERROR("IoAllocateMdl failed");
        IoFreeIrp(Irp);
        ExFreePoolWithTag(Buffer, DRIVER_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    MmBuildMdlForNonPagedPool(Mdl);

    if (IsTcp) {
        TdiBuildSend(Irp, s->DeviceObject, s->ActiveFileObj, NULL, NULL, Mdl, 0, Len);
    } else {
        // UDP: Allocate Connection Information
        SIZE_T ConnInfoSize = sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS);
        PTDI_CONNECTION_INFORMATION ConnInfo = (PTDI_CONNECTION_INFORMATION)
            ExAllocatePoolWithTag(NonPagedPool, ConnInfoSize, DRIVER_TAG);

        if (!ConnInfo) {
            KTLS_LOG_ERROR("Failed to allocate connection info");
            IoFreeMdl(Mdl);
            IoFreeIrp(Irp);
            ExFreePoolWithTag(Buffer, DRIVER_TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ConnInfoToFree = ConnInfo;

        PTA_IP_ADDRESS RemoteAddr = (PTA_IP_ADDRESS)(ConnInfo + 1);
        RemoteAddr->TAAddressCount = 1;
        RemoteAddr->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
        RemoteAddr->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
        RemoteAddr->Address[0].Address[0].sin_port = HTONS(s->RemotePort);
        RemoteAddr->Address[0].Address[0].in_addr = s->RemoteIp;

        ConnInfo->RemoteAddressLength = sizeof(TA_IP_ADDRESS);
        ConnInfo->RemoteAddress = RemoteAddr;

        TdiBuildSendDatagram(Irp, s->DeviceObject, s->ActiveFileObj, NULL, NULL, Mdl, Len, ConnInfo);
    }

    Status = IoCallDriver(s->DeviceObject, Irp);

    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
    }

    // Cleanup
    if (ConnInfoToFree) {
        ExFreePoolWithTag(ConnInfoToFree, DRIVER_TAG);
    }
    ExFreePoolWithTag(Buffer, DRIVER_TAG);

    if (!NT_SUCCESS(Status)) {
        KTLS_LOG_ERROR("TdiSendGeneric failed: 0x%x", Status);
    }

    return Status;
}

static NTSTATUS TdiRecvGeneric(PKTLS_SESSION s, PVOID Buffer, ULONG Len, PULONG Received) {
    PIRP Irp;
    PMDL Mdl;
    KEVENT Event;
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;
    LARGE_INTEGER TimeValue;
    BOOLEAN IsTcp;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    IsTcp = (s->Protocol == KTLS_PROTO_TCP || s->Protocol == KTLS_PROTO_TCP_PLAIN);
    UCHAR Major = IsTcp ? TDI_RECEIVE : TDI_RECEIVE_DATAGRAM;

    Irp = TdiBuildInternalDeviceControlIrp(
        Major,
        s->DeviceObject,
        s->ActiveFileObj,
        &Event,
        &IoStatus
    );
    
    if (!Irp) {
        KTLS_LOG_ERROR("TdiBuildInternalDeviceControlIrp failed for RECEIVE");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Mdl = IoAllocateMdl(Buffer, Len, FALSE, FALSE, NULL);
    if (!Mdl) {
        KTLS_LOG_ERROR("IoAllocateMdl failed for receive");
        IoFreeIrp(Irp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    MmBuildMdlForNonPagedPool(Mdl);

    if (IsTcp) {
        TdiBuildReceive(Irp, s->DeviceObject, s->ActiveFileObj, NULL, NULL, Mdl, TDI_RECEIVE_NORMAL, Len);
    } else {
        TdiBuildReceiveDatagram(Irp, s->DeviceObject, s->ActiveFileObj, NULL, NULL, Mdl, Len, NULL, NULL, NULL);
    }

    Status = IoCallDriver(s->DeviceObject, Irp);

    if (Status == STATUS_PENDING) {
        if (s->TimeoutMs == 0) {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = IoStatus.Status;
        } else {
            // Convert milliseconds to 100-nanosecond intervals (negative for relative time)
            TimeValue.QuadPart = -(LONGLONG)s->TimeoutMs * 10000LL;

            Status = KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, &TimeValue);

            if (Status == STATUS_TIMEOUT) {
                IoCancelIrp(Irp);
                KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
                Status = STATUS_IO_TIMEOUT;
            } else {
                Status = IoStatus.Status;
            }
        }
    }

    if (NT_SUCCESS(Status)) {
        *Received = (ULONG)IoStatus.Information;
    } else {
        *Received = 0;
        if (Status != STATUS_IO_TIMEOUT) {
            KTLS_LOG_ERROR("TdiRecvGeneric failed: 0x%x", Status);
        }
    }

    return Status;
}

// =============================================================
// ENTROPY & TIMING
// =============================================================

static int KernelEntropy(void* data, unsigned char* output, size_t len, size_t* olen) {
    LARGE_INTEGER pc, st;
    ULONGLONG it;
    ULONG proc_id;
    
    UNREFERENCED_PARAMETER(data);
    
    KeQueryPerformanceCounter(&pc);
    KeQuerySystemTime(&st);
    it = KeQueryInterruptTime();
    proc_id = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    
    for (size_t i = 0; i < len; i++) {
        // Mix multiple entropy sources with bit rotation
        output[i] = (unsigned char)(
            (pc.QuadPart >> ((i * 7) % 64)) ^
            (st.QuadPart >> ((i * 11) % 64)) ^
            (it >> ((i * 13) % 64)) ^
            (proc_id << (i % 8))
        );
        
        // Rotate sources for next iteration
        pc.QuadPart = _rotl64(pc.QuadPart, 1);
        st.QuadPart = _rotl64(st.QuadPart, 1);
        it = _rotl64(it, 1);
    }
    
    *olen = len;
    return 0;
}

// Timing Callbacks for mbedTLS DTLS

void KernelTimingSetDelay(void* data, uint32_t int_ms, uint32_t fin_ms) {
    PKTLS_SESSION s = (PKTLS_SESSION)data;

    if (fin_ms == 0) {
        s->TimerInt.Active = FALSE;
        s->TimerFin.Active = FALSE;
        return;
    }

    KeQueryTickCount(&s->TimerInt.StartTick);
    s->TimerInt.DurationMs = int_ms;
    s->TimerInt.Active = TRUE;

    s->TimerFin.StartTick = s->TimerInt.StartTick;
    s->TimerFin.DurationMs = fin_ms;
    s->TimerFin.Active = TRUE;
}

int KernelTimingGetDelay(void* data) {
    PKTLS_SESSION s = (PKTLS_SESSION)data;

    if (!s->TimerFin.Active) return -1;

    ULONG Elapsed = GetElapsedMs(s->TimerFin.StartTick);

    if (Elapsed >= s->TimerFin.DurationMs) return 2;
    if (Elapsed >= s->TimerInt.DurationMs) return 1;

    return 0;
}

// =============================================================
// MBEDTLS BIO CALLBACKS
// =============================================================

static int KernelNetSend(void* ctx, const unsigned char* buf, size_t len) {
    PKTLS_SESSION s = (PKTLS_SESSION)ctx;
    NTSTATUS status = TdiSendGeneric(s, (PVOID)buf, (ULONG)len);
    
    if (!NT_SUCCESS(status)) {
        KTLS_LOG_ERROR("KernelNetSend failed: 0x%x", status);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    
    return (int)len;
}

static int KernelNetRecv(void* ctx, unsigned char* buf, size_t len) {
    PKTLS_SESSION s = (PKTLS_SESSION)ctx;
    ULONG received = 0;

    NTSTATUS status = TdiRecvGeneric(s, buf, (ULONG)len, &received);

    if (status == STATUS_IO_TIMEOUT) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    if (!NT_SUCCESS(status)) {
        KTLS_LOG_ERROR("KernelNetRecv failed: 0x%x", status);
        return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    }
    
    if ((s->Protocol == KTLS_PROTO_TCP || s->Protocol == KTLS_PROTO_TCP_PLAIN) && received == 0) {
        return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
    }

    return (int)received;
}

// =============================================================
// TLS INITIALIZATION & HANDSHAKE
// =============================================================

static int KernelVerifyCallback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(crt);
    UNREFERENCED_PARAMETER(depth);

    // Clear all verification flags (accept any certificate)
    *flags = 0;

    return 0;
}

static NTSTATUS InitializeTlsContext(PKTLS_SESSION s, PCHAR Hostname) {
    int ret;
    int transport;
    
    // Initialize mbedTLS contexts
    mbedtls_ssl_init(&s->ssl);
    mbedtls_ssl_config_init(&s->conf);
    mbedtls_ctr_drbg_init(&s->ctr_drbg);
    mbedtls_entropy_init(&s->entropy);

    // Add entropy source
    mbedtls_entropy_add_source(
        &s->entropy,
        KernelEntropy,
        NULL,
        ENTROPY_SOURCE_LENGTH,
        MBEDTLS_ENTROPY_SOURCE_STRONG
    );
    
    // Seed DRBG
    ret = mbedtls_ctr_drbg_seed(
        &s->ctr_drbg,
        mbedtls_entropy_func,
        &s->entropy,
        (const unsigned char*)PERSONALIZATION_STRING,
        PERSONALIZATION_LENGTH
    );
    
    if (ret != 0) {
        KTLS_LOG_ERROR("mbedtls_ctr_drbg_seed failed: -0x%x", -ret);
        return STATUS_UNSUCCESSFUL;
    }

    // Configure SSL/TLS
    transport = (s->Protocol == KTLS_PROTO_UDP) ? 
                MBEDTLS_SSL_TRANSPORT_DATAGRAM : 
                MBEDTLS_SSL_TRANSPORT_STREAM;

    ret = mbedtls_ssl_config_defaults(
        &s->conf,
        MBEDTLS_SSL_IS_CLIENT,
        transport,
        MBEDTLS_SSL_PRESET_DEFAULT
    );
    
    if (ret != 0) {
        KTLS_LOG_ERROR("mbedtls_ssl_config_defaults failed: -0x%x", -ret);
        return STATUS_UNSUCCESSFUL;
    }

    // Disable certificate verification
    mbedtls_ssl_conf_authmode(&s->conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_verify(&s->conf, KernelVerifyCallback, NULL);

    // Set RNG
    mbedtls_ssl_conf_rng(&s->conf, mbedtls_ctr_drbg_random, &s->ctr_drbg);

    // Configure ALPN for HTTP/1.1
    static const char* alpn_protocols[] = { "http/1.1", NULL };
    ret = mbedtls_ssl_conf_alpn_protocols(&s->conf, alpn_protocols);
    if (ret != 0) {
        KTLS_LOG_WARN("Failed to set ALPN protocols: -0x%x", -ret);
    }

    // Disable session tickets and renegotiation
    mbedtls_ssl_conf_session_tickets(&s->conf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);
    mbedtls_ssl_conf_renegotiation(&s->conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);

    // DTLS-specific configuration
    if (s->Protocol == KTLS_PROTO_UDP) {
        mbedtls_ssl_set_timer_cb(&s->ssl, s, KernelTimingSetDelay, KernelTimingGetDelay);
        mbedtls_ssl_conf_read_timeout(&s->conf, SSL_READ_TIMEOUT_MS);
    }

    // Setup SSL context
    ret = mbedtls_ssl_setup(&s->ssl, &s->conf);
    if (ret != 0) {
        KTLS_LOG_ERROR("mbedtls_ssl_setup failed: -0x%x", -ret);
        return STATUS_UNSUCCESSFUL;
    }

    // Set SNI hostname if provided
    if (Hostname && Hostname[0] != '\0') {
        ret = mbedtls_ssl_set_hostname(&s->ssl, Hostname);
        if (ret != 0) {
            KTLS_LOG_WARN("Failed to set SNI hostname: -0x%x", -ret);
        } else {
            KTLS_LOG_INFO("SNI hostname set to: %s", Hostname);
        }
    }

    // Set BIO callbacks
    mbedtls_ssl_set_bio(
        &s->ssl,
        s,
        KernelNetSend,
        KernelNetRecv,
        (s->Protocol == KTLS_PROTO_UDP) ? KernelNetRecv : NULL
    );

    return STATUS_SUCCESS;
}

static NTSTATUS EstablishTransportConnection(PKTLS_SESSION s) {
    NTSTATUS Status;
    const PROTOCOL_CONFIG* cfg = &g_ProtocolConfigs[s->Protocol];

    // Open TDI address
    Status = TdiOpenAddress(s);
    if (!NT_SUCCESS(Status)) {
        KTLS_LOG_ERROR("TdiOpenAddress failed: 0x%x", Status);
        return Status;
    }

    // UDP doesn't require connection establishment
    if (!cfg->RequiresTdiConnection) {
        s->ActiveFileObj = s->AddressFileObj;
        return STATUS_SUCCESS;
    }

    // TCP: Open connection, associate, and connect
    Status = TdiOpenConnection(s);
    if (!NT_SUCCESS(Status)) {
        KTLS_LOG_ERROR("TdiOpenConnection failed: 0x%x", Status);
        return Status;
    }

    Status = TdiAssociate(s);
    if (!NT_SUCCESS(Status)) {
        KTLS_LOG_ERROR("TdiAssociate failed: 0x%x", Status);
        return Status;
    }

    Status = TdiConnect(s);
    if (!NT_SUCCESS(Status)) {
        KTLS_LOG_ERROR("TdiConnect failed: 0x%x", Status);
        return Status;
    }

    s->ActiveFileObj = s->ConnFileObj;
    
    KTLS_LOG_INFO("Transport connection established successfully");
    return STATUS_SUCCESS;
}

static NTSTATUS PerformTlsHandshake(PKTLS_SESSION s) {
    LARGE_INTEGER StartTime, Now;
    ULONG Inc;
    int ret;

    KeQueryTickCount(&StartTime);
    Inc = KeQueryTimeIncrement();

    KTLS_LOG_INFO("Starting TLS handshake...");

    do {
        ret = mbedtls_ssl_handshake(&s->ssl);

        // Check for global timeout
        KeQueryTickCount(&Now);
        ULONG Elapsed = (ULONG)((Now.QuadPart - StartTime.QuadPart) * Inc / TICKS_TO_MS_DIVISOR);
        
        if (Elapsed > HANDSHAKE_TIMEOUT_MS) {
            KTLS_LOG_ERROR("Handshake global timeout (%u ms)", HANDSHAKE_TIMEOUT_MS);
            return STATUS_IO_TIMEOUT;
        }

    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    // Handle certificate verification errors
    if (ret == MBEDTLS_X509_CERT_VERIFY_FAILED) {
        uint32_t verify_flags = mbedtls_ssl_get_verify_result(&s->ssl);

        if (verify_flags == 0) {
            // Our callback cleared flags but mbedTLS internal check failed
            KTLS_LOG_WARN("Cert internal check failed but verification disabled - accepting");
            ret = 0;
        } else {
            KTLS_LOG_ERROR("Certificate verification failed (flags: 0x%x)", verify_flags);
            return STATUS_CONNECTION_REFUSED;
        }
    }

    if (ret != 0) {
        KTLS_LOG_ERROR("Handshake failed: -0x%x", -ret);
        return STATUS_CONNECTION_REFUSED;
    }

    KTLS_LOG_INFO("TLS handshake successful");

    // Log ALPN protocol
    const char* alpn_selected = mbedtls_ssl_get_alpn_protocol(&s->ssl);
    if (alpn_selected) {
        KTLS_LOG_INFO("ALPN protocol: %s", alpn_selected);
    }

    return STATUS_SUCCESS;
}

// =============================================================
// PUBLIC API IMPLEMENTATION
// =============================================================

VOID KtlsSetTimeout(PKTLS_SESSION Session, ULONG TimeoutMs) {
    if (Session) {
        Session->TimeoutMs = TimeoutMs;
        KTLS_LOG_DEBUG("Timeout set to %u ms", TimeoutMs);
    }
}

NTSTATUS KtlsGlobalInit(void) {
    mbedtls_platform_set_calloc_free(KernelCalloc, KernelFree);
    KTLS_LOG_INFO("KTLS library initialized");
    return STATUS_SUCCESS;
}

VOID KtlsGlobalCleanup(void) {
    KTLS_LOG_INFO("KTLS library cleanup");
}

NTSTATUS KtlsConnect(
    ULONG Ip,
    USHORT Port,
    KTLS_PROTOCOL Protocol,
    PCHAR Hostname,
    PKTLS_SESSION* SessionOut
) {
    NTSTATUS Status;
    PKTLS_SESSION s;

    // Validate parameters
    Status = ValidateSessionParams(Ip, Port, Protocol, SessionOut);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    // Allocate session
    s = (PKTLS_SESSION)ExAllocatePoolWithTag(NonPagedPool, sizeof(KTLS_SESSION), DRIVER_TAG);
    if (!s) {
        KTLS_LOG_ERROR("Failed to allocate session structure");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(s, sizeof(KTLS_SESSION));

    // Initialize session parameters
    s->Protocol = Protocol;
    s->RemoteIp = Ip;
    s->RemotePort = Port;
    s->UseTls = g_ProtocolConfigs[Protocol].SupportsTls;
    s->TimeoutMs = g_ProtocolConfigs[Protocol].DefaultTimeout;

    KTLS_LOG_INFO("Connecting to %u.%u.%u.%u:%u (Protocol: %d, TLS: %d)",
        (Ip >> 0) & 0xFF, (Ip >> 8) & 0xFF, (Ip >> 16) & 0xFF, (Ip >> 24) & 0xFF,
        Port, Protocol, s->UseTls);

    // Initialize TLS context (only if using TLS)
    if (s->UseTls) {
        Status = InitializeTlsContext(s, Hostname);
        if (!NT_SUCCESS(Status)) {
            goto cleanup;
        }
    }

    // Establish transport connection
    Status = EstablishTransportConnection(s);
    if (!NT_SUCCESS(Status)) {
        goto cleanup;
    }

    // Perform TLS handshake (only if using TLS)
    if (s->UseTls) {
        Status = PerformTlsHandshake(s);
        if (!NT_SUCCESS(Status)) {
            goto cleanup;
        }
    }

    *SessionOut = s;
    KTLS_LOG_INFO("Connection established successfully");
    return STATUS_SUCCESS;

cleanup:
    KtlsClose(s);
    return Status;
}

NTSTATUS KtlsSend(PKTLS_SESSION Session, PVOID Data, ULONG Length, PULONG BytesSent) {
    if (!Session || !Data || !BytesSent) {
        KTLS_LOG_ERROR("Invalid parameters in KtlsSend");
        return STATUS_INVALID_PARAMETER;
    }

    if (!Session->UseTls) {
        // Plain TCP - send directly
        NTSTATUS Status = TdiSendGeneric(Session, Data, Length);
        if (NT_SUCCESS(Status)) {
            *BytesSent = Length;
            return STATUS_SUCCESS;
        }
        *BytesSent = 0;
        return Status;
    }

    // TLS - use mbedTLS
    int ret = mbedtls_ssl_write(&Session->ssl, (const unsigned char*)Data, Length);
    if (ret > 0) {
        *BytesSent = (ULONG)ret;
        return STATUS_SUCCESS;
    }
    
    *BytesSent = 0;
    KTLS_LOG_ERROR("mbedtls_ssl_write failed: -0x%x", -ret);
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS KtlsRecv(PKTLS_SESSION Session, PVOID Buffer, ULONG BufferSize, PULONG BytesReceived) {
    if (!Session || !Buffer || !BytesReceived) {
        KTLS_LOG_ERROR("Invalid parameters in KtlsRecv");
        return STATUS_INVALID_PARAMETER;
    }

    if (!Session->UseTls) {
        // Plain TCP - receive directly
        NTSTATUS Status = TdiRecvGeneric(Session, Buffer, BufferSize, BytesReceived);

        if (Status == STATUS_IO_TIMEOUT) {
            *BytesReceived = 0;
            return STATUS_IO_TIMEOUT;
        }

        if (!NT_SUCCESS(Status)) {
            *BytesReceived = 0;
            return Status;
        }

        if (*BytesReceived == 0) {
            return STATUS_END_OF_FILE;
        }

        return STATUS_SUCCESS;
    }

    // TLS - use mbedTLS
    int ret = mbedtls_ssl_read(&Session->ssl, (unsigned char*)Buffer, BufferSize);

    if (ret > 0) {
        *BytesReceived = (ULONG)ret;
        return STATUS_SUCCESS;
    }

    *BytesReceived = 0;

    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0) {
        return STATUS_END_OF_FILE;
    }

    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return STATUS_IO_TIMEOUT;
    }

    if (ret == MBEDTLS_ERR_SSL_TIMEOUT) {
        return STATUS_IO_TIMEOUT;
    }

    KTLS_LOG_ERROR("mbedtls_ssl_read failed: -0x%x", -ret);
    return STATUS_UNSUCCESSFUL;
}

VOID KtlsClose(PKTLS_SESSION s) {
    if (!s) return;

    KTLS_LOG_INFO("Closing session");

    // Close TLS connection gracefully
    if (s->UseTls && s->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
        mbedtls_ssl_close_notify(&s->ssl);
    }

    // Clean mbedTLS contexts (only if initialized)
    if (s->UseTls) {
        mbedtls_ssl_free(&s->ssl);
        mbedtls_ssl_config_free(&s->conf);
        mbedtls_ctr_drbg_free(&s->ctr_drbg);
        mbedtls_entropy_free(&s->entropy);
    }

    // Clean TDI resources
    if (s->ConnFileObj) {
        ObDereferenceObject(s->ConnFileObj);
    }
    if (s->ConnectionHandle) {
        ZwClose(s->ConnectionHandle);
    }
    if (s->AddressFileObj) {
        ObDereferenceObject(s->AddressFileObj);
    }
    if (s->AddressHandle) {
        ZwClose(s->AddressHandle);
    }

    ExFreePoolWithTag(s, DRIVER_TAG);
    
    KTLS_LOG_INFO("Session closed successfully");
}
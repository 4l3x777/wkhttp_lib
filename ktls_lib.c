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
// INTERNAL CONSTANTS & MACROS
// =============================================================

#define DRIVER_TAG 'KTLS'
#define TCP_DEVICE_NAME L"\\Device\\Tcp"
#define UDP_DEVICE_NAME L"\\Device\\Udp"

#define HTONS(a) (((0xFF&(a))<<8) + ((0xFF00&(a))>>8))

// =============================================================
// INTERNAL STRUCTURES
// =============================================================

// Internal struct to hold timing state
typedef struct _KTLS_TIMING_CONTEXT {
    LARGE_INTEGER StartTick;
    ULONG DurationMs;
    BOOLEAN Active;
} KTLS_TIMING_CONTEXT;

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

    // NEW: Flag to indicate if TLS is active
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
// MEMORY ALLOCATORS
// =============================================================

static void* KernelCalloc(size_t n, size_t size) {
    size_t total = n * size;
    if (n != 0 && total / n != size) return NULL;
    void* p = ExAllocatePoolWithTag(NonPagedPool, total, DRIVER_TAG);
    if (p) RtlZeroMemory(p, total);
    return p;
}

static void KernelFree(void* ptr) {
    if (ptr) ExFreePoolWithTag(ptr, DRIVER_TAG);
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

    // Select TCP device for both TCP modes, UDP device for UDP
    BOOLEAN IsTcp = (s->Protocol == KTLS_PROTO_TCP || s->Protocol == KTLS_PROTO_TCP_PLAIN);
    RtlInitUnicodeString(&Name, IsTcp ? TCP_DEVICE_NAME : UDP_DEVICE_NAME);

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

    Status = ZwCreateFile(&s->AddressHandle, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &Attr, &IoStatus,
        NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, 0, Ea, sizeof(EaBuffer));

    if (NT_SUCCESS(Status)) {
        Status = ObReferenceObjectByHandle(s->AddressHandle, FILE_ANY_ACCESS, NULL, KernelMode,
            (PVOID*)&s->AddressFileObj, NULL);
        if (NT_SUCCESS(Status)) {
            s->DeviceObject = IoGetRelatedDeviceObject(s->AddressFileObj);
            DbgPrint("KTLS: Address opened successfully (Device: %S)\n",
                IsTcp ? L"TCP" : L"UDP");
        }
        else {
            ZwClose(s->AddressHandle);
            s->AddressHandle = NULL;
        }
    }
    else {
        DbgPrint("KTLS: ZwCreateFile failed for %S: 0x%x\n",
            IsTcp ? L"TCP" : L"UDP", Status);
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

    Status = ZwCreateFile(&s->ConnectionHandle, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &Attr, &IoStatus,
        NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, 0, Ea, sizeof(EaBuffer));

    if (NT_SUCCESS(Status)) {
        Status = ObReferenceObjectByHandle(s->ConnectionHandle, FILE_ANY_ACCESS, NULL, KernelMode, (PVOID*)&s->ConnFileObj, NULL);
    }
    return Status;
}

static NTSTATUS TdiAssociate(PKTLS_SESSION s) {
    PIRP Irp;
    KEVENT Event;
    IO_STATUS_BLOCK IoStatus;
    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Irp = TdiBuildInternalDeviceControlIrp(TDI_ASSOCIATE_ADDRESS, s->DeviceObject, s->ConnFileObj, &Event, &IoStatus);
    if (!Irp) return STATUS_INSUFFICIENT_RESOURCES;

    TdiBuildAssociateAddress(Irp, s->DeviceObject, s->ConnFileObj, NULL, NULL, s->AddressHandle);

    NTSTATUS Status = IoCallDriver(s->DeviceObject, Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
    }
    return Status;
}

static NTSTATUS TdiConnect(PKTLS_SESSION s) {
    PIRP Irp;
    KEVENT Event;
    IO_STATUS_BLOCK IoStatus;
    TA_IP_ADDRESS RemoteAddr;
    TDI_CONNECTION_INFORMATION ConnInfo;

    RemoteAddr.TAAddressCount = 1;
    RemoteAddr.Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    RemoteAddr.Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    RemoteAddr.Address[0].Address[0].sin_port = HTONS(s->RemotePort);
    RemoteAddr.Address[0].Address[0].in_addr = s->RemoteIp;

    RtlZeroMemory(&ConnInfo, sizeof(ConnInfo));
    ConnInfo.RemoteAddressLength = sizeof(RemoteAddr);
    ConnInfo.RemoteAddress = &RemoteAddr;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Irp = TdiBuildInternalDeviceControlIrp(TDI_CONNECT, s->DeviceObject, s->ConnFileObj, &Event, &IoStatus);
    if (!Irp) return STATUS_INSUFFICIENT_RESOURCES;

    TdiBuildConnect(Irp, s->DeviceObject, s->ConnFileObj, NULL, NULL, NULL, &ConnInfo, NULL);

    NTSTATUS Status = IoCallDriver(s->DeviceObject, Irp);
    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
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

    // 1. Allocate Buffer (NonPagedPool) - REQUIRED for MDL
    Buffer = ExAllocatePoolWithTag(NonPagedPool, Len, DRIVER_TAG);
    if (!Buffer) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(Buffer, Data, Len);

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    // 2. Build IRP
    UCHAR MajorFunction = (s->Protocol == KTLS_PROTO_TCP || s->Protocol == KTLS_PROTO_TCP_PLAIN)
        ? TDI_SEND : TDI_SEND_DATAGRAM;

    Irp = TdiBuildInternalDeviceControlIrp(MajorFunction, s->DeviceObject, s->ActiveFileObj, &Event, &IoStatus);
    if (!Irp) {
        ExFreePoolWithTag(Buffer, DRIVER_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 3. Allocate MDL
    Mdl = IoAllocateMdl(Buffer, Len, FALSE, FALSE, NULL);
    if (!Mdl) {
        IoFreeIrp(Irp);
        ExFreePoolWithTag(Buffer, DRIVER_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    MmBuildMdlForNonPagedPool(Mdl);

    // 4. Setup Transport parameters
    if (s->Protocol == KTLS_PROTO_TCP || s->Protocol == KTLS_PROTO_TCP_PLAIN) {
        // TCP: Use TdiBuildSend with proper flags [web:112]
        TdiBuildSend(Irp, s->DeviceObject, s->ActiveFileObj, NULL, NULL, Mdl, 0, Len);
    }
    else {
        // UDP: Allocate Connection Information
        PTDI_CONNECTION_INFORMATION ConnInfo = (PTDI_CONNECTION_INFORMATION)
            ExAllocatePoolWithTag(NonPagedPool, sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS), DRIVER_TAG);

        if (!ConnInfo) {
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

    // 5. Call Driver
    Status = IoCallDriver(s->DeviceObject, Irp);

    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
    }

    // 6. Cleanup
    if (ConnInfoToFree) {
        ExFreePoolWithTag(ConnInfoToFree, DRIVER_TAG);
    }

    ExFreePoolWithTag(Buffer, DRIVER_TAG);

    return Status;
}

static NTSTATUS TdiRecvGeneric(PKTLS_SESSION s, PVOID Buffer, ULONG Len, PULONG Received) {
    PIRP Irp;
    PMDL Mdl;
    KEVENT Event;
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;
    LARGE_INTEGER TimeValue;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    UCHAR Major = (s->Protocol == KTLS_PROTO_TCP || s->Protocol == KTLS_PROTO_TCP_PLAIN)
        ? TDI_RECEIVE : TDI_RECEIVE_DATAGRAM;

    Irp = TdiBuildInternalDeviceControlIrp(Major, s->DeviceObject, s->ActiveFileObj, &Event, &IoStatus);
    if (!Irp) return STATUS_INSUFFICIENT_RESOURCES;

    Mdl = IoAllocateMdl(Buffer, Len, FALSE, FALSE, NULL);
    if (!Mdl) {
        IoFreeIrp(Irp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    MmBuildMdlForNonPagedPool(Mdl);

    if (s->Protocol == KTLS_PROTO_TCP || s->Protocol == KTLS_PROTO_TCP_PLAIN) {
        TdiBuildReceive(Irp, s->DeviceObject, s->ActiveFileObj, NULL, NULL, Mdl, TDI_RECEIVE_NORMAL, Len);
    }
    else {
        TdiBuildReceiveDatagram(Irp, s->DeviceObject, s->ActiveFileObj, NULL, NULL, Mdl, Len, NULL, NULL, NULL);
    }

    Status = IoCallDriver(s->DeviceObject, Irp);

    if (Status == STATUS_PENDING) {
        if (s->TimeoutMs == 0) {
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = IoStatus.Status;
        }
        else {
            TimeValue.QuadPart = -(LONGLONG)s->TimeoutMs * 10000;

            Status = KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, &TimeValue);

            if (Status == STATUS_TIMEOUT) {
                IoCancelIrp(Irp);
                KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
                Status = STATUS_IO_TIMEOUT;
            }
            else {
                Status = IoStatus.Status;
            }
        }
    }

    if (NT_SUCCESS(Status)) *Received = (ULONG)IoStatus.Information;
    else *Received = 0;

    return Status;
}

// =============================================================
// ENTROPY & TIMING
// =============================================================

static int KernelEntropy(void* data, unsigned char* output, size_t len, size_t* olen) {
    LARGE_INTEGER pc, st;
    KeQueryPerformanceCounter(&pc);
    KeQuerySystemTime(&st);
    for (size_t i = 0; i < len; i++) {
        output[i] = (unsigned char)(pc.QuadPart ^ st.QuadPart ^ (ULONG_PTR)PsGetCurrentProcessId());
        pc.QuadPart = _rotl64(pc.QuadPart, 1);
    }
    *olen = len;
    return 0;
}

// ---------------------------------------------------------
// Timing Implementations
// ---------------------------------------------------------

static ULONG GetElapsedMs(LARGE_INTEGER Start) {
    LARGE_INTEGER Now, Freq;
    KeQueryTickCount(&Now);
    // Ticks -> Ms. (Tick * 1000 * Inc) / 10000000
    // Simplified: KeQueryTickCount gives ticks. KeQueryTimeIncrement gives 100ns units per tick.
    // Ms = (Now - Start) * Inc / 10000
    ULONG Inc = KeQueryTimeIncrement();
    return (ULONG)((Now.QuadPart - Start.QuadPart) * Inc / 10000);
}

// Callback: Set Delay
// int_ms: Intermediate delay (milliseconds)
// fin_ms: Final delay (milliseconds)
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

    s->TimerFin.StartTick = s->TimerInt.StartTick; // Same start
    s->TimerFin.DurationMs = fin_ms;
    s->TimerFin.Active = TRUE;
}

// Callback: Get Delay Status
// Returns: -1 (cancelled), 0 (none), 1 (intermediate), 2 (final)
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
    return NT_SUCCESS(status) ? (int)len : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

static int KernelNetRecv(void* ctx, unsigned char* buf, size_t len) {
    PKTLS_SESSION s = (PKTLS_SESSION)ctx;
    ULONG received = 0;

    NTSTATUS status = TdiRecvGeneric(s, buf, (ULONG)len, &received);

    if (status == STATUS_IO_TIMEOUT) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    if (!NT_SUCCESS(status)) return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    if ((s->Protocol == KTLS_PROTO_TCP || s->Protocol == KTLS_PROTO_TCP_PLAIN) && received == 0)
        return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;

    return (int)received;
}

// =============================================================
// PUBLIC API IMPLEMENTATION
// =============================================================

VOID KtlsSetTimeout(PKTLS_SESSION Session, ULONG TimeoutMs) {
    if (Session) {
        Session->TimeoutMs = TimeoutMs;
    }
}

NTSTATUS KtlsGlobalInit(void) {
    mbedtls_platform_set_calloc_free(KernelCalloc, KernelFree);
    return STATUS_SUCCESS;
}

VOID KtlsGlobalCleanup(void) { }

static int KernelVerifyCallback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(crt);
    UNREFERENCED_PARAMETER(depth);

    // Clear all verification flags (accept any certificate)
    *flags = 0;

    return 0;  // Success
}

NTSTATUS KtlsConnect(ULONG Ip, USHORT Port, KTLS_PROTOCOL Protocol, PCHAR Hostname, PKTLS_SESSION* SessionOut) {
    NTSTATUS Status;
    PKTLS_SESSION s;
    int ret;

    s = (PKTLS_SESSION)ExAllocatePoolWithTag(NonPagedPool, sizeof(KTLS_SESSION), DRIVER_TAG);
    if (!s) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(s, sizeof(KTLS_SESSION));

    s->Protocol = Protocol;
    s->RemoteIp = Ip;
    s->RemotePort = Port;
    s->UseTls = (Protocol != KTLS_PROTO_TCP_PLAIN);
    s->TimeoutMs = (Protocol == KTLS_PROTO_UDP) ? 2000 : 6000;

    // 1. Init mbedTLS (only if using TLS)
    if (s->UseTls) {
        mbedtls_ssl_init(&s->ssl);
        mbedtls_ssl_config_init(&s->conf);
        mbedtls_ctr_drbg_init(&s->ctr_drbg);
        mbedtls_entropy_init(&s->entropy);

        mbedtls_entropy_add_source(&s->entropy, KernelEntropy, NULL, 32, MBEDTLS_ENTROPY_SOURCE_STRONG);
        if (mbedtls_ctr_drbg_seed(&s->ctr_drbg, mbedtls_entropy_func, &s->entropy, "KTLS", 4) != 0) {
            Status = STATUS_UNSUCCESSFUL;
            goto cleanup;
        }

        int transport = (Protocol == KTLS_PROTO_UDP) ? MBEDTLS_SSL_TRANSPORT_DATAGRAM : MBEDTLS_SSL_TRANSPORT_STREAM;

        if (mbedtls_ssl_config_defaults(&s->conf, MBEDTLS_SSL_IS_CLIENT, transport,
            MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
            Status = STATUS_UNSUCCESSFUL;
            goto cleanup;
        }

        // Completely disable certificate verification
        mbedtls_ssl_conf_authmode(&s->conf, MBEDTLS_SSL_VERIFY_NONE);

        // Add custom verify callback that accepts everything
        mbedtls_ssl_conf_verify(&s->conf, KernelVerifyCallback, NULL);

        // Set RNG
        mbedtls_ssl_conf_rng(&s->conf, mbedtls_ctr_drbg_random, &s->ctr_drbg);

        // Add ALPN support for HTTP/1.1 (required by Google and modern HTTPS servers)
        static const char* alpn_protocols[] = { "http/1.1", NULL };
        if (mbedtls_ssl_conf_alpn_protocols(&s->conf, alpn_protocols) != 0) {
            DbgPrint("KTLS: Failed to set ALPN protocols\n");
        }

        // Disable session tickets (helps with some strict servers)
        mbedtls_ssl_conf_session_tickets(&s->conf, MBEDTLS_SSL_SESSION_TICKETS_DISABLED);

        // Disable renegotiation
        mbedtls_ssl_conf_renegotiation(&s->conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);

        if (Protocol == KTLS_PROTO_UDP) {
            mbedtls_ssl_set_timer_cb(&s->ssl, s, KernelTimingSetDelay, KernelTimingGetDelay);
            mbedtls_ssl_conf_read_timeout(&s->conf, 10000);
        }

        if (mbedtls_ssl_setup(&s->ssl, &s->conf) != 0) {
            Status = STATUS_UNSUCCESSFUL;
            goto cleanup;
        }

        // Set SNI hostname if provided
        if (Hostname && Hostname[0] != '\0') {
            if (mbedtls_ssl_set_hostname(&s->ssl, Hostname) != 0) {
                DbgPrint("KTLS: Failed to set SNI hostname\n");
            }
            else {
                DbgPrint("KTLS: SNI hostname set to: %s\n", Hostname);
            }
        }

        mbedtls_ssl_set_bio(&s->ssl, s, KernelNetSend, KernelNetRecv,
            (Protocol == KTLS_PROTO_UDP) ? KernelNetRecv : NULL);
    }

    // 2. Init TDI
    Status = TdiOpenAddress(s);
    if (!NT_SUCCESS(Status)) goto cleanup;

    if (Protocol == KTLS_PROTO_UDP) {
        s->ActiveFileObj = s->AddressFileObj;
    }
    else {
        Status = TdiOpenConnection(s);
        if (!NT_SUCCESS(Status)) goto cleanup;

        Status = TdiAssociate(s);
        if (!NT_SUCCESS(Status)) goto cleanup;

        Status = TdiConnect(s);
        if (!NT_SUCCESS(Status)) goto cleanup;

        s->ActiveFileObj = s->ConnFileObj;
    }

    // 3. Handshake (only if using TLS)
    if (s->UseTls) {
        LARGE_INTEGER StartTime, Now;
        KeQueryTickCount(&StartTime);
        ULONG MaxHandshakeTimeMs = 15000;
        ULONG Inc = KeQueryTimeIncrement();

        do {
            ret = mbedtls_ssl_handshake(&s->ssl);

            KeQueryTickCount(&Now);
            ULONG Elapsed = (ULONG)((Now.QuadPart - StartTime.QuadPart) * Inc / 10000);
            if (Elapsed > MaxHandshakeTimeMs) {
                DbgPrint("KTLS: Handshake Global Timeout!\n");
                ret = MBEDTLS_ERR_SSL_TIMEOUT;
                break;
            }

        } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

        // Special handling for certificate errors when VERIFY_NONE is set
        if (ret == -0x3b00) {  // MBEDTLS_ERR_X509_CERT_VERIFY_FAILED
            uint32_t verify_flags = mbedtls_ssl_get_verify_result(&s->ssl);

            if (verify_flags == 0) {
                // Our callback cleared all flags, but mbedTLS internal check still failed
                // This happens with some servers (like Google) that have complex cert chains
                // Since we explicitly disabled verification, treat this as success
                DbgPrint("KTLS: Cert internal check failed but verification disabled - accepting\n");
                ret = 0;  // Override error
            }
            else {
                // Genuine verification failure with non-zero flags
                DbgPrint("KTLS: Certificate verification failed\n");
                DbgPrint("KTLS: Verify flags: 0x%x\n", verify_flags);
            }
        }

        if (ret != 0) {
            DbgPrint("KTLS: Handshake failed -0x%x\n", -ret);
            Status = STATUS_CONNECTION_REFUSED;
            goto cleanup;
        }

        DbgPrint("KTLS: Handshake successful\n");

        // Log negotiated ALPN protocol (for debugging)
        const char* alpn_selected = mbedtls_ssl_get_alpn_protocol(&s->ssl);
        if (alpn_selected) {
            DbgPrint("KTLS: ALPN protocol: %s\n", alpn_selected);
        }
    }

    *SessionOut = s;
    return STATUS_SUCCESS;

cleanup:
    KtlsClose(s);
    return Status;
}

NTSTATUS KtlsSend(PKTLS_SESSION Session, PVOID Data, ULONG Length, PULONG BytesSent) {
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
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS KtlsRecv(PKTLS_SESSION Session, PVOID Buffer, ULONG BufferSize, PULONG BytesReceived) {
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

    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0)
        return STATUS_END_OF_FILE;

    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return STATUS_IO_TIMEOUT;
    }

    if (ret == MBEDTLS_ERR_SSL_TIMEOUT)
        return STATUS_IO_TIMEOUT;

    return STATUS_UNSUCCESSFUL;
}

VOID KtlsClose(PKTLS_SESSION s) {
    if (!s) return;

    if (s->UseTls && s->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
        mbedtls_ssl_close_notify(&s->ssl);
    }

    // Clean mbedTLS (only if it was initialized)
    if (s->UseTls) {
        mbedtls_ssl_free(&s->ssl);
        mbedtls_ssl_config_free(&s->conf);
        mbedtls_ctr_drbg_free(&s->ctr_drbg);
        mbedtls_entropy_free(&s->entropy);
    }

    // Clean TDI
    if (s->ConnFileObj) ObDereferenceObject(s->ConnFileObj);
    if (s->ConnectionHandle) ZwClose(s->ConnectionHandle);
    if (s->AddressFileObj) ObDereferenceObject(s->AddressFileObj);
    if (s->AddressHandle) ZwClose(s->AddressHandle);

    ExFreePoolWithTag(s, DRIVER_TAG);
}
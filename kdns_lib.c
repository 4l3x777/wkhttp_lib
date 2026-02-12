#include "kdns_lib.h"
#include <tdi.h>
#include <tdikrnl.h>
#include <ntstrsafe.h>

// =============================================================
// DNS CACHE
// =============================================================

typedef struct _DNS_CACHE_ENTRY {
    CHAR Hostname[256];
    ULONG IpAddress;
    LARGE_INTEGER Timestamp;
    BOOLEAN Valid;
} DNS_CACHE_ENTRY, * PDNS_CACHE_ENTRY;

#define DNS_CACHE_SIZE 32
#define DNS_CACHE_TTL_SECONDS 300 // 5 minutes

static DNS_CACHE_ENTRY g_DnsCache[DNS_CACHE_SIZE] = { 0 };
static KSPIN_LOCK g_DnsCacheLock;
static BOOLEAN g_DnsCacheInitialized = FALSE;

// Port management for DNS requests
static volatile LONG g_LastDnsPort = 50000;

// =============================================================
// TDI & NETWORK
// =============================================================

#define KDNS_TAG 'DNSk'
#define UDP_DEVICE_NAME L"\\Device\\Udp"
#define HTONS(a) (((0xFF&(a))<<8) + ((0xFF00&(a))>>8))
#define NTOHS(a) HTONS(a)  // Same operation for network to host

// =============================================================
// INTERNAL STRUCTURES & CONSTANTS
// =============================================================

#pragma pack(push, 1)
typedef struct _DNS_HEADER {
    USHORT Id;
    USHORT Flags;
    USHORT QuestionCount;
    USHORT AnswerCount;
    USHORT AuthorityCount;
    USHORT AdditionalCount;
} DNS_HEADER, * PDNS_HEADER;
#pragma pack(pop)

#define DNS_TYPE_A      1
#define DNS_TYPE_CNAME  5
#define DNS_CLASS_IN    1
#define DNS_FLAG_RD     0x0100
#define DNS_MAX_CNAME_DEPTH 10

static ULONG g_DnsSeed = 0;

// =============================================================
// HELPERS
// =============================================================

static PVOID KdnsAlloc(ULONG Size) {
    return ExAllocatePoolWithTag(NonPagedPool, Size, KDNS_TAG);
}

static VOID KdnsFree(PVOID Ptr) {
    if (Ptr) ExFreePoolWithTag(Ptr, KDNS_TAG);
}

// Simple LCG Random Generator
static USHORT KdnsGetRandomId(void) {
    if (g_DnsSeed == 0) {
        LARGE_INTEGER Tick;
        KeQueryTickCount(&Tick);
        g_DnsSeed = Tick.LowPart;
    }
    g_DnsSeed = g_DnsSeed * 1103515245 + 12345;
    return (USHORT)((g_DnsSeed >> 16) & 0xFFFF);
}

// Encode hostname: "google.com" -> "\x06google\x03com\x00"
static ULONG KdnsEncodeName(PCHAR Host, PCHAR Buf) {
    ULONG Len = 0;
    PCHAR LabelPtr = Buf;
    PCHAR Curr = Host;
    ULONG Cnt = 0;

    Len++; // Reserve first length byte
    while (*Curr) {
        if (*Curr == '.') {
            *LabelPtr = (CHAR)Cnt;
            LabelPtr = Buf + Len;
            Cnt = 0;
            Len++;
        }
        else {
            Buf[Len++] = *Curr;
            Cnt++;
        }
        Curr++;
    }
    *LabelPtr = (CHAR)Cnt;
    Buf[Len++] = 0;
    return Len;
}

// Parse DNS name (handles compression pointers)
static ULONG KdnsParseName(PUCHAR Start, PUCHAR Ptr, PUCHAR End, PCHAR OutName, ULONG OutSize) {
    ULONG OutLen = 0;
    PUCHAR Current = Ptr;
    ULONG JumpCount = 0;
    BOOLEAN Jumped = FALSE;
    PUCHAR NextPtr = NULL;

    while (Current < End && *Current != 0 && JumpCount < 20) {
        if ((*Current & 0xC0) == 0xC0) {
            // Compression pointer
            if (Current + 1 >= End) return 0;

            USHORT Offset = ((*Current & 0x3F) << 8) | *(Current + 1);
            if (!Jumped) {
                NextPtr = Current + 2;
                Jumped = TRUE;
            }
            Current = Start + Offset;
            JumpCount++;

            if (Current >= End || Current < Start) return 0;
            continue;
        }

        // Regular label
        UCHAR LabelLen = *Current++;
        if (LabelLen > 63 || LabelLen == 0) break;
        if (Current + LabelLen > End) return 0;

        if (OutLen + LabelLen + 1 >= OutSize) return 0;
        RtlCopyMemory(OutName + OutLen, Current, LabelLen);
        OutLen += LabelLen;
        OutName[OutLen++] = '.';
        Current += LabelLen;
    }

    // Remove trailing dot
    if (OutLen > 0 && OutName[OutLen - 1] == '.') OutLen--;
    OutName[OutLen] = '\0';

    // Return bytes consumed from original pointer
    return (ULONG)(Jumped && NextPtr ? (NextPtr - Ptr) : (Current - Ptr + 1));
}

// =============================================================
// DNS CACHE API
// =============================================================

// Get unique port for DNS request
USHORT KdnsGetUniquePort(VOID)
{
    LONG LocalPort = InterlockedIncrement(&g_LastDnsPort);
    if (LocalPort > 60000) {
        InterlockedExchange(&g_LastDnsPort, 50000);
        LocalPort = 50000;
    }
    return (USHORT)LocalPort;
}

// Initialize DNS cache
VOID KdnsInitializeCache(VOID)
{
    if (!g_DnsCacheInitialized) {
        KeInitializeSpinLock(&g_DnsCacheLock);
        RtlZeroMemory(g_DnsCache, sizeof(g_DnsCache));
        g_DnsCacheInitialized = TRUE;
        DbgPrint("KDNS: Cache initialized\n");
    }
}

// Cleanup DNS cache
VOID KdnsCleanupCache(VOID)
{
    if (g_DnsCacheInitialized) {
        KIRQL OldIrql;
        KeAcquireSpinLock(&g_DnsCacheLock, &OldIrql);
        RtlZeroMemory(g_DnsCache, sizeof(g_DnsCache));
        KeReleaseSpinLock(&g_DnsCacheLock, OldIrql);
        g_DnsCacheInitialized = FALSE;
        DbgPrint("KDNS: Cache cleaned up\n");
    }
}

// Lookup DNS cache
static BOOLEAN KdnsLookupCache(_In_ PCHAR Hostname, _Out_ PULONG IpAddress)
{
    if (!g_DnsCacheInitialized || !Hostname || !IpAddress) {
        return FALSE;
    }

    KIRQL OldIrql;
    LARGE_INTEGER CurrentTime;
    KeQuerySystemTime(&CurrentTime);

    KeAcquireSpinLock(&g_DnsCacheLock, &OldIrql);

    for (ULONG i = 0; i < DNS_CACHE_SIZE; i++) {
        if (g_DnsCache[i].Valid && _stricmp(g_DnsCache[i].Hostname, Hostname) == 0) {
            LARGE_INTEGER Elapsed;
            Elapsed.QuadPart = (CurrentTime.QuadPart - g_DnsCache[i].Timestamp.QuadPart) / 10000000LL;

            if (Elapsed.QuadPart < DNS_CACHE_TTL_SECONDS) {
                *IpAddress = g_DnsCache[i].IpAddress;
                KeReleaseSpinLock(&g_DnsCacheLock, OldIrql);
                DbgPrint("KDNS: Cache hit for %s -> %08X\n", Hostname, *IpAddress);
                return TRUE;
            }
            else {
                g_DnsCache[i].Valid = FALSE;
            }
        }
    }

    KeReleaseSpinLock(&g_DnsCacheLock, OldIrql);
    return FALSE;
}

// Update DNS cache
static VOID KdnsUpdateCache(_In_ PCHAR Hostname, _In_ ULONG IpAddress)
{
    if (!g_DnsCacheInitialized || !Hostname) {
        return;
    }

    KIRQL OldIrql;
    LARGE_INTEGER CurrentTime;
    KeQuerySystemTime(&CurrentTime);

    KeAcquireSpinLock(&g_DnsCacheLock, &OldIrql);

    ULONG OldestIndex = 0;
    LARGE_INTEGER OldestTime = g_DnsCache[0].Timestamp;

    for (ULONG i = 0; i < DNS_CACHE_SIZE; i++) {
        if (!g_DnsCache[i].Valid) {
            OldestIndex = i;
            break;
        }
        if (g_DnsCache[i].Timestamp.QuadPart < OldestTime.QuadPart) {
            OldestTime = g_DnsCache[i].Timestamp;
            OldestIndex = i;
        }
    }

    RtlStringCchCopyA(g_DnsCache[OldestIndex].Hostname, 256, Hostname);
    g_DnsCache[OldestIndex].IpAddress = IpAddress;
    g_DnsCache[OldestIndex].Timestamp = CurrentTime;
    g_DnsCache[OldestIndex].Valid = TRUE;

    KeReleaseSpinLock(&g_DnsCacheLock, OldIrql);
    DbgPrint("KDNS: Cached %s -> %08X\n", Hostname, IpAddress);
}

// =============================================================
// TDI UDP ENGINE
// =============================================================

static NTSTATUS KdnsSendAndRecvWithPort(
    ULONG ServerIp,
    PVOID ReqData,
    ULONG ReqLen,
    PVOID RespBuf,
    ULONG RespMax,
    PULONG RespLen,
    ULONG TimeoutMs,
    USHORT LocalPort
) {
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        DbgPrint("KDNS: [Error] Called at IRQL > PASSIVE_LEVEL\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    NTSTATUS Status;
    HANDLE AddrHandle;
    PFILE_OBJECT AddrObj;
    PDEVICE_OBJECT DevObj;
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attr;
    IO_STATUS_BLOCK IoStatus;
    PIRP Irp;
    KEVENT Event;
    PMDL Mdl;

    // 1. Open UDP Address with SPECIFIC LOCAL PORT
    UCHAR EaBuf[sizeof(FILE_FULL_EA_INFORMATION) + sizeof(TdiTransportAddress) + sizeof(TA_IP_ADDRESS)] = { 0 };
    PFILE_FULL_EA_INFORMATION Ea = (PFILE_FULL_EA_INFORMATION)EaBuf;
    PTA_IP_ADDRESS TaIp;

    RtlInitUnicodeString(&Name, UDP_DEVICE_NAME);
    InitializeObjectAttributes(&Attr, &Name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    Ea->EaNameLength = sizeof(TdiTransportAddress) - 1;
    RtlCopyMemory(Ea->EaName, TdiTransportAddress, Ea->EaNameLength + 1);
    Ea->EaValueLength = sizeof(TA_IP_ADDRESS);

    TaIp = (PTA_IP_ADDRESS)(Ea->EaName + Ea->EaNameLength + 1);
    TaIp->TAAddressCount = 1;
    TaIp->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    TaIp->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;

    // Bind to specific local port
    TaIp->Address[0].Address[0].sin_port = HTONS(LocalPort);  // Use unique port
    TaIp->Address[0].Address[0].in_addr = 0;  // INADDR_ANY
    DbgPrint("KDNS: Binding to local port %u\n", LocalPort);

    Status = ZwCreateFile(&AddrHandle, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &Attr, &IoStatus, NULL, 0, 0,
        FILE_CREATE, 0, Ea, sizeof(EaBuf));

    if (!NT_SUCCESS(Status)) {
        DbgPrint("KDNS: [Error] ZwCreateFile failed: 0x%08X (port %u)\n", Status, LocalPort);
        return Status;
    }

    Status = ObReferenceObjectByHandle(AddrHandle, FILE_ANY_ACCESS, NULL, KernelMode, (PVOID*)&AddrObj, NULL);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("KDNS: [Error] ObRef failed: 0x%08X\n", Status);
        ZwClose(AddrHandle);
        return Status;
    }
    DevObj = IoGetRelatedDeviceObject(AddrObj);

    // 2. SEND
    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Irp = TdiBuildInternalDeviceControlIrp(TDI_SEND_DATAGRAM, DevObj, AddrObj, &Event, &IoStatus);
    if (!Irp) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    Mdl = IoAllocateMdl(ReqData, ReqLen, FALSE, FALSE, NULL);
    if (!Mdl) {
        IoFreeIrp(Irp);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }
    MmBuildMdlForNonPagedPool(Mdl);

    PTDI_CONNECTION_INFORMATION ConnInfo = KdnsAlloc(sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS));
    if (!ConnInfo) {
        IoFreeMdl(Mdl);
        IoFreeIrp(Irp);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    PTA_IP_ADDRESS IP = (PTA_IP_ADDRESS)(ConnInfo + 1);
    IP->TAAddressCount = 1;
    IP->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    IP->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    IP->Address[0].Address[0].sin_port = HTONS(53);  // DNS server port
    IP->Address[0].Address[0].in_addr = ServerIp;
    ConnInfo->RemoteAddressLength = sizeof(TA_IP_ADDRESS);
    ConnInfo->RemoteAddress = IP;

    TdiBuildSendDatagram(Irp, DevObj, AddrObj, NULL, NULL, Mdl, ReqLen, ConnInfo);
    Status = IoCallDriver(DevObj, Irp);

    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
    }
    KdnsFree(ConnInfo);

    if (!NT_SUCCESS(Status)) {
        DbgPrint("KDNS: [Error] Send failed: 0x%08X (port %u)\n", Status, LocalPort);
        goto cleanup;
    }

    DbgPrint("KDNS: Sent %lu bytes from port %u\n", ReqLen, LocalPort);

    // 3. RECEIVE
    KeClearEvent(&Event);
    Irp = TdiBuildInternalDeviceControlIrp(TDI_RECEIVE_DATAGRAM, DevObj, AddrObj, &Event, &IoStatus);
    if (!Irp) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }

    Mdl = IoAllocateMdl(RespBuf, RespMax, FALSE, FALSE, NULL);
    if (!Mdl) {
        IoFreeIrp(Irp);
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup;
    }
    MmBuildMdlForNonPagedPool(Mdl);

    TdiBuildReceiveDatagram(Irp, DevObj, AddrObj, NULL, NULL, Mdl, RespMax, NULL, NULL, NULL);
    Status = IoCallDriver(DevObj, Irp);

    if (Status == STATUS_PENDING) {
        LARGE_INTEGER Timeout;
        Timeout.QuadPart = -(LONGLONG)TimeoutMs * 10000;

        Status = KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, &Timeout);

        if (Status == STATUS_TIMEOUT) {
            DbgPrint("KDNS: [Error] Receive timeout (port %u)\n", LocalPort);
            IoCancelIrp(Irp);
            KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
            Status = STATUS_IO_TIMEOUT;
        }
        else {
            Status = IoStatus.Status;
        }
    }

    if (NT_SUCCESS(Status)) {
        *RespLen = (ULONG)IoStatus.Information;
        DbgPrint("KDNS: Received %lu bytes on port %u\n", *RespLen, LocalPort);
    }
    else {
        DbgPrint("KDNS: [Error] Receive failed: 0x%08X (port %u)\n", Status, LocalPort);
    }

cleanup:
    ObDereferenceObject(AddrObj);
    ZwClose(AddrHandle);

    // Delay after closing to release port
    LARGE_INTEGER Delay;
    Delay.QuadPart = -10000LL * 150; // 150ms delay
    KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    DbgPrint("KDNS: Port %u released\n", LocalPort);

    return Status;
}

static NTSTATUS KdnsSendAndRecv(
    ULONG ServerIp,
    PVOID ReqData,
    ULONG ReqLen,
    PVOID RespBuf,
    ULONG RespMax,
    PULONG RespLen,
    ULONG TimeoutMs
) {
    return KdnsSendAndRecvWithPort(
        ServerIp,
        ReqData,
        ReqLen,
        RespBuf,
        RespMax,
        RespLen,
        TimeoutMs,
        KdnsGetUniquePort()
    );
}

// =============================================================
// RECURSIVE DNS RESOLUTION WITH CNAME SUPPORT
// =============================================================

static NTSTATUS KdnsResolveInternal(PCHAR Hostname, ULONG DnsServerIp, ULONG TimeoutMs, PULONG ResolvedIp, ULONG Depth) {
    if (Depth >= DNS_MAX_CNAME_DEPTH) {
        DbgPrint("KDNS: [Error] CNAME chain too deep (>%d)\n", DNS_MAX_CNAME_DEPTH);
        return STATUS_TOO_MANY_LINKS;
    }

    // Validate hostname before dns query
    if (!Hostname) {
        DbgPrint("KDNS: [Error] NULL hostname\n");
        return STATUS_INVALID_PARAMETER;
    }

    ULONG HostnameLen = 0;
    while (Hostname[HostnameLen] != '\0' && HostnameLen < 256) {
        HostnameLen++;
    }

    DbgPrint("KDNS: [DEBUG] Hostname to resolve: '%s' (length: %lu)\n",
        Hostname, HostnameLen);

    // Check length (DNS FQDN max 253, labels max 63)
    if (HostnameLen == 0) {
        DbgPrint("KDNS: [Error] Empty hostname\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (HostnameLen > 253) {
        DbgPrint("KDNS: [Error] Hostname too long: %lu > 253\n", HostnameLen);
        return STATUS_INVALID_PARAMETER;
    }

    // Check for invalid characters
    for (ULONG i = 0; i < HostnameLen; i++) {
        CHAR c = Hostname[i];
        if (c == '/' || c == '?' || c == '#' || c == '\\' || c == ' ') {
            DbgPrint("KDNS: [Error] Invalid character '%c' (0x%02X) at position %lu in hostname: %s\n",
                c, (UCHAR)c, i, Hostname);
            return STATUS_INVALID_PARAMETER;
        }
    }

    USHORT LocalPort = KdnsGetUniquePort();
    DbgPrint("KDNS: Resolving %s using local port %u (depth: %lu)\n", Hostname, LocalPort, Depth);

    PVOID Req = KdnsAlloc(512);
    PVOID Res = KdnsAlloc(512);
    ULONG ReqLen = sizeof(DNS_HEADER), ResLen = 0;
    DNS_HEADER* Hdr;
    NTSTATUS Status;

    if (!Req || !Res) {
        if (Req) KdnsFree(Req);
        if (Res) KdnsFree(Res);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(Req, 512);

    // Build Query
    Hdr = (DNS_HEADER*)Req;
    Hdr->Id = HTONS(KdnsGetRandomId());
    Hdr->Flags = HTONS(DNS_FLAG_RD);
    Hdr->QuestionCount = HTONS(1);

    PCHAR Curr = (PCHAR)(Hdr + 1);
    ULONG NameLen = KdnsEncodeName(Hostname, Curr);
    Curr += NameLen;
    ReqLen += NameLen;

    USHORT* Type = (USHORT*)Curr;
    Type[0] = HTONS(DNS_TYPE_A);
    Type[1] = HTONS(DNS_CLASS_IN);
    ReqLen += 4;

    // Send & Receive
    Status = KdnsSendAndRecvWithPort(
        DnsServerIp,
        Req,
        ReqLen,
        Res,
        512,
        &ResLen,
        TimeoutMs,
        LocalPort
    );
    if (!NT_SUCCESS(Status)) {
        DbgPrint("KDNS: Send/Recv failed for %s: 0x%08X\n", Hostname, Status);

        KdnsFree(Req);
        KdnsFree(Res);

        // Delay before returning on error
        LARGE_INTEGER Delay;
        Delay.QuadPart = -10000LL * 100; // 100ms
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);

        return Status;
    }

    // Parse Response
    if (ResLen < sizeof(DNS_HEADER)) {
        Status = STATUS_INVALID_NETWORK_RESPONSE;
        goto cleanup;
    }

    UCHAR* Start = (UCHAR*)Res;
    UCHAR* End = (UCHAR*)Res + ResLen;
    UCHAR* Ptr = (UCHAR*)Res + sizeof(DNS_HEADER);

    if (((DNS_HEADER*)Res)->Id != Hdr->Id) {
        Status = STATUS_INVALID_NETWORK_RESPONSE;
        goto cleanup;
    }

    USHORT AnswerCount = NTOHS(((DNS_HEADER*)Res)->AnswerCount);
    if (AnswerCount == 0) {
        DbgPrint("KDNS: No answers for %s\n", Hostname);
        Status = STATUS_NOT_FOUND;
        goto cleanup;
    }

    // Skip Question Section
    while (Ptr < End && *Ptr != 0) {
        if ((*Ptr & 0xC0) == 0xC0) {
            Ptr += 2;
            break;
        }
        ULONG L = *Ptr;
        Ptr += (L + 1);
        if (Ptr >= End) {
            Status = STATUS_INVALID_NETWORK_RESPONSE;
            goto cleanup;
        }
    }
    if (Ptr < End && *Ptr == 0) Ptr++;
    if (Ptr + 4 > End) {
        Status = STATUS_INVALID_NETWORK_RESPONSE;
        goto cleanup;
    }
    Ptr += 4; // Skip Type + Class

    // Parse Answer Section(s)
    for (USHORT i = 0; i < AnswerCount && Ptr < End; i++) {
        // Skip answer name
        if ((*Ptr & 0xC0) == 0xC0) {
            Ptr += 2;
        }
        else {
            while (Ptr < End && *Ptr != 0) {
                ULONG L = *Ptr;
                Ptr += (L + 1);
                if (Ptr >= End) {
                    Status = STATUS_INVALID_NETWORK_RESPONSE;
                    goto cleanup;
                }
            }
            if (Ptr >= End) {
                Status = STATUS_INVALID_NETWORK_RESPONSE;
                goto cleanup;
            }
            Ptr++;
        }

        if (Ptr + 10 > End) {
            Status = STATUS_INVALID_NETWORK_RESPONSE;
            goto cleanup;
        }

        USHORT RecordType = NTOHS(*(USHORT*)Ptr);
        Ptr += 2;
        Ptr += 2; // Class
        Ptr += 4; // TTL
        USHORT DataLen = NTOHS(*(USHORT*)Ptr);
        Ptr += 2;

        if (Ptr + DataLen > End) {
            Status = STATUS_INVALID_NETWORK_RESPONSE;
            goto cleanup;
        }

        if (RecordType == DNS_TYPE_A) {
            // A Record found
            if (DataLen != 4) {
                Status = STATUS_INVALID_NETWORK_RESPONSE;
                goto cleanup;
            }
            *ResolvedIp = *(ULONG*)Ptr;
            DbgPrint("KDNS: Resolved %s -> %08x (depth %lu)\n", Hostname, *ResolvedIp, Depth);
            Status = STATUS_SUCCESS;
            goto cleanup;
        }
        else if (RecordType == DNS_TYPE_CNAME) {
            // CNAME Record - extract and recurse
            CHAR CnameTarget[256];
            ULONG Parsed = KdnsParseName(Start, Ptr, End, CnameTarget, sizeof(CnameTarget));

            if (Parsed == 0 || CnameTarget[0] == '\0') {
                DbgPrint("KDNS: Failed to parse CNAME\n");
                Status = STATUS_INVALID_NETWORK_RESPONSE;
                goto cleanup;
            }

            DbgPrint("KDNS: %s -> CNAME -> %s\n", Hostname, CnameTarget);

            // Free buffers and recurse
            KdnsFree(Req);
            KdnsFree(Res);

            // Delay before recursion
            LARGE_INTEGER Delay;
            Delay.QuadPart = -10000LL * 100; // 100ms
            KeDelayExecutionThread(KernelMode, FALSE, &Delay);

            return KdnsResolveInternal(CnameTarget, DnsServerIp, TimeoutMs, ResolvedIp, Depth + 1);
        }
        else {
            // Skip other record types
            Ptr += DataLen;
        }
    }

    // No A record found
    DbgPrint("KDNS: No A record in response for %s\n", Hostname);
    Status = STATUS_NOT_FOUND;

cleanup:
    KdnsFree(Req);
    KdnsFree(Res);

    // Delay before returning to allow port release
    LARGE_INTEGER Delay;
    Delay.QuadPart = -10000LL * 200; // 200ms delay
    KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    DbgPrint("KDNS: Cleanup completed for %s (status: 0x%08X)\n", Hostname, Status);

    return Status;
}

// =============================================================
// PUBLIC API
// =============================================================

NTSTATUS KdnsGlobalInit(void) {
    LARGE_INTEGER Tick;
    KeQueryTickCount(&Tick);
    g_DnsSeed = Tick.LowPart;
    return STATUS_SUCCESS;
}

VOID KdnsGlobalCleanup(void) { }

NTSTATUS KdnsResolve(PCHAR Hostname, ULONG DnsServerIp, ULONG TimeoutMs, PULONG ResolvedIp) {
    return KdnsResolveInternal(Hostname, DnsServerIp, TimeoutMs, ResolvedIp, 0);
}

NTSTATUS KdnsResolveWithCache(
    _In_ PCHAR Hostname,
    _In_ ULONG DnsServerIp,
    _In_ ULONG TimeoutMs,
    _Out_ PULONG ResolvedIp
)
{
    if (!Hostname || !ResolvedIp) {
        return STATUS_INVALID_PARAMETER;
    }

    *ResolvedIp = 0;

    CHAR CleanHostname[256];
    PCHAR PathStart = NULL;
    ULONG HostnameLen = 0;

    // Find '/' or '?' which indicates path/query start
    for (PCHAR p = Hostname; *p != '\0'; p++) {
        if (*p == '/' || *p == '?') {
            PathStart = p;
            break;
        }
        HostnameLen++;
    }

    // Copy only hostname part (without path)
    if (PathStart != NULL) {
        if (HostnameLen >= sizeof(CleanHostname)) {
            DbgPrint("KDNS: [Error] Hostname too long: %lu bytes\n", HostnameLen);
            return STATUS_INVALID_PARAMETER;
        }
        RtlCopyMemory(CleanHostname, Hostname, HostnameLen);
        CleanHostname[HostnameLen] = '\0';
        DbgPrint("KDNS: Stripped path from hostname: '%s' -> '%s'\n", Hostname, CleanHostname);
        Hostname = CleanHostname;
    }

    // Check hostname length (DNS label max 63 chars, FQDN max 253)
    if (HostnameLen > 253) {
        DbgPrint("KDNS: [Error] Hostname exceeds 253 characters\n");
        return STATUS_INVALID_PARAMETER;
    }

    // Check cache
    if (KdnsLookupCache(Hostname, ResolvedIp)) {
        return STATUS_SUCCESS;
    }

    DbgPrint("KDNS: Cache miss for %s, performing DNS query\n", Hostname);

    // If not in cache, make DNS request
    NTSTATUS Status = KdnsResolve(Hostname, DnsServerIp, TimeoutMs, ResolvedIp);

    if (NT_SUCCESS(Status) && *ResolvedIp != 0) {
        // Store in cache
        KdnsUpdateCache(Hostname, *ResolvedIp);
    }

    return Status;
}

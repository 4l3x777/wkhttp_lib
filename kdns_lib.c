#include "kdns_lib.h"
#include "kdns_cache.h"
#include "kdns_packet.h"
#include "kdns_ip.h"
#include "kdns_tdi.h"
#include <ntstrsafe.h>

// =============================================================
// DNS RESOLUTION ENGINE
// =============================================================

static NTSTATUS KdnsResolveInternal(
    _In_ PCHAR Hostname,
    _In_ ULONG DnsServerIp,
    _In_ ULONG TimeoutMs,
    _Out_ PULONG ResolvedIp,
    _In_ ULONG RecursionDepth
);

static NTSTATUS KdnsParseResponse(
    _In_ PVOID ResponseBuffer,
    _In_ ULONG ResponseLength,
    _In_ USHORT ExpectedTransactionId,
    _Out_ PULONG ResolvedIp,
    _Out_writes_(256) PCHAR CnameTarget,
    _Out_ PBOOLEAN IsCname
)
{
    if (!ResponseBuffer || !ResolvedIp || !CnameTarget || !IsCname) {
        return STATUS_INVALID_PARAMETER;
    }

    *IsCname = FALSE;
    *ResolvedIp = 0;
    CnameTarget[0] = '\0';

    // Validate minimum size
    if (ResponseLength < sizeof(DNS_HEADER)) {
        DbgPrint("KDNS: Response too small: %lu bytes\n", ResponseLength);
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    PDNS_HEADER Header = (PDNS_HEADER)ResponseBuffer;
    PUCHAR Start = (PUCHAR)ResponseBuffer;
    PUCHAR End = Start + ResponseLength;
    PUCHAR Ptr = Start + sizeof(DNS_HEADER);

    // Verify transaction ID
    if (Header->Id != HTONS(ExpectedTransactionId)) {
        DbgPrint("KDNS: Transaction ID mismatch: expected 0x%04X, got 0x%04X\n",
            ExpectedTransactionId, NTOHS(Header->Id));
        return STATUS_INVALID_NETWORK_RESPONSE;
    }

    USHORT AnswerCount = NTOHS(Header->AnswerCount);
    if (AnswerCount == 0) {
        DbgPrint("KDNS: No answers in response\n");
        return STATUS_NOT_FOUND;
    }

    DbgPrint("KDNS: Parsing %u answer(s)\n", AnswerCount);

    // Skip question section
    while (Ptr < End && *Ptr != 0) {
        if ((*Ptr & 0xC0) == 0xC0) {
            Ptr += 2;
            break;
        }
        ULONG LabelLen = *Ptr;
        Ptr += (LabelLen + 1);
        if (Ptr >= End) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }
    }
    if (Ptr < End && *Ptr == 0) Ptr++;
    if (Ptr + 4 > End) {
        return STATUS_INVALID_NETWORK_RESPONSE;
    }
    Ptr += 4; // Skip QTYPE + QCLASS

    // Parse answer records
    for (USHORT i = 0; i < AnswerCount && Ptr < End; i++) {
        // Skip name
        if ((*Ptr & 0xC0) == 0xC0) {
            Ptr += 2;
        }
        else {
            while (Ptr < End && *Ptr != 0) {
                ULONG LabelLen = *Ptr;
                Ptr += (LabelLen + 1);
                if (Ptr >= End) return STATUS_INVALID_NETWORK_RESPONSE;
            }
            if (Ptr >= End) return STATUS_INVALID_NETWORK_RESPONSE;
            Ptr++;
        }

        if (Ptr + 10 > End) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        USHORT RecordType = NTOHS(*(USHORT*)Ptr);
        Ptr += 2; // Type
        Ptr += 2; // Class
        Ptr += 4; // TTL
        USHORT DataLen = NTOHS(*(USHORT*)Ptr);
        Ptr += 2;

        if (Ptr + DataLen > End) {
            return STATUS_INVALID_NETWORK_RESPONSE;
        }

        if (RecordType == DNS_TYPE_A) {
            // A record found
            if (DataLen != 4) {
                DbgPrint("KDNS: Invalid A record length: %u\n", DataLen);
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            *ResolvedIp = *(ULONG*)Ptr;
            DbgPrint("KDNS: Found A record: %u.%u.%u.%u\n",
                (*ResolvedIp >> 0) & 0xFF,
                (*ResolvedIp >> 8) & 0xFF,
                (*ResolvedIp >> 16) & 0xFF,
                (*ResolvedIp >> 24) & 0xFF);
            return STATUS_SUCCESS;
        }
        else if (RecordType == DNS_TYPE_CNAME) {
            // CNAME record
            ULONG Parsed = KdnsParseDnsName(Start, Ptr, End, CnameTarget, 256);
            if (Parsed == 0 || CnameTarget[0] == '\0') {
                DbgPrint("KDNS: Failed to parse CNAME\n");
                return STATUS_INVALID_NETWORK_RESPONSE;
            }
            DbgPrint("KDNS: Found CNAME: %s\n", CnameTarget);
            *IsCname = TRUE;
            // Continue parsing in case A record is also present
            Ptr += DataLen;
        }
        else {
            // Skip other record types
            Ptr += DataLen;
        }
    }

    // If we found CNAME but no A record
    if (*IsCname) {
        return STATUS_SUCCESS;
    }

    DbgPrint("KDNS: No A record found in response\n");
    return STATUS_NOT_FOUND;
}

static NTSTATUS KdnsResolveInternal(
    _In_ PCHAR Hostname,
    _In_ ULONG DnsServerIp,
    _In_ ULONG TimeoutMs,
    _Out_ PULONG ResolvedIp,
    _In_ ULONG RecursionDepth
)
{
    if (!Hostname || !ResolvedIp) {
        return STATUS_INVALID_PARAMETER;
    }

    if (RecursionDepth >= DNS_MAX_CNAME_DEPTH) {
        DbgPrint("KDNS: CNAME chain too deep (depth=%lu)\n", RecursionDepth);
        return STATUS_TOO_MANY_LINKS;
    }

    // Calculate hostname length
    ULONG HostnameLen = 0;
    while (Hostname[HostnameLen] != '\0' && HostnameLen < 256) {
        HostnameLen++;
    }

    if (HostnameLen == 0 || HostnameLen > KDNS_MAX_HOSTNAME_LEN) {
        DbgPrint("KDNS: Invalid hostname length: %lu\n", HostnameLen);
        return STATUS_INVALID_PARAMETER;
    }

    DbgPrint("KDNS: Resolving '%s' (depth=%lu, len=%lu)\n",
        Hostname, RecursionDepth, HostnameLen);

    // Check if hostname is already an IP address
    NTSTATUS Status = KdnsTryParseIpv4(Hostname, HostnameLen, ResolvedIp);
    if (NT_SUCCESS(Status)) {
        DbgPrint("KDNS: Hostname is IP address, no DNS query needed\n");
        return STATUS_SUCCESS;
    }

    // Allocate buffers
    PVOID QueryBuffer = KdnsAlloc(512);
    PVOID ResponseBuffer = KdnsAlloc(512);

    if (!QueryBuffer || !ResponseBuffer) {
        if (QueryBuffer) KdnsFree(QueryBuffer);
        if (ResponseBuffer) KdnsFree(ResponseBuffer);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Build DNS query
    USHORT TransactionId = KdnsGenerateTransactionId();
    ULONG QueryLength = 0;

    Status = KdnsBuildQuery(Hostname, TransactionId, QueryBuffer, 512, &QueryLength);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("KDNS: Failed to build query: 0x%08X\n", Status);
        KdnsFree(QueryBuffer);
        KdnsFree(ResponseBuffer);
        return Status;
    }

    // Validate query packet (debug)
    KdnsValidateQueryPacket(QueryBuffer, QueryLength, Hostname);

    // Send and receive
    USHORT LocalPort = KdnsTdiGetUniquePort();
    ULONG ResponseLength = 0;

    Status = KdnsTdiSendAndReceive(
        DnsServerIp,
        QueryBuffer,
        QueryLength,
        ResponseBuffer,
        512,
        &ResponseLength,
        TimeoutMs,
        LocalPort
    );

    if (!NT_SUCCESS(Status)) {
        DbgPrint("KDNS: TDI send/recv failed: 0x%08X\n", Status);
        KdnsFree(QueryBuffer);
        KdnsFree(ResponseBuffer);
        return Status;
    }

    // Parse response
    CHAR CnameTarget[256];
    BOOLEAN IsCname = FALSE;

    Status = KdnsParseResponse(
        ResponseBuffer,
        ResponseLength,
        TransactionId,
        ResolvedIp,
        CnameTarget,
        &IsCname
    );

    KdnsFree(QueryBuffer);
    KdnsFree(ResponseBuffer);

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    // Handle CNAME recursion
    if (IsCname && *ResolvedIp == 0) {
        DbgPrint("KDNS: Following CNAME: %s -> %s\n", Hostname, CnameTarget);
        
        // Small delay before recursion
        LARGE_INTEGER Delay;
        Delay.QuadPart = -10000LL * 50; // 50ms
        KeDelayExecutionThread(KernelMode, FALSE, &Delay);

        return KdnsResolveInternal(
            CnameTarget,
            DnsServerIp,
            TimeoutMs,
            ResolvedIp,
            RecursionDepth + 1
        );
    }

    if (*ResolvedIp != 0) {
        DbgPrint("KDNS: Resolution complete: %s -> %u.%u.%u.%u\n",
            Hostname,
            (*ResolvedIp >> 0) & 0xFF,
            (*ResolvedIp >> 8) & 0xFF,
            (*ResolvedIp >> 16) & 0xFF,
            (*ResolvedIp >> 24) & 0xFF);
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

// =============================================================
// PUBLIC API IMPLEMENTATION
// =============================================================

NTSTATUS KdnsGlobalInit(VOID)
{
    KdnsInitializeRandom();
    KdnsCacheInitialize();
    DbgPrint("KDNS: Library initialized\n");
    return STATUS_SUCCESS;
}

VOID KdnsGlobalCleanup(VOID)
{
    KdnsCacheCleanup();
    DbgPrint("KDNS: Library cleanup complete\n");
}

NTSTATUS KdnsResolve(
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

    // Strip path from hostname (e.g., "host/path" -> "host")
    CHAR CleanHostname[256];
    ULONG HostnameLen = 0;
    PCHAR PathStart = NULL;

    for (PCHAR p = Hostname; *p != '\0' && HostnameLen < 255; p++, HostnameLen++) {
        if (*p == '/' || *p == '?') {
            PathStart = p;
            break;
        }
    }

    if (PathStart) {
        if (HostnameLen >= sizeof(CleanHostname)) {
            return STATUS_INVALID_PARAMETER;
        }
        RtlCopyMemory(CleanHostname, Hostname, HostnameLen);
        CleanHostname[HostnameLen] = '\0';
        Hostname = CleanHostname;
        DbgPrint("KDNS: Stripped path from hostname: '%s'\n", Hostname);
    }

    // Check cache
    if (KdnsCacheLookup(Hostname, ResolvedIp)) {
        return STATUS_SUCCESS;
    }

    DbgPrint("KDNS: Cache miss, querying DNS\n");

    // Resolve via DNS
    NTSTATUS Status = KdnsResolve(Hostname, DnsServerIp, TimeoutMs, ResolvedIp);

    if (NT_SUCCESS(Status) && *ResolvedIp != 0) {
        // Update cache
        KdnsCacheUpdate(Hostname, *ResolvedIp);
    }

    return Status;
}

VOID KdnsInitializeCache(VOID)
{
    KdnsCacheInitialize();
}

VOID KdnsCleanupCache(VOID)
{
    KdnsCacheCleanup();
}

VOID KdnsClearCache(VOID)
{
    KdnsCacheClear();
}

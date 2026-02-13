#pragma once
#include "kdns_types.h"

// =============================================================
// TDI TRANSPORT API
// =============================================================

#define KDNS_DEFAULT_DNS_PORT 53
#define KDNS_MIN_LOCAL_PORT 50000
#define KDNS_MAX_LOCAL_PORT 60000
#define KDNS_DEFAULT_TIMEOUT_MS 5000

// Get unique ephemeral port for DNS request
USHORT KdnsTdiGetUniquePort(VOID);

// Send DNS query and receive response via UDP/TDI
NTSTATUS KdnsTdiSendAndReceive(
    _In_ ULONG DnsServerIp,
    _In_reads_bytes_(RequestLength) PVOID RequestData,
    _In_ ULONG RequestLength,
    _Out_writes_bytes_(ResponseBufferSize) PVOID ResponseBuffer,
    _In_ ULONG ResponseBufferSize,
    _Out_ PULONG ResponseLength,
    _In_ ULONG TimeoutMs,
    _In_ USHORT LocalPort
);

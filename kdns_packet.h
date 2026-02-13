#pragma once
#include "kdns_types.h"

// =============================================================
// DNS PACKET API
// =============================================================

// Generate random DNS transaction ID
USHORT KdnsGenerateTransactionId(VOID);

// Initialize random seed for transaction IDs
VOID KdnsInitializeRandom(VOID);

// Encode hostname to DNS QNAME format
// Returns encoded length, or 0 on error
ULONG KdnsEncodeDnsName(
    _In_ PCHAR Hostname,
    _Out_writes_(BufferSize) PCHAR Buffer,
    _In_ ULONG BufferSize
);

// Parse DNS name from response (handles compression)
// Returns bytes consumed from Ptr, or 0 on error
ULONG KdnsParseDnsName(
    _In_ PUCHAR PacketStart,
    _In_ PUCHAR Ptr,
    _In_ PUCHAR PacketEnd,
    _Out_writes_(OutSize) PCHAR OutName,
    _In_ ULONG OutSize
);

// Build DNS query packet
NTSTATUS KdnsBuildQuery(
    _In_ PCHAR Hostname,
    _In_ USHORT TransactionId,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG QueryLength
);

// Validate DNS query packet structure (debug)
VOID KdnsValidateQueryPacket(
    _In_ PVOID Packet,
    _In_ ULONG Length,
    _In_ PCHAR Hostname
);

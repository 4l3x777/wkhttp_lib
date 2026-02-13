#pragma once
#include "kdns_types.h"

// =============================================================
// IP ADDRESS UTILITIES
// =============================================================

// Check if string is a valid IPv4 address
BOOLEAN KdnsIsIpv4Address(
    _In_ PCSTR String,
    _In_ ULONG Length
);

// Parse IPv4 address string to ULONG (network byte order)
NTSTATUS KdnsParseIpv4(
    _In_ PCSTR String,
    _In_ ULONG Length,
    _Out_ PULONG IpAddress
);

// Try to parse as IPv4, returns STATUS_SUCCESS if valid IP
NTSTATUS KdnsTryParseIpv4(
    _In_ PCSTR String,
    _In_ ULONG Length,
    _Out_ PULONG IpAddress
);

// Format IP address for printing
VOID KdnsFormatIpv4(
    _In_ ULONG IpAddress,
    _Out_writes_(16) PCHAR Buffer
);

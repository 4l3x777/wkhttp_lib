#include "kdns_ip.h"
#include <ntstrsafe.h>

// =============================================================
// IPv4 UTILITIES
// =============================================================

BOOLEAN KdnsIsIpv4Address(
    _In_ PCSTR String,
    _In_ ULONG Length
)
{
    if (!String || Length == 0 || Length > 15) {
        return FALSE; // IPv4 max: "255.255.255.255" = 15 chars
    }

    ULONG DotCount = 0;
    ULONG DigitCount = 0;
    ULONG SegmentValue = 0;

    for (ULONG i = 0; i < Length; i++) {
        CHAR c = String[i];

        if (c >= '0' && c <= '9') {
            DigitCount++;
            SegmentValue = SegmentValue * 10 + (c - '0');

            if (SegmentValue > 255 || DigitCount > 3) {
                return FALSE;
            }
        }
        else if (c == '.') {
            if (DigitCount == 0) {
                return FALSE; // No digits before dot
            }

            DotCount++;
            DigitCount = 0;
            SegmentValue = 0;

            if (DotCount > 3) {
                return FALSE;
            }
        }
        else {
            return FALSE; // Invalid character
        }
    }

    // Valid IPv4: exactly 3 dots, last segment has digits
    return (DotCount == 3 && DigitCount > 0);
}

NTSTATUS KdnsParseIpv4(
    _In_ PCSTR String,
    _In_ ULONG Length,
    _Out_ PULONG IpAddress
)
{
    if (!String || !IpAddress) {
        return STATUS_INVALID_PARAMETER;
    }

    ULONG Parts[4] = { 0 };
    ULONG PartIndex = 0;
    ULONG CurrentValue = 0;

    for (ULONG i = 0; i < Length; i++) {
        CHAR c = String[i];

        if (c >= '0' && c <= '9') {
            CurrentValue = CurrentValue * 10 + (c - '0');
            if (CurrentValue > 255) {
                return STATUS_INVALID_PARAMETER;
            }
        }
        else if (c == '.') {
            if (PartIndex >= 3) {
                return STATUS_INVALID_PARAMETER;
            }
            Parts[PartIndex++] = CurrentValue;
            CurrentValue = 0;
        }
        else {
            return STATUS_INVALID_PARAMETER;
        }
    }

    // Last segment
    if (PartIndex != 3) {
        return STATUS_INVALID_PARAMETER;
    }
    Parts[PartIndex] = CurrentValue;

    // Convert to network byte order (little-endian)
    *IpAddress = (Parts[0]) | (Parts[1] << 8) | (Parts[2] << 16) | (Parts[3] << 24);

    return STATUS_SUCCESS;
}

NTSTATUS KdnsTryParseIpv4(
    _In_ PCSTR String,
    _In_ ULONG Length,
    _Out_ PULONG IpAddress
)
{
    if (!KdnsIsIpv4Address(String, Length)) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS Status = KdnsParseIpv4(String, Length, IpAddress);
    
    if (NT_SUCCESS(Status)) {
        DbgPrint("KDNS: Parsed IPv4: %u.%u.%u.%u -> 0x%08X\n",
            (*IpAddress >> 0) & 0xFF,
            (*IpAddress >> 8) & 0xFF,
            (*IpAddress >> 16) & 0xFF,
            (*IpAddress >> 24) & 0xFF,
            *IpAddress);
    }

    return Status;
}

VOID KdnsFormatIpv4(
    _In_ ULONG IpAddress,
    _Out_writes_(16) PCHAR Buffer
)
{
    if (!Buffer) return;

    RtlStringCchPrintfA(Buffer, 16, "%u.%u.%u.%u",
        (IpAddress >> 0) & 0xFF,
        (IpAddress >> 8) & 0xFF,
        (IpAddress >> 16) & 0xFF,
        (IpAddress >> 24) & 0xFF);
}

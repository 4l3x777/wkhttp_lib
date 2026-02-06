#ifndef _KDNS_LIB_H_
#define _KDNS_LIB_H_

#include <ntddk.h>

#define DNS_TYPE_A      1   // A record (IPv4 address)
#define DNS_TYPE_CNAME  5   // CNAME record (Canonical name/alias)
#define DNS_MAX_CNAME_DEPTH 10  // Prevent infinite loops

// Initialize the DNS library (Allocators)
NTSTATUS KdnsGlobalInit(void);

// Cleanup
VOID KdnsGlobalCleanup(void);

// Resolve a hostname
// Hostname: "google.com"
// DnsServerIp: Network Byte Order (e.g. INETADDR(8,8,8,8))
// TimeoutMs: Wait time in milliseconds (e.g. 2000)
// ResolvedIp: Output IPv4
NTSTATUS KdnsResolve(
    _In_ PCHAR Hostname,
    _In_ ULONG DnsServerIp,
    _In_ ULONG TimeoutMs,
    _Out_ PULONG ResolvedIp
);

// Helper Macro
#ifndef INETADDR
#define INETADDR(a, b, c, d) ((a) + ((b)<<8) + ((c)<<16) + ((d)<<24))
#endif

// DNS Cache functions
VOID KdnsInitializeCache(VOID);
VOID KdnsCleanupCache(VOID);

NTSTATUS KdnsResolveWithCache(
    _In_ PCHAR Hostname,
    _In_ ULONG DnsServerIp,
    _In_ ULONG TimeoutMs,
    _Out_ PULONG ResolvedIp
);

#endif // _KDNS_LIB_H_

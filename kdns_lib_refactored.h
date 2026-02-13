#ifndef _KDNS_LIB_REFACTORED_H_
#define _KDNS_LIB_REFACTORED_H_

#include <ntddk.h>
#include "kdns_types.h"

// =============================================================
// PUBLIC DNS RESOLVER API
// =============================================================

// Helper Macro for IP address construction
#ifndef INETADDR
#define INETADDR(a, b, c, d) ((a) + ((b)<<8) + ((c)<<16) + ((d)<<24))
#endif

// Initialize DNS library (must be called once at driver load)
NTSTATUS KdnsGlobalInit(VOID);

// Cleanup DNS library (must be called at driver unload)
VOID KdnsGlobalCleanup(VOID);

// Resolve hostname to IPv4 address (without cache)
// - Hostname: domain name (e.g., "google.com")
// - DnsServerIp: DNS server in network byte order (e.g., INETADDR(8,8,8,8))
// - TimeoutMs: timeout in milliseconds
// - ResolvedIp: output IPv4 address in network byte order
NTSTATUS KdnsResolve(
    _In_ PCHAR Hostname,
    _In_ ULONG DnsServerIp,
    _In_ ULONG TimeoutMs,
    _Out_ PULONG ResolvedIp
);

// Resolve hostname with caching support
// Same parameters as KdnsResolve(), but uses DNS cache for faster lookups
NTSTATUS KdnsResolveWithCache(
    _In_ PCHAR Hostname,
    _In_ ULONG DnsServerIp,
    _In_ ULONG TimeoutMs,
    _Out_ PULONG ResolvedIp
);

// Initialize DNS cache (optional, called automatically if needed)
VOID KdnsInitializeCache(VOID);

// Cleanup DNS cache (optional, called automatically in KdnsGlobalCleanup)
VOID KdnsCleanupCache(VOID);

// Clear all cached entries
VOID KdnsClearCache(VOID);

#endif // _KDNS_LIB_REFACTORED_H_

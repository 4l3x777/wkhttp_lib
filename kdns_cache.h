#pragma once
#include "kdns_types.h"

// =============================================================
// DNS CACHE API
// =============================================================

#define DNS_CACHE_SIZE 32
#define DNS_CACHE_TTL_SECONDS 300

typedef struct _DNS_CACHE_ENTRY {
    CHAR Hostname[256];
    ULONG IpAddress;
    LARGE_INTEGER Timestamp;
    BOOLEAN Valid;
} DNS_CACHE_ENTRY, *PDNS_CACHE_ENTRY;

typedef struct _DNS_CACHE_STATS {
    ULONG Hits;
    ULONG Misses;
    ULONG Evictions;
} DNS_CACHE_STATS, *PDNS_CACHE_STATS;

// Initialize DNS cache
VOID KdnsCacheInitialize(VOID);

// Cleanup DNS cache
VOID KdnsCacheCleanup(VOID);

// Lookup entry in cache
BOOLEAN KdnsCacheLookup(
    _In_ PCHAR Hostname,
    _Out_ PULONG IpAddress
);

// Update cache with new entry
VOID KdnsCacheUpdate(
    _In_ PCHAR Hostname,
    _In_ ULONG IpAddress
);

// Get cache statistics
VOID KdnsCacheGetStats(
    _Out_ PDNS_CACHE_STATS Stats
);

// Clear all cache entries
VOID KdnsCacheClear(VOID);

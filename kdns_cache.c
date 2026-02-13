#include "kdns_cache.h"
#include <ntstrsafe.h>

// =============================================================
// CACHE IMPLEMENTATION
// =============================================================

static DNS_CACHE_ENTRY g_DnsCache[DNS_CACHE_SIZE] = { 0 };
static KSPIN_LOCK g_DnsCacheLock;
static BOOLEAN g_DnsCacheInitialized = FALSE;
static DNS_CACHE_STATS g_CacheStats = { 0 };

VOID KdnsCacheInitialize(VOID)
{
    if (!g_DnsCacheInitialized) {
        KeInitializeSpinLock(&g_DnsCacheLock);
        RtlZeroMemory(g_DnsCache, sizeof(g_DnsCache));
        RtlZeroMemory(&g_CacheStats, sizeof(g_CacheStats));
        g_DnsCacheInitialized = TRUE;
        DbgPrint("KDNS: Cache initialized (size=%d, TTL=%ds)\n", 
            DNS_CACHE_SIZE, DNS_CACHE_TTL_SECONDS);
    }
}

VOID KdnsCacheCleanup(VOID)
{
    if (g_DnsCacheInitialized) {
        KIRQL OldIrql;
        KeAcquireSpinLock(&g_DnsCacheLock, &OldIrql);
        RtlZeroMemory(g_DnsCache, sizeof(g_DnsCache));
        KeReleaseSpinLock(&g_DnsCacheLock, OldIrql);
        g_DnsCacheInitialized = FALSE;
        DbgPrint("KDNS: Cache cleanup (hits=%lu, misses=%lu, evictions=%lu)\n",
            g_CacheStats.Hits, g_CacheStats.Misses, g_CacheStats.Evictions);
    }
}

BOOLEAN KdnsCacheLookup(
    _In_ PCHAR Hostname,
    _Out_ PULONG IpAddress
)
{
    if (!g_DnsCacheInitialized || !Hostname || !IpAddress) {
        return FALSE;
    }

    KIRQL OldIrql;
    LARGE_INTEGER CurrentTime;
    KeQuerySystemTime(&CurrentTime);

    KeAcquireSpinLock(&g_DnsCacheLock, &OldIrql);

    for (ULONG i = 0; i < DNS_CACHE_SIZE; i++) {
        if (!g_DnsCache[i].Valid) {
            continue;
        }

        if (_stricmp(g_DnsCache[i].Hostname, Hostname) != 0) {
            continue;
        }

        // Check TTL
        LARGE_INTEGER Elapsed;
        Elapsed.QuadPart = (CurrentTime.QuadPart - g_DnsCache[i].Timestamp.QuadPart) / 10000000LL;

        if (Elapsed.QuadPart < DNS_CACHE_TTL_SECONDS) {
            *IpAddress = g_DnsCache[i].IpAddress;
            g_CacheStats.Hits++;
            KeReleaseSpinLock(&g_DnsCacheLock, OldIrql);
            
            DbgPrint("KDNS: Cache HIT [%s -> %u.%u.%u.%u]\n", 
                Hostname,
                (*IpAddress >> 0) & 0xFF,
                (*IpAddress >> 8) & 0xFF,
                (*IpAddress >> 16) & 0xFF,
                (*IpAddress >> 24) & 0xFF);
            return TRUE;
        }
        else {
            // Expired entry
            g_DnsCache[i].Valid = FALSE;
            DbgPrint("KDNS: Cache entry expired for %s\n", Hostname);
        }
    }

    g_CacheStats.Misses++;
    KeReleaseSpinLock(&g_DnsCacheLock, OldIrql);
    return FALSE;
}

VOID KdnsCacheUpdate(
    _In_ PCHAR Hostname,
    _In_ ULONG IpAddress
)
{
    if (!g_DnsCacheInitialized || !Hostname) {
        return;
    }

    KIRQL OldIrql;
    LARGE_INTEGER CurrentTime;
    KeQuerySystemTime(&CurrentTime);

    KeAcquireSpinLock(&g_DnsCacheLock, &OldIrql);

    // Find oldest entry for eviction
    ULONG TargetIndex = 0;
    LARGE_INTEGER OldestTime = g_DnsCache[0].Timestamp;
    BOOLEAN FoundEmpty = FALSE;

    for (ULONG i = 0; i < DNS_CACHE_SIZE; i++) {
        if (!g_DnsCache[i].Valid) {
            TargetIndex = i;
            FoundEmpty = TRUE;
            break;
        }
        if (g_DnsCache[i].Timestamp.QuadPart < OldestTime.QuadPart) {
            OldestTime = g_DnsCache[i].Timestamp;
            TargetIndex = i;
        }
    }

    if (!FoundEmpty && g_DnsCache[TargetIndex].Valid) {
        g_CacheStats.Evictions++;
        DbgPrint("KDNS: Evicting cache entry: %s\n", g_DnsCache[TargetIndex].Hostname);
    }

    // Store new entry
    RtlStringCchCopyA(g_DnsCache[TargetIndex].Hostname, 256, Hostname);
    g_DnsCache[TargetIndex].IpAddress = IpAddress;
    g_DnsCache[TargetIndex].Timestamp = CurrentTime;
    g_DnsCache[TargetIndex].Valid = TRUE;

    KeReleaseSpinLock(&g_DnsCacheLock, OldIrql);
    
    DbgPrint("KDNS: Cached [%s -> %u.%u.%u.%u]\n", 
        Hostname,
        (IpAddress >> 0) & 0xFF,
        (IpAddress >> 8) & 0xFF,
        (IpAddress >> 16) & 0xFF,
        (IpAddress >> 24) & 0xFF);
}

VOID KdnsCacheGetStats(
    _Out_ PDNS_CACHE_STATS Stats
)
{
    if (!Stats) return;
    
    KIRQL OldIrql;
    KeAcquireSpinLock(&g_DnsCacheLock, &OldIrql);
    RtlCopyMemory(Stats, &g_CacheStats, sizeof(DNS_CACHE_STATS));
    KeReleaseSpinLock(&g_DnsCacheLock, OldIrql);
}

VOID KdnsCacheClear(VOID)
{
    if (!g_DnsCacheInitialized) return;
    
    KIRQL OldIrql;
    KeAcquireSpinLock(&g_DnsCacheLock, &OldIrql);
    RtlZeroMemory(g_DnsCache, sizeof(g_DnsCache));
    KeReleaseSpinLock(&g_DnsCacheLock, OldIrql);
    
    DbgPrint("KDNS: Cache cleared\n");
}

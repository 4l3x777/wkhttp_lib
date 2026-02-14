#pragma once
#include <ntddk.h>

// =============================================================
// COMMON TYPES & CONSTANTS
// =============================================================

#define KDNS_TAG 'DNSk'
#define KDNS_MAX_HOSTNAME_LEN 253
#define KDNS_MAX_LABEL_LEN 63
#define DNS_MAX_CNAME_DEPTH 10

// DNS Record Types
#define DNS_TYPE_A      1
#define DNS_TYPE_CNAME  5
#define DNS_CLASS_IN    1
#define DNS_FLAG_RD     0x0100

// Network byte order macros
#define HTONS(a) (((0xFF&(a))<<8) + ((0xFF00&(a))>>8))
#define NTOHS(a) HTONS(a)

// DNS Header Structure
#pragma pack(push, 1)
typedef struct _DNS_HEADER {
    USHORT Id;
    USHORT Flags;
    USHORT QuestionCount;
    USHORT AnswerCount;
    USHORT AuthorityCount;
    USHORT AdditionalCount;
} DNS_HEADER, *PDNS_HEADER;
#pragma pack(pop)

// Memory management
static __inline PVOID KdnsAlloc(ULONG Size) {
    return ExAllocatePoolWithTag(NonPagedPool, Size, KDNS_TAG);
}

static __inline VOID KdnsFree(PVOID Ptr) {
    if (Ptr) ExFreePoolWithTag(Ptr, KDNS_TAG);
}

// Resource cleanup helper
typedef struct _KDNS_RESOURCE_GUARD {
    PVOID Resource;
    VOID (*Cleanup)(PVOID);
} KDNS_RESOURCE_GUARD, *PKDNS_RESOURCE_GUARD;

#define KDNS_GUARD_INIT(guard, res, cleanup_fn) \
    do { (guard).Resource = (res); (guard).Cleanup = (cleanup_fn); } while(0)

#define KDNS_GUARD_RELEASE(guard) \
    do { if ((guard).Cleanup && (guard).Resource) { \
        (guard).Cleanup((guard).Resource); \
        (guard).Resource = NULL; \
    } } while(0)

#pragma once
#include <ntddk.h>

// HTTP Methods
typedef enum _KHTTP_METHOD {
    KHTTP_GET,
    KHTTP_POST,
    KHTTP_PUT,
    KHTTP_DELETE,
    KHTTP_HEAD,
    KHTTP_PATCH
} KHTTP_METHOD;

// HTTP Response Structure
typedef struct _KHTTP_RESPONSE {
    ULONG StatusCode;
    PCHAR Headers;
    ULONG HeadersLength;
    PCHAR Body;
    ULONG BodyLength;
    ULONG TotalLength;
} KHTTP_RESPONSE, * PKHTTP_RESPONSE;

// HTTP Request Configuration
typedef struct _KHTTP_CONFIG {
    BOOLEAN UseHttps;           // TRUE for HTTPS, FALSE for HTTP
    ULONG TimeoutMs;            // Timeout in milliseconds
    PCHAR UserAgent;            // Custom User-Agent header
    ULONG MaxResponseSize;      // Maximum response buffer size
    ULONG DnsServerIp;          // DNS server IP (0 for default 8.8.8.8)
} KHTTP_CONFIG, * PKHTTP_CONFIG;

// --- Global Initialization ---
NTSTATUS KhttpGlobalInit(VOID);
VOID KhttpGlobalCleanup(VOID);

// --- High-Level API ---
NTSTATUS KhttpRequest(
    _In_ KHTTP_METHOD Method,
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PCHAR Body,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
);

// --- All HTTP Method Convenience Functions ---

NTSTATUS KhttpGet(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
);

NTSTATUS KhttpPost(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_ PCHAR Body,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
);

NTSTATUS KhttpPut(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_ PCHAR Body,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
);

NTSTATUS KhttpPatch(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_ PCHAR Body,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
);

NTSTATUS KhttpDelete(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
);

NTSTATUS KhttpHead(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
);

// --- Response Management ---
VOID KhttpFreeResponse(_In_ PKHTTP_RESPONSE Response);

// --- Utility Functions ---
NTSTATUS KhttpParseUrl(
    _In_ PCHAR Url,
    _Out_ PCHAR* Hostname,
    _Out_ PUSHORT Port,
    _Out_ PCHAR* Path,
    _Out_ PBOOLEAN IsHttps
);

PCHAR KhttpBuildRequest(
    _In_ KHTTP_METHOD Method,
    _In_ PCHAR Host,
    _In_ PCHAR Path,
    _In_opt_ PCHAR Headers,
    _In_opt_ PCHAR Body,
    _Out_ PULONG RequestLength
);

NTSTATUS KhttpParseResponse(
    _In_ PCHAR RawResponse,
    _In_ ULONG Length,
    _Out_ PKHTTP_RESPONSE* Response
);

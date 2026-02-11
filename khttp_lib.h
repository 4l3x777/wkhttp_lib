#pragma once
#include <ntddk.h>
#include <ntstrsafe.h>

// Size limits and chunked transfer support
#define KHTTP_MAX_MEMORY_BODY_SIZE (2 * 1024 * 1024)    // 2MB for in-memory
#define KHTTP_CHUNK_SIZE (64 * 1024)                    // 64KB default chunk
#define KHTTP_MAX_CHUNK_SIZE (256 * 1024)               // 256KB max chunk

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
    NTSTATUS InternalStatus;    // Internal error code
    PCHAR ErrorMessage;         // Human-readable error (optional)
} KHTTP_RESPONSE, * PKHTTP_RESPONSE;

// Progress callback for file uploads
typedef VOID(*PKHTTP_PROGRESS_CALLBACK)(
    ULONG BytesSent,
    ULONG TotalBytes,
    PVOID Context
    );

// HTTP Request Configuration
typedef struct _KHTTP_CONFIG {
    BOOLEAN UseHttps;                           // TRUE for HTTPS, FALSE for HTTP
    ULONG TimeoutMs;                            // Timeout in milliseconds
    PCHAR UserAgent;                            // Custom User-Agent header
    ULONG MaxResponseSize;                      // Maximum response buffer size
    ULONG DnsServerIp;                          // DNS server IP (0 for default 8.8.8.8)
    PKHTTP_PROGRESS_CALLBACK ProgressCallback;  // Upload progress callback
    PVOID CallbackContext;                      // Context for progress callback
    BOOLEAN UseChunkedTransfer;                 // Enable chunked encoding
    ULONG ChunkSize;                            // Chunk size (0 = default 64KB)
} KHTTP_CONFIG, * PKHTTP_CONFIG;

// File upload structure for multipart/form-data
typedef struct _KHTTP_FILE {
    PCHAR FieldName;          // Form field name (e.g., "file")
    PCHAR FileName;           // Original filename
    PCHAR ContentType;        // MIME type (e.g., "application/octet-stream")
    PVOID Data;              // File data buffer (must be NonPagedPool)
    ULONG DataLength;        // Size of data in bytes

    // Stream from disk support
    BOOLEAN UseFileStream;    // TRUE = read from disk, FALSE = use Data buffer
    PUNICODE_STRING FilePath; // Path to file on disk (if UseFileStream = TRUE)
} KHTTP_FILE, * PKHTTP_FILE;

// Form field for multipart requests
typedef struct _KHTTP_FORM_FIELD {
    PCHAR Name;              // Field name
    PCHAR Value;             // Field value
} KHTTP_FORM_FIELD, * PKHTTP_FORM_FIELD;

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

// --- HTTP Method Convenience Functions ---

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

// --- Multipart File Upload Functions ---

NTSTATUS KhttpPostMultipart(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_FORM_FIELD FormFields,
    _In_ ULONG FormFieldCount,
    _In_opt_ PKHTTP_FILE Files,
    _In_ ULONG FileCount,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
);

NTSTATUS KhttpPutMultipart(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_FORM_FIELD FormFields,
    _In_ ULONG FormFieldCount,
    _In_opt_ PKHTTP_FILE Files,
    _In_ ULONG FileCount,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
);

// --- Response Management ---
VOID KhttpFreeResponse(_In_ PKHTTP_RESPONSE Response);

// --- Http helper functions ---
VOID KhttpSleep(ULONG Milliseconds);

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

// --- Multipart Utility Functions ---
PCHAR KhttpGenerateBoundary(VOID);

PCHAR KhttpBuildMultipartBody(
    _In_opt_ PKHTTP_FORM_FIELD FormFields,
    _In_ ULONG FormFieldCount,
    _In_opt_ PKHTTP_FILE Files,
    _In_ ULONG FileCount,
    _In_ PCHAR Boundary,
    _Out_ PULONG BodyLength
);

NTSTATUS KhttpDecodeChunked(
    _In_ PCHAR ChunkedData,
    _In_ ULONG ChunkedLength,
    _Out_ PCHAR* DecodedData,
    _Out_ PULONG DecodedLength
);

// --- Chunked multipart upload functions ---
NTSTATUS KhttpPostMultipartChunked(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_FORM_FIELD FormFields,
    _In_ ULONG FormFieldCount,
    _In_opt_ PKHTTP_FILE Files,
    _In_ ULONG FileCount,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
);

NTSTATUS KhttpPutMultipartChunked(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_FORM_FIELD FormFields,
    _In_ ULONG FormFieldCount,
    _In_opt_ PKHTTP_FILE Files,
    _In_ ULONG FileCount,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
);

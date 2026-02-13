/**
 * @file khttp_lib.h
 * @brief Windows Kernel HTTP/HTTPS Client Library
 * 
 * A comprehensive HTTP/HTTPS client implementation for Windows kernel mode.
 * Supports TLS/DTLS, DNS resolution with caching, chunked transfer encoding,
 * multipart/form-data uploads, and streaming file transfers.
 * 
 * @author 4l3x777
 * @date 2026
 * @version 1.0
 * 
 * @section features Features
 * - HTTP/1.1 and HTTPS (TLS 1.2/1.3) support
 * - DNS resolution with intelligent caching
 * - RESTful API methods (GET, POST, PUT, DELETE, HEAD, PATCH)
 * - Chunked transfer encoding for large payloads
 * - Multipart/form-data file uploads
 * - Streaming uploads from disk
 * - Progress callbacks for long operations
 * - Connection pooling and timeout configuration
 * 
 * @section usage Basic Usage
 * @code
 * // Initialize library
 * NTSTATUS status = KhttpGlobalInit();
 * if (!NT_SUCCESS(status)) return status;
 * 
 * // Simple GET request
 * PKHTTP_RESPONSE response = NULL;
 * status = KhttpGet("https://httpbin.org/get", NULL, NULL, &response);
 * if (NT_SUCCESS(status)) {
 *     DbgPrint("Status: %d\n", response->StatusCode);
 *     DbgPrint("Body: %s\n", response->Body);
 *     KhttpFreeResponse(response);
 * }
 * 
 * // Cleanup
 * KhttpGlobalCleanup();
 * @endcode
 * 
 * @section dependencies Dependencies
 * - ktls_lib.h: TLS/DTLS transport layer
 * - kdns_lib.h: DNS resolution with caching
 * - ntddk.h: Windows kernel mode support
 */

#pragma once

// =============================================================================
// INCLUDES
// =============================================================================

#include <ntddk.h>
#include <ntstrsafe.h>

// =============================================================================
// CONSTANTS AND LIMITS
// =============================================================================

/**
 * @brief Maximum size for in-memory request/response bodies
 * 
 * Bodies larger than this will automatically trigger chunked transfer encoding.
 * Default: 2MB
 */
#define KHTTP_MAX_MEMORY_BODY_SIZE (2 * 1024 * 1024)

/**
 * @brief Default chunk size for chunked transfer encoding
 * 
 * Used when streaming large payloads. Balances memory usage and performance.
 * Default: 64KB
 */
#define KHTTP_CHUNK_SIZE (64 * 1024)

/**
 * @brief Maximum allowed chunk size
 * 
 * Upper limit for chunk size to prevent excessive memory allocation.
 * Default: 256KB
 */
#define KHTTP_MAX_CHUNK_SIZE (256 * 1024)

// =============================================================================
// ENUMERATIONS
// =============================================================================

/**
 * @enum KHTTP_METHOD
 * @brief HTTP request methods
 * 
 * Standard HTTP/1.1 methods as defined in RFC 7231.
 */
typedef enum _KHTTP_METHOD {
    KHTTP_GET,      ///< Retrieve resource (idempotent, no body)
    KHTTP_POST,     ///< Submit data, create resource (non-idempotent)
    KHTTP_PUT,      ///< Replace resource (idempotent)
    KHTTP_DELETE,   ///< Remove resource (idempotent)
    KHTTP_HEAD,     ///< Like GET but returns only headers
    KHTTP_PATCH     ///< Partial resource modification
} KHTTP_METHOD;

// =============================================================================
// STRUCTURES
// =============================================================================

/**
 * @struct KHTTP_RESPONSE
 * @brief HTTP response container
 * 
 * Contains all data returned from an HTTP request including status code,
 * headers, and body. Must be freed with KhttpFreeResponse() after use.
 * 
 * @note All string buffers are allocated in NonPagedPool and null-terminated.
 */
typedef struct _KHTTP_RESPONSE {
    ULONG StatusCode;           ///< HTTP status code (200, 404, etc.)
    PCHAR Headers;              ///< Raw HTTP headers (null-terminated)
    ULONG HeadersLength;        ///< Length of Headers buffer in bytes
    PCHAR Body;                 ///< Response body data (null-terminated if text)
    ULONG BodyLength;           ///< Length of Body buffer in bytes
    ULONG TotalLength;          ///< Total bytes received (headers + body)
    NTSTATUS InternalStatus;    ///< Internal error code (STATUS_SUCCESS on success)
    PCHAR ErrorMessage;         ///< Human-readable error description (optional)
} KHTTP_RESPONSE, *PKHTTP_RESPONSE;

/**
 * @typedef PKHTTP_PROGRESS_CALLBACK
 * @brief Progress callback for long-running operations
 * 
 * Called periodically during file uploads to report progress.
 * 
 * @param BytesSent Number of bytes transmitted so far
 * @param TotalBytes Total bytes to transmit (0 if unknown)
 * @param Context User-provided context pointer
 * 
 * @note Callback is invoked at DISPATCH_LEVEL; keep processing minimal.
 * 
 * @warning Do NOT perform blocking operations in the callback.
 */
typedef VOID(*PKHTTP_PROGRESS_CALLBACK)(
    ULONG BytesSent,
    ULONG TotalBytes,
    PVOID Context
);

/**
 * @struct KHTTP_CONFIG
 * @brief HTTP request configuration options
 * 
 * Optional configuration for fine-tuning request behavior.
 * Pass NULL to functions to use default values.
 * 
 * @note Default values:
 * - UseHttps: Detected from URL scheme
 * - TimeoutMs: 30000 (30 seconds)
 * - MaxResponseSize: 10MB
 * - DnsServerIp: 0.0.0.0 (uses 8.8.8.8)
 * - ChunkSize: 64KB
 */
typedef struct _KHTTP_CONFIG {
    BOOLEAN UseHttps;                           ///< Force HTTPS (TRUE) or HTTP (FALSE). Auto-detected if not set.
    ULONG TimeoutMs;                            ///< Request timeout in milliseconds (0 = infinite)
    PCHAR UserAgent;                            ///< Custom User-Agent header (NULL = default "KHTTP/1.0")
    ULONG MaxResponseSize;                      ///< Maximum response buffer size in bytes
    ULONG DnsServerIp;                          ///< Custom DNS server IP (network byte order, 0 = use 8.8.8.8)
    PKHTTP_PROGRESS_CALLBACK ProgressCallback;  ///< Upload progress notification callback
    PVOID CallbackContext;                      ///< User context passed to ProgressCallback
    BOOLEAN UseChunkedTransfer;                 ///< Force chunked encoding (auto-enabled for large bodies)
    ULONG ChunkSize;                            ///< Chunk size in bytes (0 = use KHTTP_CHUNK_SIZE)
} KHTTP_CONFIG, *PKHTTP_CONFIG;

/**
 * @struct KHTTP_FILE
 * @brief File upload descriptor for multipart/form-data
 * 
 * Represents a file to upload in a multipart request.
 * Supports both in-memory buffers and streaming from disk.
 * 
 * @section example Usage Example
 * @code
 * // Upload from memory buffer
 * KHTTP_FILE file = {0};
 * file.FieldName = "document";
 * file.FileName = "report.pdf";
 * file.ContentType = "application/pdf";
 * file.Data = pdfBuffer;
 * file.DataLength = pdfSize;
 * file.UseFileStream = FALSE;
 * 
 * // Upload from disk (streaming)
 * UNICODE_STRING path;
 * RtlInitUnicodeString(&path, L"\\??\\C:\\temp\\large_file.bin");
 * KHTTP_FILE fileStream = {0};
 * fileStream.FieldName = "upload";
 * fileStream.FileName = "large_file.bin";
 * fileStream.ContentType = "application/octet-stream";
 * fileStream.UseFileStream = TRUE;
 * fileStream.FilePath = &path;
 * @endcode
 */
typedef struct _KHTTP_FILE {
    PCHAR FieldName;          ///< HTML form field name (e.g., "file", "attachment")
    PCHAR FileName;           ///< Original filename presented to server
    PCHAR ContentType;        ///< MIME type (e.g., "image/jpeg", "application/octet-stream")
    PVOID Data;              ///< File data buffer (NonPagedPool, required if UseFileStream=FALSE)
    ULONG DataLength;        ///< Size of Data buffer in bytes
    
    // Streaming from disk
    BOOLEAN UseFileStream;    ///< TRUE = stream from FilePath, FALSE = use Data buffer
    PUNICODE_STRING FilePath; ///< NT path to file (e.g., L"\\??\\C:\\file.txt")
} KHTTP_FILE, *PKHTTP_FILE;

/**
 * @struct KHTTP_FORM_FIELD
 * @brief Form field for multipart/form-data requests
 * 
 * Represents a simple text field in a multipart upload.
 * 
 * @code
 * KHTTP_FORM_FIELD fields[] = {
 *     { "username", "john.doe" },
 *     { "email", "john@example.com" },
 *     { "description", "Test upload" }
 * };
 * @endcode
 */
typedef struct _KHTTP_FORM_FIELD {
    PCHAR Name;              ///< Field name
    PCHAR Value;             ///< Field value (null-terminated string)
} KHTTP_FORM_FIELD, *PKHTTP_FORM_FIELD;

// =============================================================================
// GLOBAL INITIALIZATION
// =============================================================================

/**
 * @brief Initialize the KHTTP library
 * 
 * Must be called once before using any other KHTTP functions.
 * Initializes underlying TLS and DNS subsystems.
 * 
 * @return STATUS_SUCCESS on success, error code otherwise
 * 
 * @note Must be called at PASSIVE_LEVEL
 * @see KhttpGlobalCleanup()
 */
NTSTATUS KhttpGlobalInit(VOID);

/**
 * @brief Clean up the KHTTP library
 * 
 * Releases all global resources. No KHTTP functions should be called after this.
 * 
 * @note Must be called at PASSIVE_LEVEL
 * @see KhttpGlobalInit()
 */
VOID KhttpGlobalCleanup(VOID);

// =============================================================================
// HIGH-LEVEL REQUEST API
// =============================================================================

/**
 * @brief Execute an HTTP request with specified method
 * 
 * Universal request function supporting all HTTP methods.
 * 
 * @param[in] Method HTTP method (GET, POST, PUT, DELETE, HEAD, PATCH)
 * @param[in] Url Target URL (http:// or https://)
 * @param[in] Headers Optional custom headers (e.g., "Accept: application/json\r\n")
 * @param[in] Body Optional request body (required for POST/PUT/PATCH)
 * @param[in] Config Optional configuration (NULL = defaults)
 * @param[out] Response Pointer to receive response structure (must free with KhttpFreeResponse)
 * 
 * @return STATUS_SUCCESS on success, error code otherwise
 * 
 * @note Caller must free Response with KhttpFreeResponse()
 * @note Must be called at PASSIVE_LEVEL
 * 
 * @code
 * PKHTTP_RESPONSE resp = NULL;
 * NTSTATUS status = KhttpRequest(
 *     KHTTP_POST,
 *     "https://api.example.com/data",
 *     "Content-Type: application/json\r\n",
 *     "{\"key\":\"value\"}",
 *     NULL,
 *     &resp
 * );
 * if (NT_SUCCESS(status)) {
 *     DbgPrint("Status: %d\n", resp->StatusCode);
 *     KhttpFreeResponse(resp);
 * }
 * @endcode
 */
NTSTATUS KhttpRequest(
    _In_ KHTTP_METHOD Method,
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PCHAR Body,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
);

// =============================================================================
// CONVENIENCE FUNCTIONS (HTTP METHODS)
// =============================================================================

/**
 * @brief Execute HTTP GET request
 * 
 * @param[in] Url Target URL
 * @param[in] Headers Optional headers
 * @param[in] Config Optional configuration
 * @param[out] Response Response structure
 * 
 * @return STATUS_SUCCESS on success
 * 
 * @see KhttpRequest()
 */
NTSTATUS KhttpGet(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
);

/**
 * @brief Execute HTTP POST request
 * 
 * @param[in] Url Target URL
 * @param[in] Headers Optional headers
 * @param[in] Body Request body (required)
 * @param[in] Config Optional configuration
 * @param[out] Response Response structure
 * 
 * @return STATUS_SUCCESS on success
 * 
 * @see KhttpRequest()
 */
NTSTATUS KhttpPost(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_ PCHAR Body,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
);

/**
 * @brief Execute HTTP PUT request
 * 
 * @param[in] Url Target URL
 * @param[in] Headers Optional headers
 * @param[in] Body Request body (required)
 * @param[in] Config Optional configuration
 * @param[out] Response Response structure
 * 
 * @return STATUS_SUCCESS on success
 * 
 * @see KhttpRequest()
 */
NTSTATUS KhttpPut(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_ PCHAR Body,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
);

/**
 * @brief Execute HTTP PATCH request
 * 
 * @param[in] Url Target URL
 * @param[in] Headers Optional headers
 * @param[in] Body Request body (required)
 * @param[in] Config Optional configuration
 * @param[out] Response Response structure
 * 
 * @return STATUS_SUCCESS on success
 * 
 * @see KhttpRequest()
 */
NTSTATUS KhttpPatch(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_ PCHAR Body,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
);

/**
 * @brief Execute HTTP DELETE request
 * 
 * @param[in] Url Target URL
 * @param[in] Headers Optional headers
 * @param[in] Config Optional configuration
 * @param[out] Response Response structure
 * 
 * @return STATUS_SUCCESS on success
 * 
 * @see KhttpRequest()
 */
NTSTATUS KhttpDelete(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
);

/**
 * @brief Execute HTTP HEAD request
 * 
 * Returns only headers, no body. Useful for checking resource existence
 * or getting metadata without downloading content.
 * 
 * @param[in] Url Target URL
 * @param[in] Headers Optional headers
 * @param[in] Config Optional configuration
 * @param[out] Response Response structure (Body will be NULL)
 * 
 * @return STATUS_SUCCESS on success
 * 
 * @see KhttpRequest()
 */
NTSTATUS KhttpHead(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
);

// =============================================================================
// MULTIPART/FORM-DATA FILE UPLOADS
// =============================================================================

/**
 * @brief Upload files using multipart/form-data (POST)
 * 
 * Supports multiple files and form fields in a single request.
 * Automatically detects large files and uses chunked transfer encoding.
 * 
 * @param[in] Url Target URL
 * @param[in] Headers Optional headers (Content-Type added automatically)
 * @param[in] FormFields Array of text form fields (can be NULL)
 * @param[in] FormFieldCount Number of form fields
 * @param[in] Files Array of files to upload (can be NULL)
 * @param[in] FileCount Number of files
 * @param[in] Config Optional configuration (supports progress callbacks)
 * @param[out] Response Response structure
 * 
 * @return STATUS_SUCCESS on success
 * 
 * @note Either FormFields or Files (or both) must be provided
 * @note Large files (>2MB) automatically trigger streaming upload
 * 
 * @code
 * KHTTP_FORM_FIELD fields[] = {{ "description", "Test file" }};
 * KHTTP_FILE file = {
 *     .FieldName = "upload",
 *     .FileName = "document.pdf",
 *     .ContentType = "application/pdf",
 *     .Data = pdfBuffer,
 *     .DataLength = pdfSize
 * };
 * 
 * PKHTTP_RESPONSE resp = NULL;
 * NTSTATUS status = KhttpPostMultipart(
 *     "https://httpbin.org/post",
 *     NULL,
 *     fields, 1,
 *     &file, 1,
 *     NULL,
 *     &resp
 * );
 * @endcode
 */
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

/**
 * @brief Upload files using multipart/form-data (PUT)
 * 
 * Same as KhttpPostMultipart but uses PUT method.
 * 
 * @see KhttpPostMultipart() for parameters and usage
 */
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

/**
 * @brief Upload files with forced chunked encoding (POST)
 * 
 * Explicitly uses chunked transfer encoding regardless of file size.
 * Useful for streaming large files or when total size is unknown.
 * 
 * @see KhttpPostMultipart() for parameters and usage
 */
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

/**
 * @brief Upload files with forced chunked encoding (PUT)
 * 
 * Same as KhttpPostMultipartChunked but uses PUT method.
 * 
 * @see KhttpPostMultipart() for parameters and usage
 */
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

// =============================================================================
// RESPONSE MANAGEMENT
// =============================================================================

/**
 * @brief Free HTTP response structure
 * 
 * Releases all memory associated with a response returned by KHTTP functions.
 * 
 * @param[in] Response Response to free (can be NULL)
 * 
 * @note Safe to call with NULL pointer
 * @note Must be called for every successful response
 */
VOID KhttpFreeResponse(_In_ PKHTTP_RESPONSE Response);

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * @brief Sleep for specified milliseconds
 * 
 * Kernel-mode sleep function safe to use in driver context.
 * 
 * @param[in] Milliseconds Time to sleep in milliseconds
 * 
 * @note Must be called at PASSIVE_LEVEL
 */
VOID KhttpSleep(ULONG Milliseconds);

/**
 * @brief Parse URL into components
 * 
 * Extracts hostname, port, path, and protocol from a URL.
 * 
 * @param[in] Url URL to parse (e.g., "https://example.com:8443/path")
 * @param[out] Hostname Pointer to receive hostname (caller must free)
 * @param[out] Port Pointer to receive port number
 * @param[out] Path Pointer to receive path (caller must free)
 * @param[out] IsHttps Pointer to receive HTTPS flag
 * 
 * @return STATUS_SUCCESS on success
 * 
 * @note Caller must free Hostname and Path with ExFreePoolWithTag
 * 
 * @code
 * PCHAR hostname = NULL, path = NULL;
 * USHORT port = 0;
 * BOOLEAN isHttps = FALSE;
 * 
 * NTSTATUS status = KhttpParseUrl(
 *     "https://api.example.com:8443/v1/users",
 *     &hostname,  // "api.example.com"
 *     &port,      // 8443
 *     &path,      // "/v1/users"
 *     &isHttps    // TRUE
 * );
 * @endcode
 */
NTSTATUS KhttpParseUrl(
    _In_ PCHAR Url,
    _Out_ PCHAR* Hostname,
    _Out_ PUSHORT Port,
    _Out_ PCHAR* Path,
    _Out_ PBOOLEAN IsHttps
);

/**
 * @brief Build HTTP request string
 * 
 * Constructs a complete HTTP/1.1 request with proper headers.
 * 
 * @param[in] Method HTTP method
 * @param[in] Host Target hostname
 * @param[in] Path Request path
 * @param[in] Headers Optional custom headers
 * @param[in] Body Optional request body
 * @param[in] UseChunked Use chunked transfer encoding
 * @param[out] RequestLength Length of generated request
 * 
 * @return Pointer to request string (caller must free)
 * 
 * @note Caller must free returned buffer with ExFreePoolWithTag
 */
PCHAR KhttpBuildRequest(
    _In_ KHTTP_METHOD Method,
    _In_ PCHAR Host,
    _In_ PCHAR Path,
    _In_opt_ PCHAR Headers,
    _In_opt_ PCHAR Body,
    _In_ BOOLEAN UseChunked,
    _Out_ PULONG RequestLength
);

/**
 * @brief Parse HTTP response
 * 
 * Parses raw HTTP response into structured format.
 * 
 * @param[in] RawResponse Raw HTTP response data
 * @param[in] Length Length of raw response
 * @param[out] Response Pointer to receive parsed response (must free)
 * 
 * @return STATUS_SUCCESS on success
 * 
 * @note Caller must free Response with KhttpFreeResponse
 */
NTSTATUS KhttpParseResponse(
    _In_ PCHAR RawResponse,
    _In_ ULONG Length,
    _Out_ PKHTTP_RESPONSE* Response
);

// =============================================================================
// MULTIPART UTILITY FUNCTIONS
// =============================================================================

/**
 * @brief Generate random multipart boundary
 * 
 * Creates a unique boundary string for multipart/form-data encoding.
 * 
 * @return Pointer to boundary string (caller must free)
 * 
 * @note Caller must free returned string with ExFreePoolWithTag
 * @note Boundary format: "----[40 random alphanumeric characters]"
 */
PCHAR KhttpGenerateBoundary(VOID);

/**
 * @brief Build multipart/form-data body
 * 
 * Constructs a complete multipart body with form fields and files.
 * 
 * @param[in] FormFields Array of form fields (can be NULL)
 * @param[in] FormFieldCount Number of form fields
 * @param[in] Files Array of files (can be NULL)
 * @param[in] FileCount Number of files
 * @param[in] Boundary Multipart boundary string
 * @param[out] BodyLength Length of generated body
 * 
 * @return Pointer to multipart body (caller must free)
 * 
 * @note Caller must free returned buffer with ExFreePoolWithTag
 */
PCHAR KhttpBuildMultipartBody(
    _In_opt_ PKHTTP_FORM_FIELD FormFields,
    _In_ ULONG FormFieldCount,
    _In_opt_ PKHTTP_FILE Files,
    _In_ ULONG FileCount,
    _In_ PCHAR Boundary,
    _Out_ PULONG BodyLength
);

/**
 * @brief Decode chunked transfer encoding
 * 
 * Decodes HTTP chunked transfer encoding into plain data.
 * 
 * @param[in] ChunkedData Chunked encoded data
 * @param[in] ChunkedLength Length of chunked data
 * @param[out] DecodedData Pointer to receive decoded data (caller must free)
 * @param[out] DecodedLength Length of decoded data
 * 
 * @return STATUS_SUCCESS on success
 * 
 * @note Caller must free DecodedData with ExFreePoolWithTag
 */
NTSTATUS KhttpDecodeChunked(
    _In_ PCHAR ChunkedData,
    _In_ ULONG ChunkedLength,
    _Out_ PCHAR* DecodedData,
    _Out_ PULONG DecodedLength
);

// =============================================================================
// END OF HEADER
// =============================================================================

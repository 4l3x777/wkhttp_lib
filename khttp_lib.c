#include "khttp_lib.h"
#include "ktls_lib.h"
#include "kdns_lib.h"
#include <ntstrsafe.h>

// Memory pool tag for http requests operations
#define KHTTP_TAG 'pttH'

// Memory pool tag for multipart operations
#define KHTTP_MULTIPART_TAG 'tpmK'

#define DEFAULT_TIMEOUT 10000
#define DEFAULT_MAX_RESPONSE 1048576  // 1MB
#define DEFAULT_DNS_SERVER INETADDR(8, 8, 8, 8)

// --- Global State ---
static BOOLEAN g_Initialized = FALSE;

// --- Method Names ---
static const char* MethodNames[] = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"
};

// --- Helper: String Functions ---

// Http delay function
VOID KhttpSleep(ULONG Milliseconds)
{
    LARGE_INTEGER Interval;
    Interval.QuadPart = -10000LL * Milliseconds; // Negative for relative time
    KeDelayExecutionThread(KernelMode, FALSE, &Interval);
}

ULONG KhttpStrLen(PCHAR Str) {
    ULONG Len = 0;
    if (!Str) return 0;
    while (*Str++) Len++;
    return Len;
}

INT KhttpStrCmp(PCHAR Str1, PCHAR Str2, ULONG MaxLen) {
    for (ULONG i = 0; i < MaxLen; i++) {
        if (Str1[i] != Str2[i]) return Str1[i] - Str2[i];
        if (Str1[i] == '\0') break;
    }
    return 0;
}

PCHAR KhttpStrStr(PCHAR Haystack, PCHAR Needle) {
    ULONG NeedleLen = KhttpStrLen(Needle);
    if (NeedleLen == 0) return Haystack;

    while (*Haystack) {
        if (KhttpStrCmp(Haystack, Needle, NeedleLen) == 0)
            return Haystack;
        Haystack++;
    }
    return NULL;
}

PCHAR KhttpStrDup(PCHAR Str) {
    if (!Str) return NULL;
    ULONG Len = KhttpStrLen(Str);
    PCHAR Dup = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, Len + 1, KHTTP_TAG);
    if (Dup) {
        RtlCopyMemory(Dup, Str, Len);
        Dup[Len] = '\0';
    }
    return Dup;
}

// --- Initialization ---
NTSTATUS KhttpGlobalInit(VOID) {
    if (g_Initialized) return STATUS_SUCCESS;

    NTSTATUS Status = KtlsGlobalInit();
    if (!NT_SUCCESS(Status)) return Status;

    Status = KdnsGlobalInit();
    if (!NT_SUCCESS(Status)) {
        KtlsGlobalCleanup();
        return Status;
    }

    KdnsInitializeCache();

    g_Initialized = TRUE;
    DbgPrint("[KHTTP] Initialized\n");
    return STATUS_SUCCESS;
}

VOID KhttpGlobalCleanup(VOID) {
    if (!g_Initialized) return;

    KtlsGlobalCleanup();
    KdnsCleanupCache();
    KdnsGlobalCleanup();
    g_Initialized = FALSE;
    DbgPrint("[KHTTP] Cleaned up\n");
}

// --- URL Parser ---
NTSTATUS KhttpParseUrl(
    _In_ PCHAR Url,
    _Out_ PCHAR* Hostname,
    _Out_ PUSHORT Port,
    _Out_ PCHAR* Path,
    _Out_ PBOOLEAN IsHttps
) {
    if (!Url || !Hostname || !Port || !Path || !IsHttps)
        return STATUS_INVALID_PARAMETER;

    *Hostname = NULL;
    *Path = NULL;
    *Port = 0;
    *IsHttps = FALSE;

    // Determine protocol
    PCHAR Start = Url;
    if (KhttpStrCmp(Url, "https://", 8) == 0) {
        *IsHttps = TRUE;
        *Port = 443;
        Start += 8;
    }
    else if (KhttpStrCmp(Url, "http://", 7) == 0) {
        *Port = 80;
        Start += 7;
    }
    else {
        return STATUS_INVALID_PARAMETER;
    }

    // Find end of hostname (either ':', '/' or end of string)
    PCHAR HostEnd = Start;
    while (*HostEnd && *HostEnd != ':' && *HostEnd != '/') HostEnd++;

    // Extract hostname
    ULONG HostLen = (ULONG)(HostEnd - Start);
    *Hostname = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, HostLen + 1, KHTTP_TAG);
    if (!*Hostname) return STATUS_INSUFFICIENT_RESOURCES;

    RtlCopyMemory(*Hostname, Start, HostLen);
    (*Hostname)[HostLen] = '\0';

    // Check for custom port
    if (*HostEnd == ':') {
        USHORT CustomPort = 0;
        HostEnd++;
        while (*HostEnd >= '0' && *HostEnd <= '9') {
            CustomPort = CustomPort * 10 + (*HostEnd - '0');
            HostEnd++;
        }
        if (CustomPort > 0) *Port = CustomPort;
    }

    // Extract path
    PCHAR PathStart = (*HostEnd == '/') ? HostEnd : "/";
    *Path = KhttpStrDup(PathStart);
    if (!*Path) {
        ExFreePoolWithTag(*Hostname, KHTTP_TAG);
        *Hostname = NULL;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;
}

// --- Request Builder ---
PCHAR KhttpBuildRequest(
    _In_ KHTTP_METHOD Method,
    _In_ PCHAR Host,
    _In_ PCHAR Path,
    _In_opt_ PCHAR Headers,
    _In_opt_ PCHAR Body,
    _Out_ PULONG RequestLength
) {
    ULONG BodyLen = Body ? KhttpStrLen(Body) : 0;
    ULONG HeadersLen = Headers ? KhttpStrLen(Headers) : 0;

    // Calculate buffer size
    ULONG BufferSize = 512 + KhttpStrLen(Host) + KhttpStrLen(Path) + HeadersLen + BodyLen;
    PCHAR Buffer = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, BufferSize, KHTTP_TAG);
    if (!Buffer) return NULL;

    NTSTATUS Status;
    ULONG Offset = 0;
    size_t Remaining = BufferSize;

    // Build request line
    Status = RtlStringCbPrintfA(Buffer + Offset, Remaining,
        "%s %s HTTP/1.1\r\n",
        MethodNames[Method], Path);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Buffer, KHTTP_TAG);
        return NULL;
    }

    RtlStringCbLengthA(Buffer, BufferSize, (size_t*)&Offset);
    Remaining = BufferSize - Offset;

    // Add Host header
    Status = RtlStringCbPrintfA(Buffer + Offset, Remaining, "Host: %s\r\n", Host);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Buffer, KHTTP_TAG);
        return NULL;
    }

    RtlStringCbLengthA(Buffer, BufferSize, (size_t*)&Offset);
    Remaining = BufferSize - Offset;

    // Add custom headers
    if (Headers) {
        if (HeadersLen < Remaining) {
            RtlCopyMemory(Buffer + Offset, Headers, HeadersLen);
            Offset += HeadersLen;
            Remaining -= HeadersLen;

            // Ensure headers end with \r\n
            if (HeadersLen < 2 || Buffer[Offset - 2] != '\r' || Buffer[Offset - 1] != '\n') {
                if (Remaining >= 2) {
                    Buffer[Offset++] = '\r';
                    Buffer[Offset++] = '\n';
                    Remaining -= 2;
                }
            }
        }
    }

    // Add Content-Length if body present
    if (Body) {
        Status = RtlStringCbPrintfA(Buffer + Offset, Remaining,
            "Content-Length: %lu\r\n", BodyLen);
        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(Buffer, KHTTP_TAG);
            return NULL;
        }

        RtlStringCbLengthA(Buffer, BufferSize, (size_t*)&Offset);
        Remaining = BufferSize - Offset;
    }

    // Add Connection close
    Status = RtlStringCbPrintfA(Buffer + Offset, Remaining, "Connection: close\r\n");
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Buffer, KHTTP_TAG);
        return NULL;
    }

    RtlStringCbLengthA(Buffer, BufferSize, (size_t*)&Offset);
    Remaining = BufferSize - Offset;

    // End headers
    if (Remaining >= 2) {
        Buffer[Offset++] = '\r';
        Buffer[Offset++] = '\n';
        Remaining -= 2;
    }

    // Add body
    if (Body && BodyLen < Remaining) {
        RtlCopyMemory(Buffer + Offset, Body, BodyLen);
        Offset += BodyLen;
    }

    *RequestLength = Offset;
    return Buffer;
}

// --- Response Parser ---
NTSTATUS KhttpParseResponse(
    _In_ PCHAR RawResponse,
    _In_ ULONG Length,
    _Out_ PKHTTP_RESPONSE* Response
) {
    if (!RawResponse || Length == 0 || !Response)
        return STATUS_INVALID_PARAMETER;

    PKHTTP_RESPONSE Resp = (PKHTTP_RESPONSE)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(KHTTP_RESPONSE), KHTTP_TAG);
    if (!Resp) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(Resp, sizeof(KHTTP_RESPONSE));
    Resp->TotalLength = Length;

    // Parse status line: HTTP/1.x STATUS_CODE
    PCHAR StatusLine = RawResponse;
    PCHAR Space = KhttpStrStr(StatusLine, " ");
    if (Space) {
        Resp->StatusCode = 0;
        Space++;
        while (*Space >= '0' && *Space <= '9') {
            Resp->StatusCode = Resp->StatusCode * 10 + (*Space - '0');
            Space++;
        }
    }

    // Find header/body separator
    PCHAR BodyStart = KhttpStrStr(RawResponse, "\r\n\r\n");
    if (BodyStart) {
        BodyStart += 4;  // Skip \r\n\r\n

        // Extract headers
        Resp->HeadersLength = (ULONG)(BodyStart - RawResponse - 4);
        Resp->Headers = (PCHAR)ExAllocatePoolWithTag(
            NonPagedPool, Resp->HeadersLength + 1, KHTTP_TAG);
        if (Resp->Headers) {
            RtlCopyMemory(Resp->Headers, RawResponse, Resp->HeadersLength);
            Resp->Headers[Resp->HeadersLength] = '\0';
        }

        // Extract body
        Resp->BodyLength = Length - (ULONG)(BodyStart - RawResponse);
        Resp->Body = (PCHAR)ExAllocatePoolWithTag(
            NonPagedPool, Resp->BodyLength + 1, KHTTP_TAG);
        if (Resp->Body) {
            RtlCopyMemory(Resp->Body, BodyStart, Resp->BodyLength);
            Resp->Body[Resp->BodyLength] = '\0';
        }
    }
    else {
        // No body separator found, treat all as headers
        Resp->HeadersLength = Length;
        Resp->Headers = (PCHAR)ExAllocatePoolWithTag(
            NonPagedPool, Length + 1, KHTTP_TAG);
        if (Resp->Headers) {
            RtlCopyMemory(Resp->Headers, RawResponse, Length);
            Resp->Headers[Length] = '\0';
        }
    }

    *Response = Resp;
    return STATUS_SUCCESS;
}

// --- Core Request Function ---
NTSTATUS KhttpRequest(
    _In_ KHTTP_METHOD Method,
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PCHAR Body,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
) {
    if (!g_Initialized) return STATUS_DEVICE_NOT_READY;
    if (!Url || !Response) return STATUS_INVALID_PARAMETER;

    *Response = NULL;
    NTSTATUS Status;
    PCHAR Hostname = NULL, Path = NULL;
    USHORT Port;
    BOOLEAN IsHttps;
    PKTLS_SESSION Session = NULL;
    PCHAR RequestBuffer = NULL;
    PVOID ResponseBuffer = NULL;

    // Apply defaults
    KHTTP_CONFIG DefaultConfig = {
        .UseHttps = FALSE,
        .TimeoutMs = DEFAULT_TIMEOUT,
        .UserAgent = "KHTTP/1.0",
        .MaxResponseSize = DEFAULT_MAX_RESPONSE,
        .DnsServerIp = DEFAULT_DNS_SERVER
    };
    PKHTTP_CONFIG Cfg = Config ? Config : &DefaultConfig;

    // Parse URL
    Status = KhttpParseUrl(Url, &Hostname, &Port, &Path, &IsHttps);
    if (!NT_SUCCESS(Status)) goto Cleanup;

    // Override HTTPS setting based on URL scheme OR config
    if (Config && Config->UseHttps) IsHttps = TRUE;

    DbgPrint("[KHTTP] %s %s (Host: %s:%u, HTTPS: %d)\n",
        MethodNames[Method], Path, Hostname, Port, IsHttps);

    // Resolve hostname to IP
    ULONG HostIp;

    // Check if hostname is already an IP address (skip DNS)
    BOOLEAN IsDirectIp = TRUE;
    for (PCHAR c = Hostname; *c; c++) {
        if (*c != '.' && (*c < '0' || *c > '9')) {
            IsDirectIp = FALSE;
            break;
        }
    }

    if (IsDirectIp) {
        // Parse IP address manually (a.b.c.d)
        UCHAR Parts[4] = { 0 };
        ULONG PartIdx = 0;
        ULONG Val = 0;
        for (PCHAR c = Hostname; *c && PartIdx < 4; c++) {
            if (*c == '.') {
                Parts[PartIdx++] = (UCHAR)Val;
                Val = 0;
            }
            else {
                Val = Val * 10 + (*c - '0');
            }
        }
        Parts[PartIdx] = (UCHAR)Val;
        HostIp = INETADDR(Parts[0], Parts[1], Parts[2], Parts[3]);
        DbgPrint("[KHTTP] Using direct IP: %u.%u.%u.%u\n",
            Parts[0], Parts[1], Parts[2], Parts[3]);
    }
    else {
        // Resolve via DNS
        Status = KdnsResolveWithCache(Hostname, Cfg->DnsServerIp, Cfg->TimeoutMs, &HostIp);
        if (!NT_SUCCESS(Status)) {
            DbgPrint("[KHTTP] DNS resolution failed: 0x%x\n", Status);
            goto Cleanup;
        }
    }

    // Connect with appropriate protocol
    ULONG Protocol;
    if (IsHttps) {
        Protocol = KTLS_PROTO_TCP;  // TCP with TLS
    }
    else {
        Protocol = KTLS_PROTO_TCP_PLAIN;  // Plain TCP without TLS
    }

    Status = KtlsConnect(HostIp, Port, Protocol, Hostname, &Session);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[KHTTP] Connection failed: 0x%x\n", Status);
        goto Cleanup;
    }

    // IMPORTANT: Only set TLS mode if HTTPS
    // Your KTLS library needs to support plain TCP mode
    // For now, we need to check if KTLS always does handshake

    KtlsSetTimeout(Session, Cfg->TimeoutMs);

    // Build and send request
    ULONG RequestLen;
    RequestBuffer = KhttpBuildRequest(Method, Hostname, Path, Headers, Body, &RequestLen);
    if (!RequestBuffer) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    ULONG BytesSent;
    Status = KtlsSend(Session, RequestBuffer, RequestLen, &BytesSent);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[KHTTP] Send failed: 0x%x\n", Status);
        goto Cleanup;
    }

    // Receive response
    ResponseBuffer = ExAllocatePoolWithTag(NonPagedPool, Cfg->MaxResponseSize, KHTTP_TAG);
    if (!ResponseBuffer) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    ULONG TotalReceived = 0;
    do {
        ULONG BytesRecv;
        Status = KtlsRecv(Session, (PCHAR)ResponseBuffer + TotalReceived,
            Cfg->MaxResponseSize - TotalReceived - 1, &BytesRecv);

        if (Status == STATUS_SUCCESS) {
            TotalReceived += BytesRecv;
        }
    } while (Status == STATUS_SUCCESS && TotalReceived < Cfg->MaxResponseSize - 1);

    if (TotalReceived > 0) {
        ((PCHAR)ResponseBuffer)[TotalReceived] = '\0';
        Status = KhttpParseResponse((PCHAR)ResponseBuffer, TotalReceived, Response);
    }
    else {
        Status = STATUS_NO_DATA_DETECTED;
    }

Cleanup:
    if (Session) KtlsClose(Session);
    if (Hostname) ExFreePoolWithTag(Hostname, KHTTP_TAG);
    if (Path) ExFreePoolWithTag(Path, KHTTP_TAG);
    if (RequestBuffer) ExFreePoolWithTag(RequestBuffer, KHTTP_TAG);
    if (ResponseBuffer) ExFreePoolWithTag(ResponseBuffer, KHTTP_TAG);

    return Status;
}

// --- Convenience Functions ---
//
// --- GET: Retrieve/Read Resources ---
// Used to fetch data without modifying server state
// Idempotent and safe - multiple calls have same effect
NTSTATUS KhttpGet(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
) {
    return KhttpRequest(KHTTP_GET, Url, Headers, NULL, Config, Response);
}

// --- POST: Create New Resources ---
// Used to submit data to create a new resource
// Not idempotent - multiple calls create multiple resources
// Typically returns 201 Created with Location header
NTSTATUS KhttpPost(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_ PCHAR Body,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
) {
    return KhttpRequest(KHTTP_POST, Url, Headers, Body, Config, Response);
}

// --- PUT: Replace/Update Entire Resource ---
// Used to completely replace a resource with new data
// Idempotent - multiple identical calls have same effect
// If resource doesn't exist, can create it at specified URI
// Returns 200 OK or 204 No Content
NTSTATUS KhttpPut(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_ PCHAR Body,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
) {
    return KhttpRequest(KHTTP_PUT, Url, Headers, Body, Config, Response);
}

// --- PATCH: Partial Update of Resource ---
// Used to apply partial modifications to a resource
// Not idempotent - outcome may depend on current state
// More efficient than PUT when updating single fields
// Content-Type often: application/json-patch+json
// Returns 200 OK or 204 No Content
NTSTATUS KhttpPatch(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_ PCHAR Body,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
) {
    return KhttpRequest(KHTTP_PATCH, Url, Headers, Body, Config, Response);
}

// --- DELETE: Remove Resource ---
// Used to delete the specified resource
// Idempotent - deleting multiple times has same effect
// First call deletes, subsequent return 404 Not Found
// Returns 204 No Content or 200 OK
NTSTATUS KhttpDelete(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
) {
    return KhttpRequest(KHTTP_DELETE, Url, Headers, NULL, Config, Response);
}

// --- HEAD: Retrieve Headers Only ---
// Identical to GET but returns NO response body
// Used to check if resource exists or get metadata
// Useful for checking Content-Length, ETag, Last-Modified
// without downloading entire resource
// Saves bandwidth when only metadata needed
NTSTATUS KhttpHead(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
) {
    return KhttpRequest(KHTTP_HEAD, Url, Headers, NULL, Config, Response);
}

// --- Response Cleanup ---
VOID KhttpFreeResponse(_In_ PKHTTP_RESPONSE Response) {
    if (!Response) return;

    if (Response->Headers)
        ExFreePoolWithTag(Response->Headers, KHTTP_TAG);
    if (Response->Body)
        ExFreePoolWithTag(Response->Body, KHTTP_TAG);

    ExFreePoolWithTag(Response, KHTTP_TAG);
}

// --- Multipart operations ---

// Simple hash function for entropy mixing
ULONG64 KhttpSimpleHash(ULONG64 Value, ULONG Iteration)
{
    Value ^= Value >> 33;
    Value *= 0xFF51AFD7ED558CCDULL;
    Value ^= Value >> 33;
    Value *= 0xC4CEB9FE1A85EC53ULL;
    Value ^= Value >> 33;
    Value ^= (ULONG64)Iteration * 0x9E3779B97F4A7C15ULL;
    return Value;
}

// Generate cryptographically-strong random boundary
PCHAR KhttpGenerateBoundary(VOID)
{
    PCHAR Boundary = (PCHAR)ExAllocatePoolWithTag(
        NonPagedPool,
        80,
        KHTTP_MULTIPART_TAG
    );

    if (!Boundary) {
        return NULL;
    }

    // Collect maximum entropy
    LARGE_INTEGER TickCount, SystemTime, PerformanceCounter;
    ULONG64 InterruptTime;
    ULONG ProcessorNumber;
    PVOID StackAddr = &Boundary;

    KeQueryTickCount(&TickCount);
    KeQuerySystemTime(&SystemTime);
    PerformanceCounter = KeQueryPerformanceCounter(NULL);
    InterruptTime = KeQueryInterruptTime();
    ProcessorNumber = KeGetCurrentProcessorNumber();

    // Hash all entropy sources
    ULONG64 Hash = 0x9E3779B97F4A7C15ULL; // Initial seed (golden ratio)
    Hash ^= KhttpSimpleHash(TickCount.QuadPart, 0);
    Hash ^= KhttpSimpleHash(SystemTime.QuadPart, 1);
    Hash ^= KhttpSimpleHash(PerformanceCounter.QuadPart, 2);
    Hash ^= KhttpSimpleHash(InterruptTime, 3);
    Hash ^= KhttpSimpleHash((ULONG64)(ULONG_PTR)StackAddr, 4);
    Hash ^= KhttpSimpleHash((ULONG64)ProcessorNumber, 5);

    // Base62 charset
    static const CHAR Charset[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    // Generate boundary prefix (4 dashes)
    Boundary[0] = '-';
    Boundary[1] = '-';
    Boundary[2] = '-';
    Boundary[3] = '-';

    // Generate 40 random characters
    ULONG Pos = 4;
    for (ULONG i = 0; i < 40; i++) {
        Hash = KhttpSimpleHash(Hash, i + 10);
        ULONG Index = (ULONG)(Hash % 62);
        Boundary[Pos++] = Charset[Index];
    }

    Boundary[Pos] = '\0';

    return Boundary;
}

// Build multipart/form-data body
PCHAR KhttpBuildMultipartBody(
    _In_opt_ PKHTTP_FORM_FIELD FormFields,
    _In_ ULONG FormFieldCount,
    _In_opt_ PKHTTP_FILE Files,
    _In_ ULONG FileCount,
    _In_ PCHAR Boundary,
    _Out_ PULONG BodyLength
)
{
    if (!Boundary || !BodyLength) {
        return NULL;
    }

    *BodyLength = 0;

    // Calculate total size needed more accurately
    ULONG TotalSize = 0;
    ULONG i;
    size_t BoundaryLen = strlen(Boundary);

    // Size for form fields
    for (i = 0; i < FormFieldCount; i++) {
        if (!FormFields[i].Name || !FormFields[i].Value) {
            continue;
        }

        size_t NameLen = strlen(FormFields[i].Name);
        size_t ValueLen = strlen(FormFields[i].Value);

        // "--" + boundary + "\r\n"
        TotalSize += 2 + (ULONG)BoundaryLen + 2;
        // "Content-Disposition: form-data; name=\"\"\r\n\r\n"
        TotalSize += 40 + (ULONG)NameLen;
        // value + "\r\n"
        TotalSize += (ULONG)ValueLen + 2;
    }

    // Size for files
    for (i = 0; i < FileCount; i++) {
        if (!Files[i].FieldName || !Files[i].FileName || !Files[i].Data) {
            continue;
        }

        size_t FieldNameLen = strlen(Files[i].FieldName);
        size_t FileNameLen = strlen(Files[i].FileName);
        size_t ContentTypeLen = Files[i].ContentType ?
            strlen(Files[i].ContentType) :
            strlen("application/octet-stream");

        // "--" + boundary + "\r\n"
        TotalSize += 2 + (ULONG)BoundaryLen + 2;
        // "Content-Disposition: form-data; name=\"\"; filename=\"\"\r\n"
        TotalSize += 50 + (ULONG)FieldNameLen + (ULONG)FileNameLen;
        // "Content-Type: \r\n\r\n"
        TotalSize += 16 + (ULONG)ContentTypeLen;
        // File data + "\r\n"
        TotalSize += Files[i].DataLength + 2;
    }

    // Final boundary: "--" + boundary + "--\r\n"
    TotalSize += 2 + (ULONG)BoundaryLen + 4;

    // Add safety margin
    TotalSize += 256;

    // Check if size is reasonable (max 100MB for safety)
    if (TotalSize > 100 * 1024 * 1024) {
        DbgPrint("[KHTTP] Multipart body too large: %lu bytes\n", TotalSize);
        return NULL;
    }

    // Allocate buffer
    PCHAR Body = (PCHAR)ExAllocatePoolWithTag(
        NonPagedPool,
        TotalSize,
        KHTTP_MULTIPART_TAG
    );

    if (!Body) {
        DbgPrint("[KHTTP] Failed to allocate %lu bytes for multipart body\n", TotalSize);
        return NULL;
    }

    // Clear buffer
    RtlZeroMemory(Body, TotalSize);

    PCHAR Current = Body;
    ULONG Remaining = TotalSize;
    NTSTATUS Status;

    // Add form fields
    for (i = 0; i < FormFieldCount; i++) {
        if (!FormFields[i].Name || !FormFields[i].Value) {
            continue;
        }

        Status = RtlStringCchPrintfA(
            Current,
            Remaining,
            "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n",
            Boundary,
            FormFields[i].Name,
            FormFields[i].Value
        );

        if (!NT_SUCCESS(Status)) {
            DbgPrint("[KHTTP] Failed to format form field: 0x%08X\n", Status);
            ExFreePoolWithTag(Body, KHTTP_MULTIPART_TAG);
            return NULL;
        }

        size_t Written;
        Status = RtlStringCchLengthA(Current, Remaining, &Written);
        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(Body, KHTTP_MULTIPART_TAG);
            return NULL;
        }

        Current += Written;
        Remaining -= (ULONG)Written;
    }

    // Add files
    for (i = 0; i < FileCount; i++) {
        if (!Files[i].FieldName || !Files[i].FileName || !Files[i].Data) {
            continue;
        }

        PCHAR ContentType = Files[i].ContentType ?
            Files[i].ContentType :
            "application/octet-stream";

        Status = RtlStringCchPrintfA(
            Current,
            Remaining,
            "--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\nContent-Type: %s\r\n\r\n",
            Boundary,
            Files[i].FieldName,
            Files[i].FileName,
            ContentType
        );

        if (!NT_SUCCESS(Status)) {
            DbgPrint("[KHTTP] Failed to format file header: 0x%08X\n", Status);
            ExFreePoolWithTag(Body, KHTTP_MULTIPART_TAG);
            return NULL;
        }

        size_t Written;
        Status = RtlStringCchLengthA(Current, Remaining, &Written);
        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(Body, KHTTP_MULTIPART_TAG);
            return NULL;
        }

        Current += Written;
        Remaining -= (ULONG)Written;

        // Copy file data
        if (Files[i].DataLength > Remaining - 2) {
            DbgPrint("[KHTTP] Insufficient buffer for file data\n");
            ExFreePoolWithTag(Body, KHTTP_MULTIPART_TAG);
            return NULL;
        }

        RtlCopyMemory(Current, Files[i].Data, Files[i].DataLength);
        Current += Files[i].DataLength;
        Remaining -= Files[i].DataLength;

        // Add CRLF after data
        *Current++ = '\r';
        *Current++ = '\n';
        Remaining -= 2;
    }

    // Add final boundary
    Status = RtlStringCchPrintfA(
        Current,
        Remaining,
        "--%s--\r\n",
        Boundary
    );

    if (!NT_SUCCESS(Status)) {
        DbgPrint("[KHTTP] Failed to format final boundary: 0x%08X\n", Status);
        ExFreePoolWithTag(Body, KHTTP_MULTIPART_TAG);
        return NULL;
    }

    *BodyLength = (ULONG)(Current - Body) + (ULONG)strlen(Current);

    DbgPrint("[KHTTP] Built multipart body: %lu bytes\n", *BodyLength);

    return Body;
}

// Internal multipart request handler
NTSTATUS KhttpMultipartRequest(
    _In_ KHTTP_METHOD Method,
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_FORM_FIELD FormFields,
    _In_ ULONG FormFieldCount,
    _In_opt_ PKHTTP_FILE Files,
    _In_ ULONG FileCount,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
)
{
    if (!Url || !Response) {
        return STATUS_INVALID_PARAMETER;
    }

    *Response = NULL;

    DbgPrint("[KHTTP] Starting multipart request to %s\n", Url);

    // Generate boundary
    PCHAR Boundary = KhttpGenerateBoundary();
    if (!Boundary) {
        DbgPrint("[KHTTP] Failed to generate boundary\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DbgPrint("[KHTTP] Generated boundary: %s\n", Boundary);

    // Build multipart body
    ULONG BodyLength = 0;
    PCHAR Body = KhttpBuildMultipartBody(
        FormFields,
        FormFieldCount,
        Files,
        FileCount,
        Boundary,
        &BodyLength
    );

    if (!Body) {
        DbgPrint("[KHTTP] Failed to build multipart body\n");
        ExFreePoolWithTag(Boundary, KHTTP_MULTIPART_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    DbgPrint("[KHTTP] Built multipart body: %lu bytes\n", BodyLength);

    // Build Content-Type header with boundary
    ULONG ContentTypeLen = 256;
    PCHAR ContentTypeHeader = (PCHAR)ExAllocatePoolWithTag(
        NonPagedPool,
        ContentTypeLen,
        KHTTP_MULTIPART_TAG
    );

    if (!ContentTypeHeader) {
        DbgPrint("[KHTTP] Failed to allocate Content-Type header\n");
        ExFreePoolWithTag(Body, KHTTP_MULTIPART_TAG);
        ExFreePoolWithTag(Boundary, KHTTP_MULTIPART_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS Status = RtlStringCchPrintfA(
        ContentTypeHeader,
        ContentTypeLen,
        "Content-Type: multipart/form-data; boundary=%s\r\n",
        Boundary
    );

    if (!NT_SUCCESS(Status)) {
        DbgPrint("[KHTTP] Failed to format Content-Type: 0x%08X\n", Status);
        ExFreePoolWithTag(ContentTypeHeader, KHTTP_MULTIPART_TAG);
        ExFreePoolWithTag(Body, KHTTP_MULTIPART_TAG);
        ExFreePoolWithTag(Boundary, KHTTP_MULTIPART_TAG);
        return Status;
    }

    // Combine with user headers
    ULONG TotalHeaderLen = (ULONG)strlen(ContentTypeHeader);
    if (Headers) {
        TotalHeaderLen += (ULONG)strlen(Headers);
    }
    TotalHeaderLen += 1; // Null terminator

    PCHAR CombinedHeaders = (PCHAR)ExAllocatePoolWithTag(
        NonPagedPool,
        TotalHeaderLen,
        KHTTP_MULTIPART_TAG
    );

    if (!CombinedHeaders) {
        DbgPrint("[KHTTP] Failed to allocate combined headers\n");
        ExFreePoolWithTag(ContentTypeHeader, KHTTP_MULTIPART_TAG);
        ExFreePoolWithTag(Body, KHTTP_MULTIPART_TAG);
        ExFreePoolWithTag(Boundary, KHTTP_MULTIPART_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = RtlStringCchCopyA(CombinedHeaders, TotalHeaderLen, ContentTypeHeader);
    if (NT_SUCCESS(Status) && Headers) {
        Status = RtlStringCchCatA(CombinedHeaders, TotalHeaderLen, Headers);
    }

    if (!NT_SUCCESS(Status)) {
        DbgPrint("[KHTTP] Failed to combine headers: 0x%08X\n", Status);
        ExFreePoolWithTag(CombinedHeaders, KHTTP_MULTIPART_TAG);
        ExFreePoolWithTag(ContentTypeHeader, KHTTP_MULTIPART_TAG);
        ExFreePoolWithTag(Body, KHTTP_MULTIPART_TAG);
        ExFreePoolWithTag(Boundary, KHTTP_MULTIPART_TAG);
        return Status;
    }

    DbgPrint("[KHTTP] Making HTTP request\n");

    // Make the request
    Status = KhttpRequest(
        Method,
        Url,
        CombinedHeaders,
        Body,
        Config,
        Response
    );

    DbgPrint("[KHTTP] Request completed: 0x%08X\n", Status);

    // Cleanup
    ExFreePoolWithTag(CombinedHeaders, KHTTP_MULTIPART_TAG);
    ExFreePoolWithTag(ContentTypeHeader, KHTTP_MULTIPART_TAG);
    ExFreePoolWithTag(Body, KHTTP_MULTIPART_TAG);
    ExFreePoolWithTag(Boundary, KHTTP_MULTIPART_TAG);

    return Status;
}

// POST multipart request
NTSTATUS KhttpPostMultipart(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_FORM_FIELD FormFields,
    _In_ ULONG FormFieldCount,
    _In_opt_ PKHTTP_FILE Files,
    _In_ ULONG FileCount,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
)
{
    return KhttpMultipartRequest(
        KHTTP_POST,
        Url,
        Headers,
        FormFields,
        FormFieldCount,
        Files,
        FileCount,
        Config,
        Response
    );
}

// PUT multipart request
NTSTATUS KhttpPutMultipart(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_FORM_FIELD FormFields,
    _In_ ULONG FormFieldCount,
    _In_opt_ PKHTTP_FILE Files,
    _In_ ULONG FileCount,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
)
{
    return KhttpMultipartRequest(
        KHTTP_PUT,
        Url,
        Headers,
        FormFields,
        FormFieldCount,
        Files,
        FileCount,
        Config,
        Response
    );
}

// Decode chunked transfer encoding
NTSTATUS KhttpDecodeChunked(
    _In_ PCHAR ChunkedData,
    _In_ ULONG ChunkedLength,
    _Out_ PCHAR* DecodedData,
    _Out_ PULONG DecodedLength
)
{
    if (!ChunkedData || !DecodedData || !DecodedLength) {
        return STATUS_INVALID_PARAMETER;
    }

    // Allocate buffer for decoded data (worst case: same size)
    PCHAR Decoded = (PCHAR)ExAllocatePoolWithTag(
        NonPagedPool,
        ChunkedLength,
        KHTTP_MULTIPART_TAG
    );

    if (!Decoded) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PCHAR Source = ChunkedData;
    PCHAR Dest = Decoded;
    ULONG TotalDecoded = 0;

    while (TRUE) {
        // Parse chunk size (hex number followed by \r\n)
        ULONG ChunkSize = 0;
        while (*Source != '\r' && Source < ChunkedData + ChunkedLength) {
            char c = *Source++;
            if (c >= '0' && c <= '9') {
                ChunkSize = ChunkSize * 16 + (c - '0');
            }
            else if (c >= 'a' && c <= 'f') {
                ChunkSize = ChunkSize * 16 + (c - 'a' + 10);
            }
            else if (c >= 'A' && c <= 'F') {
                ChunkSize = ChunkSize * 16 + (c - 'A' + 10);
            }
            else {
                break; // Ignore chunk extensions
            }
        }

        // Skip \r\n
        if (*Source == '\r') Source++;
        if (*Source == '\n') Source++;

        // If chunk size is 0, we're done
        if (ChunkSize == 0) {
            break;
        }

        // Copy chunk data
        if (Source + ChunkSize > ChunkedData + ChunkedLength) {
            ExFreePoolWithTag(Decoded, KHTTP_MULTIPART_TAG);
            return STATUS_INVALID_PARAMETER;
        }

        RtlCopyMemory(Dest, Source, ChunkSize);
        Dest += ChunkSize;
        Source += ChunkSize;
        TotalDecoded += ChunkSize;

        // Skip trailing \r\n
        if (*Source == '\r') Source++;
        if (*Source == '\n') Source++;
    }

    *DecodedData = Decoded;
    *DecodedLength = TotalDecoded;

    return STATUS_SUCCESS;
}
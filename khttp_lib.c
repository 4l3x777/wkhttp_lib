#include "khttp_lib.h"
#include "ktls_lib.h"
#include "kdns_lib.h"
#include <ntstrsafe.h>

#define KHTTP_TAG 'pttH'
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

    g_Initialized = TRUE;
    DbgPrint("[KHTTP] Initialized\n");
    return STATUS_SUCCESS;
}

VOID KhttpGlobalCleanup(VOID) {
    if (!g_Initialized) return;

    KtlsGlobalCleanup();
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
        Status = KdnsResolve(Hostname, Cfg->DnsServerIp, Cfg->TimeoutMs, &HostIp);
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

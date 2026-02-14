#include "khttp_lib.h"
#include "ktls_lib.h"
#include "kdns_lib.h"
#include <ntstrsafe.h>

// ========================================
// CONSTANTS AND DEFINITIONS
// ========================================

#define KHTTP_TAG 'pttH'
#define KHTTP_MULTIPART_TAG 'tpmK'
#define DEFAULT_TIMEOUT 10000
#define DEFAULT_MAX_RESPONSE 1048576  // 1MB
#define DEFAULT_DNS_SERVER INETADDR(1, 0, 0, 1)
#define MAX_SEND_SIZE 65536  // 64KB per TLS send

// Chunked transfer limits
#define MAX_CHUNK_SIZE (16 * 1024 * 1024)  // 16MB max chunk size
#define MAX_CHUNK_LINE_LENGTH 16           // Max length for chunk size line (hex + CRLF)

// ========================================
// INTERNAL STRUCTURES
// ========================================

// Connection context
typedef struct _KHTTP_CONNECTION {
    PKTLS_SESSION Session;
    PCHAR Hostname;
    PCHAR Path;
    USHORT Port;
    BOOLEAN IsHttps;
    ULONG HostIp;
} KHTTP_CONNECTION, *PKHTTP_CONNECTION;

// Chunked encoder state
typedef struct _KHTTP_CHUNKED_ENCODER {
    PKTLS_SESSION Session;
    ULONG ChunkSize;
    ULONG TotalSent;
    ULONG TotalSize;
    PKHTTP_PROGRESS_CALLBACK ProgressCallback;
    PVOID CallbackContext;
} KHTTP_CHUNKED_ENCODER, *PKHTTP_CHUNKED_ENCODER;

// Resource tracking for cleanup
#define MAX_TRACKED_RESOURCES 16
typedef struct _KHTTP_RESOURCE_TRACKER {
    PVOID Resources[MAX_TRACKED_RESOURCES];
    ULONG Tags[MAX_TRACKED_RESOURCES];
    ULONG Count;
} KHTTP_RESOURCE_TRACKER, *PKHTTP_RESOURCE_TRACKER;

// ========================================
// GLOBAL STATE
// ========================================

static BOOLEAN g_Initialized = FALSE;
static const char* MethodNames[] = {
    "GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"
};

// ========================================
// UTILITY FUNCTIONS
// ========================================

VOID KhttpSleep(ULONG Milliseconds)
{
    LARGE_INTEGER Interval;
    Interval.QuadPart = -10000LL * Milliseconds;
    KeDelayExecutionThread(KernelMode, FALSE, &Interval);
}

static ULONG KhttpStrLen(PCHAR Str) {
    if (!Str) return 0;
    ULONG Len = 0;
    while (*Str++) Len++;
    return Len;
}

static INT KhttpStrCmp(PCHAR Str1, PCHAR Str2, ULONG MaxLen) {
    for (ULONG i = 0; i < MaxLen; i++) {
        if (Str1[i] != Str2[i]) return Str1[i] - Str2[i];
        if (Str1[i] == '\0') break;
    }
    return 0;
}

static PCHAR KhttpStrStr(PCHAR Haystack, PCHAR Needle) {
    ULONG NeedleLen = KhttpStrLen(Needle);
    if (NeedleLen == 0) return Haystack;
    while (*Haystack) {
        if (KhttpStrCmp(Haystack, Needle, NeedleLen) == 0)
            return Haystack;
        Haystack++;
    }
    return NULL;
}

static PCHAR KhttpStrDup(PCHAR Str) {
    if (!Str) return NULL;
    ULONG Len = KhttpStrLen(Str);
    PCHAR Dup = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, Len + 1, KHTTP_TAG);
    if (Dup) {
        RtlCopyMemory(Dup, Str, Len);
        Dup[Len] = '\0';
    }
    return Dup;
}

// ========================================
// SAFE MEMORY OPERATIONS
// ========================================

static NTSTATUS KhttpSafeMemcpy(
    _Out_writes_bytes_(Length) PVOID Dest,
    _In_reads_bytes_(Length) PVOID Src,
    _In_ SIZE_T Length
)
{
    if (!Dest || !Src || Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    // Sanity check for absurd lengths
    if (Length > MAX_CHUNK_SIZE) {
        DbgPrint("[KHTTP] [ERROR] SafeMemcpy: Excessive length %zu (max %u)\n",
            Length, MAX_CHUNK_SIZE);
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        RtlCopyMemory(Dest, Src, Length);
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ULONG ExceptionCode = GetExceptionCode();
        DbgPrint("[KHTTP] [ERROR] SafeMemcpy exception: 0x%08X\n", ExceptionCode);
        DbgPrint("[KHTTP] [ERROR]   Dest=%p, Src=%p, Length=%zu\n", Dest, Src, Length);
        return STATUS_ACCESS_VIOLATION;
    }
}

static BOOLEAN KhttpIsAddressValid(
    _In_ PVOID Address,
    _In_ SIZE_T Length
)
{
    if (!Address || Length == 0) {
        return FALSE;
    }

    // Check for overflow
    if ((ULONG_PTR)Address + Length < (ULONG_PTR)Address) {
        DbgPrint("[KHTTP] [ERROR] Address overflow detected: %p + %zu\n",
            Address, Length);
        return FALSE;
    }

    // Basic validity check
    __try {
        ProbeForRead(Address, Length, 1);
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

// ========================================
// RESOURCE TRACKING
// ========================================

static VOID KhttpInitResourceTracker(PKHTTP_RESOURCE_TRACKER Tracker) {
    RtlZeroMemory(Tracker, sizeof(KHTTP_RESOURCE_TRACKER));
}

static VOID KhttpTrackResource(
    _Inout_ PKHTTP_RESOURCE_TRACKER Tracker,
    _In_ PVOID Resource,
    _In_ ULONG Tag
) {
    if (Tracker->Count < MAX_TRACKED_RESOURCES && Resource) {
        Tracker->Resources[Tracker->Count] = Resource;
        Tracker->Tags[Tracker->Count] = Tag;
        Tracker->Count++;
    }
}

static VOID KhttpCleanupResources(PKHTTP_RESOURCE_TRACKER Tracker) {
    for (ULONG i = 0; i < Tracker->Count; i++) {
        if (Tracker->Resources[i]) {
            ExFreePoolWithTag(Tracker->Resources[i], Tracker->Tags[i]);
            Tracker->Resources[i] = NULL;
        }
    }
    Tracker->Count = 0;
}

// ========================================
// INITIALIZATION
// ========================================

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

// ========================================
// URL PARSING
// ========================================

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

    // Find end of hostname
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

// ========================================
// REQUEST BUILDER
// ========================================

PCHAR KhttpBuildRequest(
    _In_ KHTTP_METHOD Method,
    _In_ PCHAR Host,
    _In_ PCHAR Path,
    _In_opt_ PCHAR Headers,
    _In_opt_ PCHAR Body,
    _In_ BOOLEAN UseChunked,
    _Out_ PULONG RequestLength
) {
    ULONG BodyLen = Body ? KhttpStrLen(Body) : 0;
    ULONG HeadersLen = Headers ? KhttpStrLen(Headers) : 0;
    ULONG BufferSize = 512 + KhttpStrLen(Host) + KhttpStrLen(Path) + HeadersLen + BodyLen;
    
    PCHAR Buffer = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, BufferSize, KHTTP_TAG);
    if (!Buffer) return NULL;

    NTSTATUS Status;
    ULONG Offset = 0;
    size_t Remaining = BufferSize;

    // Request line
    Status = RtlStringCbPrintfA(Buffer + Offset, Remaining,
        "%s %s HTTP/1.1\r\nHost: %s\r\n",
        MethodNames[Method], Path, Host);
    
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Buffer, KHTTP_TAG);
        return NULL;
    }

    RtlStringCbLengthA(Buffer, BufferSize, (size_t*)&Offset);
    Remaining = BufferSize - Offset;

    // Custom headers
    if (Headers && HeadersLen < Remaining) {
        RtlCopyMemory(Buffer + Offset, Headers, HeadersLen);
        Offset += HeadersLen;
        Remaining -= HeadersLen;

        // Ensure headers end with CRLF
        if (HeadersLen < 2 || Buffer[Offset - 2] != '\r' || Buffer[Offset - 1] != '\n') {
            if (Remaining >= 2) {
                Buffer[Offset++] = '\r';
                Buffer[Offset++] = '\n';
                Remaining -= 2;
            }
        }
    }

    // Content-Length if body present and NOT chunked
    if (Body && !UseChunked) {
        Status = RtlStringCbPrintfA(Buffer + Offset, Remaining,
            "Content-Length: %lu\r\n", BodyLen);
        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(Buffer, KHTTP_TAG);
            return NULL;
        }
        RtlStringCbLengthA(Buffer, BufferSize, (size_t*)&Offset);
        Remaining = BufferSize - Offset;
    }

    // Connection close
    Status = RtlStringCbPrintfA(Buffer + Offset, Remaining, "Connection: close\r\n\r\n");
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Buffer, KHTTP_TAG);
        return NULL;
    }

    RtlStringCbLengthA(Buffer, BufferSize, (size_t*)&Offset);
    Remaining = BufferSize - Offset;

    // Add body
    if (Body && BodyLen < Remaining) {
        RtlCopyMemory(Buffer + Offset, Body, BodyLen);
        Offset += BodyLen;
    }

    *RequestLength = Offset;
    return Buffer;
}

// ========================================
// RESPONSE PARSER
// ========================================

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

    // Parse status code
    PCHAR Space = KhttpStrStr(RawResponse, " ");
    if (Space) {
        Space++;
        Resp->StatusCode = 0;
        while (*Space >= '0' && *Space <= '9') {
            Resp->StatusCode = Resp->StatusCode * 10 + (*Space - '0');
            Space++;
        }
    }

    // Find header/body separator
    PCHAR BodyStart = KhttpStrStr(RawResponse, "\r\n\r\n");
    if (BodyStart) {
        BodyStart += 4;

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
        // No body separator, treat all as headers
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

// ========================================
// CONNECTION MANAGEMENT
// ========================================

static NTSTATUS KhttpEstablishConnection(
    _In_ PCHAR Url,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_CONNECTION* Connection
) {
    if (!Url || !Connection) return STATUS_INVALID_PARAMETER;

    PKHTTP_CONNECTION Conn = (PKHTTP_CONNECTION)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(KHTTP_CONNECTION), KHTTP_TAG);
    if (!Conn) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(Conn, sizeof(KHTTP_CONNECTION));

    // Parse URL
    NTSTATUS Status = KhttpParseUrl(Url, &Conn->Hostname, &Conn->Port, &Conn->Path, &Conn->IsHttps);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Conn, KHTTP_TAG);
        return Status;
    }

    DbgPrint("[KHTTP] Connecting to %s:%u (HTTPS: %d)\n",
        Conn->Hostname, Conn->Port, Conn->IsHttps);

    // Resolve hostname
    ULONG DnsServer = Config && Config->DnsServerIp ? Config->DnsServerIp : DEFAULT_DNS_SERVER;
    ULONG Timeout = Config ? Config->TimeoutMs : DEFAULT_TIMEOUT;

    Status = KdnsResolveWithCache(Conn->Hostname, DnsServer, Timeout, &Conn->HostIp);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[KHTTP] DNS resolution failed: 0x%08X\n", Status);
        ExFreePoolWithTag(Conn->Path, KHTTP_TAG);
        ExFreePoolWithTag(Conn->Hostname, KHTTP_TAG);
        ExFreePoolWithTag(Conn, KHTTP_TAG);
        return Status;
    }

    // Connect
    ULONG Protocol = Conn->IsHttps ? KTLS_PROTO_TCP : KTLS_PROTO_TCP_PLAIN;
    Status = KtlsConnect(Conn->HostIp, Conn->Port, Protocol, Conn->Hostname, &Conn->Session);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[KHTTP] Connection failed: 0x%08X\n", Status);
        ExFreePoolWithTag(Conn->Path, KHTTP_TAG);
        ExFreePoolWithTag(Conn->Hostname, KHTTP_TAG);
        ExFreePoolWithTag(Conn, KHTTP_TAG);
        return Status;
    }

    if (Config) {
        KtlsSetTimeout(Conn->Session, Config->TimeoutMs);
    }

    *Connection = Conn;
    return STATUS_SUCCESS;
}

static VOID KhttpCloseConnection(PKHTTP_CONNECTION Connection) {
    if (!Connection) return;

    if (Connection->Session) {
        KtlsClose(Connection->Session);
    }
    if (Connection->Hostname) {
        ExFreePoolWithTag(Connection->Hostname, KHTTP_TAG);
    }
    if (Connection->Path) {
        ExFreePoolWithTag(Connection->Path, KHTTP_TAG);
    }

    ExFreePoolWithTag(Connection, KHTTP_TAG);
}

// ========================================
// SEND/RECEIVE HELPERS
// ========================================

static NTSTATUS KhttpSendWithRetry(
    _In_ PKTLS_SESSION Session,
    _In_ PVOID Data,
    _In_ ULONG Length,
    _In_ ULONG MaxChunkSize
) {
    ULONG TotalSent = 0;

    while (TotalSent < Length) {
        ULONG ToSend = min(MaxChunkSize, Length - TotalSent);
        ULONG Sent = 0;

        NTSTATUS Status = KtlsSend(Session, (PCHAR)Data + TotalSent, ToSend, &Sent);
        if (!NT_SUCCESS(Status)) return Status;
        if (Sent == 0) return STATUS_CONNECTION_DISCONNECTED;

        TotalSent += Sent;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS KhttpReceiveResponse(
    _In_ PKHTTP_CONNECTION Connection,
    _In_ ULONG MaxResponseSize,
    _Out_ PKHTTP_RESPONSE* Response
) {
    // Ensure reasonable buffer size
    if (MaxResponseSize > 100 * 1024 * 1024) {  // 100MB limit
        DbgPrint("[KHTTP] [WARN] Response size too large: %lu, clamping to 100MB\n",
            MaxResponseSize);
        MaxResponseSize = 100 * 1024 * 1024;
    }

    PVOID Buffer = ExAllocatePoolWithTag(NonPagedPool, MaxResponseSize, KHTTP_TAG);
    if (!Buffer) {
        DbgPrint("[KHTTP] [ERROR] Failed to allocate %lu bytes for response\n",
            MaxResponseSize);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Buffer, MaxResponseSize);
    ULONG TotalReceived = 0;
    NTSTATUS Status = STATUS_SUCCESS;

    DbgPrint("[KHTTP] Receiving response (max %lu bytes)...\n", MaxResponseSize);

    do {
        // Ensure we don't overflow buffer
        if (TotalReceived >= MaxResponseSize - 1) {
            DbgPrint("[KHTTP] [WARN] Response buffer full at %lu bytes\n", TotalReceived);
            break;
        }

        ULONG BytesRecv = 0;
        ULONG MaxRecv = MaxResponseSize - TotalReceived - 1;
        
        __try {
            Status = KtlsRecv(Connection->Session, (PCHAR)Buffer + TotalReceived,
                MaxRecv, &BytesRecv);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[KHTTP] [ERROR] Exception in KtlsRecv: 0x%08X\n",
                GetExceptionCode());
            Status = STATUS_ACCESS_VIOLATION;
            break;
        }

        if (Status == STATUS_SUCCESS && BytesRecv > 0) {
            // Validate received bytes don't exceed buffer
            if (BytesRecv > MaxRecv) {
                DbgPrint("[KHTTP] [ERROR] Received %lu bytes exceeds max %lu\n",
                    BytesRecv, MaxRecv);
                Status = STATUS_BUFFER_OVERFLOW;
                break;
            }
            TotalReceived += BytesRecv;
            DbgPrint("[KHTTP] Received %lu bytes (total: %lu)\n", BytesRecv, TotalReceived);
        }
        else if (Status == STATUS_END_OF_FILE ||
                 Status == STATUS_CONNECTION_RESET ||
                 Status == STATUS_CONNECTION_DISCONNECTED ||
                 Status == STATUS_DATA_NOT_ACCEPTED) {
            if (TotalReceived > 0) {
                Status = STATUS_SUCCESS;
            }
            DbgPrint("[KHTTP] Connection closed, total received: %lu bytes\n", TotalReceived);
            break;
        }
        else if (!NT_SUCCESS(Status)) {
            DbgPrint("[KHTTP] [ERROR] Receive failed: 0x%08X\n", Status);
            break;
        }

        if (BytesRecv == 0) {
            DbgPrint("[KHTTP] No more data to receive\n");
            break;
        }

    } while (TotalReceived < MaxResponseSize - 1);

    if (TotalReceived > 0 && NT_SUCCESS(Status)) {
        ((PCHAR)Buffer)[TotalReceived] = '\0';
        Status = KhttpParseResponse((PCHAR)Buffer, TotalReceived, Response);
    }
    else if (TotalReceived == 0) {
        DbgPrint("[KHTTP] [WARN] No data received\n");
        Status = STATUS_NO_DATA_DETECTED;
    }

    ExFreePoolWithTag(Buffer, KHTTP_TAG);
    return Status;
}

// ========================================
// CHUNKED ENCODER
// ========================================

static VOID KhttpInitChunkedEncoder(
    _Out_ PKHTTP_CHUNKED_ENCODER Encoder,
    _In_ PKTLS_SESSION Session,
    _In_ ULONG ChunkSize,
    _In_ ULONG TotalSize,
    _In_opt_ PKHTTP_PROGRESS_CALLBACK ProgressCallback,
    _In_opt_ PVOID CallbackContext
) {
    Encoder->Session = Session;
    Encoder->ChunkSize = ChunkSize;
    Encoder->TotalSent = 0;
    Encoder->TotalSize = TotalSize;
    Encoder->ProgressCallback = ProgressCallback;
    Encoder->CallbackContext = CallbackContext;
}

static NTSTATUS KhttpChunkedEncoderSend(
    _Inout_ PKHTTP_CHUNKED_ENCODER Encoder,
    _In_ PVOID Data,
    _In_ ULONG Length
) {
    if (Length == 0) return STATUS_SUCCESS;

    // Validate chunk length
    if (Length > MAX_CHUNK_SIZE) {
        DbgPrint("[KHTTP] [ERROR] Chunk too large: %lu bytes (max %u)\n",
            Length, MAX_CHUNK_SIZE);
        return STATUS_INVALID_PARAMETER;
    }

    // Format chunk header
    CHAR ChunkHeader[32];
    RtlStringCchPrintfA(ChunkHeader, sizeof(ChunkHeader), "%X\r\n", Length);

    // Send header
    NTSTATUS Status = KhttpSendWithRetry(
        Encoder->Session,
        ChunkHeader,
        (ULONG)strlen(ChunkHeader),
        (ULONG)strlen(ChunkHeader)
    );
    if (!NT_SUCCESS(Status)) return Status;

    // Send data in 64KB portions
    Status = KhttpSendWithRetry(Encoder->Session, Data, Length, MAX_SEND_SIZE);
    if (!NT_SUCCESS(Status)) return Status;

    // Send trailer
    Status = KhttpSendWithRetry(Encoder->Session, "\r\n", 2, 2);
    if (!NT_SUCCESS(Status)) return Status;

    // Update progress
    Encoder->TotalSent += Length;
    if (Encoder->ProgressCallback && Encoder->TotalSize > 0) {
        Encoder->ProgressCallback(Encoder->TotalSent, Encoder->TotalSize, Encoder->CallbackContext);

        if (Encoder->TotalSent % (Encoder->ChunkSize * 10) == 0 || 
            Encoder->TotalSent >= Encoder->TotalSize) {
            ULONG Percent = (Encoder->TotalSent * 100) / Encoder->TotalSize;
            DbgPrint("[KHTTP] Upload progress: %lu%%\n", Percent);
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS KhttpChunkedEncoderFinalize(PKHTTP_CHUNKED_ENCODER Encoder) {
    DbgPrint("[KHTTP] [STREAMING] Sending chunk terminator\n");
    ULONG BytesSent;
    return KtlsSend(Encoder->Session, "0\r\n\r\n", 5, &BytesSent);
}

// ========================================
// MULTIPART HELPERS
// ========================================

static ULONG64 KhttpSimpleHash(ULONG64 Value, ULONG Iteration)
{
    Value ^= Value >> 33;
    Value *= 0xFF51AFD7ED558CCDULL;
    Value ^= Value >> 33;
    Value *= 0xC4CEB9FE1A85EC53ULL;
    Value ^= Value >> 33;
    Value ^= (ULONG64)Iteration * 0x9E3779B97F4A7C15ULL;
    return Value;
}

PCHAR KhttpGenerateBoundary(VOID)
{
    PCHAR Boundary = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, 80, KHTTP_MULTIPART_TAG);
    if (!Boundary) return NULL;

    // Collect entropy
    LARGE_INTEGER TickCount, SystemTime, PerformanceCounter;
    ULONG64 InterruptTime;
    ULONG ProcessorNumber;
    PVOID StackAddr = &Boundary;

    KeQueryTickCount(&TickCount);
    KeQuerySystemTime(&SystemTime);
    PerformanceCounter = KeQueryPerformanceCounter(NULL);
    InterruptTime = KeQueryInterruptTime();
    ProcessorNumber = KeGetCurrentProcessorNumber();

    // Mix entropy
    ULONG64 Hash = 0x9E3779B97F4A7C15ULL;
    Hash ^= KhttpSimpleHash(TickCount.QuadPart, 0);
    Hash ^= KhttpSimpleHash(SystemTime.QuadPart, 1);
    Hash ^= KhttpSimpleHash(PerformanceCounter.QuadPart, 2);
    Hash ^= KhttpSimpleHash(InterruptTime, 3);
    Hash ^= KhttpSimpleHash((ULONG64)(ULONG_PTR)StackAddr, 4);
    Hash ^= KhttpSimpleHash((ULONG64)ProcessorNumber, 5);

    static const CHAR Charset[] =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    Boundary[0] = '-';
    Boundary[1] = '-';
    Boundary[2] = '-';
    Boundary[3] = '-';

    ULONG Pos = 4;
    for (ULONG i = 0; i < 40; i++) {
        Hash = KhttpSimpleHash(Hash, i + 10);
        ULONG Index = (ULONG)(Hash % 62);
        Boundary[Pos++] = Charset[Index];
    }

    Boundary[Pos] = '\0';
    return Boundary;
}

PCHAR KhttpBuildMultipartBody(
    _In_opt_ PKHTTP_FORM_FIELD FormFields,
    _In_ ULONG FormFieldCount,
    _In_opt_ PKHTTP_FILE Files,
    _In_ ULONG FileCount,
    _In_ PCHAR Boundary,
    _Out_ PULONG BodyLength
)
{
    if (!Boundary || !BodyLength) return NULL;

    *BodyLength = 0;

    // Calculate size
    ULONG TotalSize = 0;
    size_t BoundaryLen = strlen(Boundary);

    for (ULONG i = 0; i < FormFieldCount; i++) {
        if (!FormFields[i].Name || !FormFields[i].Value) continue;
        TotalSize += 2 + (ULONG)BoundaryLen + 2;
        TotalSize += 40 + (ULONG)strlen(FormFields[i].Name);
        TotalSize += (ULONG)strlen(FormFields[i].Value) + 2;
    }

    for (ULONG i = 0; i < FileCount; i++) {
        if (!Files[i].FieldName || !Files[i].FileName) continue;
        if (!Files[i].UseFileStream && !Files[i].Data) continue;

        TotalSize += 2 + (ULONG)BoundaryLen + 2;
        TotalSize += 50 + (ULONG)strlen(Files[i].FieldName) + (ULONG)strlen(Files[i].FileName);
        TotalSize += 16 + (ULONG)strlen(Files[i].ContentType ? Files[i].ContentType : "application/octet-stream");

        if (!Files[i].UseFileStream) {
            TotalSize += Files[i].DataLength + 2;
        } else {
            TotalSize += 2;
        }
    }

    TotalSize += 2 + (ULONG)BoundaryLen + 4 + 256;

    if (TotalSize > 100 * 1024 * 1024) {
        DbgPrint("[KHTTP] Multipart body too large: %lu bytes\n", TotalSize);
        return NULL;
    }

    PCHAR Body = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, TotalSize, KHTTP_MULTIPART_TAG);
    if (!Body) return NULL;

    RtlZeroMemory(Body, TotalSize);

    PCHAR Current = Body;
    ULONG Remaining = TotalSize;
    NTSTATUS Status;

    // Add form fields
    for (ULONG i = 0; i < FormFieldCount; i++) {
        if (!FormFields[i].Name || !FormFields[i].Value) continue;

        Status = RtlStringCchPrintfA(Current, Remaining,
            "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n",
            Boundary, FormFields[i].Name, FormFields[i].Value);

        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(Body, KHTTP_MULTIPART_TAG);
            return NULL;
        }

        size_t Written;
        RtlStringCchLengthA(Current, Remaining, &Written);
        Current += Written;
        Remaining -= (ULONG)Written;
    }

    // Add files
    for (ULONG i = 0; i < FileCount; i++) {
        if (!Files[i].FieldName || !Files[i].FileName) continue;

        PCHAR ContentType = Files[i].ContentType ? Files[i].ContentType : "application/octet-stream";

        Status = RtlStringCchPrintfA(Current, Remaining,
            "--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\nContent-Type: %s\r\n\r\n",
            Boundary, Files[i].FieldName, Files[i].FileName, ContentType);

        if (!NT_SUCCESS(Status)) {
            ExFreePoolWithTag(Body, KHTTP_MULTIPART_TAG);
            return NULL;
        }

        size_t Written;
        RtlStringCchLengthA(Current, Remaining, &Written);
        Current += Written;
        Remaining -= (ULONG)Written;

        if (!Files[i].UseFileStream && Files[i].Data && Files[i].DataLength > 0) {
            if (Files[i].DataLength > Remaining - 2) {
                ExFreePoolWithTag(Body, KHTTP_MULTIPART_TAG);
                return NULL;
            }

            RtlCopyMemory(Current, Files[i].Data, Files[i].DataLength);
            Current += Files[i].DataLength;
            Remaining -= Files[i].DataLength;

            *Current++ = '\r';
            *Current++ = '\n';
            Remaining -= 2;
        }
    }

    // Final boundary
    Status = RtlStringCchPrintfA(Current, Remaining, "--%s--\r\n", Boundary);
    if (!NT_SUCCESS(Status)) {
        ExFreePoolWithTag(Body, KHTTP_MULTIPART_TAG);
        return NULL;
    }

    *BodyLength = (ULONG)(Current - Body) + (ULONG)strlen(Current);
    DbgPrint("[KHTTP] Built multipart body: %lu bytes\n", *BodyLength);

    return Body;
}

// ========================================
// STREAMING FILE UPLOAD
// ========================================

static NTSTATUS KhttpStreamFileWithChunks(
    _Inout_ PKHTTP_CHUNKED_ENCODER Encoder,
    _In_ PUNICODE_STRING FilePath,
    _In_ ULONG ChunkSize
) {
    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatus;
    OBJECT_ATTRIBUTES ObjAttr;

    InitializeObjectAttributes(&ObjAttr, FilePath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    NTSTATUS Status = ZwCreateFile(&FileHandle, GENERIC_READ, &ObjAttr, &IoStatus,
        NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
        FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(Status)) {
        DbgPrint("[KHTTP] [STREAMING] Failed to open file: 0x%08X\n", Status);
        return Status;
    }

    // Get file size
    FILE_STANDARD_INFORMATION FileInfo;
    Status = ZwQueryInformationFile(FileHandle, &IoStatus, &FileInfo,
        sizeof(FileInfo), FileStandardInformation);

    if (!NT_SUCCESS(Status)) {
        ZwClose(FileHandle);
        return Status;
    }

    ULONG FileSize = (ULONG)FileInfo.EndOfFile.QuadPart;
    DbgPrint("[KHTTP] [STREAMING] File size: %lu bytes\n", FileSize);

    // Update encoder total size
    Encoder->TotalSize = FileSize;

    // Allocate chunk buffer
    PVOID ChunkBuffer = ExAllocatePoolWithTag(NonPagedPool, ChunkSize, KHTTP_TAG);
    if (!ChunkBuffer) {
        ZwClose(FileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG TotalRead = 0;
    LARGE_INTEGER ByteOffset = { 0 };

    while (TotalRead < FileSize) {
        ULONG ToRead = min(ChunkSize, FileSize - TotalRead);

        Status = ZwReadFile(FileHandle, NULL, NULL, NULL, &IoStatus,
            ChunkBuffer, ToRead, &ByteOffset, NULL);

        if (!NT_SUCCESS(Status)) {
            DbgPrint("[KHTTP] [STREAMING] File read error: 0x%08X\n", Status);
            break;
        }

        ULONG BytesRead = (ULONG)IoStatus.Information;
        if (BytesRead == 0) break;

        Status = KhttpChunkedEncoderSend(Encoder, ChunkBuffer, BytesRead);
        if (!NT_SUCCESS(Status)) {
            DbgPrint("[KHTTP] [STREAMING] Chunk send failed: 0x%08X\n", Status);
            break;
        }

        TotalRead += BytesRead;
        ByteOffset.QuadPart += BytesRead;
    }

    ExFreePoolWithTag(ChunkBuffer, KHTTP_TAG);
    ZwClose(FileHandle);

    return Status;
}

// ========================================
// CORE REQUEST FUNCTION
// ========================================

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

    PKHTTP_CONNECTION Connection = NULL;
    PCHAR RequestBuffer = NULL;

    // Establish connection
    NTSTATUS Status = KhttpEstablishConnection(Url, Config, &Connection);
    if (!NT_SUCCESS(Status)) return Status;

    DbgPrint("[KHTTP] %s %s (Host: %s:%u, HTTPS: %d)\n",
        MethodNames[Method], Connection->Path, Connection->Hostname, 
        Connection->Port, Connection->IsHttps);

    // Build and send request
    ULONG RequestLen;
    RequestBuffer = KhttpBuildRequest(Method, Connection->Hostname, Connection->Path,
        Headers, Body, FALSE, &RequestLen);

    if (!RequestBuffer) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    ULONG BytesSent;
    Status = KtlsSend(Connection->Session, RequestBuffer, RequestLen, &BytesSent);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[KHTTP] Send failed: 0x%08X\n", Status);
        goto Cleanup;
    }

    // Receive response
    ULONG MaxResp = Config ? Config->MaxResponseSize : DEFAULT_MAX_RESPONSE;
    Status = KhttpReceiveResponse(Connection, MaxResp, Response);

Cleanup:
    if (RequestBuffer) ExFreePoolWithTag(RequestBuffer, KHTTP_TAG);
    if (Connection) KhttpCloseConnection(Connection);

    return Status;
}

// ========================================
// CONVENIENCE FUNCTIONS
// ========================================

NTSTATUS KhttpGet(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
) {
    return KhttpRequest(KHTTP_GET, Url, Headers, NULL, Config, Response);
}

NTSTATUS KhttpPost(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_ PCHAR Body,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
) {
    return KhttpRequest(KHTTP_POST, Url, Headers, Body, Config, Response);
}

NTSTATUS KhttpPut(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_ PCHAR Body,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
) {
    return KhttpRequest(KHTTP_PUT, Url, Headers, Body, Config, Response);
}

NTSTATUS KhttpPatch(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_ PCHAR Body,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
) {
    return KhttpRequest(KHTTP_PATCH, Url, Headers, Body, Config, Response);
}

NTSTATUS KhttpDelete(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
) {
    return KhttpRequest(KHTTP_DELETE, Url, Headers, NULL, Config, Response);
}

NTSTATUS KhttpHead(
    _In_ PCHAR Url,
    _In_opt_ PCHAR Headers,
    _In_opt_ PKHTTP_CONFIG Config,
    _Out_ PKHTTP_RESPONSE* Response
) {
    return KhttpRequest(KHTTP_HEAD, Url, Headers, NULL, Config, Response);
}

VOID KhttpFreeResponse(_In_ PKHTTP_RESPONSE Response) {
    if (!Response) return;
    if (Response->Headers) ExFreePoolWithTag(Response->Headers, KHTTP_TAG);
    if (Response->Body) ExFreePoolWithTag(Response->Body, KHTTP_TAG);
    ExFreePoolWithTag(Response, KHTTP_TAG);
}

// ========================================
// CHUNKED DECODING (WITH VALIDATION)
// ========================================

NTSTATUS KhttpDecodeChunked(
    _In_ PCHAR ChunkedData,
    _In_ ULONG ChunkedLength,
    _Out_ PCHAR* DecodedData,
    _Out_ PULONG DecodedLength
)
{
    if (!ChunkedData || !DecodedData || !DecodedLength) {
        DbgPrint("[KHTTP] [ERROR] KhttpDecodeChunked: Invalid parameters\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (ChunkedLength == 0 || ChunkedLength > MAX_CHUNK_SIZE) {
        DbgPrint("[KHTTP] [ERROR] Invalid chunked length: %lu (max %u)\n",
            ChunkedLength, MAX_CHUNK_SIZE);
        return STATUS_INVALID_PARAMETER;
    }

    // Validate source buffer
    if (!KhttpIsAddressValid(ChunkedData, ChunkedLength)) {
        DbgPrint("[KHTTP] [ERROR] Invalid source buffer address: %p (len=%lu)\n",
            ChunkedData, ChunkedLength);
        return STATUS_ACCESS_VIOLATION;
    }

    DbgPrint("[KHTTP] Decoding chunked data: %lu bytes\n", ChunkedLength);

    // Allocate output buffer (same size as input, will be smaller or equal)
    PCHAR Decoded = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, ChunkedLength, KHTTP_MULTIPART_TAG);
    if (!Decoded) {
        DbgPrint("[KHTTP] [ERROR] Failed to allocate %lu bytes for decoded data\n",
            ChunkedLength);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Decoded, ChunkedLength);

    PCHAR Source = ChunkedData;
    PCHAR SourceEnd = ChunkedData + ChunkedLength;
    PCHAR Dest = Decoded;
    ULONG TotalDecoded = 0;
    ULONG ChunkCount = 0;

    while (Source < SourceEnd) {
        // Parse chunk size (hex number)
        ULONG ChunkSize = 0;
        ULONG HexDigits = 0;
        BOOLEAN OverflowDetected = FALSE;

        DbgPrint("[KHTTP] [CHUNK %lu] Parsing size at offset %lu\n",
            ChunkCount, (ULONG)(Source - ChunkedData));

        // Parse hex chunk size with overflow detection
        while (Source < SourceEnd && *Source != '\r' && HexDigits < MAX_CHUNK_LINE_LENGTH) {
            char c = *Source;
            ULONG digit = 0;

            if (c >= '0' && c <= '9') {
                digit = c - '0';
            }
            else if (c >= 'a' && c <= 'f') {
                digit = c - 'a' + 10;
            }
            else if (c >= 'A' && c <= 'F') {
                digit = c - 'A' + 10;
            }
            else if (c == ';' || c == ' ') {
                // Chunk extension, skip to CRLF
                break;
            }
            else {
                // Invalid character
                DbgPrint("[KHTTP] [ERROR] Invalid hex char '%c' at offset %lu\n",
                    c, (ULONG)(Source - ChunkedData));
                ExFreePoolWithTag(Decoded, KHTTP_MULTIPART_TAG);
                return STATUS_INVALID_PARAMETER;
            }

            // Check for overflow before multiplication
            if (ChunkSize > (MAX_CHUNK_SIZE / 16)) {
                OverflowDetected = TRUE;
                break;
            }

            ULONG NewChunkSize = ChunkSize * 16 + digit;
            
            // Check for overflow after addition
            if (NewChunkSize < ChunkSize) {
                OverflowDetected = TRUE;
                break;
            }

            ChunkSize = NewChunkSize;
            Source++;
            HexDigits++;
        }

        if (OverflowDetected || ChunkSize > MAX_CHUNK_SIZE) {
            DbgPrint("[KHTTP] [ERROR] Chunk size too large or overflow: 0x%X (max 0x%X)\n",
                ChunkSize, MAX_CHUNK_SIZE);
            ExFreePoolWithTag(Decoded, KHTTP_MULTIPART_TAG);
            return STATUS_INTEGER_OVERFLOW;
        }

        // Skip to CRLF (chunk extensions)
        while (Source < SourceEnd && *Source != '\r') {
            Source++;
        }

        // Expect CRLF
        if (Source >= SourceEnd || *Source != '\r') {
            DbgPrint("[KHTTP] [ERROR] Expected CR at offset %lu\n",
                (ULONG)(Source - ChunkedData));
            ExFreePoolWithTag(Decoded, KHTTP_MULTIPART_TAG);
            return STATUS_INVALID_PARAMETER;
        }
        Source++; // Skip CR

        if (Source >= SourceEnd || *Source != '\n') {
            DbgPrint("[KHTTP] [ERROR] Expected LF at offset %lu\n",
                (ULONG)(Source - ChunkedData));
            ExFreePoolWithTag(Decoded, KHTTP_MULTIPART_TAG);
            return STATUS_INVALID_PARAMETER;
        }
        Source++; // Skip LF

        DbgPrint("[KHTTP] [CHUNK %lu] Size: %lu (0x%X) bytes\n",
            ChunkCount, ChunkSize, ChunkSize);

        // Last chunk (size = 0)
        if (ChunkSize == 0) {
            DbgPrint("[KHTTP] [CHUNK %lu] Last chunk reached\n", ChunkCount);
            break;
        }

        // Validate chunk size against remaining input
        if (Source + ChunkSize > SourceEnd) {
            DbgPrint("[KHTTP] [ERROR] Chunk exceeds buffer: offset %lu + size %lu > total %lu\n",
                (ULONG)(Source - ChunkedData), ChunkSize, ChunkedLength);
            ExFreePoolWithTag(Decoded, KHTTP_MULTIPART_TAG);
            return STATUS_BUFFER_OVERFLOW;
        }

        // Validate chunk won't overflow output buffer
        if (TotalDecoded + ChunkSize > ChunkedLength) {
            DbgPrint("[KHTTP] [ERROR] Output overflow: %lu + %lu > %lu\n",
                TotalDecoded, ChunkSize, ChunkedLength);
            ExFreePoolWithTag(Decoded, KHTTP_MULTIPART_TAG);
            return STATUS_BUFFER_OVERFLOW;
        }

        // Copy chunk data with safe memcpy
        NTSTATUS Status = KhttpSafeMemcpy(Dest, Source, ChunkSize);
        if (!NT_SUCCESS(Status)) {
            DbgPrint("[KHTTP] [ERROR] SafeMemcpy failed for chunk %lu: 0x%08X\n",
                ChunkCount, Status);
            ExFreePoolWithTag(Decoded, KHTTP_MULTIPART_TAG);
            return Status;
        }

        Dest += ChunkSize;
        Source += ChunkSize;
        TotalDecoded += ChunkSize;
        ChunkCount++;

        DbgPrint("[KHTTP] [CHUNK %lu] Copied %lu bytes, total: %lu\n",
            ChunkCount - 1, ChunkSize, TotalDecoded);

        // Expect trailing CRLF after chunk data
        if (Source >= SourceEnd || *Source != '\r') {
            DbgPrint("[KHTTP] [WARN] Expected CR after chunk data at offset %lu\n",
                (ULONG)(Source - ChunkedData));
            // Some servers may omit trailing CRLF, continue anyway
        } else {
            Source++; // Skip CR
            if (Source < SourceEnd && *Source == '\n') {
                Source++; // Skip LF
            }
        }
    }

    DbgPrint("[KHTTP] Chunked decoding complete: %lu chunks, %lu bytes decoded\n",
        ChunkCount, TotalDecoded);

    *DecodedData = Decoded;
    *DecodedLength = TotalDecoded;

    return STATUS_SUCCESS;
}

// ========================================
// MULTIPART REQUEST HANDLING
// ========================================

static NTSTATUS KhttpMultipartRequestInternal(
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
    if (!Url || !Response) return STATUS_INVALID_PARAMETER;

    *Response = NULL;

    // Check for streaming files
    BOOLEAN HasStreamFiles = FALSE;
    for (ULONG i = 0; i < FileCount; i++) {
        if (Files && Files[i].UseFileStream) {
            HasStreamFiles = TRUE;
            break;
        }
    }

    BOOLEAN UseChunked = HasStreamFiles;
    ULONG ChunkSize = KHTTP_CHUNK_SIZE;

    if (Config) {
        if (Config->UseChunkedTransfer || HasStreamFiles) {
            UseChunked = TRUE;
        }
        if (Config->ChunkSize > 0 && Config->ChunkSize <= KHTTP_MAX_CHUNK_SIZE) {
            ChunkSize = Config->ChunkSize;
        }
    }

    // Calculate total size for auto-chunked
    if (!HasStreamFiles) {
        ULONG TotalFileSize = 0;
        for (ULONG i = 0; i < FileCount; i++) {
            if (Files[i].Data && Files[i].DataLength > 0) {
                TotalFileSize += Files[i].DataLength;
            }
        }

        if (TotalFileSize > KHTTP_MAX_MEMORY_BODY_SIZE) {
            UseChunked = TRUE;
            DbgPrint("[KHTTP] Large body detected (%lu bytes), enabling chunked transfer\n",
                TotalFileSize);
        }
    }

    DbgPrint("[KHTTP] Starting multipart request to %s (chunked: %d, streaming: %d)\n",
        Url, UseChunked, HasStreamFiles);

    KHTTP_RESOURCE_TRACKER Tracker;
    KhttpInitResourceTracker(&Tracker);

    // Generate boundary
    PCHAR Boundary = KhttpGenerateBoundary();
    if (!Boundary) return STATUS_INSUFFICIENT_RESOURCES;
    KhttpTrackResource(&Tracker, Boundary, KHTTP_MULTIPART_TAG);

    DbgPrint("[KHTTP] Generated boundary: %s\n", Boundary);

    // Build headers
    CHAR ContentTypeHeader[512];
    NTSTATUS Status = RtlStringCchPrintfA(ContentTypeHeader, sizeof(ContentTypeHeader),
        "Content-Type: multipart/form-data; boundary=%s\r\n%s%s",
        Boundary,
        UseChunked ? "Transfer-Encoding: chunked\r\n" : "",
        Headers ? Headers : "");

    if (!NT_SUCCESS(Status)) {
        KhttpCleanupResources(&Tracker);
        return Status;
    }

    // Establish connection
    PKHTTP_CONNECTION Connection = NULL;
    Status = KhttpEstablishConnection(Url, Config, &Connection);
    if (!NT_SUCCESS(Status)) {
        KhttpCleanupResources(&Tracker);
        return Status;
    }

    DbgPrint("[KHTTP] %s %s (Host: %s:%u, HTTPS: %d)\n",
        MethodNames[Method], Connection->Path, Connection->Hostname,
        Connection->Port, Connection->IsHttps);

    // Build multipart body (if not streaming)
    ULONG BodyLength = 0;
    PCHAR Body = NULL;

    if (!HasStreamFiles) {
        Body = KhttpBuildMultipartBody(FormFields, FormFieldCount, Files, FileCount,
            Boundary, &BodyLength);
        if (!Body) {
            KhttpCloseConnection(Connection);
            KhttpCleanupResources(&Tracker);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        KhttpTrackResource(&Tracker, Body, KHTTP_MULTIPART_TAG);
        DbgPrint("[KHTTP] Built multipart body: %lu bytes\n", BodyLength);
    }
    else {
        DbgPrint("[KHTTP] Using streaming mode\n");
    }

    // Build and send request headers
    ULONG RequestLen;
    PCHAR RequestHeaders = KhttpBuildRequest(Method, Connection->Hostname, Connection->Path,
        ContentTypeHeader, UseChunked ? NULL : Body, UseChunked, &RequestLen);

    if (!RequestHeaders) {
        KhttpCloseConnection(Connection);
        KhttpCleanupResources(&Tracker);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ULONG BytesSent;
    Status = KtlsSend(Connection->Session, RequestHeaders, RequestLen, &BytesSent);
    ExFreePoolWithTag(RequestHeaders, KHTTP_TAG);

    if (!NT_SUCCESS(Status)) {
        DbgPrint("[KHTTP] Failed to send headers: 0x%08X\n", Status);
        KhttpCloseConnection(Connection);
        KhttpCleanupResources(&Tracker);
        return Status;
    }

    DbgPrint("[KHTTP] Headers sent: %lu bytes\n", BytesSent);

    // Send body
    if (UseChunked) {
        KHTTP_CHUNKED_ENCODER Encoder;
        KhttpInitChunkedEncoder(&Encoder, Connection->Session, ChunkSize,
            HasStreamFiles ? 0 : BodyLength,
            Config ? Config->ProgressCallback : NULL,
            Config ? Config->CallbackContext : NULL);

        if (HasStreamFiles) {
            // Send form fields first
            for (ULONG i = 0; i < FormFieldCount; i++) {
                CHAR FieldData[1024];
                RtlStringCchPrintfA(FieldData, sizeof(FieldData),
                    "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n",
                    Boundary, FormFields[i].Name, FormFields[i].Value);

                Status = KhttpChunkedEncoderSend(&Encoder, FieldData, (ULONG)strlen(FieldData));
                if (!NT_SUCCESS(Status)) goto SendCleanup;
            }

            // Stream files
            for (ULONG i = 0; i < FileCount; i++) {
                PKHTTP_FILE File = &Files[i];

                // Send file header
                CHAR FileHeader[512];
                RtlStringCchPrintfA(FileHeader, sizeof(FileHeader),
                    "--%s\r\nContent-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n"
                    "Content-Type: %s\r\n\r\n",
                    Boundary, File->FieldName, File->FileName,
                    File->ContentType ? File->ContentType : "application/octet-stream");

                Status = KhttpChunkedEncoderSend(&Encoder, FileHeader, (ULONG)strlen(FileHeader));
                if (!NT_SUCCESS(Status)) goto SendCleanup;

                // Stream file data
                if (File->UseFileStream) {
                    Status = KhttpStreamFileWithChunks(&Encoder, File->FilePath, ChunkSize);
                    if (!NT_SUCCESS(Status)) goto SendCleanup;
                }
                else {
                    Status = KhttpChunkedEncoderSend(&Encoder, File->Data, File->DataLength);
                    if (!NT_SUCCESS(Status)) goto SendCleanup;
                }

                // Send CRLF after file
                Status = KhttpChunkedEncoderSend(&Encoder, "\r\n", 2);
                if (!NT_SUCCESS(Status)) goto SendCleanup;
            }

            // Send final boundary
            CHAR FinalBoundary[128];
            RtlStringCchPrintfA(FinalBoundary, sizeof(FinalBoundary), "--%s--\r\n", Boundary);
            Status = KhttpChunkedEncoderSend(&Encoder, FinalBoundary, (ULONG)strlen(FinalBoundary));
            if (!NT_SUCCESS(Status)) goto SendCleanup;
        }
        else {
            // Send pre-built body in chunks
            ULONG Sent = 0;
            while (Sent < BodyLength) {
                ULONG ToSend = min(ChunkSize, BodyLength - Sent);
                Status = KhttpChunkedEncoderSend(&Encoder, Body + Sent, ToSend);
                if (!NT_SUCCESS(Status)) goto SendCleanup;
                Sent += ToSend;
            }
        }

        // Finalize chunked encoding
        Status = KhttpChunkedEncoderFinalize(&Encoder);
    }
    else {
        // Regular send
        Status = KtlsSend(Connection->Session, Body, BodyLength, &BytesSent);
    }

SendCleanup:
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[KHTTP] Failed to send body: 0x%08X\n", Status);
        KhttpCloseConnection(Connection);
        KhttpCleanupResources(&Tracker);
        return Status;
    }

    // Receive response
    ULONG MaxResp = Config ? Config->MaxResponseSize : DEFAULT_MAX_RESPONSE;
    Status = KhttpReceiveResponse(Connection, MaxResp, Response);

    if (NT_SUCCESS(Status) && *Response) {
        DbgPrint("[KHTTP] Response received: status %lu\n", (*Response)->StatusCode);
    }

    KhttpCloseConnection(Connection);
    KhttpCleanupResources(&Tracker);

    return Status;
}

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
    return KhttpMultipartRequestInternal(
        KHTTP_POST, Url, Headers, FormFields, FormFieldCount,
        Files, FileCount, Config, Response
    );
}

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
    return KhttpMultipartRequestInternal(
        KHTTP_PUT, Url, Headers, FormFields, FormFieldCount,
        Files, FileCount, Config, Response
    );
}

NTSTATUS KhttpPostMultipartChunked(
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
    // Just call internal function - chunked mode auto-detected
    return KhttpMultipartRequestInternal(
        KHTTP_POST, Url, Headers, FormFields, FormFieldCount,
        Files, FileCount, Config, Response
    );
}

NTSTATUS KhttpPutMultipartChunked(
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
    // Just call internal function - chunked mode auto-detected
    return KhttpMultipartRequestInternal(
        KHTTP_PUT, Url, Headers, FormFields, FormFieldCount,
        Files, FileCount, Config, Response
    );
}
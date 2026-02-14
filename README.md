# wkhttp: Windows Kernel HTTP & TLS

Kernel-mode HTTP/HTTPS client and TLS/DTLS transport library for Windows drivers.

---

## Проект был создан из-за отсутсвия на GitHub толковых библиотек для работы с http в контексте ядра Windows

## Если понравился проект, жмякни стар (if you like the project, click star) ^_^

---

## 1. Integration Overview

```C
#include <ntddk.h>
#include "ktls_lib.h"   // TLS / DTLS transport
#include "kdns_lib.h"   // DNS resolver
#include "khttp_lib.h"  // High-level HTTP
```

```C
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;

    KhttpGlobalInit();
    
    // Your code here...
    
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    KhttpGlobalCleanup();
}
```

---

## 2. HTTP/HTTPS API (`khttp_lib.h`)

High-level, blocking HTTP client with automatic TCP/TLS handling.

```C
typedef struct _KHTTP_RESPONSE {
    ULONG StatusCode;
    ULONG BodyLength;
    PCHAR Body;
} KHTTP_RESPONSE, *PKHTTP_RESPONSE;
```

Supported methods (all return `NTSTATUS` with `PKHTTP_RESPONSE`):

- `KhttpGet`
- `KhttpPost`
- `KhttpPut`
- `KhttpPatch`
- `KhttpDelete`
- `KhttpHead`

### HTTP GET Example

```C
PKHTTP_RESPONSE Response = NULL;
NTSTATUS Status = KhttpGet(
    "http://httpbin.org/get",
    NULL,
    NULL,
    &Response
);

if (NT_SUCCESS(Status) && Response) {
    DbgPrint("Status: %lu, Body: %lu bytes\n", 
        Response->StatusCode, Response->BodyLength);
    KhttpFreeResponse(Response);
}
```

### HTTPS POST Example

```C
PKHTTP_RESPONSE Response = NULL;
NTSTATUS Status = KhttpPost(
    "https://httpbin.org/post",
    "Content-Type: application/json\r\n",
    "{\"secure\":true,\"kernel\":\"mode\",\"tls\":\"1.3\"}",
    NULL,
    &Response
);

if (NT_SUCCESS(Status) && Response) {
    DbgPrint("Status: %lu\n", Response->StatusCode);
    KhttpFreeResponse(Response);
}
```

### REST API Operations

```C
// GET
KhttpGet("https://jsonplaceholder.typicode.com/posts/1", NULL, NULL, &Response);

// POST
KhttpPost(
    "https://jsonplaceholder.typicode.com/posts",
    "Content-Type: application/json\r\n",
    "{\"title\":\"test\",\"body\":\"content\",\"userId\":1}",
    NULL, &Response);

// PUT
KhttpPut(
    "https://jsonplaceholder.typicode.com/posts/1",
    "Content-Type: application/json\r\n",
    "{\"id\":1,\"title\":\"updated\",\"body\":\"modified\",\"userId\":1}",
    NULL, &Response);

// PATCH
KhttpPatch(
    "https://jsonplaceholder.typicode.com/posts/1",
    "Content-Type: application/json\r\n",
    "{\"title\":\"patched\"}",
    NULL, &Response);

// DELETE
KhttpDelete("https://jsonplaceholder.typicode.com/posts/1", NULL, NULL, &Response);

// HEAD
KhttpHead("https://ya.ru/", NULL, NULL, &Response);
```

---

## 3. Multipart File Upload

### Upload files using multipart/form-data encoding. Supports automatic chunked transfer for large files

### Upload Single File

```C
// Allocate file data in NonPagedPool
PVOID FileData = ExAllocatePoolWithTag(NonPagedPool, FileSize, 'FILE');
RtlCopyMemory(FileData, SourceData, FileSize);

KHTTP_FILE File = {
    .FieldName = "document",
    .FileName = "test.bin",
    .ContentType = "application/octet-stream",
    .Data = FileData,
    .DataLength = FileSize
};

PKHTTP_RESPONSE Response = NULL;
NTSTATUS Status = KhttpPostMultipart(
    "https://httpbin.org/post",
    "Authorization: Bearer token123\r\n",
    NULL,
    0,
    &File,
    1,
    NULL,
    &Response
);

if (NT_SUCCESS(Status) && Response) {
    DbgPrint("Upload success: %lu\n", Response->StatusCode);
    KhttpFreeResponse(Response);
}

ExFreePoolWithTag(FileData, 'FILE');
```

### Upload Multiple Files with Form Data

```C
// Form fields
KHTTP_FORM_FIELD Fields[] = {
    { .Name = "title", .Value = "My Photo" },
    { .Name = "description", .Value = "Uploaded from Windows kernel mode driver" }
};

// Files
KHTTP_FILE Files[] = {
    {
        .FieldName = "file1",
        .FileName = "document1.txt",
        .ContentType = "text/plain",
        .Data = ImageData,
        .DataLength = ImageSize
    },
    {
        .FieldName = "file2",
        .FileName = "document2.bin",
        .ContentType = "application/octet-stream",
        .Data = JsonData,
        .DataLength = JsonSize
    }
};

KHTTP_CONFIG Config = {
    .UseHttps = TRUE,
    .TimeoutMs = 30000,
    .UserAgent = "KernelHTTP/1.0",
    .MaxResponseSize = 5 * 1024 * 1024,
    .ProgressCallback = ProgressCallback,
    .CallbackContext = NULL
};

PKHTTP_RESPONSE Response = NULL;
NTSTATUS Status = KhttpPostMultipart(
    "https://httpbin.org/post",
    NULL,
    Fields,
    2,
    Files,
    2,
    &Config,
    &Response
);
```

### Upload with Progress Callback

```C
VOID ProgressCallback(
    ULONG BytesSent,
    ULONG TotalBytes,
    PVOID Context
)
{
    UNREFERENCED_PARAMETER(Context);
    if (TotalBytes > 0) {
        ULONG Percent = (BytesSent * 100) / TotalBytes;
        DbgPrint("[PROGRESS] %lu%% (%lu/%lu bytes)\n", 
                 Percent, BytesSent, TotalBytes);
    }
}

KHTTP_CONFIG Config = {
    .UseHttps = TRUE,
    .TimeoutMs = 120000,
    .ProgressCallback = ProgressCallback,
    .CallbackContext = NULL,
    .UseChunkedTransfer = TRUE
};
```

### Large File Upload with Chunked Transfer

```C
// For large files (5MB+)
PVOID FileData = ExAllocatePoolWithTag(NonPagedPool, 5 * 1024 * 1024, 'FILE');
if (!FileData) {
    return STATUS_INSUFFICIENT_RESOURCES;
}

// Fill with sequential pattern
for (ULONG i = 0; i < (5 * 1024 * 1024) / 4; i++) {
    ((ULONG*)FileData)[i] = i;
}

KHTTP_FILE File = {
    .FieldName = "largefile",
    .FileName = "large5mb.bin",
    .ContentType = "application/octet-stream",
    .Data = FileData,
    .DataLength = 5 * 1024 * 1024
};

KHTTP_CONFIG Config = {
    .UseHttps = TRUE,
    .TimeoutMs = 120000,        // 2 minutes
    .MaxResponseSize = 5 * 1024 * 1024,
    .UseChunkedTransfer = TRUE,
    .ChunkSize = 64 * 1024,     // 64KB chunks
    .ProgressCallback = NULL
};

PKHTTP_RESPONSE Response = NULL;
NTSTATUS Status = KhttpPostMultipartChunked(
    "http://192.168.56.1:8080/upload",
    NULL,
    NULL, 0,
    &File, 1,
    &Config,
    &Response
);

if (NT_SUCCESS(Status) && Response) {
    DbgPrint("Upload success: %lu bytes\n", File.DataLength);
    KhttpFreeResponse(Response);
}

ExFreePoolWithTag(FileData, 'FILE');
```

### Streaming File Upload from Disk

```C
// Stream file from disk without loading into memory
UNICODE_STRING FilePath;
RtlInitUnicodeString(&FilePath, L"\\??\\C:\\test_file.bin");

KHTTP_FILE File = {
    .FieldName = "file",
    .FileName = "test_file.bin",
    .ContentType = "application/octet-stream",
    .UseFileStream = TRUE,
    .FilePath = &FilePath,
    .Data = NULL,
    .DataLength = 0
};

KHTTP_CONFIG Config = {
    .UseHttps = TRUE,
    .TimeoutMs = 300000,        // 5 minutes
    .UseChunkedTransfer = TRUE,
    .ChunkSize = 256 * 1024,    // 256KB chunks
    .ProgressCallback = ProgressCallback
};

PKHTTP_RESPONSE Response = NULL;
NTSTATUS Status = KhttpPostMultipartChunked(
    "https://192.168.56.1:8443/upload",
    NULL,
    NULL, 0,
    &File, 1,
    &Config,
    &Response
);
```

### File Size Recommendations

| File Size | Transfer Method  | Chunk Size | Timeout | Notes                        |
| --------- | ---------------- | ---------- | ------- | ---------------------------- |
| < 2 MB    | Regular          | N/A        | 30s     | Fast, single buffer          |
| 2-10 MB   | Chunked          | 64KB       | 2min    | Progress tracking available  |
| 10-100 MB | Chunked          | 256KB      | 5min    | Use larger chunks            |
| > 100 MB  | Streaming (disk) | 256-512KB  | 10min+  | Avoid loading into memory    |

---

## 4. TLS/DTLS Transport (`ktls_lib.h`)

Low-level encrypted socket abstraction.

```C
PKTLS_SESSION Session = NULL;

NTSTATUS Status = KtlsConnect(
    INETADDR(192,168,56,1),
    4443,
    KTLS_PROTO_TCP,      // or KTLS_PROTO_UDP for DTLS
    "192.168.56.1",
    &Session
);

if (NT_SUCCESS(Status)) {
    KtlsSetTimeout(Session, 9000);

    ULONG Sent, Recv;
    CHAR Buffer[4096];
    
    // Send HTTP request
    const char* Request = "GET / HTTP/1.1\r\nHost: 192.168.56.1\r\nConnection: close\r\n\r\n";
    KtlsSend(Session, (PVOID)Request, (ULONG)strlen(Request), &Sent);
    
    // Receive response
    KtlsRecv(Session, Buffer, sizeof(Buffer) - 1, &Recv);
    if (Recv > 0) {
        Buffer[Recv] = '\0';
        DbgPrint("Received: %s\n", Buffer);
    }
    
    KtlsClose(Session);
}
```

### DTLS (UDP) Example

```C
PKTLS_SESSION Session = NULL;

NTSTATUS Status = KtlsConnect(
    INETADDR(192,168,56,1),
    4443,
    KTLS_PROTO_UDP,      // DTLS over UDP
    "192.168.56.1",
    &Session
);

if (NT_SUCCESS(Status)) {
    KtlsSetTimeout(Session, 9000);

    ULONG Sent, Recv;
    CHAR Buffer[1024];
    
    // Send message
    const char* Message = "Hello DTLS";
    KtlsSend(Session, (PVOID)Message, (ULONG)strlen(Message), &Sent);
    
    // Receive echo
    KtlsRecv(Session, Buffer, sizeof(Buffer) - 1, &Recv);
    if (Recv > 0) {
        Buffer[Recv] = '\0';
        DbgPrint("Echo: %s\n", Buffer);
    }
    
    KtlsClose(Session);
}
```

Requirements:

- Buffers for `KtlsRecv` must be from `NonPagedPool`.
- Every successful `KtlsConnect` must be followed by `KtlsClose`.

---

## 5. DNS Helper (`kdns_lib.h`)

```C
ULONG Ip = 0;

NTSTATUS Status = KdnsResolve(
    "ya.ru",
    INETADDR(8,8,8,8),  // Google DNS
    3000,               // 3 seconds timeout
    &Ip
);

if (NT_SUCCESS(Status)) {
    DbgPrint("IP: %u.%u.%u.%u\n",
        (Ip >> 0) & 0xFF,
        (Ip >> 8) & 0xFF,
        (Ip >> 16) & 0xFF,
        (Ip >> 24) & 0xFF);
}
```

---

## 6. Test Server (Go TLS/DTLS Echo)

Located in `test server/`, this Go program provides a dual TLS/DTLS echo endpoint on `0.0.0.0:4443` for testing `KtlsConnect`, `KtlsSend`, and `KtlsRecv`.

Build and run:

```bash
cd "test server"
go mod init test_server
go get github.com/pion/dtls/v2
go run main.go
```

It generates an in-memory self-signed certificate and echoes back any data received over both TCP (TLS) and UDP (DTLS).

---

## 7. Test Results

### Comprehensive test suite validates all functionality with real-world endpoints

| Test Category            | Tests | Status  | Endpoints                         |
| ------------------------ | ----- | ------- | --------------------------------- |
| DNS Resolution           | 1     | ✅ PASS | Google DNS (8.8.8.8)              |
| TLS/DTLS                 | 2     | ✅ PASS | Local test server                 |
| HTTP Methods             | 3     | ✅ PASS | httpbin.org, ya.ru                |
| HTTPS Requests           | 4     | ✅ PASS | httpbin.org, jsonplaceholder      |
| REST API (HTTP)          | 5     | ✅ PASS | jsonplaceholder.typicode.com      |
| REST API (HTTPS)         | 4     | ✅ PASS | jsonplaceholder.typicode.com      |
| File Upload (Small)      | 1     | ✅ PASS | httpbin.org (1KB)                 |
| File Upload (With Form)  | 1     | ✅ PASS | example.com (2KB)                 |
| File Upload (Multiple)   | 1     | ✅ PASS | httpbin.org (512B + 1KB)          |
| File Upload (Large)      | 1     | ✅ PASS | Local server (5MB chunked)        |
| File Upload (Streaming)  | 1     | ✅ PASS | Local server (disk streaming)     |
| **Total**                | **24**| ✅ **100%** |                               |

### Test Features

- **Protocol Tests**: DNS resolution, TLS handshake, DTLS handshake
- **HTTP/HTTPS**: All methods (GET, POST, PUT, PATCH, DELETE, HEAD)
- **REST API**: Full CRUD operations with JSON payloads
- **File Uploads**: Single file, multiple files, form fields, chunked transfer, streaming
- **Progress Tracking**: Callback support for monitoring upload progress
- **Large Files**: 5MB chunked upload with sequential pattern verification
- **Streaming**: Direct disk-to-network streaming without memory buffering

### Running Tests

All tests are implemented in `wkhttp_tests.c` and run automatically on driver load:

```C
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;

    // Initialize library
    NTSTATUS Status = KhttpGlobalInit();
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    // Tests run here automatically
    // See wkhttp_tests.c for details
    
    return STATUS_SUCCESS;
}
```

---

## 8. Configuration Options

```C
typedef struct _KHTTP_CONFIG {
    BOOLEAN UseHttps;                    // Use HTTPS instead of HTTP
    ULONG TimeoutMs;                     // Request timeout in milliseconds
    PCHAR UserAgent;                     // Custom User-Agent header
    ULONG MaxResponseSize;               // Maximum response body size
    ULONG DnsServerIp;                   // Custom DNS server (0 = use 8.8.8.8)
    BOOLEAN UseChunkedTransfer;          // Enable chunked transfer encoding
    ULONG ChunkSize;                     // Chunk size for uploads (default 64KB)
    PKHTTP_PROGRESS_CALLBACK ProgressCallback;  // Upload progress callback
    PVOID CallbackContext;               // User context for callback
} KHTTP_CONFIG, *PKHTTP_CONFIG;
```

### Example Configuration

```C
KHTTP_CONFIG Config = {
    .UseHttps = TRUE,
    .TimeoutMs = 60000,              // 60 seconds
    .UserAgent = "MyDriver/1.0",
    .MaxResponseSize = 10 * 1024 * 1024,  // 10MB
    .DnsServerIp = INETADDR(8,8,8,8),
    .UseChunkedTransfer = TRUE,
    .ChunkSize = 128 * 1024,         // 128KB chunks
    .ProgressCallback = MyProgressCallback,
    .CallbackContext = MyContext
};
```

---

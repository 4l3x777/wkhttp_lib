
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
    
    // Your tests here...
    
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

Example HTTPS POST:

```C
PKHTTP_RESPONSE Resp = NULL;
NTSTATUS Status = KhttpPost(
    "https://httpbin.org/post",
    "Content-Type: application/json\r\n",
    "{\"secure\":true,\"kernel\":\"mode\"}",
    NULL,
    &Resp
);

if (NT_SUCCESS(Status) && Resp) {
    DbgPrint("Status: %lu, Body %lu bytes\n", Resp->StatusCode, Resp->BodyLength);
    KhttpFreeResponse(Resp);
}
```

---

## 3. Multipart File Upload

## Upload files using multipart/form-data encoding. Supports automatic chunked transfer for large files

## Upload Single File

```C
// Allocate file data in NonPagedPool
PVOID FileData = ExAllocatePoolWithTag(NonPagedPool, FileSize, 'FILE');
RtlCopyMemory(FileData, SourceData, FileSize);

KHTTP_FILE File = {
    .FieldName = "file",
    .FileName = "document.pdf",
    .ContentType = "application/pdf",
    .Data = FileData,
    .DataLength = FileSize
};

KHTTP_CONFIG Config = {
    .UseHttps = TRUE,
    .TimeoutMs = 60000,  // 60 seconds
    .MaxResponseSize = 5 * 1024 * 1024,
    .UseChunkedTransfer = TRUE,  // Enable for large files
    .ChunkSize = 64 * 1024       // 64KB chunks
};

PKHTTP_RESPONSE Response = NULL;
NTSTATUS Status = KhttpPostMultipartChunked(
    "https://example.com/upload",
    NULL,
    NULL,
    0,
    &File,
    1,
    &Config,
    &Response
);

if (NT_SUCCESS(Status) && Response) {
    DbgPrint("Upload success: %lu\n", Response->StatusCode);
    KhttpFreeResponse(Response);
}

ExFreePoolWithTag(FileData, 'FILE');
```

## Upload Multiple Files with Form Data

```C
// Form fields
KHTTP_FORM_FIELD Fields[] = {
    { .Name = "username", .Value = "john_doe" },
    { .Name = "description", .Value = "My files" }
};

// Files
KHTTP_FILE Files[] = {
    {
        .FieldName = "file1",
        .FileName = "image.jpg",
        .ContentType = "image/jpeg",
        .Data = ImageData,
        .DataLength = ImageSize
    },
    {
        .FieldName = "file2",
        .FileName = "data.json",
        .ContentType = "application/json",
        .Data = JsonData,
        .DataLength = JsonSize
    }
};

PKHTTP_RESPONSE Response = NULL;
NTSTATUS Status = KhttpPostMultipartChunked(
    "https://api.example.com/upload",
    "Authorization: Bearer token123\r\n",
    Fields,
    2,
    Files,
    2,
    &Config,
    &Response
);
```

## Upload with Progress Callback

```C
VOID UploadProgressCallback(
    ULONG BytesSent,
    ULONG TotalBytes,
    PVOID Context
)
{
    ULONG Percent = (BytesSent * 100) / TotalBytes;
    DbgPrint("[Upload] Progress: %lu%% (%lu/%lu bytes)\n", 
             Percent, BytesSent, TotalBytes);
}

KHTTP_CONFIG Config = {
    .UseHttps = TRUE,
    .TimeoutMs = 120000,
    .ProgressCallback = UploadProgressCallback,
    .CallbackContext = NULL,
    .UseChunkedTransfer = TRUE
};
```

## File Size Limits

| File Size | Transfer Method  | Notes                               |
| --------- | ---------------- | ----------------------------------- |
| < 2 MB    | Regular          | Fast, single buffer                 |
| 2-10 MB   | Chunked (auto)   | 64KB chunks, progress tracking      |
| 10-100 MB | Chunked (manual) | Increase timeout, use larger chunks |

```C
// For large files (10-100MB)
KHTTP_CONFIG LargeConfig = {
    .UseHttps = TRUE,
    .TimeoutMs = 300000,        // 5 minutes
    .MaxResponseSize = 10 * 1024 * 1024,
    .UseChunkedTransfer = TRUE,
    .ChunkSize = 256 * 1024,    // 256KB chunks for better performance
    .ProgressCallback = UploadProgressCallback
};
```

---

## 4. TLS/DTLS Transport (`ktls_lib.h`)

Low-level encrypted socket abstraction.

```C
PKTLS_SESSION Sess = NULL;

NTSTATUS Status = KtlsConnect(
    INETADDR(1,1,1,1),
    4443,
    KTLS_PROTO_TCP,      // or KTLS_PROTO_UDP for DTLS
    "1.1.1.1",
    &Sess
);

if (NT_SUCCESS(Status)) {
    KtlsSetTimeout(Sess, 9000);

    ULONG Sent, Recv;
    CHAR Buf;
    
    KtlsSend(Sess, "Hello", 5, &Sent);
    KtlsRecv(Sess, Buf, sizeof(Buf), &Recv);
    
    KtlsClose(Sess);
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
    INETADDR(8,8,8,8),
    3000,
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

Located in `test server/`, this Go program provides a dual TLS/DTLS echo endpoint on `0.0.0.0:4443` for exercising `KtlsConnect`, `KtlsSend`, and `KtlsRecv`.

Build and run:

```go
cd "test server"
go mod init test_server
go get github.com/pion/dtls/v2
go run main.go
```

It generates an in-memory self-signed certificate and echoes back any data received over both TCP (TLS) and UDP (DTLS).

## Test Results

## All tests passed successfully with the following metrics

| Test Category          | Tests | Status |
| ---------------------- | ----- | ------ |
| HTTP Methods           | 6     | ✅ PASS |
| HTTPS Requests         | 6     | ✅ PASS |
| REST API (HTTP/HTTPS)  | 8     | ✅ PASS |
| Multipart Upload       | 3     | ✅ PASS |
| Chunked Transfer (5MB) | 1     | ✅ PASS |
| TLS/DTLS               | 2     | ✅ PASS |
| Total                  | 26    | ✅ 100% |

---

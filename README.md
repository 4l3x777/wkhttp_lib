
# wkhttp: Windows Kernel HTTP & TLS

Kernel-mode HTTP/HTTPS client and TLS/DTLS transport library for Windows drivers.

---

## Проект был создан из-за отсутсвия на GitHub толковых библиотек для работы с htpp в контексте ядра Windows

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
"{"secure":true,"kernel":"mode"}",
NULL,
&Resp
);

if (NT_SUCCESS(Status) && Resp) {
DbgPrint("Status: %lu, Body %lu bytes\n", Resp->StatusCode, Resp->BodyLength);
KhttpFreeResponse(Resp);
}

```

---

## 3. TLS/DTLS Transport (`ktls_lib.h`)

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

## 4. DNS Helper (`kdns_lib.h`)

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

## 5. Test Server (Go TLS/DTLS Echo)

Located in `test server/`, this Go program provides a dual TLS/DTLS echo endpoint on `0.0.0.0:4443` for exercising `KtlsConnect`, `KtlsSend`, and `KtlsRecv`.

Build and run:

```go

cd "test server"
go mod init test_server
go get github.com/pion/dtls/v2
go run main.go

```

It generates an in-memory self-signed certificate and echoes back any data received over both TCP (TLS) and UDP (DTLS).

---

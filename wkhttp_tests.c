#include <ntddk.h>
#include "ktls_lib.h"
#include "kdns_lib.h"
#include "khttp_lib.h"

// =============================================================
// HELPER FUNCTIONS
// =============================================================

VOID PrintResponse(PCHAR Buffer, ULONG Length) {
    ULONG Offset = 0;
    while (Offset < Length) {
        ULONG Chunk = (Length - Offset) > 500 ? 500 : (Length - Offset);
        CHAR Temp = Buffer[Offset + Chunk];
        Buffer[Offset + Chunk] = 0;
        DbgPrint("%s", &Buffer[Offset]);
        Buffer[Offset + Chunk] = Temp;
        Offset += Chunk;
    }
    DbgPrint("\n");
}

// =============================================================
// TESTS
// =============================================================

VOID TestDns(void) {
    NTSTATUS Status;
    ULONG Ip;

    DbgPrint("\n[DNS] Resolving ya.ru...\n");
    Status = KdnsResolve("ya.ru", INETADDR(8, 8, 8, 8), 3000, &Ip);
    if (NT_SUCCESS(Status)) {
        DbgPrint("[DNS] OK - IP: %02x.%02x.%02x.%02x\n",
            (Ip >> 0) & 0xFF, (Ip >> 8) & 0xFF,
            (Ip >> 16) & 0xFF, (Ip >> 24) & 0xFF);
    }
    else {
        DbgPrint("[DNS] FAIL - 0x%08x\n", Status);
    }
}

VOID TestTls(void) {
    PKTLS_SESSION Session = NULL;
    PVOID Buffer = NULL;
    ULONG Bytes;
    NTSTATUS Status;

    DbgPrint("\n[TLS] Connecting to 192.168.56.1:4443...\n");
    Status = KtlsConnect(INETADDR(192, 168, 56, 1), 4443, KTLS_PROTO_TCP, "192.168.56.1", &Session);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[TLS] FAIL - 0x%08x\n", Status);
        return;
    }
    DbgPrint("[TLS] Connected\n");

    KtlsSetTimeout(Session, 9000);
    const char* Req = "GET / HTTP/1.1\r\nHost: 192.168.56.1\r\nConnection: close\r\n\r\n";
    KtlsSend(Session, (PVOID)Req, (ULONG)strlen(Req), &Bytes);

    Buffer = ExAllocatePoolWithTag(NonPagedPool, 4096, 'TEST');
    if (Buffer) {
        Status = KtlsRecv(Session, Buffer, 4095, &Bytes);
        if (Status == STATUS_SUCCESS) {
            DbgPrint("[TLS] RX %u bytes:\n", Bytes);
            PrintResponse((PCHAR)Buffer, Bytes);
        }
        ExFreePoolWithTag(Buffer, 'TEST');
    }
    KtlsClose(Session);
}

VOID TestDtls(void) {
    PKTLS_SESSION Session = NULL;
    PVOID Buffer = NULL;
    ULONG Bytes;
    NTSTATUS Status;

    DbgPrint("\n[DTLS] Connecting to 192.168.56.1:4443...\n");
    Status = KtlsConnect(INETADDR(192, 168, 56, 1), 4443, KTLS_PROTO_UDP, "192.168.56.1", &Session);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[DTLS] FAIL - 0x%08x\n", Status);
        return;
    }
    DbgPrint("[DTLS] Connected\n");

    KtlsSetTimeout(Session, 9000);
    const char* Msg = "Hello DTLS";
    KtlsSend(Session, (PVOID)Msg, (ULONG)strlen(Msg), &Bytes);

    Buffer = ExAllocatePoolWithTag(NonPagedPool, 1024, 'TEST');
    if (Buffer) {
        Status = KtlsRecv(Session, Buffer, 1024, &Bytes);
        if (NT_SUCCESS(Status)) {
            DbgPrint("[DTLS] RX %u bytes:\n", Bytes);
            PrintResponse((PCHAR)Buffer, Bytes);
        }
        ExFreePoolWithTag(Buffer, 'TEST');
    }
    KtlsClose(Session);
}

VOID TestHttp(void) {
    PKHTTP_RESPONSE Response = NULL;
    NTSTATUS Status;

    // GET
    DbgPrint("\n[HTTP] GET httpbin.org/get\n");
    Status = KhttpGet("http://httpbin.org/get", NULL, NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[HTTP] Status %lu, Size %lu\n", Response->StatusCode, Response->BodyLength);
        KhttpFreeResponse(Response);
    }
    else {
        DbgPrint("[HTTP] FAIL - 0x%08x\n", Status);
    }

    // POST
    DbgPrint("\n[HTTP] POST httpbin.org/post\n");
    Status = KhttpPost("http://httpbin.org/post",
        "Content-Type: application/json\r\n",
        "{\"test\":\"data\"}",
        NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[HTTP] Status %lu\n", Response->StatusCode);
        KhttpFreeResponse(Response);
    }
    else {
        DbgPrint("[HTTP] FAIL - 0x%08x\n", Status);
    }

    // HEAD - Changed to ya.ru
    DbgPrint("\n[HTTP] HEAD ya.ru\n");
    Status = KhttpHead("http://ya.ru/", NULL, NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[HTTP] Status %lu, Body %lu bytes\n", Response->StatusCode, Response->BodyLength);
        KhttpFreeResponse(Response);
    }
    else {
        DbgPrint("[HTTP] FAIL - 0x%08x\n", Status);
    }
}

VOID TestHttps(void) {
    PKHTTP_RESPONSE Response = NULL;
    NTSTATUS Status;

    // HTTPS GET with domain name
    DbgPrint("\n[HTTPS] GET httpbin.org/get\n");
    Status = KhttpGet("https://httpbin.org/get",
        "Accept: application/json\r\n",
        NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[HTTPS] Status %lu, Size %lu\n", Response->StatusCode, Response->BodyLength);
        if (Response->Body && Response->BodyLength > 0) {
            ULONG PrintLen = min(Response->BodyLength, 150);
            DbgPrint("[HTTPS] Body: %.*s...\n", PrintLen, Response->Body);
        }
        KhttpFreeResponse(Response);
    }
    else {
        DbgPrint("[HTTPS] FAIL - 0x%08x\n", Status);
    }

    // HTTPS POST
    DbgPrint("\n[HTTPS] POST httpbin.org/post\n");
    Status = KhttpPost("https://httpbin.org/post",
        "Content-Type: application/json\r\n",
        "{\"secure\":true,\"kernel\":\"mode\"}",
        NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[HTTPS] Status %lu\n", Response->StatusCode);
        KhttpFreeResponse(Response);
    }
    else {
        DbgPrint("[HTTPS] FAIL - 0x%08x\n", Status);
    }

    // HTTPS with JSONPlaceholder
    DbgPrint("\n[HTTPS] GET jsonplaceholder.typicode.com/posts/1\n");
    Status = KhttpGet("https://jsonplaceholder.typicode.com/posts/1",
        NULL, NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[HTTPS] Status %lu\n", Response->StatusCode);
        if (Response->Body && Response->BodyLength > 0) {
            ULONG PrintLen = min(Response->BodyLength, 100);
            DbgPrint("[HTTPS] Body: %.*s...\n", PrintLen, Response->Body);
        }
        KhttpFreeResponse(Response);
    }
    else {
        DbgPrint("[HTTPS] FAIL - 0x%08x\n", Status);
    }

    // HTTPS HEAD to ya.ru
    DbgPrint("\n[HTTPS] HEAD ya.ru\n");
    Status = KhttpHead("https://ya.ru/", NULL, NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[HTTPS] Status %lu, Body %lu bytes\n", Response->StatusCode, Response->BodyLength);
        KhttpFreeResponse(Response);
    }
    else {
        DbgPrint("[HTTPS] FAIL - 0x%08x\n", Status);
    }
}

VOID TestRestApi(void) {
    PKHTTP_RESPONSE Response = NULL;
    NTSTATUS Status;

    DbgPrint("\n[REST] GET /posts/1\n");
    Status = KhttpGet("http://jsonplaceholder.typicode.com/posts/1", NULL, NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[REST] Status %lu\n", Response->StatusCode);
        KhttpFreeResponse(Response);
    }

    DbgPrint("\n[REST] POST /posts\n");
    Status = KhttpPost("http://jsonplaceholder.typicode.com/posts",
        "Content-Type: application/json\r\n",
        "{\"title\":\"test\",\"body\":\"kernel\",\"userId\":1}",
        NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[REST] Status %lu\n", Response->StatusCode);
        KhttpFreeResponse(Response);
    }

    DbgPrint("\n[REST] PUT /posts/1\n");
    Status = KhttpPut("http://jsonplaceholder.typicode.com/posts/1",
        "Content-Type: application/json\r\n",
        "{\"id\":1,\"title\":\"updated\",\"body\":\"content\",\"userId\":1}",
        NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[REST] Status %lu\n", Response->StatusCode);
        KhttpFreeResponse(Response);
    }

    DbgPrint("\n[REST] PATCH /posts/1\n");
    Status = KhttpPatch("http://jsonplaceholder.typicode.com/posts/1",
        "Content-Type: application/json\r\n",
        "{\"title\":\"patched\"}",
        NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[REST] Status %lu\n", Response->StatusCode);
        KhttpFreeResponse(Response);
    }

    DbgPrint("\n[REST] DELETE /posts/1\n");
    Status = KhttpDelete("http://jsonplaceholder.typicode.com/posts/1", NULL, NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[REST] Status %lu\n", Response->StatusCode);
        KhttpFreeResponse(Response);
    }
}

VOID TestRestApiHttps(void) {
    PKHTTP_RESPONSE Response = NULL;
    NTSTATUS Status;

    DbgPrint("\n[REST-HTTPS] GET /posts/1\n");
    Status = KhttpGet("https://jsonplaceholder.typicode.com/posts/1", NULL, NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[REST-HTTPS] Status %lu\n", Response->StatusCode);
        KhttpFreeResponse(Response);
    }
    else {
        DbgPrint("[REST-HTTPS] FAIL - 0x%08x\n", Status);
    }

    DbgPrint("\n[REST-HTTPS] POST /posts\n");
    Status = KhttpPost("https://jsonplaceholder.typicode.com/posts",
        "Content-Type: application/json\r\n",
        "{\"title\":\"secure test\",\"body\":\"https kernel\",\"userId\":1}",
        NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[REST-HTTPS] Status %lu\n", Response->StatusCode);
        KhttpFreeResponse(Response);
    }
    else {
        DbgPrint("[REST-HTTPS] FAIL - 0x%08x\n", Status);
    }

    DbgPrint("\n[REST-HTTPS] PUT /posts/1\n");
    Status = KhttpPut("https://jsonplaceholder.typicode.com/posts/1",
        "Content-Type: application/json\r\n",
        "{\"id\":1,\"title\":\"secure update\",\"body\":\"https content\",\"userId\":1}",
        NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[REST-HTTPS] Status %lu\n", Response->StatusCode);
        KhttpFreeResponse(Response);
    }
    else {
        DbgPrint("[REST-HTTPS] FAIL - 0x%08x\n", Status);
    }

    DbgPrint("\n[REST-HTTPS] DELETE /posts/1\n");
    Status = KhttpDelete("https://jsonplaceholder.typicode.com/posts/1", NULL, NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[REST-HTTPS] Status %lu\n", Response->StatusCode);
        KhttpFreeResponse(Response);
    }
    else {
        DbgPrint("[REST-HTTPS] FAIL - 0x%08x\n", Status);
    }
}

// TEST: One file upload
VOID TestFileUpload(VOID)
{
    DbgPrint("\n[UPLOAD KHTTP] Test one file upload\n");

    PVOID FileData = ExAllocatePoolWithTag(NonPagedPool, 1024, 'tseT');
    if (!FileData) return;

    RtlFillMemory(FileData, 1024, 0xAA);

    KHTTP_FILE File = {
        .FieldName = "document",
        .FileName = "test.bin",
        .ContentType = "application/octet-stream",
        .Data = FileData,
        .DataLength = 1024
    };

    PKHTTP_RESPONSE Response = NULL;
    NTSTATUS Status = KhttpPostMultipart(
        "https://httpbin.org/post",
        "Authorization: Bearer token123\r\n",
        NULL,           // No form fields
        0,
        &File,
        1,              // One file
        NULL,           // Default config
        &Response
    );

    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[KHTTP] Upload status: %lu\n", Response->StatusCode);
        if (Response->Body) {
            DbgPrint("[KHTTP] Response body length: %lu\n", Response->BodyLength);
        }
        KhttpFreeResponse(Response);
    }
    else {
        DbgPrint("[KHTTP] Upload failed: 0x%08X\n", Status);
    }

    ExFreePoolWithTag(FileData, 'tseT');
}

// TEST: Upload file with form
VOID TestFileUploadWithForm(VOID)
{
    DbgPrint("\n[UPLOAD KHTTP] Test one file with form upload\n");

    PVOID FileData = ExAllocatePoolWithTag(NonPagedPool, 2048, 'tseT');
    if (!FileData) return;

    RtlFillMemory(FileData, 2048, 0xBB);

    KHTTP_FILE File = {
        .FieldName = "image",
        .FileName = "photo.jpg",
        .ContentType = "image/jpeg",
        .Data = FileData,
        .DataLength = 2048
    };

    KHTTP_FORM_FIELD Fields[2] = {
        {.Name = "title", .Value = "My Photo" },
        {.Name = "description", .Value = "Test upload from kernel" }
    };

    PKHTTP_RESPONSE Response = NULL;
    NTSTATUS Status = KhttpPostMultipart(
        "https://example.com/upload",
        NULL,
        Fields,
        2,
        &File,
        1,
        NULL,
        &Response
    );

    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[KHTTP] Upload completed: %lu\n", Response->StatusCode);
        KhttpFreeResponse(Response);
    }
    else {
        DbgPrint("[KHTTP] Upload failed: 0x%08X\n", Status);
    }

    ExFreePoolWithTag(FileData, 'tseT');
}

// TEST: Upload multiple files with progressbar
VOID ProgressCallback(ULONG BytesSent, ULONG TotalBytes, PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    ULONG Percent = (BytesSent * 100) / TotalBytes;
    DbgPrint("[KHTTP] Upload progress: %lu%%\n", Percent);
}

VOID TestMultipleFilesUpload(VOID)
{
    DbgPrint("\n[UPLOAD KHTTP] Test multiple files upload\n");

    PVOID File1Data = ExAllocatePoolWithTag(NonPagedPool, 512, 'tseT');
    if (!File1Data) return;
    RtlFillMemory(File1Data, 512, 0x11);

    PVOID File2Data = ExAllocatePoolWithTag(NonPagedPool, 1024, 'tseT');
    if (!File2Data) {
        ExFreePoolWithTag(File1Data, 'tseT');
        return;
    }
    RtlFillMemory(File2Data, 1024, 0x22);

    KHTTP_FILE Files[2] = {
        {
            .FieldName = "file1",
            .FileName = "document1.txt",
            .ContentType = "text/plain",
            .Data = File1Data,
            .DataLength = 512
        },
        {
            .FieldName = "file2",
            .FileName = "document2.bin",
            .ContentType = "application/octet-stream",
            .Data = File2Data,
            .DataLength = 1024
        }
    };

    KHTTP_CONFIG Config = {
        .UseHttps = TRUE,
        .TimeoutMs = 30000,
        .UserAgent = "KernelHTTP/1.0",
        .MaxResponseSize = 5 * 1024 * 1024,
        .DnsServerIp = 0,
        .ProgressCallback = ProgressCallback,
        .CallbackContext = NULL
    };

    PKHTTP_RESPONSE Response = NULL;
    NTSTATUS Status = KhttpPostMultipart(
        "https://httpbin.org/post",
        NULL,
        NULL,
        0,
        Files,
        2,
        &Config,
        &Response
    );

    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[KHTTP] Multiple files uploaded: %lu\n", Response->StatusCode);
        KhttpFreeResponse(Response);
    }
    else {
        DbgPrint("[KHTTP] Upload failed: 0x%08X\n", Status);
    }

    ExFreePoolWithTag(File1Data, 'tseT');
    ExFreePoolWithTag(File2Data, 'tseT');
}

// Test: Large file upload with chunked transfer
VOID TestLargeFileUploadChunked(VOID)
{
    DbgPrint("\n[UPLOAD KHTTP] Test large file chunked upload\n");

    // 5MB file
    ULONG FileSize = 5 * 1024 * 1024;

    PVOID FileData = ExAllocatePoolWithTag(NonPagedPool, FileSize, 'tseT');
    if (!FileData) {
        DbgPrint("[KHTTP] Failed to allocate %lu bytes\n", FileSize);
        return;
    }

    // Fill with pattern for verification
    for (ULONG i = 0; i < FileSize / 4; i++) {
        ((ULONG*)FileData)[i] = i;
    }

    KHTTP_FILE File = {
        .FieldName = "largefile",
        .FileName = "large5mb.bin",
        .ContentType = "application/octet-stream",
        .Data = FileData,
        .DataLength = FileSize
    };

    // Config with chunked transfer enabled
    KHTTP_CONFIG Config = {
        .UseHttps = TRUE,
        .TimeoutMs = 120000,  // 2 minutes
        .MaxResponseSize = 5 * 1024 * 1024,
        .DnsServerIp = 0,
        .UserAgent = "KernelHTTP/1.0",
        .UseChunkedTransfer = TRUE,  // Enable chunked
        .ChunkSize = 64 * 1024,      // 64KB chunks
        .ProgressCallback = NULL,
        .CallbackContext = NULL
    };

    PKHTTP_RESPONSE Response = NULL;
    NTSTATUS Status = KhttpPostMultipartChunked(
        "http://192.168.56.1:8080/upload",
        NULL,
        NULL,
        0,
        &File,
        1,
        &Config,
        &Response
    );

    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[KHTTP] Large file uploaded: %lu (size: %lu bytes)\n",
            Response->StatusCode, FileSize);
        KhttpFreeResponse(Response);
    }
    else {
        DbgPrint("[KHTTP] Large file upload failed: 0x%08X\n", Status);
    }

    ExFreePoolWithTag(FileData, 'tseT');
}

// Test: File Stream upload with chunked transfer
VOID TestFileStreamUpload()
{
    DbgPrint("\n[UPLOAD KHTTP] Test streaming file chunked upload\n");

    // Initialize file path
    UNICODE_STRING FilePath;
    RtlInitUnicodeString(&FilePath, L"\\??\\C:\\test_file.bin");

    KHTTP_FILE File = {
        .FieldName = "file",
        .FileName = "test_file.bin",
        .ContentType = "application/octet-stream",
        .UseFileStream = TRUE,      // Enable streaming
        .FilePath = &FilePath,      // File path
        .Data = NULL,               // Not used
        .DataLength = 0             // Not used
    };

    KHTTP_CONFIG Config = {
        .UseHttps = TRUE,
        .TimeoutMs = 300000,            // 5 minutes
        .UseChunkedTransfer = TRUE,
        .ChunkSize = 256 * 1024,        // 256KB chunks
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

    if (NT_SUCCESS(Status) && Response) {
        DbgPrint("[KHTTP] Streaming file uploaded: %lu\n", Response->StatusCode);
        KhttpFreeResponse(Response);
    }
    else {
        DbgPrint("[KHTTP] Streaming upload failed: 0x%08X\n", Status);
    }
}


// =============================================================
// DRIVER ENTRY
// =============================================================

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    KhttpGlobalCleanup();
    DbgPrint("\n[Driver] Unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("\n[Driver] Windows Kernel HTTP Library\n");

    KhttpGlobalInit();

    // Low-level tests
    TestDns();
    TestTls();
    TestDtls();

    // HTTP tests (plain TCP)
    TestHttp();
    TestRestApi();

    // HTTPS tests (TLS)
    TestHttps();
    TestRestApiHttps();

    // HTTP tests multipart
    TestFileUpload();
    
    // Delay between tests
    KhttpSleep(2000); // 2 seconds
    TestFileUploadWithForm();
    
    // Delay between tests
    KhttpSleep(2000); // 2 seconds
    TestMultipleFilesUpload();
    
    // Delay between tests
    KhttpSleep(2000); // 2 seconds
    TestLargeFileUploadChunked();

    // Delay between tests
    KhttpSleep(2000); // 2 seconds
    TestFileStreamUpload();

    DbgPrint("\n[Driver] Tests complete\n");

    return STATUS_SUCCESS;
}

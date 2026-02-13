/**
 * @file wkhttp_tests.c
 * @brief Comprehensive test suite for Windows Kernel HTTP Library
 * 
 * This file contains integration tests for KHTTP, KTLS, and KDNS libraries.
 * Tests are organized into categories:
 * - Low-level protocol tests (DNS, TLS, DTLS)
 * - HTTP/HTTPS request tests (GET, POST, PUT, DELETE, HEAD, PATCH)
 * - REST API tests
 * - File upload tests (single, multiple, streaming, chunked)
 * 
 * @section test_organization Test Organization
 * 1. DNS Resolution Tests
 * 2. TLS/DTLS Connection Tests
 * 3. Plain HTTP Tests
 * 4. HTTPS Tests
 * 5. REST API Tests (HTTP & HTTPS)
 * 6. File Upload Tests (various scenarios)
 * 
 * @note All tests use public APIs for integration testing
 * @note Tests require internet connectivity and local test servers
 */

#include <ntddk.h>
#include "ktls_lib.h"
#include "kdns_lib.h"
#include "khttp_lib.h"

// =============================================================================
// TEST CONFIGURATION
// =============================================================================

// Local test server configuration (adjust as needed)
#define TEST_SERVER_IP      INETADDR(192, 168, 56, 1)
#define TEST_TLS_PORT       4443
#define TEST_HTTP_PORT      8080
#define TEST_HTTPS_PORT     8443
#define TEST_DNS_SERVER     INETADDR(8, 8, 8, 8)  // Google DNS

// Test delays (milliseconds)
#define TEST_DELAY_SHORT    2000    // 2 seconds between tests
#define TEST_TIMEOUT_NORMAL 9000    // 9 seconds for normal operations
#define TEST_TIMEOUT_LONG   120000  // 2 minutes for large uploads
#define TEST_TIMEOUT_VLONG  300000  // 5 minutes for streaming

// Test data sizes
#define TEST_SIZE_SMALL     512
#define TEST_SIZE_MEDIUM    2048
#define TEST_SIZE_LARGE     (5 * 1024 * 1024)  // 5MB

// Response printing limits
#define MAX_PRINT_CHUNK     500
#define MAX_BODY_PREVIEW    150

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * @brief Print large response buffer in chunks
 * 
 * Prints buffer content in chunks to avoid DbgPrint buffer overflow.
 * 
 * @param Buffer Response buffer to print
 * @param Length Total buffer length
 */
VOID PrintResponse(PCHAR Buffer, ULONG Length) 
{
    ULONG Offset = 0;
    while (Offset < Length) {
        ULONG Chunk = (Length - Offset) > MAX_PRINT_CHUNK ? MAX_PRINT_CHUNK : (Length - Offset);
        CHAR Temp = Buffer[Offset + Chunk];
        Buffer[Offset + Chunk] = 0;
        DbgPrint("%s", &Buffer[Offset]);
        Buffer[Offset + Chunk] = Temp;
        Offset += Chunk;
    }
    DbgPrint("\n");
}

/**
 * @brief Print test section header
 * 
 * @param SectionName Name of the test section
 */
VOID PrintTestHeader(PCHAR SectionName)
{
    DbgPrint("\n========================================\n");
    DbgPrint("  %s\n", SectionName);
    DbgPrint("========================================\n");
}

/**
 * @brief Print test result
 * 
 * @param TestName Name of the test
 * @param Status NTSTATUS result
 * @param AdditionalInfo Optional additional information
 */
VOID PrintTestResult(PCHAR TestName, NTSTATUS Status, PCHAR AdditionalInfo)
{
    if (NT_SUCCESS(Status)) {
        DbgPrint("[✓] %s - SUCCESS", TestName);
        if (AdditionalInfo) {
            DbgPrint(" (%s)", AdditionalInfo);
        }
        DbgPrint("\n");
    } else {
        DbgPrint("[✗] %s - FAILED (0x%08X)", TestName, Status);
        if (AdditionalInfo) {
            DbgPrint(" - %s", AdditionalInfo);
        }
        DbgPrint("\n");
    }
}

// =============================================================================
// CATEGORY 1: PROTOCOL TESTS (DNS, TLS, DTLS)
// =============================================================================

/**
 * @brief Test DNS resolution functionality
 * 
 * Tests DNS query to resolve ya.ru using Google DNS (8.8.8.8).
 * Verifies DNS cache functionality and response parsing.
 */
VOID TestDns(VOID) 
{
    NTSTATUS Status;
    ULONG Ip;

    DbgPrint("\n[DNS] Resolving ya.ru...\n");
    Status = KdnsResolve("ya.ru", TEST_DNS_SERVER, 3000, &Ip);
    
    if (NT_SUCCESS(Status)) {
        DbgPrint("[DNS] Resolved to: %u.%u.%u.%u\n",
            (Ip >> 0) & 0xFF, (Ip >> 8) & 0xFF,
            (Ip >> 16) & 0xFF, (Ip >> 24) & 0xFF);
        PrintTestResult("DNS Resolution", Status, NULL);
    } else {
        PrintTestResult("DNS Resolution", Status, "Failed to resolve hostname");
    }
}

/**
 * @brief Test TLS over TCP connection
 * 
 * Connects to local TLS test server, sends HTTP request, and receives response.
 * Tests TLS handshake, SNI, data encryption/decryption.
 */
VOID TestTls(VOID) 
{
    PKTLS_SESSION Session = NULL;
    PVOID Buffer = NULL;
    ULONG Bytes = 0;
    NTSTATUS Status;

    DbgPrint("\n[TLS] Connecting to %u.%u.%u.%u:%u...\n",
        (TEST_SERVER_IP >> 0) & 0xFF, (TEST_SERVER_IP >> 8) & 0xFF,
        (TEST_SERVER_IP >> 16) & 0xFF, (TEST_SERVER_IP >> 24) & 0xFF,
        TEST_TLS_PORT);
    
    Status = KtlsConnect(TEST_SERVER_IP, TEST_TLS_PORT, KTLS_PROTO_TCP, "192.168.56.1", &Session);
    if (!NT_SUCCESS(Status)) {
        PrintTestResult("TLS Connection", Status, "Failed to establish TLS connection");
        return;
    }
    DbgPrint("[TLS] Handshake completed\n");

    // Send HTTP GET request
    KtlsSetTimeout(Session, TEST_TIMEOUT_NORMAL);
    const char* Req = "GET / HTTP/1.1\r\nHost: 192.168.56.1\r\nConnection: close\r\n\r\n";
    Status = KtlsSend(Session, (PVOID)Req, (ULONG)strlen(Req), &Bytes);
    
    if (NT_SUCCESS(Status)) {
        DbgPrint("[TLS] Sent %u bytes\n", Bytes);
        
        // Receive response
        Buffer = ExAllocatePoolWithTag(NonPagedPool, 4096, 'TEST');
        if (Buffer) {
            Status = KtlsRecv(Session, Buffer, 4095, &Bytes);
            if (Status == STATUS_SUCCESS && Bytes > 0) {
                ((PCHAR)Buffer)[Bytes] = '\0';  // Null-terminate
                DbgPrint("[TLS] Received %u bytes:\n", Bytes);
                PrintResponse((PCHAR)Buffer, Bytes);
                PrintTestResult("TLS Communication", Status, NULL);
            } else {
                PrintTestResult("TLS Receive", Status, "No data received");
            }
            ExFreePoolWithTag(Buffer, 'TEST');
        }
    } else {
        PrintTestResult("TLS Send", Status, "Failed to send data");
    }
    
    KtlsClose(Session);
}

/**
 * @brief Test DTLS over UDP connection
 * 
 * Connects to local DTLS test server, sends message, and receives echo response.
 * Tests DTLS handshake, cookie exchange, and UDP reliability.
 */
VOID TestDtls(VOID) 
{
    PKTLS_SESSION Session = NULL;
    PVOID Buffer = NULL;
    ULONG Bytes = 0;
    NTSTATUS Status;

    DbgPrint("\n[DTLS] Connecting to %u.%u.%u.%u:%u...\n",
        (TEST_SERVER_IP >> 0) & 0xFF, (TEST_SERVER_IP >> 8) & 0xFF,
        (TEST_SERVER_IP >> 16) & 0xFF, (TEST_SERVER_IP >> 24) & 0xFF,
        TEST_TLS_PORT);
    
    Status = KtlsConnect(TEST_SERVER_IP, TEST_TLS_PORT, KTLS_PROTO_UDP, "192.168.56.1", &Session);
    if (!NT_SUCCESS(Status)) {
        PrintTestResult("DTLS Connection", Status, "Failed to establish DTLS connection");
        return;
    }
    DbgPrint("[DTLS] Handshake completed\n");

    // Send test message
    KtlsSetTimeout(Session, TEST_TIMEOUT_NORMAL);
    const char* Msg = "Hello DTLS";
    Status = KtlsSend(Session, (PVOID)Msg, (ULONG)strlen(Msg), &Bytes);
    
    if (NT_SUCCESS(Status)) {
        DbgPrint("[DTLS] Sent %u bytes\n", Bytes);
        
        // Receive echo response
        Buffer = ExAllocatePoolWithTag(NonPagedPool, 1024, 'TEST');
        if (Buffer) {
            Status = KtlsRecv(Session, Buffer, 1024, &Bytes);
            if (NT_SUCCESS(Status) && Bytes > 0) {
                ((PCHAR)Buffer)[Bytes] = '\0';
                DbgPrint("[DTLS] Received %u bytes:\n", Bytes);
                PrintResponse((PCHAR)Buffer, Bytes);
                PrintTestResult("DTLS Communication", Status, NULL);
            } else {
                PrintTestResult("DTLS Receive", Status, "No data received");
            }
            ExFreePoolWithTag(Buffer, 'TEST');
        }
    } else {
        PrintTestResult("DTLS Send", Status, "Failed to send data");
    }
    
    KtlsClose(Session);
}

// =============================================================================
// CATEGORY 2: HTTP TESTS (PLAIN TCP)
// =============================================================================

/**
 * @brief Test basic HTTP operations (GET, POST, HEAD)
 * 
 * Tests plain HTTP requests without encryption.
 * Uses httpbin.org for GET/POST and ya.ru for HEAD.
 */
VOID TestHttp(VOID) 
{
    PKHTTP_RESPONSE Response = NULL;
    NTSTATUS Status;
    CHAR Info[64];

    // TEST: HTTP GET
    DbgPrint("\n[HTTP GET] httpbin.org/get\n");
    Status = KhttpGet("http://httpbin.org/get", NULL, NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu, Body: %lu bytes", 
            Response->StatusCode, Response->BodyLength);
        PrintTestResult("HTTP GET", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("HTTP GET", Status, "Request failed");
    }

    // TEST: HTTP POST
    DbgPrint("\n[HTTP POST] httpbin.org/post\n");
    Status = KhttpPost(
        "http://httpbin.org/post",
        "Content-Type: application/json\r\n",
        "{\"test\":\"data\",\"kernel\":true}",
        NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu", Response->StatusCode);
        PrintTestResult("HTTP POST", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("HTTP POST", Status, "Request failed");
    }

    // TEST: HTTP HEAD
    DbgPrint("\n[HTTP HEAD] ya.ru\n");
    Status = KhttpHead("http://ya.ru/", NULL, NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu, Body: %lu bytes", 
            Response->StatusCode, Response->BodyLength);
        PrintTestResult("HTTP HEAD", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("HTTP HEAD", Status, "Request failed");
    }
}

// =============================================================================
// CATEGORY 3: HTTPS TESTS (TLS)
// =============================================================================

/**
 * @brief Test HTTPS operations (GET, POST, HEAD)
 * 
 * Tests HTTPS requests with TLS encryption.
 * Uses httpbin.org, jsonplaceholder.typicode.com, and ya.ru.
 */
VOID TestHttps(VOID) 
{
    PKHTTP_RESPONSE Response = NULL;
    NTSTATUS Status;
    CHAR Info[64];

    // TEST: HTTPS GET with JSON response
    DbgPrint("\n[HTTPS GET] httpbin.org/get\n");
    Status = KhttpGet(
        "https://httpbin.org/get",
        "Accept: application/json\r\n",
        NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu, Body: %lu bytes", 
            Response->StatusCode, Response->BodyLength);
        PrintTestResult("HTTPS GET", Status, Info);
        
        if (Response->Body && Response->BodyLength > 0) {
            ULONG PrintLen = min(Response->BodyLength, MAX_BODY_PREVIEW);
            DbgPrint("[Preview] %.*s...\n", PrintLen, Response->Body);
        }
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("HTTPS GET", Status, "Request failed");
    }

    // TEST: HTTPS POST
    DbgPrint("\n[HTTPS POST] httpbin.org/post\n");
    Status = KhttpPost(
        "https://httpbin.org/post",
        "Content-Type: application/json\r\n",
        "{\"secure\":true,\"kernel\":\"mode\",\"tls\":\"1.3\"}",
        NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu", Response->StatusCode);
        PrintTestResult("HTTPS POST", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("HTTPS POST", Status, "Request failed");
    }

    // TEST: HTTPS GET from REST API
    DbgPrint("\n[HTTPS GET] jsonplaceholder.typicode.com/posts/1\n");
    Status = KhttpGet("https://jsonplaceholder.typicode.com/posts/1", NULL, NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu", Response->StatusCode);
        PrintTestResult("HTTPS REST API", Status, Info);
        
        if (Response->Body && Response->BodyLength > 0) {
            ULONG PrintLen = min(Response->BodyLength, 100);
            DbgPrint("[Preview] %.*s...\n", PrintLen, Response->Body);
        }
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("HTTPS REST API", Status, "Request failed");
    }

    // TEST: HTTPS HEAD
    DbgPrint("\n[HTTPS HEAD] ya.ru\n");
    Status = KhttpHead("https://ya.ru/", NULL, NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu", Response->StatusCode);
        PrintTestResult("HTTPS HEAD", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("HTTPS HEAD", Status, "Request failed");
    }
}

// =============================================================================
// CATEGORY 4: REST API TESTS
// =============================================================================

/**
 * @brief Test RESTful API operations (GET, POST, PUT, PATCH, DELETE)
 * 
 * Tests all HTTP methods against JSONPlaceholder fake REST API.
 * Uses plain HTTP for faster execution.
 */
VOID TestRestApi(VOID) 
{
    PKHTTP_RESPONSE Response = NULL;
    NTSTATUS Status;
    CHAR Info[64];

    // GET
    DbgPrint("\n[REST] GET /posts/1\n");
    Status = KhttpGet("http://jsonplaceholder.typicode.com/posts/1", NULL, NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu", Response->StatusCode);
        PrintTestResult("REST GET", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("REST GET", Status, NULL);
    }

    // POST
    DbgPrint("\n[REST] POST /posts\n");
    Status = KhttpPost(
        "http://jsonplaceholder.typicode.com/posts",
        "Content-Type: application/json\r\n",
        "{\"title\":\"test\",\"body\":\"kernel mode\",\"userId\":1}",
        NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu", Response->StatusCode);
        PrintTestResult("REST POST", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("REST POST", Status, NULL);
    }

    // PUT
    DbgPrint("\n[REST] PUT /posts/1\n");
    Status = KhttpPut(
        "http://jsonplaceholder.typicode.com/posts/1",
        "Content-Type: application/json\r\n",
        "{\"id\":1,\"title\":\"updated\",\"body\":\"modified\",\"userId\":1}",
        NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu", Response->StatusCode);
        PrintTestResult("REST PUT", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("REST PUT", Status, NULL);
    }

    // PATCH
    DbgPrint("\n[REST] PATCH /posts/1\n");
    Status = KhttpPatch(
        "http://jsonplaceholder.typicode.com/posts/1",
        "Content-Type: application/json\r\n",
        "{\"title\":\"patched\"}",
        NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu", Response->StatusCode);
        PrintTestResult("REST PATCH", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("REST PATCH", Status, NULL);
    }

    // DELETE
    DbgPrint("\n[REST] DELETE /posts/1\n");
    Status = KhttpDelete("http://jsonplaceholder.typicode.com/posts/1", NULL, NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu", Response->StatusCode);
        PrintTestResult("REST DELETE", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("REST DELETE", Status, NULL);
    }
}

/**
 * @brief Test RESTful API operations over HTTPS
 * 
 * Same as TestRestApi but uses HTTPS for secure communication.
 */
VOID TestRestApiHttps(VOID) 
{
    PKHTTP_RESPONSE Response = NULL;
    NTSTATUS Status;
    CHAR Info[64];

    // GET
    DbgPrint("\n[REST-HTTPS] GET /posts/1\n");
    Status = KhttpGet("https://jsonplaceholder.typicode.com/posts/1", NULL, NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu", Response->StatusCode);
        PrintTestResult("REST-HTTPS GET", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("REST-HTTPS GET", Status, NULL);
    }

    // POST
    DbgPrint("\n[REST-HTTPS] POST /posts\n");
    Status = KhttpPost(
        "https://jsonplaceholder.typicode.com/posts",
        "Content-Type: application/json\r\n",
        "{\"title\":\"secure test\",\"body\":\"https kernel\",\"userId\":1}",
        NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu", Response->StatusCode);
        PrintTestResult("REST-HTTPS POST", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("REST-HTTPS POST", Status, NULL);
    }

    // PUT
    DbgPrint("\n[REST-HTTPS] PUT /posts/1\n");
    Status = KhttpPut(
        "https://jsonplaceholder.typicode.com/posts/1",
        "Content-Type: application/json\r\n",
        "{\"id\":1,\"title\":\"secure update\",\"body\":\"https content\",\"userId\":1}",
        NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu", Response->StatusCode);
        PrintTestResult("REST-HTTPS PUT", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("REST-HTTPS PUT", Status, NULL);
    }

    // DELETE
    DbgPrint("\n[REST-HTTPS] DELETE /posts/1\n");
    Status = KhttpDelete("https://jsonplaceholder.typicode.com/posts/1", NULL, NULL, &Response);
    if (NT_SUCCESS(Status) && Response) {
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu", Response->StatusCode);
        PrintTestResult("REST-HTTPS DELETE", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("REST-HTTPS DELETE", Status, NULL);
    }
}

// =============================================================================
// CATEGORY 5: FILE UPLOAD TESTS
// =============================================================================

/**
 * @brief Progress callback for file uploads
 * 
 * Called periodically during upload to report progress.
 */
VOID ProgressCallback(ULONG BytesSent, ULONG TotalBytes, PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    if (TotalBytes > 0) {
        ULONG Percent = (BytesSent * 100) / TotalBytes;
        DbgPrint("[PROGRESS] %lu%% (%lu/%lu bytes)\n", Percent, BytesSent, TotalBytes);
    }
}

/**
 * @brief Test single file upload
 * 
 * Uploads a small binary file (1KB) to httpbin.org.
 * Tests basic multipart/form-data functionality.
 */
VOID TestFileUpload(VOID)
{
    DbgPrint("\n[UPLOAD] Single file test (1KB)\n");

    PVOID FileData = ExAllocatePoolWithTag(NonPagedPool, 1024, 'tseT');
    if (!FileData) {
        PrintTestResult("Single File Upload", STATUS_INSUFFICIENT_RESOURCES, "Memory allocation failed");
        return;
    }

    RtlFillMemory(FileData, 1024, 0xAA);  // Pattern fill

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
        NULL, 0,
        &File, 1,
        NULL,
        &Response
    );

    if (NT_SUCCESS(Status) && Response) {
        CHAR Info[64];
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu, Response: %lu bytes", 
            Response->StatusCode, Response->BodyLength);
        PrintTestResult("Single File Upload", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("Single File Upload", Status, "Upload failed");
    }

    ExFreePoolWithTag(FileData, 'tseT');
}

/**
 * @brief Test file upload with form fields
 * 
 * Uploads a file (2KB) along with additional form fields.
 * Tests multipart/form-data with mixed content.
 */
VOID TestFileUploadWithForm(VOID)
{
    DbgPrint("\n[UPLOAD] File with form fields (2KB)\n");

    PVOID FileData = ExAllocatePoolWithTag(NonPagedPool, TEST_SIZE_MEDIUM, 'tseT');
    if (!FileData) {
        PrintTestResult("File+Form Upload", STATUS_INSUFFICIENT_RESOURCES, "Memory allocation failed");
        return;
    }

    RtlFillMemory(FileData, TEST_SIZE_MEDIUM, 0xBB);

    KHTTP_FILE File = {
        .FieldName = "image",
        .FileName = "photo.jpg",
        .ContentType = "image/jpeg",
        .Data = FileData,
        .DataLength = TEST_SIZE_MEDIUM
    };

    KHTTP_FORM_FIELD Fields[2] = {
        {.Name = "title", .Value = "My Photo" },
        {.Name = "description", .Value = "Uploaded from Windows kernel mode driver" }
    };

    PKHTTP_RESPONSE Response = NULL;
    NTSTATUS Status = KhttpPostMultipart(
        "https://example.com/upload",
        NULL,
        Fields, 2,
        &File, 1,
        NULL,
        &Response
    );

    if (NT_SUCCESS(Status) && Response) {
        CHAR Info[64];
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu", Response->StatusCode);
        PrintTestResult("File+Form Upload", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("File+Form Upload", Status, "Upload failed");
    }

    ExFreePoolWithTag(FileData, 'tseT');
}

/**
 * @brief Test multiple files upload with progress callback
 * 
 * Uploads two files simultaneously with progress reporting.
 * Tests multi-file multipart/form-data and progress callbacks.
 */
VOID TestMultipleFilesUpload(VOID)
{
    DbgPrint("\n[UPLOAD] Multiple files with progress (512B + 1KB)\n");

    PVOID File1Data = ExAllocatePoolWithTag(NonPagedPool, TEST_SIZE_SMALL, 'tseT');
    if (!File1Data) {
        PrintTestResult("Multiple Files Upload", STATUS_INSUFFICIENT_RESOURCES, "File1 allocation failed");
        return;
    }
    RtlFillMemory(File1Data, TEST_SIZE_SMALL, 0x11);

    PVOID File2Data = ExAllocatePoolWithTag(NonPagedPool, 1024, 'tseT');
    if (!File2Data) {
        ExFreePoolWithTag(File1Data, 'tseT');
        PrintTestResult("Multiple Files Upload", STATUS_INSUFFICIENT_RESOURCES, "File2 allocation failed");
        return;
    }
    RtlFillMemory(File2Data, 1024, 0x22);

    KHTTP_FILE Files[2] = {
        {
            .FieldName = "file1",
            .FileName = "document1.txt",
            .ContentType = "text/plain",
            .Data = File1Data,
            .DataLength = TEST_SIZE_SMALL
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
        NULL, 0,
        Files, 2,
        &Config,
        &Response
    );

    if (NT_SUCCESS(Status) && Response) {
        CHAR Info[64];
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu", Response->StatusCode);
        PrintTestResult("Multiple Files Upload", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("Multiple Files Upload", Status, "Upload failed");
    }

    ExFreePoolWithTag(File1Data, 'tseT');
    ExFreePoolWithTag(File2Data, 'tseT');
}

/**
 * @brief Test large file upload with chunked transfer encoding
 * 
 * Uploads a 5MB file using chunked transfer encoding.
 * Tests automatic chunking for large payloads.
 */
VOID TestLargeFileUploadChunked(VOID)
{
    DbgPrint("\n[UPLOAD] Large file chunked transfer (5MB)\n");

    PVOID FileData = ExAllocatePoolWithTag(NonPagedPool, TEST_SIZE_LARGE, 'tseT');
    if (!FileData) {
        PrintTestResult("Large File Upload", STATUS_INSUFFICIENT_RESOURCES, "Failed to allocate 5MB");
        return;
    }

    // Fill with sequential pattern for verification
    for (ULONG i = 0; i < TEST_SIZE_LARGE / 4; i++) {
        ((ULONG*)FileData)[i] = i;
    }

    KHTTP_FILE File = {
        .FieldName = "largefile",
        .FileName = "large5mb.bin",
        .ContentType = "application/octet-stream",
        .Data = FileData,
        .DataLength = TEST_SIZE_LARGE
    };

    KHTTP_CONFIG Config = {
        .UseHttps = FALSE,  // Use HTTP for faster upload to local server
        .TimeoutMs = TEST_TIMEOUT_LONG,
        .MaxResponseSize = 5 * 1024 * 1024,
        .DnsServerIp = 0,
        .UserAgent = "KernelHTTP/1.0",
        .UseChunkedTransfer = TRUE,
        .ChunkSize = 64 * 1024,  // 64KB chunks
        .ProgressCallback = NULL,
        .CallbackContext = NULL
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
        CHAR Info[64];
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu, Size: %lu bytes", 
            Response->StatusCode, TEST_SIZE_LARGE);
        PrintTestResult("Large File Upload", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("Large File Upload", Status, "Upload failed");
    }

    ExFreePoolWithTag(FileData, 'tseT');
}

/**
 * @brief Test streaming file upload from disk
 * 
 * Streams a file from disk without loading it entirely into memory.
 * Tests chunked upload with disk I/O.
 */
VOID TestFileStreamUpload(VOID)
{
    DbgPrint("\n[UPLOAD] Streaming file from disk\n");

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
        .TimeoutMs = TEST_TIMEOUT_VLONG,
        .UseChunkedTransfer = TRUE,
        .ChunkSize = 256 * 1024,  // 256KB chunks
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
        CHAR Info[64];
        RtlStringCbPrintfA(Info, sizeof(Info), "Status: %lu", Response->StatusCode);
        PrintTestResult("Streaming Upload", Status, Info);
        KhttpFreeResponse(Response);
    } else {
        PrintTestResult("Streaming Upload", Status, "Upload failed or file not found");
    }
}

// =============================================================================
// DRIVER ENTRY AND TEST ORCHESTRATION
// =============================================================================

/**
 * @brief Driver unload routine
 * 
 * Cleans up all library resources before driver unload.
 */
VOID DriverUnload(PDRIVER_OBJECT DriverObject) 
{
    UNREFERENCED_PARAMETER(DriverObject);
    
    DbgPrint("\n========================================\n");
    DbgPrint("  Unloading Driver\n");
    DbgPrint("========================================\n");
    
    KhttpGlobalCleanup();
    DbgPrint("[✓] Driver unloaded successfully\n");
}

/**
 * @brief Driver entry point - runs all test suites
 * 
 * Initializes the library and executes all test categories in sequence:
 * 1. Protocol tests (DNS, TLS, DTLS)
 * 2. HTTP tests (GET, POST, HEAD)
 * 3. HTTPS tests
 * 4. REST API tests (HTTP & HTTPS)
 * 5. File upload tests (various scenarios)
 * 
 * @param DriverObject Pointer to driver object
 * @param RegistryPath Registry path for driver parameters
 * @return STATUS_SUCCESS on successful initialization
 */
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) 
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("\n========================================\n");
    DbgPrint("  Windows Kernel HTTP Library\n");
    DbgPrint("  Comprehensive Test Suite\n");
    DbgPrint("========================================\n");

    // Initialize library
    NTSTATUS Status = KhttpGlobalInit();
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[✗] Library initialization failed: 0x%08X\n", Status);
        return Status;
    }
    DbgPrint("[✓] Library initialized\n");

    // Category 1: Protocol Tests
    PrintTestHeader("PROTOCOL TESTS");
    TestDns();
    TestTls();
    TestDtls();

    // Category 2: HTTP Tests
    PrintTestHeader("HTTP TESTS (Plain TCP)");
    TestHttp();
    TestRestApi();

    // Category 3: HTTPS Tests
    PrintTestHeader("HTTPS TESTS (TLS)");
    TestHttps();
    TestRestApiHttps();

    // Category 4: File Upload Tests
    PrintTestHeader("FILE UPLOAD TESTS");
    
    TestFileUpload();
    KhttpSleep(TEST_DELAY_SHORT);
    
    TestFileUploadWithForm();
    KhttpSleep(TEST_DELAY_SHORT);
    
    TestMultipleFilesUpload();
    KhttpSleep(TEST_DELAY_SHORT);
    
    TestLargeFileUploadChunked();
    KhttpSleep(TEST_DELAY_SHORT);
    
    TestFileStreamUpload();

    // Test summary
    DbgPrint("\n========================================\n");
    DbgPrint("  All Tests Completed\n");
    DbgPrint("========================================\n");

    return STATUS_SUCCESS;
}

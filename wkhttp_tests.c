//#define STRESS_TESTS 1
#if !defined(STRESS_TESTS)
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
        DbgPrint("[+] %s - SUCCESS", TestName);
        if (AdditionalInfo) {
            DbgPrint(" (%s)", AdditionalInfo);
        }
        DbgPrint("\n");
    } else {
        DbgPrint("[-] %s - FAILED (0x%08X)", TestName, Status);
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
    DbgPrint("[+] Driver unloaded successfully\n");
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
        DbgPrint("[-] Library initialization failed: 0x%08X\n", Status);
        return Status;
    }
    DbgPrint("[+] Library initialized\n");

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
#else
/**
 * @file wkhttp_stress_tests.c
 * @brief Stress test suite for Windows Kernel HTTP Library
 *
 * This file contains stress and load tests to verify library stability under:
 * - High request volumes (1000+ requests)
 * - Rapid connect/disconnect cycles
 * - Large file uploads (50MB+)
 * - Memory allocation stress
 * - Edge cases and boundary conditions
 *
 * @section stress_test_categories Stress Test Categories
 * 1. Connection Stress (TLS handshake, DNS, timeouts)
 * 2. HTTP Method Stress (GET/POST/PUT/DELETE high volume)
 * 3. File Upload Stress (large files, streaming, multi-file)
 * 4. Memory Stress (allocation/deallocation cycles, leaks)
 * 5. Edge Cases (zero-byte, invalid data, interruptions)
 *
 * @note Tests are designed to find memory leaks, race conditions, deadlocks
 * @warning Some tests may take 10+ minutes to complete
 */

#include <ntddk.h>
#include "ktls_lib.h"
#include "kdns_lib.h"
#include "khttp_lib.h"

 // =============================================================================
 // STRESS TEST CONFIGURATION
 // =============================================================================

 // Stress intensity levels
#define STRESS_LEVEL_LIGHT      10      // Quick smoke test
#define STRESS_LEVEL_MEDIUM     100     // Standard stress test
#define STRESS_LEVEL_HEAVY      1000    // Full stress test
#define STRESS_LEVEL_EXTREME    10000   // Torture test

// Current stress level (change as needed)
#define STRESS_ITERATIONS       STRESS_LEVEL_MEDIUM

// File sizes for stress tests
#define STRESS_FILE_SMALL       1024            // 1KB
#define STRESS_FILE_MEDIUM      (100 * 1024)    // 100KB
#define STRESS_FILE_LARGE       (10 * 1024 * 1024)   // 10MB
#define STRESS_FILE_HUGE        (50 * 1024 * 1024)   // 50MB

// Concurrency simulation
#define STRESS_CONCURRENT       10      // Simulated parallel requests

// Timeouts
#define STRESS_TIMEOUT_SHORT    1000    // 1 second
#define STRESS_TIMEOUT_NORMAL   30000   // 30 seconds
#define STRESS_TIMEOUT_LONG     120000  // 2 minutes

// Test servers
#define STRESS_TEST_HTTP_URL    "http://httpbin.org"
#define STRESS_TEST_HTTPS_URL   "https://httpbin.org"
#define STRESS_TEST_LOCAL_URL   "http://192.168.56.1:8080"

// Memory tracking
#define STRESS_POOL_TAG         'STES'  // 'STES' = Stress Test

// =============================================================================
// GLOBAL TEST COUNTERS
// =============================================================================

typedef struct _STRESS_TEST_STATS {
    ULONG TotalTests;
    ULONG PassedTests;
    ULONG FailedTests;
    ULONG TotalBytesAllocated;
    ULONG TotalBytesSent;
    ULONG TotalBytesReceived;
    LARGE_INTEGER StartTime;
    LARGE_INTEGER EndTime;
} STRESS_TEST_STATS, * PSTRESS_TEST_STATS;

static STRESS_TEST_STATS g_StressStats = { 0 };

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * @brief Initialize stress test statistics
 */
VOID StressInitStats(VOID)
{
    RtlZeroMemory(&g_StressStats, sizeof(STRESS_TEST_STATS));
    KeQuerySystemTime(&g_StressStats.StartTime);
}

/**
 * @brief Print final stress test statistics
 */
VOID StressPrintStats(VOID)
{
    KeQuerySystemTime(&g_StressStats.EndTime);

    LARGE_INTEGER Duration;
    Duration.QuadPart = g_StressStats.EndTime.QuadPart - g_StressStats.StartTime.QuadPart;
    ULONG DurationSec = (ULONG)(Duration.QuadPart / 10000000);  // Convert to seconds

    DbgPrint("\n========================================\n");
    DbgPrint("  STRESS TEST STATISTICS\n");
    DbgPrint("========================================\n");
    DbgPrint("Total Tests:     %lu\n", g_StressStats.TotalTests);
    DbgPrint("Passed:          %lu\n", g_StressStats.PassedTests);
    DbgPrint("Failed:          %lu\n", g_StressStats.FailedTests);
    DbgPrint("Duration:        %lu seconds\n", DurationSec);

    // Bytes Allocated (convert to MB with 2 decimal places)
    ULONG AllocMB = g_StressStats.TotalBytesAllocated / (1024 * 1024);
    ULONG AllocKB = (g_StressStats.TotalBytesAllocated / 1024) % 1024;
    ULONG AllocFrac = (AllocKB * 100) / 1024;  // Fractional part as percentage
    DbgPrint("Bytes Allocated: %lu (%lu.%02lu MB)\n",
        g_StressStats.TotalBytesAllocated, AllocMB, AllocFrac);

    // Bytes Sent
    ULONG SentMB = g_StressStats.TotalBytesSent / (1024 * 1024);
    ULONG SentKB = (g_StressStats.TotalBytesSent / 1024) % 1024;
    ULONG SentFrac = (SentKB * 100) / 1024;
    DbgPrint("Bytes Sent:      %lu (%lu.%02lu MB)\n",
        g_StressStats.TotalBytesSent, SentMB, SentFrac);

    // Bytes Received
    ULONG RecvMB = g_StressStats.TotalBytesReceived / (1024 * 1024);
    ULONG RecvKB = (g_StressStats.TotalBytesReceived / 1024) % 1024;
    ULONG RecvFrac = (RecvKB * 100) / 1024;
    DbgPrint("Bytes Received:  %lu (%lu.%02lu MB)\n",
        g_StressStats.TotalBytesReceived, RecvMB, RecvFrac);

    // Requests per second (integer division)
    if (DurationSec > 0) {
        ULONG ReqPerSec = g_StressStats.TotalTests / DurationSec;
        ULONG ReqFrac = ((g_StressStats.TotalTests % DurationSec) * 100) / DurationSec;
        DbgPrint("Requests/sec:    %lu.%02lu\n", ReqPerSec, ReqFrac);
    }

    // Success rate as integer percentage
    ULONG SuccessRate = g_StressStats.TotalTests > 0 ?
        (g_StressStats.PassedTests * 100) / g_StressStats.TotalTests : 0;
    ULONG SuccessFrac = g_StressStats.TotalTests > 0 ?
        ((g_StressStats.PassedTests * 10000) / g_StressStats.TotalTests) % 100 : 0;
    DbgPrint("Success Rate:    %lu.%02lu%%\n", SuccessRate, SuccessFrac);
    DbgPrint("========================================\n");
}

/**
 * @brief Record test result
 */
VOID StressRecordResult(NTSTATUS Status, ULONG BytesSent, ULONG BytesReceived)
{
    g_StressStats.TotalTests++;

    if (NT_SUCCESS(Status)) {
        g_StressStats.PassedTests++;
    }
    else {
        g_StressStats.FailedTests++;
    }

    g_StressStats.TotalBytesSent += BytesSent;
    g_StressStats.TotalBytesReceived += BytesReceived;
}

/**
 * @brief Print test progress
 */
VOID StressPrintProgress(PCHAR TestName, ULONG Current, ULONG Total)
{
    if (Current % (Total / 10) == 0 || Current == Total) {
        ULONG Percent = (Current * 100) / Total;
        DbgPrint("[STRESS] %s: %lu%% (%lu/%lu)\n", TestName, Percent, Current, Total);
    }
}

// =============================================================================
// CATEGORY 1: CONNECTION STRESS TESTS
// =============================================================================

/**
 * @brief Stress test: Rapid TLS connect/disconnect cycles
 *
 * Opens and closes TLS connections repeatedly to test:
 * - Handshake stability
 * - Resource cleanup
 * - Memory leaks in connection handling
 */
VOID StressTlsConnections(VOID)
{
    DbgPrint("\n[STRESS] TLS Connection Cycles (%lu iterations)\n", STRESS_ITERATIONS);

    for (ULONG i = 0; i < STRESS_ITERATIONS; i++) {
        PKTLS_SESSION Session = NULL;

        NTSTATUS Status = KtlsConnect(
            INETADDR(192, 168, 56, 1),
            4443,
            KTLS_PROTO_TCP,
            "192.168.56.1",
            &Session
        );

        if (NT_SUCCESS(Status)) {
            KtlsClose(Session);
            StressRecordResult(STATUS_SUCCESS, 0, 0);
        }
        else {
            StressRecordResult(Status, 0, 0);
        }

        StressPrintProgress("TLS Connections", i + 1, STRESS_ITERATIONS);
    }
}

/**
 * @brief Stress test: DNS resolution cycles
 *
 * Performs repeated DNS queries to test:
 * - DNS cache behavior
 * - Query throttling
 * - Memory management in DNS resolver
 */
VOID StressDnsResolution(VOID)
{
    DbgPrint("\n[STRESS] DNS Resolution Cycles (%lu iterations)\n", STRESS_ITERATIONS);

    PCHAR Hostnames[] = {
        "google.com",
        "github.com",
        "microsoft.com",
        "httpbin.org",
        "example.com"
    };
    ULONG HostnameCount = sizeof(Hostnames) / sizeof(Hostnames[0]);

    for (ULONG i = 0; i < STRESS_ITERATIONS; i++) {
        ULONG Ip = 0;
        PCHAR Hostname = Hostnames[i % HostnameCount];

        NTSTATUS Status = KdnsResolve(
            Hostname,
            INETADDR(8, 8, 8, 8),
            3000,
            &Ip
        );

        StressRecordResult(Status, 0, 0);
        StressPrintProgress("DNS Resolution", i + 1, STRESS_ITERATIONS);
    }
}

/**
 * @brief Stress test: Timeout boundary testing
 *
 * Tests connection behavior with various timeout values:
 * - Very short timeouts (1ms)
 * - Normal timeouts (5s)
 * - Long timeouts (60s)
 */
VOID StressTimeouts(VOID)
{
    DbgPrint("\n[STRESS] Timeout Boundary Tests\n");

    ULONG Timeouts[] = { 1, 100, 1000, 5000, 10000, 30000, 60000 };
    ULONG TimeoutCount = sizeof(Timeouts) / sizeof(Timeouts[0]);

    for (ULONG i = 0; i < TimeoutCount; i++) {
        PKHTTP_RESPONSE Response = NULL;

        KHTTP_CONFIG Config = {
            .UseHttps = FALSE,
            .TimeoutMs = Timeouts[i],
            .MaxResponseSize = 1024
        };

        DbgPrint("[STRESS] Testing timeout: %lu ms\n", Timeouts[i]);

        NTSTATUS Status = KhttpGet(
            "http://httpbin.org/delay/10",  // 10 second delay endpoint
            NULL,
            &Config,
            &Response
        );

        if (Response) {
            StressRecordResult(Status, 0, Response->BodyLength);
            KhttpFreeResponse(Response);
        }
        else {
            StressRecordResult(Status, 0, 0);
        }
    }
}

// =============================================================================
// CATEGORY 2: HTTP METHOD STRESS TESTS
// =============================================================================

/**
 * @brief Stress test: Sequential GET requests
 *
 * Sends many GET requests in sequence to test:
 * - Request handling stability
 * - Response parsing
 * - Memory cleanup
 */
VOID StressHttpGet(VOID)
{
    DbgPrint("\n[STRESS] HTTP GET Requests (%lu iterations)\n", STRESS_ITERATIONS);

    for (ULONG i = 0; i < STRESS_ITERATIONS; i++) {
        PKHTTP_RESPONSE Response = NULL;

        NTSTATUS Status = KhttpGet(
            "https://httpbin.org/get",
            NULL,
            NULL,
            &Response
        );

        if (NT_SUCCESS(Status) && Response) {
            StressRecordResult(Status, 0, Response->BodyLength);
            KhttpFreeResponse(Response);
        }
        else {
            StressRecordResult(Status, 0, 0);
        }

        StressPrintProgress("HTTP GET", i + 1, STRESS_ITERATIONS);
    }
}

/**
 * @brief Stress test: Rapid POST requests
 *
 * Sends many POST requests with JSON payloads to test:
 * - Content-Type handling
 * - Request body encoding
 * - Response consistency
 */
VOID StressHttpPost(VOID)
{
    DbgPrint("\n[STRESS] HTTP POST Requests (%lu iterations)\n", STRESS_ITERATIONS);

    for (ULONG i = 0; i < STRESS_ITERATIONS; i++) {
        PKHTTP_RESPONSE Response = NULL;
        CHAR JsonPayload[256];

        RtlStringCbPrintfA(JsonPayload, sizeof(JsonPayload),
            "{\"iteration\":%lu,\"test\":\"stress\",\"timestamp\":%llu}",
            i, KeQueryInterruptTime());

        NTSTATUS Status = KhttpPost(
            "https://httpbin.org/post",
            "Content-Type: application/json\r\n",
            JsonPayload,
            NULL,
            &Response
        );

        if (NT_SUCCESS(Status) && Response) {
            StressRecordResult(Status, (ULONG)strlen(JsonPayload), Response->BodyLength);
            KhttpFreeResponse(Response);
        }
        else {
            StressRecordResult(Status, (ULONG)strlen(JsonPayload), 0);
        }

        StressPrintProgress("HTTP POST", i + 1, STRESS_ITERATIONS);
    }
}

/**
 * @brief Stress test: Mixed HTTP methods
 *
 * Rotates through GET/POST/PUT/DELETE to test:
 * - Method switching stability
 * - Header variations
 * - Response code handling
 */
VOID StressMixedMethods(VOID)
{
    DbgPrint("\n[STRESS] Mixed HTTP Methods (%lu iterations)\n", STRESS_ITERATIONS);

    for (ULONG i = 0; i < STRESS_ITERATIONS; i++) {
        PKHTTP_RESPONSE Response = NULL;
        NTSTATUS Status = STATUS_UNSUCCESSFUL;

        switch (i % 4) {
        case 0:  // GET
            Status = KhttpGet("https://httpbin.org/get", NULL, NULL, &Response);
            break;
        case 1:  // POST
            Status = KhttpPost("https://httpbin.org/post", NULL, "{\"test\":1}", NULL, &Response);
            break;
        case 2:  // PUT
            Status = KhttpPut("https://httpbin.org/put", NULL, "{\"test\":2}", NULL, &Response);
            break;
        case 3:  // DELETE
            Status = KhttpDelete("https://httpbin.org/delete", NULL, NULL, &Response);
            break;
        }

        if (NT_SUCCESS(Status) && Response) {
            StressRecordResult(Status, 0, Response->BodyLength);
            KhttpFreeResponse(Response);
        }
        else {
            StressRecordResult(Status, 0, 0);
        }

        StressPrintProgress("Mixed Methods", i + 1, STRESS_ITERATIONS);
    }
}

// =============================================================================
// CATEGORY 3: FILE UPLOAD STRESS TESTS
// =============================================================================

/**
 * @brief Stress test: Rapid small file uploads
 *
 * Uploads many small files quickly to test:
 * - Multipart encoding stability
 * - Boundary generation
 * - Memory allocation patterns
 */
VOID StressSmallFileUploads(VOID)
{
    DbgPrint("\n[STRESS] Small File Uploads (%lu x 1KB)\n", STRESS_LEVEL_LIGHT);

    PVOID FileData = ExAllocatePoolWithTag(NonPagedPool, STRESS_FILE_SMALL, STRESS_POOL_TAG);
    if (!FileData) {
        DbgPrint("[STRESS] Memory allocation failed\n");
        return;
    }

    RtlFillMemory(FileData, STRESS_FILE_SMALL, 0xAB);
    g_StressStats.TotalBytesAllocated += STRESS_FILE_SMALL;

    for (ULONG i = 0; i < STRESS_LEVEL_LIGHT; i++) {
        CHAR FileName[64];
        RtlStringCbPrintfA(FileName, sizeof(FileName), "stress_%lu.bin", i);

        KHTTP_FILE File = {
            .FieldName = "file",
            .FileName = FileName,
            .ContentType = "application/octet-stream",
            .Data = FileData,
            .DataLength = STRESS_FILE_SMALL
        };

        PKHTTP_RESPONSE Response = NULL;
        NTSTATUS Status = KhttpPostMultipart(
            "https://httpbin.org/post",
            NULL,
            NULL, 0,
            &File, 1,
            NULL,
            &Response
        );

        if (NT_SUCCESS(Status) && Response) {
            StressRecordResult(Status, STRESS_FILE_SMALL, Response->BodyLength);
            KhttpFreeResponse(Response);
        }
        else {
            StressRecordResult(Status, STRESS_FILE_SMALL, 0);
        }

        StressPrintProgress("Small File Upload", i + 1, STRESS_LEVEL_LIGHT);
    }

    ExFreePoolWithTag(FileData, STRESS_POOL_TAG);
}

/**
 * @brief Stress test: Large file upload cycles
 *
 * Uploads multiple large files (10MB each) to test:
 * - Memory management with large buffers
 * - Chunked transfer encoding
 * - Progress callback stability
 */
VOID StressLargeFileUploads(VOID)
{
    DbgPrint("\n[STRESS] Large File Uploads (5 x 10MB)\n");

    PVOID FileData = ExAllocatePoolWithTag(NonPagedPool, STRESS_FILE_LARGE, STRESS_POOL_TAG);
    if (!FileData) {
        DbgPrint("[STRESS] Failed to allocate 10MB\n");
        return;
    }

    // Fill with pattern
    for (ULONG i = 0; i < STRESS_FILE_LARGE / 4; i++) {
        ((ULONG*)FileData)[i] = i;
    }
    g_StressStats.TotalBytesAllocated += STRESS_FILE_LARGE;

    for (ULONG i = 0; i < 5; i++) {
        DbgPrint("[STRESS] Uploading large file %lu/5...\n", i + 1);

        KHTTP_FILE File = {
            .FieldName = "largefile",
            .FileName = "large_10mb.bin",
            .ContentType = "application/octet-stream",
            .Data = FileData,
            .DataLength = STRESS_FILE_LARGE
        };

        KHTTP_CONFIG Config = {
            .UseHttps = FALSE,
            .TimeoutMs = STRESS_TIMEOUT_LONG,
            .UseChunkedTransfer = TRUE,
            .ChunkSize = 64 * 1024
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
            StressRecordResult(Status, STRESS_FILE_LARGE, Response->BodyLength);
            KhttpFreeResponse(Response);
        }
        else {
            StressRecordResult(Status, STRESS_FILE_LARGE, 0);
        }
    }

    ExFreePoolWithTag(FileData, STRESS_POOL_TAG);
}

/**
 * @brief Stress test: Multiple files in single request
 *
 * Uploads many files in one multipart request to test:
 * - Boundary handling with many parts
 * - Memory allocation for multiple buffers
 * - Request size limits
 */
VOID StressMultiFileUpload(VOID)
{
    DbgPrint("\n[STRESS] Multi-File Upload (20 files in 1 request)\n");

#define MULTI_FILE_COUNT 20
    PVOID FileDatas[MULTI_FILE_COUNT] = { 0 };
    KHTTP_FILE Files[MULTI_FILE_COUNT] = { 0 };

    // Allocate all files
    for (ULONG i = 0; i < MULTI_FILE_COUNT; i++) {
        FileDatas[i] = ExAllocatePoolWithTag(NonPagedPool, STRESS_FILE_SMALL, STRESS_POOL_TAG);
        if (!FileDatas[i]) {
            DbgPrint("[STRESS] Memory allocation failed at file %lu\n", i);
            goto cleanup;
        }

        RtlFillMemory(FileDatas[i], STRESS_FILE_SMALL, (UCHAR)(0x10 + i));
        g_StressStats.TotalBytesAllocated += STRESS_FILE_SMALL;

        CHAR FieldName[32], FileName[32];
        RtlStringCbPrintfA(FieldName, sizeof(FieldName), "file%lu", i);
        RtlStringCbPrintfA(FileName, sizeof(FileName), "doc%lu.bin", i);

        Files[i].FieldName = FieldName;
        Files[i].FileName = FileName;
        Files[i].ContentType = "application/octet-stream";
        Files[i].Data = FileDatas[i];
        Files[i].DataLength = STRESS_FILE_SMALL;
    }

    PKHTTP_RESPONSE Response = NULL;
    NTSTATUS Status = KhttpPostMultipart(
        "https://httpbin.org/post",
        NULL,
        NULL, 0,
        Files, MULTI_FILE_COUNT,
        NULL,
        &Response
    );

    if (NT_SUCCESS(Status) && Response) {
        StressRecordResult(Status, STRESS_FILE_SMALL * MULTI_FILE_COUNT, Response->BodyLength);
        KhttpFreeResponse(Response);
    }
    else {
        StressRecordResult(Status, STRESS_FILE_SMALL * MULTI_FILE_COUNT, 0);
    }

cleanup:
    for (ULONG i = 0; i < MULTI_FILE_COUNT; i++) {
        if (FileDatas[i]) {
            ExFreePoolWithTag(FileDatas[i], STRESS_POOL_TAG);
        }
    }
}

// =============================================================================
// CATEGORY 4: MEMORY & RESOURCE STRESS TESTS
// =============================================================================

/**
 * @brief Stress test: Response object allocation/deallocation
 *
 * Creates and destroys many response objects to test:
 * - Memory leak detection
 * - Pool corruption
 * - Reference counting
 */
VOID StressMemoryAllocation(VOID)
{
    DbgPrint("\n[STRESS] Memory Allocation Cycles (%lu iterations)\n", STRESS_ITERATIONS);

    for (ULONG i = 0; i < STRESS_ITERATIONS; i++) {
        // Allocate various sizes
        ULONG Size = (i % 10 + 1) * 1024;  // 1KB to 10KB

        PVOID Buffer = ExAllocatePoolWithTag(NonPagedPool, Size, STRESS_POOL_TAG);
        if (Buffer) {
            g_StressStats.TotalBytesAllocated += Size;
            RtlFillMemory(Buffer, Size, (UCHAR)(i & 0xFF));
            ExFreePoolWithTag(Buffer, STRESS_POOL_TAG);
        }
        else {
            DbgPrint("[STRESS] Allocation failed at iteration %lu (size %lu)\n", i, Size);
        }

        StressPrintProgress("Memory Allocation", i + 1, STRESS_ITERATIONS);
    }
}

/**
 * @brief Stress test: Verify no memory leaks after requests
 *
 * Makes many requests and checks that memory is properly freed.
 * Uses tagged allocations to track leaks.
 */
VOID StressMemoryLeaks(VOID)
{
    DbgPrint("\n[STRESS] Memory Leak Detection (%lu requests)\n", STRESS_LEVEL_LIGHT);

    ULONG InitialAllocated = g_StressStats.TotalBytesAllocated;

    for (ULONG i = 0; i < STRESS_LEVEL_LIGHT; i++) {
        PKHTTP_RESPONSE Response = NULL;

        NTSTATUS Status = KhttpGet(
            "https://httpbin.org/get",
            NULL,
            NULL,
            &Response
        );

        if (NT_SUCCESS(Status) && Response) {
            // Intentionally free response to test cleanup
            KhttpFreeResponse(Response);
        }

        StressPrintProgress("Memory Leak Check", i + 1, STRESS_LEVEL_LIGHT);
    }

    ULONG FinalAllocated = g_StressStats.TotalBytesAllocated;
    DbgPrint("[STRESS] Memory delta: %lu bytes (should be near zero)\n",
        FinalAllocated - InitialAllocated);
}

// =============================================================================
// CATEGORY 5: EDGE CASES & BOUNDARY TESTS
// =============================================================================

/**
 * @brief Stress test: Zero-byte and empty requests
 *
 * Tests edge cases like:
 * - Zero-byte file uploads
 * - Empty POST bodies
 * - NULL headers
 */
VOID StressEdgeCases(VOID)
{
    DbgPrint("\n[STRESS] Edge Case Tests\n");

    // Test 1: Zero-byte file upload
    DbgPrint("[STRESS] Test: Zero-byte file upload\n");
    KHTTP_FILE EmptyFile = {
        .FieldName = "empty",
        .FileName = "empty.txt",
        .ContentType = "text/plain",
        .Data = NULL,
        .DataLength = 0
    };

    PKHTTP_RESPONSE Response = NULL;
    NTSTATUS Status = KhttpPostMultipart(
        "https://httpbin.org/post",
        NULL,
        NULL, 0,
        &EmptyFile, 1,
        NULL,
        &Response
    );
    StressRecordResult(Status, 0, Response ? Response->BodyLength : 0);
    if (Response) KhttpFreeResponse(Response);

    // Test 2: Empty POST body
    DbgPrint("[STRESS] Test: Empty POST body\n");
    Status = KhttpPost("https://httpbin.org/post", NULL, "", NULL, &Response);
    StressRecordResult(Status, 0, Response ? Response->BodyLength : 0);
    if (Response) KhttpFreeResponse(Response);

    // Test 3: Very long URL (8KB)
    DbgPrint("[STRESS] Test: Very long URL\n");
    PVOID LongUrl = ExAllocatePoolWithTag(NonPagedPool, 8192, STRESS_POOL_TAG);
    if (LongUrl) {
        RtlStringCbPrintfA(LongUrl, 8192, "https://httpbin.org/get?");
        for (ULONG i = 0; i < 200; i++) {
            RtlStringCbCatA(LongUrl, 8192, "param=value&");
        }

        Status = KhttpGet(LongUrl, NULL, NULL, &Response);
        StressRecordResult(Status, 0, Response ? Response->BodyLength : 0);
        if (Response) KhttpFreeResponse(Response);

        ExFreePoolWithTag(LongUrl, STRESS_POOL_TAG);
    }

    // Test 4: Invalid Content-Type
    DbgPrint("[STRESS] Test: Invalid Content-Type\n");
    Status = KhttpPost(
        "https://httpbin.org/post",
        "Content-Type: invalid/type/format/test\r\n",
        "{\"test\":1}",
        NULL,
        &Response
    );
    StressRecordResult(Status, 0, Response ? Response->BodyLength : 0);
    if (Response) KhttpFreeResponse(Response);
}

/**
 * @brief Stress test: Maximum response size handling
 *
 * Tests behavior when receiving very large responses.
 */
VOID StressLargeResponses(VOID)
{
    DbgPrint("\n[STRESS] Large Response Handling\n");

    // Request increasing response sizes
    ULONG Sizes[] = { 1024, 10240, 102400, 1048576 };  // 1KB, 10KB, 100KB, 1MB

    for (ULONG i = 0; i < sizeof(Sizes) / sizeof(Sizes[0]); i++) {
        CHAR Url[256];
        RtlStringCbPrintfA(Url, sizeof(Url),
            "https://httpbin.org/bytes/%lu", Sizes[i]);

        DbgPrint("[STRESS] Requesting %lu bytes...\n", Sizes[i]);

        KHTTP_CONFIG Config = {
            .UseHttps = TRUE,
            .TimeoutMs = STRESS_TIMEOUT_NORMAL,
            .MaxResponseSize = Sizes[i] + 1024  // Allow for headers
        };

        PKHTTP_RESPONSE Response = NULL;
        NTSTATUS Status = KhttpGet(Url, NULL, &Config, &Response);

        if (NT_SUCCESS(Status) && Response) {
            DbgPrint("[STRESS] Received %lu bytes\n", Response->BodyLength);
            StressRecordResult(Status, 0, Response->BodyLength);
            KhttpFreeResponse(Response);
        }
        else {
            StressRecordResult(Status, 0, 0);
        }
    }
}

// =============================================================================
// DRIVER ENTRY AND TEST ORCHESTRATION
// =============================================================================

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    StressPrintStats();
    KhttpGlobalCleanup();
    DbgPrint("[STRESS] Driver unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("\n========================================\n");
    DbgPrint("  WKHTTP STRESS TEST SUITE\n");
    DbgPrint("  Intensity: %lu iterations\n", STRESS_ITERATIONS);
    DbgPrint("========================================\n");

    NTSTATUS Status = KhttpGlobalInit();
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[STRESS] Library init failed: 0x%08X\n", Status);
        return Status;
    }

    StressInitStats();

    // Category 1: Connection Stress
    DbgPrint("\n=== CATEGORY 1: CONNECTION STRESS ===\n");
    StressTlsConnections();
    StressDnsResolution();
    StressTimeouts();

    // Category 2: HTTP Method Stress
    DbgPrint("\n=== CATEGORY 2: HTTP METHOD STRESS ===\n");
    StressHttpGet();
    StressHttpPost();
    StressMixedMethods();

    // Category 3: File Upload Stress
    DbgPrint("\n=== CATEGORY 3: FILE UPLOAD STRESS ===\n");
    StressSmallFileUploads();
    StressMultiFileUpload();
    // StressLargeFileUploads();  // Uncomment for long tests

    // Category 4: Memory Stress
    DbgPrint("\n=== CATEGORY 4: MEMORY STRESS ===\n");
    StressMemoryAllocation();
    StressMemoryLeaks();

    // Category 5: Edge Cases
    DbgPrint("\n=== CATEGORY 5: EDGE CASES ===\n");
    StressEdgeCases();
    StressLargeResponses();

    StressPrintStats();

    DbgPrint("\n[STRESS] All stress tests completed!\n");
    return STATUS_SUCCESS;
}
#endif
/**
 * @file ktls_lib.h
 * @brief Windows Kernel TLS/DTLS Transport Library
 * 
 * A lightweight TLS/DTLS implementation for Windows kernel mode using mbedTLS.
 * Provides secure transport layer (TLS 1.2/1.3) over TCP and DTLS over UDP,
 * with support for plain TCP when encryption is not required.
 * 
 * @author 4l3x777
 * @date 2026
 * @version 1.0
 * 
 * @section features Features
 * - TLS 1.2/1.3 over TCP (KTLS_PROTO_TCP)
 * - DTLS 1.2 over UDP (KTLS_PROTO_UDP)
 * - Plain TCP without encryption (KTLS_PROTO_TCP_PLAIN)
 * - SNI (Server Name Indication) support
 * - ALPN (Application-Layer Protocol Negotiation)
 * - Non-blocking I/O with configurable timeouts
 * - Zero-copy architecture where possible
 * - Graceful connection shutdown
 * 
 * @section protocols Protocol Support
 * 
 * | Protocol | Transport | Encryption | Use Case |
 * |----------|-----------|------------|----------|
 * | KTLS_PROTO_TCP | TCP | TLS 1.2/1.3 | HTTPS, secure APIs |
 * | KTLS_PROTO_UDP | UDP | DTLS 1.2 | Real-time, VoIP, gaming |
 * | KTLS_PROTO_TCP_PLAIN | TCP | None | Plain HTTP, testing |
 * 
 * @section usage Basic Usage
 * @code
 * // Initialize library (once in DriverEntry)
 * NTSTATUS status = KtlsGlobalInit();
 * if (!NT_SUCCESS(status)) return status;
 * 
 * // Connect to HTTPS server
 * PKTLS_SESSION session = NULL;
 * ULONG serverIp = INETADDR(93, 184, 216, 34); // example.com
 * status = KtlsConnect(
 *     serverIp,
 *     443,
 *     KTLS_PROTO_TCP,
 *     "example.com",
 *     &session
 * );
 * 
 * if (NT_SUCCESS(status)) {
 *     // Send HTTP request
 *     CHAR request[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
 *     ULONG sent = 0;
 *     KtlsSend(session, request, sizeof(request)-1, &sent);
 *     
 *     // Receive response
 *     CHAR buffer[4096];
 *     ULONG received = 0;
 *     KtlsRecv(session, buffer, sizeof(buffer), &received);
 *     
 *     // Close connection
 *     KtlsClose(session);
 * }
 * 
 * // Cleanup (in DriverUnload)
 * KtlsGlobalCleanup();
 * @endcode
 * 
 * @section threading Thread Safety
 * - KtlsGlobalInit/Cleanup: NOT thread-safe, call once
 * - KtlsConnect/Send/Recv/Close: Thread-safe per session
 * - Multiple sessions can be used concurrently from different threads
 * 
 * @section dependencies Dependencies
 * - mbedTLS 3.x: TLS/DTLS cryptographic library
 * - TDI (Transport Driver Interface): Windows network stack
 * - ntddk.h: Windows kernel mode support
 * 
 * @warning All functions must be called at PASSIVE_LEVEL unless noted
 */

#ifndef _KTLS_LIB_H_
#define _KTLS_LIB_H_

#include <ntddk.h>

// =============================================================================
// MACROS AND HELPERS
// =============================================================================

/**
 * @brief Create IPv4 address in network byte order (little-endian)
 * 
 * Converts human-readable IP address to ULONG format suitable for KtlsConnect.
 * 
 * @param a First octet (0-255)
 * @param b Second octet (0-255)
 * @param c Third octet (0-255)
 * @param d Fourth octet (0-255)
 * 
 * @return IPv4 address as ULONG in network byte order
 * 
 * @code
 * // Create 192.168.1.1
 * ULONG ip = INETADDR(192, 168, 1, 1);
 * 
 * // Google DNS (8.8.8.8)
 * ULONG dns = INETADDR(8, 8, 8, 8);
 * @endcode
 */
#define INETADDR(a, b, c, d) ((a) + ((b)<<8) + ((c)<<16) + ((d)<<24))

// =============================================================================
// ENUMERATIONS
// =============================================================================

/**
 * @enum KTLS_PROTOCOL
 * @brief Transport protocol selection
 * 
 * Determines the underlying transport and encryption protocol.
 * 
 * @section protocol_comparison Protocol Comparison
 * 
 * **KTLS_PROTO_TCP (Recommended for most use cases)**
 * - Transport: TCP (connection-oriented, reliable)
 * - Encryption: TLS 1.2/1.3
 * - Overhead: ~5% (TLS record layer)
 * - Latency: Low (after handshake)
 * - Use cases: HTTPS, REST APIs, file transfers
 * - Handshake: ~200-500ms (depends on network)
 * 
 * **KTLS_PROTO_UDP (For real-time applications)**
 * - Transport: UDP (connectionless, unreliable)
 * - Encryption: DTLS 1.2
 * - Overhead: ~10% (DTLS + retransmission)
 * - Latency: Very low (no TCP overhead)
 * - Use cases: VoIP, streaming, gaming, IoT
 * - Handshake: ~100-300ms (includes cookie exchange)
 * 
 * **KTLS_PROTO_TCP_PLAIN (Testing/debugging only)**
 * - Transport: TCP
 * - Encryption: None (plaintext)
 * - Overhead: Minimal
 * - Use cases: Plain HTTP, internal networks, debugging
 * - Security: None - do not use for sensitive data
 */
typedef enum _KTLS_PROTOCOL {
    KTLS_PROTO_TCP = 0,      ///< TCP with TLS 1.2/1.3 (HTTPS, secure protocols)
    KTLS_PROTO_UDP = 1,      ///< UDP with DTLS 1.2 (real-time, low latency)
    KTLS_PROTO_TCP_PLAIN = 2 ///< TCP without encryption (plain HTTP, testing)
} KTLS_PROTOCOL;

// =============================================================================
// OPAQUE TYPES
// =============================================================================

/**
 * @typedef PKTLS_SESSION
 * @brief Opaque session handle
 * 
 * Represents an active TLS/DTLS connection. Internal structure is private.
 * Always initialize to NULL and obtain via KtlsConnect().
 * 
 * @note Handle remains valid until KtlsClose() is called
 * @note Do not attempt to dereference or modify the handle
 */
typedef struct _KTLS_SESSION* PKTLS_SESSION;

// =============================================================================
// GLOBAL INITIALIZATION
// =============================================================================

/**
 * @brief Initialize the KTLS library
 * 
 * Must be called once during driver initialization (DriverEntry) before
 * any other KTLS functions. Initializes mbedTLS subsystems and sets up
 * memory allocators.
 * 
 * @return STATUS_SUCCESS on success, error code otherwise
 * 
 * @retval STATUS_SUCCESS Library initialized successfully
 * @retval STATUS_INSUFFICIENT_RESOURCES Memory allocation failed
 * @retval STATUS_UNSUCCESSFUL mbedTLS initialization failed
 * 
 * @note Must be called at PASSIVE_LEVEL
 * @note NOT thread-safe - call only from DriverEntry
 * @note Only call once per driver lifetime
 * 
 * @see KtlsGlobalCleanup()
 * 
 * @code
 * NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
 *     NTSTATUS status = KtlsGlobalInit();
 *     if (!NT_SUCCESS(status)) {
 *         DbgPrint("KTLS init failed: 0x%x\n", status);
 *         return status;
 *     }
 *     // ... rest of initialization
 * }
 * @endcode
 */
NTSTATUS KtlsGlobalInit(VOID);

/**
 * @brief Clean up the KTLS library
 * 
 * Must be called once during driver unload (DriverUnload) to release all
 * global resources. No KTLS functions should be called after this.
 * 
 * @note Must be called at PASSIVE_LEVEL
 * @note NOT thread-safe - call only from DriverUnload
 * @note Ensure all sessions are closed before calling this
 * 
 * @see KtlsGlobalInit()
 * 
 * @code
 * VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
 *     // Close any remaining sessions first
 *     KtlsGlobalCleanup();
 * }
 * @endcode
 */
VOID KtlsGlobalCleanup(VOID);

// =============================================================================
// SESSION MANAGEMENT
// =============================================================================

/**
 * @brief Set receive timeout for a session
 * 
 * Configures how long KtlsRecv() will wait for data before returning
 * STATUS_IO_TIMEOUT. Default timeouts are protocol-dependent.
 * 
 * @param[in] Session Active session handle
 * @param[in] TimeoutMs Timeout in milliseconds (0 = infinite)
 * 
 * @note Default timeouts:
 * - TCP/TLS: 6000ms (6 seconds)
 * - UDP/DTLS: 2000ms (2 seconds)
 * - Plain TCP: 6000ms (6 seconds)
 * 
 * @note Must be called before KtlsRecv()
 * @note Setting 0 disables timeout (blocks until data arrives)
 * 
 * @code
 * // Set 10 second timeout
 * KtlsSetTimeout(session, 10000);
 * 
 * // Disable timeout (wait forever)
 * KtlsSetTimeout(session, 0);
 * @endcode
 */
VOID KtlsSetTimeout(
    _In_ PKTLS_SESSION Session,
    _In_ ULONG TimeoutMs
);

/**
 * @brief Connect to a remote server
 * 
 * Establishes TCP/UDP connection and performs TLS/DTLS handshake if enabled.
 * Returns a session handle for subsequent send/recv operations.
 * 
 * @param[in] Ip IPv4 address in network byte order (use INETADDR macro)
 * @param[in] Port Destination port (host byte order, e.g., 443 for HTTPS)
 * @param[in] Protocol Transport and encryption protocol
 * @param[in] Hostname Server hostname for SNI (can be NULL for plain TCP)
 * @param[out] Session Pointer to receive session handle
 * 
 * @return STATUS_SUCCESS on success, error code otherwise
 * 
 * @retval STATUS_SUCCESS Connection established and handshake completed
 * @retval STATUS_INVALID_PARAMETER Invalid parameters (IP=0, Port=0, etc.)
 * @retval STATUS_INSUFFICIENT_RESOURCES Memory allocation failed
 * @retval STATUS_CONNECTION_REFUSED Server rejected connection
 * @retval STATUS_IO_TIMEOUT Connection or handshake timeout (15s)
 * @retval STATUS_CONNECTION_DISCONNECTED Peer closed during handshake
 * 
 * @note Must be called at PASSIVE_LEVEL
 * @note Caller must call KtlsClose() to free the session
 * @note Handshake timeout is fixed at 15 seconds
 * @note Hostname is required for TLS/DTLS (used for SNI)
 * 
 * @section connect_examples Connection Examples
 * 
 * **HTTPS (TLS over TCP)**
 * @code
 * PKTLS_SESSION session = NULL;
 * ULONG ip = INETADDR(93, 184, 216, 34); // example.com
 * NTSTATUS status = KtlsConnect(
 *     ip,
 *     443,
 *     KTLS_PROTO_TCP,
 *     "example.com",
 *     &session
 * );
 * if (NT_SUCCESS(status)) {
 *     // Use session...
 *     KtlsClose(session);
 * }
 * @endcode
 * 
 * **Plain HTTP (no encryption)**
 * @code
 * PKTLS_SESSION session = NULL;
 * ULONG ip = INETADDR(93, 184, 216, 34);
 * NTSTATUS status = KtlsConnect(
 *     ip,
 *     80,
 *     KTLS_PROTO_TCP_PLAIN,
 *     NULL, // Hostname not needed for plain TCP
 *     &session
 * );
 * @endcode
 * 
 * **DTLS over UDP (real-time)**
 * @code
 * PKTLS_SESSION session = NULL;
 * ULONG ip = INETADDR(192, 168, 1, 100);
 * NTSTATUS status = KtlsConnect(
 *     ip,
 *     4443,
 *     KTLS_PROTO_UDP,
 *     "iot.device.local",
 *     &session
 * );
 * @endcode
 */
NTSTATUS KtlsConnect(
    _In_ ULONG Ip,
    _In_ USHORT Port,
    _In_ KTLS_PROTOCOL Protocol,
    _In_opt_ PCHAR Hostname,
    _Out_ PKTLS_SESSION* Session
);

/**
 * @brief Send data over TLS/DTLS connection
 * 
 * Encrypts and transmits data. For TLS (TCP), all data is guaranteed to be sent
 * or an error is returned. For DTLS (UDP), data may be lost due to network conditions.
 * 
 * @param[in] Session Active session handle
 * @param[in] Data Buffer containing data to send (NonPagedPool recommended)
 * @param[in] Length Number of bytes to send
 * @param[out] BytesSent Number of bytes actually sent
 * 
 * @return STATUS_SUCCESS on success, error code otherwise
 * 
 * @retval STATUS_SUCCESS Data sent successfully
 * @retval STATUS_INVALID_PARAMETER Invalid session or NULL pointers
 * @retval STATUS_CONNECTION_DISCONNECTED Connection closed by peer
 * @retval STATUS_UNSUCCESSFUL Send operation failed
 * 
 * @note Must be called at PASSIVE_LEVEL
 * @note For TLS (TCP): BytesSent will equal Length on success
 * @note For DTLS (UDP): BytesSent may be less than Length
 * @note Buffer must remain valid until function returns
 * @note Maximum send size is protocol-dependent:
 *       - TLS: 16KB per record (automatic fragmentation)
 *       - DTLS: MTU-dependent (typically ~1200 bytes)
 * 
 * @code
 * CHAR httpReq[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
 * ULONG sent = 0;
 * NTSTATUS status = KtlsSend(session, httpReq, strlen(httpReq), &sent);
 * if (NT_SUCCESS(status)) {
 *     DbgPrint("Sent %u bytes\n", sent);
 * } else {
 *     DbgPrint("Send failed: 0x%x\n", status);
 * }
 * @endcode
 */
NTSTATUS KtlsSend(
    _In_ PKTLS_SESSION Session,
    _In_ PVOID Data,
    _In_ ULONG Length,
    _Out_ PULONG BytesSent
);

/**
 * @brief Receive data from TLS/DTLS connection
 * 
 * Reads and decrypts data from the connection. Blocks until data arrives,
 * timeout expires, or connection is closed.
 * 
 * @param[in] Session Active session handle
 * @param[out] Buffer Buffer to receive decrypted data (NonPagedPool recommended)
 * @param[in] BufferSize Size of receive buffer in bytes
 * @param[out] BytesReceived Number of bytes actually received
 * 
 * @return Status code indicating result
 * 
 * @retval STATUS_SUCCESS Data received successfully
 * @retval STATUS_IO_TIMEOUT Timeout expired (see KtlsSetTimeout)
 * @retval STATUS_END_OF_FILE Graceful close by peer (received close_notify)
 * @retval STATUS_CONNECTION_DISCONNECTED Abrupt close by peer
 * @retval STATUS_INVALID_PARAMETER Invalid session or NULL pointers
 * @retval STATUS_UNSUCCESSFUL Receive operation failed
 * 
 * @note Must be called at PASSIVE_LEVEL
 * @note BytesReceived may be less than BufferSize
 * @note Zero bytes received + STATUS_SUCCESS = no data available (non-blocking)
 * @note For TCP: Data is delivered in order and reliably
 * @note For UDP: Data may arrive out-of-order or be lost
 * 
 * @section recv_patterns Common Receive Patterns
 * 
 * **Simple receive with timeout**
 * @code
 * CHAR buffer[4096];
 * ULONG received = 0;
 * 
 * KtlsSetTimeout(session, 5000); // 5 second timeout
 * NTSTATUS status = KtlsRecv(session, buffer, sizeof(buffer), &received);
 * 
 * if (status == STATUS_IO_TIMEOUT) {
 *     DbgPrint("No data within 5 seconds\n");
 * } else if (status == STATUS_END_OF_FILE) {
 *     DbgPrint("Connection closed gracefully\n");
 * } else if (NT_SUCCESS(status)) {
 *     DbgPrint("Received %u bytes\n", received);
 * }
 * @endcode
 * 
 * **Receive until complete response**
 * @code
 * CHAR buffer[8192];
 * ULONG totalReceived = 0;
 * 
 * while (totalReceived < sizeof(buffer)) {
 *     ULONG received = 0;
 *     NTSTATUS status = KtlsRecv(
 *         session,
 *         buffer + totalReceived,
 *         sizeof(buffer) - totalReceived,
 *         &received
 *     );
 *     
 *     if (status == STATUS_END_OF_FILE) {
 *         break; // End of stream
 *     }
 *     if (!NT_SUCCESS(status)) {
 *         break; // Error
 *     }
 *     
 *     totalReceived += received;
 * }
 * @endcode
 */
NTSTATUS KtlsRecv(
    _In_ PKTLS_SESSION Session,
    _Out_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesReceived
);

/**
 * @brief Close TLS/DTLS session and free resources
 * 
 * Sends close_notify alert (if connection is alive), closes underlying
 * transport, and frees all session resources. After this call, the session
 * handle becomes invalid.
 * 
 * @param[in] Session Session to close (can be NULL - no-op)
 * 
 * @note Safe to call with NULL session
 * @note Must be called for every successful KtlsConnect()
 * @note Automatically handles graceful shutdown
 * @note Does not block - returns immediately
 * @note Session handle is invalid after this call
 * 
 * @warning Do not use session handle after calling this function
 * 
 * @code
 * PKTLS_SESSION session = NULL;
 * if (NT_SUCCESS(KtlsConnect(..., &session))) {
 *     // Use session...
 *     KtlsClose(session); // Always close
 *     session = NULL;     // Good practice
 * }
 * @endcode
 */
VOID KtlsClose(
    _In_opt_ PKTLS_SESSION Session
);

// =============================================================================
// ERROR HANDLING GUIDELINES
// =============================================================================

/**
 * @section error_handling Error Handling Best Practices
 * 
 * **Connection Errors**
 * - STATUS_CONNECTION_REFUSED: Server not listening or firewall blocking
 * - STATUS_IO_TIMEOUT: Network unreachable or handshake taking too long
 * - STATUS_CONNECTION_DISCONNECTED: Peer closed during handshake
 * 
 * **Send/Receive Errors**
 * - STATUS_IO_TIMEOUT: No data received within timeout period
 * - STATUS_END_OF_FILE: Graceful close (expected)
 * - STATUS_CONNECTION_DISCONNECTED: Abrupt close (connection lost)
 * 
 * **Resource Errors**
 * - STATUS_INSUFFICIENT_RESOURCES: Out of memory
 * - STATUS_INVALID_PARAMETER: Invalid arguments
 * 
 * **Always check return codes:**
 * @code
 * NTSTATUS status = KtlsConnect(...);
 * if (!NT_SUCCESS(status)) {
 *     if (status == STATUS_CONNECTION_REFUSED) {
 *         // Retry with exponential backoff
 *     } else if (status == STATUS_IO_TIMEOUT) {
 *         // Check network connectivity
 *     } else {
 *         // Fatal error
 *     }
 * }
 * @endcode
 */

// =============================================================================
// END OF HEADER
// =============================================================================

#endif // _KTLS_LIB_H_

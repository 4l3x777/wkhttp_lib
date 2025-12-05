#ifndef _KTLS_LIB_H_
#define _KTLS_LIB_H_

#include <ntddk.h>

// =============================================================
// PUBLIC DEFINITIONS
// =============================================================

// Helper macro for creating IP addresses (Little Endian)
#define INETADDR(a, b, c, d) ((a) + ((b)<<8) + ((c)<<16) + ((d)<<24))

// Protocol Selection
typedef enum _KTLS_PROTOCOL {
    KTLS_PROTO_TCP = 0,      // TCP with TLS
    KTLS_PROTO_UDP = 1,      // UDP with DTLS
    KTLS_PROTO_TCP_PLAIN = 2 // TCP without TLS (plain HTTP)
} KTLS_PROTOCOL;

// Opaque handle for a TLS session
typedef struct _KTLS_SESSION* PKTLS_SESSION;

// =============================================================
// PUBLIC API
// =============================================================

// Initialize the library (Call once in DriverEntry)
NTSTATUS KtlsGlobalInit(void);

// Cleanup the library (Call once in DriverUnload)
VOID KtlsGlobalCleanup(void);

// Set receive timeout (in milliseconds). 0 = Infinite.
// Default is 6000ms for TCP, 2000ms for UDP.
VOID KtlsSetTimeout(
    _In_ PKTLS_SESSION Session,
    _In_ ULONG TimeoutMs
);

// Connect to a remote server
// Ip: IPv4 address in network byte order
// Port: Port number (e.g., 443)
// Protocol: KTLS_PROTO_TCP or KTLS_PROTO_UDP
// Hostname: SNI
NTSTATUS KtlsConnect(
    _In_ ULONG Ip,
    _In_ USHORT Port,
    _In_ KTLS_PROTOCOL Protocol,
    _In_ PCHAR Hostname,
    _Out_ PKTLS_SESSION* Session
);

// Send encrypted data
NTSTATUS KtlsSend(
    _In_ PKTLS_SESSION Session,
    _In_ PVOID Data,
    _In_ ULONG Length,
    _Out_ PULONG BytesSent
);

// Receive decrypted data
// Returns STATUS_SUCCESS on data, STATUS_END_OF_FILE on graceful close, STATUS_IO_TIMEOUT if the timeout expires.
NTSTATUS KtlsRecv(
    _In_ PKTLS_SESSION Session,
    _Out_ PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG BytesReceived
);

// Close session and free all resources
VOID KtlsClose(
    _In_ PKTLS_SESSION Session
);

#endif // _KTLS_LIB_H_

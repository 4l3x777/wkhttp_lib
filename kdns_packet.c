#include "kdns_packet.h"
#include <ntstrsafe.h>

// =============================================================
// RANDOM ID GENERATION
// =============================================================

static ULONG g_DnsSeed = 0;

VOID KdnsInitializeRandom(VOID)
{
    LARGE_INTEGER Tick;
    KeQueryTickCount(&Tick);
    g_DnsSeed = Tick.LowPart ^ (Tick.HighPart << 16);
    DbgPrint("KDNS: Random seed initialized: 0x%08X\n", g_DnsSeed);
}

USHORT KdnsGenerateTransactionId(VOID)
{
    if (g_DnsSeed == 0) {
        KdnsInitializeRandom();
    }
    // Simple LCG
    g_DnsSeed = g_DnsSeed * 1103515245 + 12345;
    return (USHORT)((g_DnsSeed >> 16) & 0xFFFF);
}

// =============================================================
// DNS NAME ENCODING
// =============================================================

static BOOLEAN IsValidDnsChar(CHAR c)
{
    return (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
           (c == '-' || c == '_' || c == '.');
}

ULONG KdnsEncodeDnsName(
    _In_ PCHAR Hostname,
    _Out_writes_(BufferSize) PCHAR Buffer,
    _In_ ULONG BufferSize
)
{
    if (!Hostname || !Buffer || BufferSize < 2) {
        return 0;
    }

    ULONG WritePos = 0;
    ULONG LabelStart = 0;
    ULONG ReadPos = 0;
    UCHAR LabelLen = 0;

    // Reserve byte for first label length
    WritePos = 1;

    while (Hostname[ReadPos] != '\0' && WritePos < BufferSize) {
        CHAR c = Hostname[ReadPos];

        // Validate character
        if (!IsValidDnsChar(c)) {
            DbgPrint("KDNS: Invalid char 0x%02X at pos %lu in '%s'\n",
                (UCHAR)c, ReadPos, Hostname);
            return 0;
        }

        if (c == '.') {
            // End of label
            if (LabelLen == 0) {
                DbgPrint("KDNS: Empty label at pos %lu\n", ReadPos);
                return 0;
            }
            if (LabelLen > KDNS_MAX_LABEL_LEN) {
                DbgPrint("KDNS: Label too long: %u > %u\n", 
                    LabelLen, KDNS_MAX_LABEL_LEN);
                return 0;
            }

            // Write label length
            Buffer[LabelStart] = (CHAR)LabelLen;
            LabelStart = WritePos;
            LabelLen = 0;
            WritePos++; // Reserve next length byte
        }
        else {
            // Regular character
            if (WritePos >= BufferSize) {
                DbgPrint("KDNS: Buffer overflow during encoding\n");
                return 0;
            }
            Buffer[WritePos++] = c;
            LabelLen++;

            if (LabelLen > KDNS_MAX_LABEL_LEN) {
                DbgPrint("KDNS: Label exceeds max length\n");
                return 0;
            }
        }

        ReadPos++;
    }

    // Write final label length
    if (LabelLen > 0) {
        if (LabelLen > KDNS_MAX_LABEL_LEN) {
            return 0;
        }
        Buffer[LabelStart] = (CHAR)LabelLen;
    }

    // Write root terminator
    if (WritePos >= BufferSize) {
        return 0;
    }
    Buffer[WritePos++] = 0;

    return WritePos;
}

// =============================================================
// DNS NAME PARSING
// =============================================================

ULONG KdnsParseDnsName(
    _In_ PUCHAR PacketStart,
    _In_ PUCHAR Ptr,
    _In_ PUCHAR PacketEnd,
    _Out_writes_(OutSize) PCHAR OutName,
    _In_ ULONG OutSize
)
{
    if (!PacketStart || !Ptr || !PacketEnd || !OutName || OutSize == 0) {
        return 0;
    }

    ULONG OutLen = 0;
    PUCHAR Current = Ptr;
    PUCHAR NextPtr = NULL;
    ULONG JumpCount = 0;
    BOOLEAN Jumped = FALSE;

    while (Current < PacketEnd && *Current != 0 && JumpCount < 20) {
        // Check for compression pointer
        if ((*Current & 0xC0) == 0xC0) {
            if (Current + 1 >= PacketEnd) {
                return 0;
            }

            USHORT Offset = ((*Current & 0x3F) << 8) | *(Current + 1);
            
            // Save position after pointer (for return value)
            if (!Jumped) {
                NextPtr = Current + 2;
                Jumped = TRUE;
            }

            // Jump to target
            Current = PacketStart + Offset;
            JumpCount++;

            // Validate jump target
            if (Current >= PacketEnd || Current < PacketStart) {
                return 0;
            }
            continue;
        }

        // Regular label
        UCHAR LabelLen = *Current++;
        
        if (LabelLen == 0) {
            break; // Root label
        }

        if (LabelLen > KDNS_MAX_LABEL_LEN) {
            return 0;
        }

        if (Current + LabelLen > PacketEnd) {
            return 0;
        }

        // Check output buffer space
        if (OutLen + LabelLen + 1 >= OutSize) {
            return 0;
        }

        // Copy label
        RtlCopyMemory(OutName + OutLen, Current, LabelLen);
        OutLen += LabelLen;
        OutName[OutLen++] = '.';
        Current += LabelLen;
    }

    // Remove trailing dot
    if (OutLen > 0 && OutName[OutLen - 1] == '.') {
        OutLen--;
    }
    OutName[OutLen] = '\0';

    // Return bytes consumed from original pointer
    if (Jumped && NextPtr) {
        return (ULONG)(NextPtr - Ptr);
    }
    else {
        return (ULONG)(Current - Ptr + 1);
    }
}

// =============================================================
// DNS QUERY BUILDING
// =============================================================

NTSTATUS KdnsBuildQuery(
    _In_ PCHAR Hostname,
    _In_ USHORT TransactionId,
    _Out_writes_bytes_(BufferSize) PVOID Buffer,
    _In_ ULONG BufferSize,
    _Out_ PULONG QueryLength
)
{
    if (!Hostname || !Buffer || !QueryLength || BufferSize < sizeof(DNS_HEADER) + 256) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Buffer, BufferSize);

    // Build DNS header
    PDNS_HEADER Header = (PDNS_HEADER)Buffer;
    Header->Id = HTONS(TransactionId);
    Header->Flags = HTONS(DNS_FLAG_RD);
    Header->QuestionCount = HTONS(1);
    Header->AnswerCount = 0;
    Header->AuthorityCount = 0;
    Header->AdditionalCount = 0;

    // Encode QNAME
    PCHAR QName = (PCHAR)(Header + 1);
    ULONG NameLen = KdnsEncodeDnsName(Hostname, QName, BufferSize - sizeof(DNS_HEADER) - 4);
    
    if (NameLen == 0) {
        DbgPrint("KDNS: Failed to encode hostname: %s\n", Hostname);
        return STATUS_INVALID_PARAMETER;
    }

    // Add QTYPE and QCLASS
    PUSHORT QType = (PUSHORT)(QName + NameLen);
    QType[0] = HTONS(DNS_TYPE_A);
    QType[1] = HTONS(DNS_CLASS_IN);

    *QueryLength = sizeof(DNS_HEADER) + NameLen + 4;

    DbgPrint("KDNS: Built query for '%s' (ID=0x%04X, len=%lu)\n",
        Hostname, TransactionId, *QueryLength);

    return STATUS_SUCCESS;
}

// =============================================================
// DEBUG VALIDATION
// =============================================================

VOID KdnsValidateQueryPacket(
    _In_ PVOID Packet,
    _In_ ULONG Length,
    _In_ PCHAR Hostname
)
{
#ifdef KDNS_DEBUG_VERBOSE
    if (!Packet || Length < sizeof(DNS_HEADER)) {
        DbgPrint("KDNS: Invalid packet (len=%lu)\n", Length);
        return;
    }

    PDNS_HEADER Hdr = (PDNS_HEADER)Packet;
    PCHAR QName = (PCHAR)(Hdr + 1);

    DbgPrint("KDNS: === Query Validation [%s] ===\n", Hostname);
    DbgPrint("  Size: %lu bytes\n", Length);
    DbgPrint("  ID: 0x%04X\n", NTOHS(Hdr->Id));
    DbgPrint("  Flags: 0x%04X\n", NTOHS(Hdr->Flags));
    DbgPrint("  Questions: %u\n", NTOHS(Hdr->QuestionCount));

    // Validate QNAME
    ULONG Offset = 0;
    while (Offset < Length - sizeof(DNS_HEADER) && QName[Offset] != 0) {
        UCHAR Len = (UCHAR)QName[Offset];
        if (Len > KDNS_MAX_LABEL_LEN) {
            DbgPrint("  [ERROR] Invalid label length: %u\n", Len);
            break;
        }
        Offset += Len + 1;
    }
    DbgPrint("  QNAME length: %lu bytes\n", Offset + 1);
#else
    UNREFERENCED_PARAMETER(Packet);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Hostname);
#endif
}

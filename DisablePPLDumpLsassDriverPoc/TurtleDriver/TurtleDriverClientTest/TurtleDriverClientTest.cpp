// TurtleDriverClientTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <stdio.h>
#include "TurtleDriverClient.h"

int Error(const char* msg) {
    printf("%s (%u)\n", msg, GetLastError());
    return 1;
}
int main(int argc,char *argv[]){
    if (argc < 2) {
        printf("Usage: Client <pid>");
        return 0;
    }
    // get handle to driver device object
    HANDLE hDevice = CreateFile(L"\\\\.\\TurtleDriver", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDevice == INVALID_HANDLE_VALUE)
        return Error("Failed to open driver device");
    ProcessData sentData;
    sentData.ProcessId = atoi(argv[1]);
    sentData.SigProtection.SignatureLevel = 0;
    sentData.SigProtection.SectionSignatureLevel = 0;
    sentData.SigProtection.Protection.Type = 0;
    sentData.SigProtection.Protection.Audit = 0;
    sentData.SigProtection.Protection.Signer = 0;
    DWORD returned;
    //BOOL success = DeviceIoControl(hDevice, IOCTL_TURTLEDRIVER_TESTER, &data, sizeof(data), &returnedData, sizeof(returnedData), &returned, nullptr);
    BOOL success = DeviceIoControl(hDevice,IOCTL_TURTLEDRIVER_CHANGE_PPL, &sentData, sizeof(sentData), nullptr, 0, &returned, nullptr);
    if (success)
        printf("Worked\n");
    else
        Error("Failed");
    printf("returned stuff -> %lu\n", sentData.ProcessId);
    CloseHandle(hDevice);
}

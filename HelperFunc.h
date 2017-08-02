#ifndef _HELPER_FUNC_H
#define _HELPER_FUNC_H

#include <ntddk.h>

NTSTATUS GetProcessImageNameById(HANDLE ProcId, POBJECT_NAME_INFORMATION pObjNameInfo, LARGE_INTEGER * pliFileId);
NTSTATUS MyPsReferenceProcessFilePointer(PEPROCESS EProcess, PVOID * outFileObject);
NTSTATUS SaveProcInfo(HANDLE ProcessId, LARGE_INTEGER * pliFileId);

#endif

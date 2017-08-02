#include <ntifs.h>
#include "HelperFunc.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, GetProcessImageNameById)
#pragma alloc_text(PAGE, MyPsReferenceProcessFilePointer)
#pragma alloc_text(PAGE, SaveProcInfo)
#endif

typedef NTSTATUS (*PF_REFERENCEPROCESSFILEPOINTER)(PEPROCESS EProcess, PVOID * OutFileObject);
PF_REFERENCEPROCESSFILEPOINTER pfPsReferenceProcessFilePointer = NULL;

NTSTATUS GetProcessImageNameById(HANDLE ProcId, POBJECT_NAME_INFORMATION pObjNameInfo, LARGE_INTEGER * pliFileId)
/*
 * get the process filename information
 * 
 * ProcId: the process id
 * pObjNameInfo: a pointer to receive the filename information
 * pliFileId: a pointer to receive the file id information
 *
 * first get the process fileobject pointer, then get file id and get a new fileobject, 
 * last call ObQueryNameString
 *
 */
{
	NTSTATUS status;
	PUNICODE_STRING imageName;
	PEPROCESS EProcess = NULL;
	PVOID FilePointer = NULL;

	FILE_INTERNAL_INFORMATION FileIdInfo;
	ULONG FileIdLen = sizeof(FileIdInfo);
	HANDLE hFile = NULL;
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING ObjName;
	IO_STATUS_BLOCK iostatus;
	HANDLE hDev = NULL;

	PVOID pNewFileObject = NULL;
	PVOID pQueryObject = NULL;

	ULONG returnedLength = pObjNameInfo->Name.MaximumLength + sizeof(UNICODE_STRING);

	PAGED_CODE();

	if(pliFileId != NULL)
		pliFileId->QuadPart = 0;

	if (NULL == pfPsReferenceProcessFilePointer) {

		UNICODE_STRING routineName;
		
		RtlInitUnicodeString(&routineName, L"PsReferenceProcessFilePointer");
		
		 pfPsReferenceProcessFilePointer = 
               (PF_REFERENCEPROCESSFILEPOINTER) MmGetSystemRoutineAddress(&routineName);
		
		if (NULL == pfPsReferenceProcessFilePointer) {
            KdPrint(("ProcMon: Cannot resolve PsReferenceProcessFilePointer\n"));
			pfPsReferenceProcessFilePointer = MyPsReferenceProcessFilePointer;
        }
    }

	//
	// get process fileobject pointer
	//
	
	status = PsLookupProcessByProcessId(ProcId, &EProcess);
	if(!NT_SUCCESS(status)) {

		return status;

	}

	__try
	{
		status = pfPsReferenceProcessFilePointer(EProcess, &FilePointer);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
	}

	ObDereferenceObject(EProcess);

	if(!NT_SUCCESS(status)){

		KdPrint(("ProcMon: get process file pointer failed!\n"));
		return status;

	}

	pQueryObject = FilePointer;

	//
	// get file id
	//
	
	status = IoQueryFileInformation(FilePointer,
				FileInternalInformation,
				FileIdLen,
				&FileIdInfo,
				&FileIdLen);

	if(!NT_SUCCESS(status))
		KdPrint(("ProcMon: query file id failed!\n"));

	//
	// get new fileobject
	//
	
	status = ObOpenObjectByPointer(((FILE_OBJECT *)FilePointer)->DeviceObject,
				OBJ_KERNEL_HANDLE,
				NULL,
				0,
				NULL,
				KernelMode,
				&hDev);
	
	if(NT_SUCCESS(status))
	{
		ObjName.MaximumLength = ObjName.Length = 8;
		ObjName.Buffer = (PWSTR)&FileIdInfo.IndexNumber;
		InitializeObjectAttributes(&oa,
			&ObjName,
			OBJ_KERNEL_HANDLE,
			hDev,
			NULL);
	
		status = ZwOpenFile(&hFile,
					GENERIC_READ,
					&oa,
					&iostatus,
					FILE_SHARE_READ,
					FILE_OPEN_BY_FILE_ID | FILE_NON_DIRECTORY_FILE);

		if(NT_SUCCESS(status))
		{
			status = ObReferenceObjectByHandle(hFile,
					FILE_READ_DATA | FILE_READ_ATTRIBUTES,
					*IoFileObjectType,
					KernelMode,
					&pNewFileObject,
					NULL);

			if(NT_SUCCESS(status))
			{
				pQueryObject = pNewFileObject;

				if(pliFileId != NULL)
					pliFileId->QuadPart = FileIdInfo.IndexNumber.QuadPart;
			}

			ZwClose(hFile);
		}
		else
		{
			KdPrint(("ProcMon: open file by fileid failed, the filesystem may not support fileid, status = %08X!\n",
						status));
		}

		ZwClose(hDev);
	}


	//
	// call ObQueryNameString to query the filename
	//
	
	status = ObQueryNameString(pQueryObject,
						pObjNameInfo,
						returnedLength,
						&returnedLength);

	if(status == STATUS_BUFFER_OVERFLOW ||
			status == STATUS_BUFFER_TOO_SMALL ||
			status == STATUS_INFO_LENGTH_MISMATCH)
	{
		pObjNameInfo->Name.Length = (USHORT)(returnedLength - sizeof(UNICODE_STRING));
	}

	if(FilePointer != NULL)
		ObDereferenceObject(FilePointer);

	if(pNewFileObject != NULL)
		ObDereferenceObject(pNewFileObject);

	return status;

}

extern ERESOURCE g_ResourceProcId;
extern HANDLE g_ProcId;
extern PVOID g_FilePointer;
extern LARGE_INTEGER g_liFileId;

NTSTATUS SaveProcInfo(HANDLE ProcessId, LARGE_INTEGER * pliFileId)
/*
 * save the process id && the process fileobject pointer and file id for later use
 *
 */
{
	NTSTATUS status;
	PVOID FilePointer = NULL;
	PEPROCESS EProcess = NULL;

	PAGED_CODE();

	if (NULL == pfPsReferenceProcessFilePointer) {

		UNICODE_STRING routineName;
		
		RtlInitUnicodeString(&routineName, L"PsReferenceProcessFilePointer");
		
		 pfPsReferenceProcessFilePointer = 
               (PF_REFERENCEPROCESSFILEPOINTER) MmGetSystemRoutineAddress(&routineName);
		
		if (NULL == pfPsReferenceProcessFilePointer) {
            KdPrint(("ProcMon: Cannot resolve PsReferenceProcessFilePointer\n"));
			pfPsReferenceProcessFilePointer = MyPsReferenceProcessFilePointer;
        }
    }

	status = PsLookupProcessByProcessId(ProcessId, &EProcess);

	if(!NT_SUCCESS(status))
	{
		return status;
	}

	__try
	{
		status = pfPsReferenceProcessFilePointer(EProcess, &FilePointer);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
	}
	ObDereferenceObject(EProcess);

	if(!NT_SUCCESS(status))
	{
		return status;
	}

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_ResourceProcId, TRUE);

	g_ProcId = ProcessId;
	g_FilePointer = FilePointer;
	g_liFileId.QuadPart = pliFileId->QuadPart;

	ExReleaseResourceLite(&g_ResourceProcId);
	KeLeaveCriticalRegion();

	return status;

}

#ifndef _WIN64

//
// for winxp 32
//

__declspec(naked) PFILE_OBJECT MyMmGetFileObjectForSection(PVOID Section)
{
	//
	// copy from ida
	//
	
	__asm
	{
		mov edi, edi
		push ebp
		mov ebp, esp
		mov eax, [ebp + 8]
		mov eax, [eax + 0x14]
		mov eax, [eax]
		mov eax, [eax + 0x24]
		pop ebp
		retn 4
	}
}

__declspec(naked) NTSTATUS MyPsReferenceProcessFilePointer(PEPROCESS EProcess, PVOID * OutFileObject)
{
	//
	// copy from ida
	//
	
	PAGED_CODE();

	__asm
	{
		mov edi, edi
		push ebp
		mov ebp, esp
		push esi
		mov esi, [ebp + 8]
		push edi
		lea edi, [esi + 0x80]
		mov ecx, edi
		call dword ptr [ExAcquireRundownProtection]
		test al, al
		jz failed1
		mov eax, [esi + 0x138]
		test eax, eax
		jz failed2
		push eax
		call MyMmGetFileObjectForSection
		mov ecx, [ebp + 0xc]
		mov [ecx], eax
		mov ecx, eax
		call dword ptr [ObfReferenceObject]
		xor esi, esi

	beforeleave:
		mov ecx, edi
		call dword ptr [ExReleaseRundownProtection]
		mov eax, esi

	leave:
		pop edi
		pop esi
		pop ebp
		retn 8
	
	failed1:
		mov eax, 0xc0000001
		jmp leave

	failed2:
		mov eax, 0xc0000001
		jmp beforeleave
	}
}

#else

// for winxp 64, as i have no xp64, just return failed
// or maybe the routine is exported by the xp64 kernel which
// we can get by MmGetSystemRoutineAddress

NTSTATUS MyPsReferenceProcessFilePointer(PEPROCESS EProcess, PVOID * OutFileObject)
{
	PAGED_CODE();

	return STATUS_UNSUCCESSFUL;
}

#endif

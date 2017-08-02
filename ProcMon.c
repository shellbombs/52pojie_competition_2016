#include <ntifs.h>
#include "HelperFunc.h"
#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
VOID ProcCreateNotify(
    IN HANDLE  ParentId,
    IN HANDLE  ProcessId,
    IN BOOLEAN  Create
    );
KSTART_ROUTINE OutputThread;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#pragma alloc_text(PAGE, ProcCreateNotify)
#pragma alloc_text(PAGE, OutputThread)
#endif

// the process id
HANDLE g_ProcId = 0;

// the file pointer of the process file
PVOID g_FilePointer = NULL;

// the file id
LARGE_INTEGER g_liFileId = {0};

// used to protect the access to the process id aboved
ERESOURCE g_ResourceProcId;

// the system thread object
PVOID g_Thread = NULL;

// used to notify the system thread to exit
KEVENT g_EventExit;

NTSTATUS DriverEntry(
		__in PDRIVER_OBJECT DriverObject,
		__in PUNICODE_STRING RegistryPath
		)
/*
 * the driver initialize routine
 *
 */
{
	NTSTATUS status;
	HANDLE hThread = NULL;

	PAGED_CODE();

	DriverObject->DriverUnload = DriverUnload;
	ExInitializeResourceLite(&g_ResourceProcId);
	KeInitializeEvent(&g_EventExit, NotificationEvent, FALSE);

	do
	{
		//
		// create a system thread to output the process filename
		//
		
		KdPrint(("ProcMon: enter driverentry!\n"));

		status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, OutputThread, NULL);
		if(!NT_SUCCESS(status))
		{
			break;
		}

		status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, 
										KernelMode, &g_Thread, NULL);
		if(!NT_SUCCESS(status))
		{
			KeSetEvent(&g_EventExit, 0, FALSE);
			break;
		}

		status = PsSetCreateProcessNotifyRoutine(ProcCreateNotify, FALSE);

		if(!NT_SUCCESS(status))
		{
			break;
		}

		ZwClose(hThread);
		return status;

	}while(FALSE);

	ExDeleteResourceLite(&g_ResourceProcId);

	if(hThread != NULL)
		ZwClose(hThread);
	
	if(g_Thread != NULL)
	{
		KeSetEvent(&g_EventExit, 0, FALSE);
		KeWaitForSingleObject(g_Thread, Executive, KernelMode, FALSE, NULL);
		ObDereferenceObject(g_Thread);
	}

	return status;
}

VOID DriverUnload(
    __in PDRIVER_OBJECT DriverObject
    )
/*
 * the driver unload routine
 * 
 * do some clean work
 *
 */
{
    PAGED_CODE();

	PsSetCreateProcessNotifyRoutine(ProcCreateNotify, TRUE);
	
	KeSetEvent(&g_EventExit, 0, FALSE);
	if(NULL != g_Thread)
	{
		KeWaitForSingleObject(g_Thread, Executive, KernelMode, FALSE, NULL);
		ObDereferenceObject(g_Thread);
	}

	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&g_ResourceProcId, TRUE);
	if(g_FilePointer != NULL)
	{
		ObDereferenceObject(g_FilePointer);
		g_FilePointer = NULL;
	}
	ExReleaseResourceLite(&g_ResourceProcId);
	KeLeaveCriticalRegion();

	ExDeleteResourceLite(&g_ResourceProcId);
}

VOID ProcCreateNotify(
    IN HANDLE  ParentId,
    IN HANDLE  ProcessId,
    IN BOOLEAN  Create
    )
/*
 * the process create callback
 * 
 * check if the process filename is like L"*\\PROCMON\\*\\*.EXE"
 * if it is, then save the process information, when the process 
 * exit, we must clear the saved process information
 *
 */
{
	NTSTATUS status;
	USHORT returnedLength = 0;
	OBJECT_NAME_INFORMATION ObjNameInfo;
	POBJECT_NAME_INFORMATION pObjNameInfo = NULL;
	LARGE_INTEGER liFileId = {0};
	UNICODE_STRING Expression = RTL_CONSTANT_STRING(L"*\\PROCMON\\*\\*.EXE");

	PAGED_CODE();

	if(Create) {

		RtlZeroMemory(&ObjNameInfo, sizeof(ObjNameInfo));
		pObjNameInfo = &ObjNameInfo;
		status = GetProcessImageNameById(ProcessId, pObjNameInfo, NULL);

		if(status == STATUS_BUFFER_OVERFLOW ||
				status == STATUS_BUFFER_TOO_SMALL ||
				status == STATUS_INFO_LENGTH_MISMATCH) {

			returnedLength = pObjNameInfo->Name.Length;
			pObjNameInfo = ExAllocatePoolWithTag(PagedPool, returnedLength + sizeof(UNICODE_STRING), 'PMON');
			pObjNameInfo->Name.MaximumLength = returnedLength;

			if(NULL != pObjNameInfo) {
				
				status = GetProcessImageNameById(ProcessId, pObjNameInfo, &liFileId);
				
				if(NT_SUCCESS(status) &&
					FsRtlIsNameInExpression(&Expression, &pObjNameInfo->Name, TRUE, NULL)) {
					
					// save process id & process file pointer
					SaveProcInfo(ProcessId, &liFileId);
				}
				else
				{
					KdPrint(("ProcMon: stauts = %08X, OtherProcName: %wZ", status, &pObjNameInfo->Name));
				}

				ExFreePoolWithTag(pObjNameInfo, 'PMON');
			}
		}
	}else {

		//
		// delete id
		//
		KeEnterCriticalRegion();
		ExAcquireResourceExclusiveLite(&g_ResourceProcId, TRUE);
		if(g_ProcId == ProcessId) {

			g_ProcId = 0;
			ObDereferenceObject(g_FilePointer);
			g_FilePointer = NULL;
			g_liFileId.QuadPart = 0;

		}
		ExReleaseResourceLite(&g_ResourceProcId);
		KeLeaveCriticalRegion();
	}
}

VOID OutputThread(PVOID Context)
/*
 * output the process filename every second
 *
 */
{
	NTSTATUS status;
	LARGE_INTEGER Timeout;
	OBJECT_NAME_INFORMATION ObjInfo = {0};
	POBJECT_NAME_INFORMATION pObjInfo = NULL;
	ULONG returnedLength = sizeof(OBJECT_NAME_INFORMATION);
	PDEVICE_OBJECT pDevObj = NULL;

	PAGED_CODE();

	Timeout.QuadPart = -10000 * 1000; // one second

	do
	{
		LARGE_INTEGER liTmpFileId;
		liTmpFileId.QuadPart = 0;

		if(STATUS_TIMEOUT != KeWaitForSingleObject(&g_EventExit, 
					Executive,
					KernelMode,
					FALSE,
					&Timeout))
			break;

		KeEnterCriticalRegion();
		ExAcquireResourceSharedLite(&g_ResourceProcId, TRUE);
		if(g_ProcId != 0)
		{
			if(g_liFileId.QuadPart != 0 && g_FilePointer != NULL)
			{
				//
				// here for ntfs filesystem
				//

				liTmpFileId.QuadPart = g_liFileId.QuadPart;
				pDevObj = ((FILE_OBJECT *)g_FilePointer)->DeviceObject;
			}
			else if(g_liFileId.QuadPart == 0 && g_FilePointer != NULL)
			{
				//
				// here for fat filesystem
				//

				pObjInfo = &ObjInfo;
				returnedLength = sizeof(OBJECT_NAME_INFORMATION);
				status = ObQueryNameString(g_FilePointer,
							pObjInfo,
							returnedLength,
							&returnedLength);

				if(status == STATUS_BUFFER_OVERFLOW ||
						status == STATUS_BUFFER_TOO_SMALL ||
						status == STATUS_INFO_LENGTH_MISMATCH)
				{
					pObjInfo = ExAllocatePoolWithTag(PagedPool,
							returnedLength, 'PMON');
					if(pObjInfo != NULL)
					{
						ObQueryNameString(g_FilePointer,
								pObjInfo,
								returnedLength,
								&returnedLength);

						KdPrint(("ProcMon: The process name is:%wZ\n", &pObjInfo->Name));
						ExFreePoolWithTag(pObjInfo, 'PMON');
					}
				}
			}
		}

		ExReleaseResourceLite(&g_ResourceProcId);
		KeLeaveCriticalRegion();

		//
		// for ntfs filesystem, we need get a new fileobject
		//

		if(liTmpFileId.QuadPart != 0)
		{
			//
			// get new fileobject
			//
			
			HANDLE hFile = NULL;
			OBJECT_ATTRIBUTES oa;
			UNICODE_STRING ObjName;
			IO_STATUS_BLOCK iostatus;
			PVOID pNewFileObject = NULL;
			HANDLE hDev = NULL;

			status = ObOpenObjectByPointer((PVOID)pDevObj,
						OBJ_KERNEL_HANDLE,
						NULL,
						0,
						NULL,
						KernelMode,
						&hDev);

			if(NT_SUCCESS(status))
			{
				ObjName.MaximumLength = ObjName.Length = 8;
				ObjName.Buffer = (PWSTR)&liTmpFileId;
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
						//
						// now query file name with the new fileobject
						//

						pObjInfo = &ObjInfo;
						returnedLength = sizeof(OBJECT_NAME_INFORMATION);
						status = ObQueryNameString(pNewFileObject,
									pObjInfo,
									returnedLength,
									&returnedLength);

						if(status == STATUS_BUFFER_OVERFLOW ||
								status == STATUS_BUFFER_TOO_SMALL ||
								status == STATUS_INFO_LENGTH_MISMATCH)
						{
							pObjInfo = ExAllocatePoolWithTag(PagedPool,
											returnedLength, 'PMON');
							if(pObjInfo != NULL)
							{
								ObQueryNameString(pNewFileObject,
										pObjInfo,
										returnedLength,
										&returnedLength);

								KdPrint(("ProcMon: The process name is:%wZ\n", &pObjInfo->Name));
								ExFreePoolWithTag(pObjInfo, 'PMON');
							}
						}

						ObDereferenceObject(pNewFileObject);
					}

					ZwClose(hFile);
				}

				ZwClose(hDev);
			}
		}

	}while(1);

	PsTerminateSystemThread(0);
}


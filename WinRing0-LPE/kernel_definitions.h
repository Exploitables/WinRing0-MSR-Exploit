#pragma once

#include <Windows.h>

typedef struct _UNICODE_STRING {
	USHORT	Length;
	USHORT	MaximumLength;
	PWSTR	Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef void(_stdcall* RtlInitUnicodeString)(
	PUNICODE_STRING         DestinationString,
	__drv_aliasesMem PCWSTR SourceString
	);

typedef PVOID(_stdcall* MmGetSystemRoutineAddress)(
	PUNICODE_STRING	SystemRoutineName
	);

typedef NTSTATUS(_stdcall* PsLookupProcessByProcessId)(
	HANDLE		ProcessId,
	PVOID* Process
	);

typedef HANDLE(_stdcall* PsGetCurrentProcessId)();

typedef PACCESS_TOKEN(_stdcall* PsReferencePrimaryToken)(
	PVOID	Process
	);

typedef void(_stdcall* PsDereferencePrimaryToken)(
	PACCESS_TOKEN	PrimaryToken
	);

typedef LONG_PTR(_stdcall* ObfDereferenceObject)(
	PVOID	Object
	);
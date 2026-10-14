// lang: C (WDK), file: driver_entry.c
// target: Windows 10/11 x64, WDK
// mevcut driver.h IOCTL kodlarıyla tam uyumlu

#include <ntddk.h>
#include "hypervisor.c"

#define DEVICE_NAME   L"\\Device\\nvvad86v"
#define SYMLINK_NAME  L"\\DosDevices\\nvvad86v"

typedef struct _IWIO_BUFFER {
    UINT64  securitycode;
    UINT64  securitycode2;
    INT32   process_id;
    UINT64* address_base;
    UINT64  pml4_base;
    INT32   offset;
    UINT64* clonedcr3_buff;
    UINT64* vgk_buff;
    BOOLEAN* operation;
    UINT64* cr3_buffer;
    UINT64  set_cr3_value;
    BOOLEAN isace;
    UINT64  address;
    UINT64  buffer;
    UINT64  size;
    UINT64  return_size;
    BOOLEAN write;
    BOOLEAN virtualrw;
    BOOLEAN normal_cr3;
    BOOLEAN cr3_1gb_pages;
    LONG    mouse_x;
    LONG    mouse_y;
    USHORT  mouse_flags;
    USHORT  key_MakeCode;
    USHORT  key_Flags;
    UINT64  window;
    UINT32  value;
    UINT64* buffer_m;
    const WCHAR* processname_m;
    const WCHAR* modulename_m;
    const CHAR*  kernelmodulename;
    UINT64  module_base;
    PCHAR   pattern;
    PCHAR   mask;
    UINT64* pattern_return;
} IWIO_BUFFER, *PIWIO_BUFFER;

#define IOCTL_FIND_BASE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x6201, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_GET_CR3    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x6202, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_READ_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x6206, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MOUSE_MOVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x6207, METHOD_BUFFERED, FILE_ANY_ACCESS)

static const UINT64 SECURITY_CODE  = 0x6E9B02D4A7F18C39;
static const UINT64 SECURITY_CODE2 = 0xC1F78024BD9A53EE;

static PDEVICE_OBJECT g_DevObj = NULL;
static PVOID g_mouse_object    = NULL;

static NTSTATUS km_copy(UINT64 src, UINT64 dst, SIZE_T size) {
    __try {
        RtlCopyMemory((PVOID)dst, (PVOID)src, size);
        return STATUS_SUCCESS;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }
}

static UINT64 find_process_base(INT32 pid) {
    PEPROCESS proc = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT64)pid, &proc)))
        return 0;
    UINT64 base = (UINT64)PsGetProcessSectionBaseAddress(proc);
    ObDereferenceObject(proc);
    return base;
}

static NTSTATUS process_rw(INT32 pid, UINT64 addr, UINT64 buf,
                            SIZE_T size, BOOLEAN write) {
    PEPROCESS proc = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(UINT64)pid, &proc)))
        return STATUS_NOT_FOUND;
    SIZE_T copied = 0;
    NTSTATUS st;
    if (write)
        st = MmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)buf,
                                 proc, (PVOID)addr, size, KernelMode, &copied);
    else
        st = MmCopyVirtualMemory(proc, (PVOID)addr,
                                 PsGetCurrentProcess(), (PVOID)buf,
                                 size, KernelMode, &copied);
    ObDereferenceObject(proc);
    return st;
}

static UINT64 get_process_cr3(PEPROCESS proc) {
    return *(UINT64*)((UINT8*)proc + 0x28);
}

typedef VOID (*MOUSE_CB)(PVOID, PMOUSE_INPUT_DATA, PMOUSE_INPUT_DATA);

static VOID find_mouse_object(VOID) {
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Driver\\MouClass");
    PDRIVER_OBJECT drv  = NULL;
    if (!NT_SUCCESS(ObReferenceObjectByName(&name, OBJ_CASE_INSENSITIVE,
            NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&drv)))
        return;
    if (drv->DeviceObject)
        g_mouse_object = drv->DeviceObject->DeviceExtension;
    ObDereferenceObject(drv);
}

static VOID kernel_mouse_move(LONG dx, LONG dy, USHORT flags) {
    if (!g_mouse_object) find_mouse_object();
    if (!g_mouse_object) return;
    MOUSE_INPUT_DATA mid = {};
    mid.Flags   = flags ? flags : MOUSE_MOVE_RELATIVE;
    mid.LastX   = dx;
    mid.LastY   = dy;
    UNICODE_STRING cb_name = RTL_CONSTANT_STRING(L"MouseClassServiceCallback");
    MOUSE_CB cb = (MOUSE_CB)MmGetSystemRoutineAddress(&cb_name);
    if (cb) cb(g_mouse_object, &mid, &mid + 1);
}

static NTSTATUS ioctl_dispatch(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    ULONG code  = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG in_sz = stack->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;

    if (in_sz < sizeof(IWIO_BUFFER)) {
        irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_BUFFER_TOO_SMALL;
    }

    PIWIO_BUFFER req = (PIWIO_BUFFER)irp->AssociatedIrp.SystemBuffer;

    if (req->securitycode  != SECURITY_CODE ||
        req->securitycode2 != SECURITY_CODE2) {
        st = STATUS_ACCESS_DENIED;
        goto done;
    }

    switch (code) {
    case IOCTL_FIND_BASE:
        if (req->address_base)
            *req->address_base = find_process_base(req->process_id);
        st = STATUS_SUCCESS;
        break;

    case IOCTL_READ_WRITE:
        st = process_rw(req->process_id, req->address,
                        req->buffer, (SIZE_T)req->size, req->write);
        break;

    case IOCTL_GET_CR3: {
        PEPROCESS proc = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId(
                (HANDLE)(UINT64)req->process_id, &proc))) {
            if (req->cr3_buffer)
                *req->cr3_buffer = get_process_cr3(proc);
            ObDereferenceObject(proc);
            st = STATUS_SUCCESS;
        }
        break;
    }

    case IOCTL_MOUSE_MOVE:
        kernel_mouse_move(req->mouse_x, req->mouse_y, req->mouse_flags);
        st = STATUS_SUCCESS;
        break;

    default:
        break;
    }

done:
    irp->IoStatus.Status      = st;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return st;
}

static NTSTATUS dispatch_create_close(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);
    irp->IoStatus.Status      = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static VOID driver_unload(PDRIVER_OBJECT drv) {
    UNREFERENCED_PARAMETER(drv);
    if (g_VmxActive) {
        KeIpiGenericCall((PKIPI_BROADCAST_WORKER)(ULONG_PTR)__vmx_off, 0);
        g_VmxActive = FALSE;
    }
    if (g_EptTable) MmFreeContiguousMemory(g_EptTable);
    if (g_VcpuArray) ExFreePoolWithTag(g_VcpuArray, 'VCPU');

    UNICODE_STRING symlink = RTL_CONSTANT_STRING(SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);
    IoDeleteDevice(g_DevObj);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    UNREFERENCED_PARAMETER(reg);

    UNICODE_STRING dev_name = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING sym_name = RTL_CONSTANT_STRING(SYMLINK_NAME);

    NTSTATUS st = IoCreateDevice(drv, 0, &dev_name,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DevObj);
    if (!NT_SUCCESS(st)) return st;

    IoCreateSymbolicLink(&sym_name, &dev_name);

    drv->DriverUnload                         = driver_unload;
    drv->MajorFunction[IRP_MJ_CREATE]         = dispatch_create_close;
    drv->MajorFunction[IRP_MJ_CLOSE]          = dispatch_create_close;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ioctl_dispatch;

    int cpu_info[4] = {};
    __cpuid(cpu_info, 1);
    if (!(cpu_info[2] & (1 << 5))) {
        IoDeleteSymbolicLink(&sym_name);
        IoDeleteDevice(g_DevObj);
        return STATUS_NOT_SUPPORTED;
    }

    PHYSICAL_ADDRESS pa_max; pa_max.QuadPart = MAXLONGLONG;
    g_EptTable = (PEPT_TABLE)MmAllocateContiguousMemory(
        sizeof(EPT_TABLE), pa_max);
    if (!g_EptTable) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_EptTable, sizeof(EPT_TABLE));
    g_EptPA = MmGetPhysicalAddress(g_EptTable);
    setup_ept(g_EptTable);

    g_CpuCount  = KeQueryActiveProcessorCount(NULL);
    g_VcpuArray = (PVCPU)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(VCPU) * g_CpuCount, 'VCPU');
    if (!g_VcpuArray) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(g_VcpuArray, sizeof(VCPU) * g_CpuCount);

    KeIpiGenericCall((PKIPI_BROADCAST_WORKER)virtualize_cpu, NULL);
    g_VmxActive = TRUE;

    return STATUS_SUCCESS;
}

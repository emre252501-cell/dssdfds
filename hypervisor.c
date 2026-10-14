// lang: C (WDK), file: hypervisor.c
// target: Windows 10/11 x64, WDK 10.0.26100+
// Intel VT-x hypervisor — VMXON + VMCS + EPT

#include <ntddk.h>
#include <intrin.h>
#include <wdm.h>

// ── VMCS field encoding ───────────────────────────────────────────────────────
#define VMCS_GUEST_CR0              0x6800
#define VMCS_GUEST_CR3              0x6802
#define VMCS_GUEST_CR4              0x6804
#define VMCS_GUEST_DR7              0x681A
#define VMCS_GUEST_RSP              0x681C
#define VMCS_GUEST_RIP              0x681E
#define VMCS_GUEST_RFLAGS           0x6820
#define VMCS_GUEST_CS_SEL           0x0802
#define VMCS_GUEST_SS_SEL           0x0804
#define VMCS_GUEST_DS_SEL           0x0806
#define VMCS_GUEST_ES_SEL           0x0808
#define VMCS_GUEST_FS_SEL           0x080A
#define VMCS_GUEST_GS_SEL           0x080C
#define VMCS_GUEST_TR_SEL           0x080E
#define VMCS_GUEST_LDTR_SEL         0x0810
#define VMCS_GUEST_CS_BASE          0x6808
#define VMCS_GUEST_SS_BASE          0x680A
#define VMCS_GUEST_DS_BASE          0x680C
#define VMCS_GUEST_ES_BASE          0x680E
#define VMCS_GUEST_FS_BASE          0x6810
#define VMCS_GUEST_GS_BASE          0x6812
#define VMCS_GUEST_TR_BASE          0x6814
#define VMCS_GUEST_LDTR_BASE        0x6816
#define VMCS_GUEST_GDTR_BASE        0x6818
#define VMCS_GUEST_IDTR_BASE        0x681A
#define VMCS_GUEST_CS_LIMIT         0x4800
#define VMCS_GUEST_SS_LIMIT         0x4802
#define VMCS_GUEST_DS_LIMIT         0x4804
#define VMCS_GUEST_ES_LIMIT         0x4806
#define VMCS_GUEST_FS_LIMIT         0x4808
#define VMCS_GUEST_GS_LIMIT         0x480A
#define VMCS_GUEST_TR_LIMIT         0x480C
#define VMCS_GUEST_LDTR_LIMIT       0x480E
#define VMCS_GUEST_GDTR_LIMIT       0x4810
#define VMCS_GUEST_IDTR_LIMIT       0x4812
#define VMCS_GUEST_CS_AR            0x4814
#define VMCS_GUEST_SS_AR            0x4816
#define VMCS_GUEST_DS_AR            0x4818
#define VMCS_GUEST_ES_AR            0x481A
#define VMCS_GUEST_FS_AR            0x481C
#define VMCS_GUEST_GS_AR            0x481E
#define VMCS_GUEST_TR_AR            0x4820
#define VMCS_GUEST_LDTR_AR          0x4822
#define VMCS_GUEST_ACTIVITY_STATE   0x4826
#define VMCS_GUEST_INTERRUPTIBILITY 0x4824
#define VMCS_GUEST_VMCS_LINK_PTR    0x2800

#define VMCS_HOST_CR0               0x6C00
#define VMCS_HOST_CR3               0x6C02
#define VMCS_HOST_CR4               0x6C04
#define VMCS_HOST_RSP               0x6C14
#define VMCS_HOST_RIP               0x6C16
#define VMCS_HOST_CS_SEL            0x0C00
#define VMCS_HOST_SS_SEL            0x0C02
#define VMCS_HOST_DS_SEL            0x0C04
#define VMCS_HOST_ES_SEL            0x0C06
#define VMCS_HOST_FS_SEL            0x0C08
#define VMCS_HOST_GS_SEL            0x0C0A
#define VMCS_HOST_TR_SEL            0x0C0C
#define VMCS_HOST_FS_BASE           0x6C06
#define VMCS_HOST_GS_BASE           0x6C08
#define VMCS_HOST_TR_BASE           0x6C0A
#define VMCS_HOST_GDTR_BASE         0x6C0C
#define VMCS_HOST_IDTR_BASE         0x6C0E

#define VMCS_CTRL_PIN_BASED         0x4000
#define VMCS_CTRL_CPU_BASED         0x4002
#define VMCS_CTRL_CPU_BASED2        0x401E
#define VMCS_CTRL_VMEXIT            0x400C
#define VMCS_CTRL_VMENTRY           0x4012
#define VMCS_CTRL_EPT_PTR           0x201A
#define VMCS_CTRL_CR3_TARGET_COUNT  0x400A

#define VMCS_EXIT_REASON            0x4402
#define VMCS_EXIT_INSTR_LEN         0x440C
#define VMCS_EXIT_QUALIFICATION     0x6400

#define CPU_BASED_HLT_EXITING        (1 << 7)
#define CPU_BASED_CR3_LOAD_EXITING   (1 << 15)
#define CPU_BASED_CR3_STORE_EXITING  (1 << 16)
#define CPU_BASED_ACTIVATE_SECONDARY (1 << 31)
#define CPU_BASED2_ENABLE_EPT        (1 << 1)
#define VMEXIT_HOST_ADDR_SPACE_SIZE  (1 << 9)
#define VMENTRY_IA32E_MODE_GUEST     (1 << 9)

#define EPT_READ    (1ULL << 0)
#define EPT_WRITE   (1ULL << 1)
#define EPT_EXEC    (1ULL << 2)
#define EPT_WB      (6ULL << 3)
#define EPT_LARGE   (1ULL << 7)

// ── vmread helper — WDK signature: __vmx_vmread(field, value*) ────────────────
#define VMREAD(field) _vmread_helper(field)
static UINT64 _vmread_helper(UINT64 field) {
    size_t val = 0;
    __vmx_vmread(field, &val);
    return (UINT64)val;
}

// ── structs ───────────────────────────────────────────────────────────────────
typedef struct _VMCS_REGION {
    UINT32 RevisionId;
    UINT32 AbortIndicator;
    UINT8  Data[0xFF6];
} VMCS_REGION, *PVMCS_REGION;

typedef struct _VCPU {
    PVMCS_REGION     VmxonRegion;
    PHYSICAL_ADDRESS VmxonPA;
    PVMCS_REGION     VmcsRegion;
    PHYSICAL_ADDRESS VmcsPA;
    UINT64           HostStack[0x2000];
    UINT64           GuestRsp;
    UINT64           GuestRip;
} VCPU, *PVCPU;

#define EPT_PML4_ENTRIES 512
#define EPT_PDPT_ENTRIES 512
#define EPT_PD_ENTRIES   512

typedef UINT64 EPT_ENTRY;

typedef struct _EPT_TABLE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_ENTRY Pml4[EPT_PML4_ENTRIES];
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_ENTRY Pdpt[EPT_PDPT_ENTRIES];
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_ENTRY Pd[EPT_PD_ENTRIES];
} EPT_TABLE, *PEPT_TABLE;

// ── globals ───────────────────────────────────────────────────────────────────
PVCPU      g_VcpuArray  = NULL;
PEPT_TABLE g_EptTable   = NULL;
PHYSICAL_ADDRESS g_EptPA;
ULONG      g_CpuCount   = 0;
BOOLEAN    g_VmxActive  = FALSE;

// ── EPT ───────────────────────────────────────────────────────────────────────
static UINT64 ept_ptr_encode(PHYSICAL_ADDRESS pa) {
    return (pa.QuadPart & ~0xFFFULL) | (3ULL << 3) | 6ULL;
}

static NTSTATUS setup_ept(PEPT_TABLE ept) {
    PHYSICAL_ADDRESS pdpt_pa = MmGetPhysicalAddress(ept->Pdpt);
    PHYSICAL_ADDRESS pd_pa   = MmGetPhysicalAddress(ept->Pd);

    ept->Pml4[0] = (pdpt_pa.QuadPart & ~0xFFFULL)
                 | EPT_READ | EPT_WRITE | EPT_EXEC;
    ept->Pdpt[0] = (pd_pa.QuadPart & ~0xFFFULL)
                 | EPT_READ | EPT_WRITE | EPT_EXEC;

    for (int i = 0; i < EPT_PD_ENTRIES; i++) {
        UINT64 phys = (UINT64)i * 0x200000ULL;
        ept->Pd[i]  = phys
                    | EPT_READ | EPT_WRITE | EPT_EXEC
                    | EPT_WB   | EPT_LARGE;
    }
    return STATUS_SUCCESS;
}

// ── CR adjust ─────────────────────────────────────────────────────────────────
static UINT64 adjust_cr(UINT64 val, UINT32 msr0, UINT32 msr1) {
    val |= __readmsr(msr0);
    val &= __readmsr(msr1);
    return val;
}

// ── segment helpers ───────────────────────────────────────────────────────────
#pragma pack(push, 1)
typedef struct _SEG_DESC {
    UINT16 LimitLow;
    UINT16 BaseLow;
    UINT8  BaseMid;
    UINT8  Attr0;
    UINT8  Attr1LimitHigh;
    UINT8  BaseHigh;
} SEG_DESC;
#pragma pack(pop)

static UINT32 seg_ar(UINT16 sel) {
    if (!sel) return 0x10000;
    UINT16 gdtr[5]; __sgdt(gdtr);
    SEG_DESC* gdt  = (SEG_DESC*)((UINT64)gdtr[1] | ((UINT64)gdtr[2] << 16));
    SEG_DESC* desc = &gdt[sel >> 3];
    return (desc->Attr0 | ((UINT32)desc->Attr1LimitHigh << 8)) & 0xF0FF;
}

static UINT64 seg_base(UINT16 sel) {
    if (!sel) return 0;
    UINT16 gdtr[5]; __sgdt(gdtr);
    SEG_DESC* gdt  = (SEG_DESC*)((UINT64)gdtr[1] | ((UINT64)gdtr[2] << 16));
    SEG_DESC* desc = &gdt[sel >> 3];
    UINT64 base = desc->BaseLow
                | ((UINT64)desc->BaseMid  << 16)
                | ((UINT64)desc->BaseHigh << 24);
    if (!(desc->Attr0 & 0x10))
        base |= (UINT64)(*(UINT32*)(desc + 1)) << 32;
    return base;
}

// ── VM-exit handler ───────────────────────────────────────────────────────────
VOID VmExitHandler(PVCPU vcpu) {
    UNREFERENCED_PARAMETER(vcpu);

    UINT32 reason = (UINT32)(VMREAD(VMCS_EXIT_REASON) & 0xFFFF);

    switch (reason) {
    case 28: { // CR access
        UINT64 qual = VMREAD(VMCS_EXIT_QUALIFICATION);
        UINT32 type = (UINT32)((qual >> 4) & 3);
        if ((qual & 0xF) == 3 && type == 0) {
            // CR3 write — INVEPT
            typedef struct { UINT64 EptPtr; UINT64 Rsvd; } INV_DESC;
            INV_DESC inv = { ept_ptr_encode(g_EptPA), 0 };
            __invept(1, &inv);
        }
        UINT64 rip = VMREAD(VMCS_GUEST_RIP);
        UINT64 len = VMREAD(VMCS_EXIT_INSTR_LEN);
        __vmx_vmwrite(VMCS_GUEST_RIP, rip + len);
        break;
    }
    case 12: { // HLT
        UINT64 rip = VMREAD(VMCS_GUEST_RIP);
        UINT64 len = VMREAD(VMCS_EXIT_INSTR_LEN);
        __vmx_vmwrite(VMCS_GUEST_RIP, rip + len);
        break;
    }
    default:
        break;
    }
}

// ── VMCS setup ────────────────────────────────────────────────────────────────
static NTSTATUS setup_vmcs(PVCPU vcpu) {
    RtlZeroMemory(vcpu->VmcsRegion, PAGE_SIZE);
    UINT64 vmx_basic = __readmsr(0x480);
    vcpu->VmcsRegion->RevisionId = (UINT32)(vmx_basic & 0x7FFFFFFF);

    if (__vmx_vmclear(&vcpu->VmcsPA) != 0) return STATUS_UNSUCCESSFUL;
    if (__vmx_vmptrld(&vcpu->VmcsPA) != 0) return STATUS_UNSUCCESSFUL;

    // host
    __vmx_vmwrite(VMCS_HOST_CR0, adjust_cr(__readcr0(), 0x486, 0x487));
    __vmx_vmwrite(VMCS_HOST_CR3, __readcr3());
    __vmx_vmwrite(VMCS_HOST_CR4, adjust_cr(__readcr4(), 0x488, 0x489));

    UINT16 gdtr[5]; __sgdt(gdtr);
    UINT16 idtr[5]; __sidt(idtr);

    __vmx_vmwrite(VMCS_HOST_CS_SEL, __readcs() & ~7ULL);
    __vmx_vmwrite(VMCS_HOST_SS_SEL, __readss() & ~7ULL);
    __vmx_vmwrite(VMCS_HOST_DS_SEL, __readds() & ~7ULL);
    __vmx_vmwrite(VMCS_HOST_ES_SEL, __reades() & ~7ULL);
    __vmx_vmwrite(VMCS_HOST_FS_SEL, __readfs() & ~7ULL);
    __vmx_vmwrite(VMCS_HOST_GS_SEL, __readgs() & ~7ULL);
    __vmx_vmwrite(VMCS_HOST_TR_SEL, __readtr() & ~7ULL);

    __vmx_vmwrite(VMCS_HOST_FS_BASE,   __readmsr(0xC0000100));
    __vmx_vmwrite(VMCS_HOST_GS_BASE,   __readmsr(0xC0000101));
    __vmx_vmwrite(VMCS_HOST_TR_BASE,   seg_base(__readtr()));
    __vmx_vmwrite(VMCS_HOST_GDTR_BASE, (UINT64)gdtr[1] | ((UINT64)gdtr[2] << 16));
    __vmx_vmwrite(VMCS_HOST_IDTR_BASE, (UINT64)idtr[1] | ((UINT64)idtr[2] << 16));
    __vmx_vmwrite(VMCS_HOST_RSP,
        (UINT64)vcpu->HostStack + sizeof(vcpu->HostStack) - 8);

    extern VOID VmExitAsmStub(VOID);
    __vmx_vmwrite(VMCS_HOST_RIP, (UINT64)VmExitAsmStub);

    // guest
    __vmx_vmwrite(VMCS_GUEST_CR0,   adjust_cr(__readcr0(), 0x486, 0x487));
    __vmx_vmwrite(VMCS_GUEST_CR3,   __readcr3());
    __vmx_vmwrite(VMCS_GUEST_CR4,   adjust_cr(__readcr4(), 0x488, 0x489));
    __vmx_vmwrite(VMCS_GUEST_DR7,   __readdr(7));
    __vmx_vmwrite(VMCS_GUEST_RFLAGS,__readeflags());
    __vmx_vmwrite(VMCS_GUEST_VMCS_LINK_PTR, ~0ULL);

    __vmx_vmwrite(VMCS_GUEST_CS_SEL,   __readcs());
    __vmx_vmwrite(VMCS_GUEST_SS_SEL,   __readss());
    __vmx_vmwrite(VMCS_GUEST_DS_SEL,   __readds());
    __vmx_vmwrite(VMCS_GUEST_ES_SEL,   __reades());
    __vmx_vmwrite(VMCS_GUEST_FS_SEL,   __readfs());
    __vmx_vmwrite(VMCS_GUEST_GS_SEL,   __readgs());
    __vmx_vmwrite(VMCS_GUEST_TR_SEL,   __readtr());
    __vmx_vmwrite(VMCS_GUEST_LDTR_SEL, __readldtr());

#define SET_SEG(REG, FIELD) \
    __vmx_vmwrite(VMCS_GUEST_##FIELD##_BASE,  seg_base(__read##REG())); \
    __vmx_vmwrite(VMCS_GUEST_##FIELD##_LIMIT, __segmentlimit(__read##REG())); \
    __vmx_vmwrite(VMCS_GUEST_##FIELD##_AR,    seg_ar(__read##REG()))

    SET_SEG(cs, CS); SET_SEG(ss, SS); SET_SEG(ds, DS);
    SET_SEG(es, ES); SET_SEG(fs, FS); SET_SEG(gs, GS);
    SET_SEG(tr, TR); SET_SEG(ldtr, LDTR);

    __vmx_vmwrite(VMCS_GUEST_GDTR_BASE,  (UINT64)gdtr[1] | ((UINT64)gdtr[2] << 16));
    __vmx_vmwrite(VMCS_GUEST_IDTR_BASE,  (UINT64)idtr[1] | ((UINT64)idtr[2] << 16));
    __vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, gdtr[0]);
    __vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, idtr[0]);
    __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE,   0);
    __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY, 0);

    // controls
    UINT64 pin  = __readmsr(0x48D);
    UINT64 cpu  = __readmsr(0x48E);
    UINT64 cpu2 = __readmsr(0x48F);
    UINT64 ex   = __readmsr(0x48B);
    UINT64 en   = __readmsr(0x490);

    UINT32 pin_v  = (UINT32)(pin  >> 32) & (UINT32)(pin  & 0xFFFFFFFF);
    UINT32 cpu_v  = (UINT32)(cpu  >> 32) & (UINT32)(cpu  & 0xFFFFFFFF);
    UINT32 cpu2_v = (UINT32)(cpu2 >> 32) & (UINT32)(cpu2 & 0xFFFFFFFF);
    UINT32 ex_v   = (UINT32)(ex   >> 32) & (UINT32)(ex   & 0xFFFFFFFF);
    UINT32 en_v   = (UINT32)(en   >> 32) & (UINT32)(en   & 0xFFFFFFFF);

    cpu_v  |= CPU_BASED_HLT_EXITING
            | CPU_BASED_CR3_LOAD_EXITING
            | CPU_BASED_ACTIVATE_SECONDARY;
    cpu2_v |= CPU_BASED2_ENABLE_EPT;
    ex_v   |= VMEXIT_HOST_ADDR_SPACE_SIZE;
    en_v   |= VMENTRY_IA32E_MODE_GUEST;

    __vmx_vmwrite(VMCS_CTRL_PIN_BASED,   pin_v);
    __vmx_vmwrite(VMCS_CTRL_CPU_BASED,   cpu_v);
    __vmx_vmwrite(VMCS_CTRL_CPU_BASED2,  cpu2_v);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT,      ex_v);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY,     en_v);
    __vmx_vmwrite(VMCS_CTRL_CR3_TARGET_COUNT, 0);
    __vmx_vmwrite(VMCS_CTRL_EPT_PTR, ept_ptr_encode(g_EptPA));

    return STATUS_SUCCESS;
}

// ── per-CPU virtualize ────────────────────────────────────────────────────────
VOID virtualize_cpu(ULONG_PTR ctx) {
    UNREFERENCED_PARAMETER(ctx);
    ULONG cpu = KeGetCurrentProcessorNumber();
    PVCPU vcpu = &g_VcpuArray[cpu];

    PHYSICAL_ADDRESS pa_max; pa_max.QuadPart = MAXLONGLONG;

    vcpu->VmxonRegion = (PVMCS_REGION)MmAllocateContiguousMemory(PAGE_SIZE, pa_max);
    if (!vcpu->VmxonRegion) return;
    RtlZeroMemory(vcpu->VmxonRegion, PAGE_SIZE);

    vcpu->VmcsRegion = (PVMCS_REGION)MmAllocateContiguousMemory(PAGE_SIZE, pa_max);
    if (!vcpu->VmcsRegion) return;
    RtlZeroMemory(vcpu->VmcsRegion, PAGE_SIZE);

    UINT64 vmx_basic = __readmsr(0x480);
    UINT32 rev = (UINT32)(vmx_basic & 0x7FFFFFFF);
    vcpu->VmxonRegion->RevisionId = rev;
    vcpu->VmcsRegion->RevisionId  = rev;

    vcpu->VmxonPA = MmGetPhysicalAddress(vcpu->VmxonRegion);
    vcpu->VmcsPA  = MmGetPhysicalAddress(vcpu->VmcsRegion);

    __writecr4(__readcr4() | 0x2000);

    UINT64 feat = __readmsr(0x3A);
    if (!(feat & 1)) {
        feat |= (1ULL | (1ULL << 2));
        __writemsr(0x3A, feat);
    }

    if (__vmx_on(&vcpu->VmxonPA) != 0) return;
    if (!NT_SUCCESS(setup_vmcs(vcpu))) { __vmx_off(); return; }

    extern VOID VmLaunchContinue(VOID);
    __vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)VmLaunchContinue);
    __vmx_vmwrite(VMCS_GUEST_RSP, vcpu->GuestRsp);

    __vmx_vmlaunch();
    __vmx_off();
    __writecr4(__readcr4() & ~0x2000ULL);
}

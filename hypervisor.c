// lang: C (WDK), file: hypervisor.c
// target: Windows 10/11 x64, WDK
// Intel VT-x — AMD-V değil, Intel CPU'lar için
// *WDK ile derle: Visual Studio + Windows Driver Kit*
// *test signing veya BYOVD ile yükle*
// *HVCI açık sistemlerde çalışmaz*

#include <ntddk.h>
#include <intrin.h>

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
#define VMCS_GUEST_GDTR_BASE        0x6816
#define VMCS_GUEST_IDTR_BASE        0x6818
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
#define VMCS_EXIT_QUALIFICATION     0x6400
#define VMCS_GUEST_PHYSICAL_ADDR    0x2400
#define VMCS_GUEST_LINEAR_ADDR      0x640A

// ── CPU kontrol sabitleri ─────────────────────────────────────────────────────
#define CPU_BASED_HLT_EXITING       (1 << 7)
#define CPU_BASED_CR3_LOAD_EXITING  (1 << 15)
#define CPU_BASED_CR3_STORE_EXITING (1 << 16)
#define CPU_BASED_ACTIVATE_SECONDARY (1 << 31)
#define CPU_BASED2_ENABLE_EPT       (1 << 1)
#define CPU_BASED2_UNRESTRICTED     (1 << 7)
#define VMEXIT_HOST_ADDR_SPACE_SIZE (1 << 9)
#define VMENTRY_IA32E_MODE_GUEST    (1 << 9)

// ── EPT sabitleri ─────────────────────────────────────────────────────────────
#define EPT_READ    (1ULL << 0)
#define EPT_WRITE   (1ULL << 1)
#define EPT_EXEC    (1ULL << 2)
#define EPT_WB      (6ULL << 3)
#define EPT_LARGE   (1ULL << 7)  // 2MB page

// ── VMCS region ───────────────────────────────────────────────────────────────
typedef struct _VMCS_REGION {
    UINT32 RevisionId;
    UINT32 AbortIndicator;
    UINT8  Data[0xFF6];
} VMCS_REGION, *PVMCS_REGION;

// ── per-CPU VCPU yapısı ───────────────────────────────────────────────────────
typedef struct _VCPU {
    PVMCS_REGION  VmxonRegion;
    PHYSICAL_ADDRESS VmxonPA;
    PVMCS_REGION  VmcsRegion;
    PHYSICAL_ADDRESS VmcsPA;
    UINT64        HostStack[0x2000]; // VM-exit handler stack
    UINT64        GuestRsp;
    UINT64        GuestRip;
} VCPU, *PVCPU;

// ── EPT tabloları ─────────────────────────────────────────────────────────────
#define EPT_PML4_ENTRIES 512
#define EPT_PDPT_ENTRIES 512
#define EPT_PD_ENTRIES   512

typedef UINT64 EPT_ENTRY;

typedef struct _EPT_TABLE {
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_ENTRY Pml4[EPT_PML4_ENTRIES];
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_ENTRY Pdpt[EPT_PDPT_ENTRIES];
    DECLSPEC_ALIGN(PAGE_SIZE) EPT_ENTRY Pd[EPT_PD_ENTRIES];  // ilk 1GB
} EPT_TABLE, *PEPT_TABLE;

// ── IOCTL kodları — driver.h ile uyumlu ──────────────────────────────────────
#define IOCTL_FIND_BASE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x6201, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_GET_CR3       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x6202, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_READ_WRITE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x6206, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MOUSE_MOVE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x6207, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ── global state ──────────────────────────────────────────────────────────────
static PVCPU      g_VcpuArray  = NULL;
static PEPT_TABLE g_EptTable   = NULL;
static PHYSICAL_ADDRESS g_EptPA;
static ULONG      g_CpuCount   = 0;
static BOOLEAN    g_VmxActive  = FALSE;
static PDEVICE_OBJECT g_DevObj = NULL;

// ── EPT pointer encode ────────────────────────────────────────────────────────
static UINT64 ept_ptr_encode(PHYSICAL_ADDRESS pa) {
    // memory type WB (6), page walk 4 (3), dirty/access bits off
    return (pa.QuadPart & ~0xFFFULL) | (3ULL << 3) | 6ULL;
}

// ── EPT setup — identity map ilk 512GB ───────────────────────────────────────
static NTSTATUS setup_ept(PEPT_TABLE ept) {
    PHYSICAL_ADDRESS pdpt_pa = MmGetPhysicalAddress(ept->Pdpt);
    PHYSICAL_ADDRESS pd_pa   = MmGetPhysicalAddress(ept->Pd);

    // PML4[0] → PDPT
    ept->Pml4[0] = (pdpt_pa.QuadPart & ~0xFFFULL)
                 | EPT_READ | EPT_WRITE | EPT_EXEC;

    // PDPT[0] → PD (ilk 1GB)
    ept->Pdpt[0] = (pd_pa.QuadPart & ~0xFFFULL)
                 | EPT_READ | EPT_WRITE | EPT_EXEC;

    // PD: 2MB sayfalarla 1GB identity map
    for (int i = 0; i < EPT_PD_ENTRIES; i++) {
        UINT64 phys = (UINT64)i * 0x200000ULL; // 2MB * i
        ept->Pd[i]  = phys
                    | EPT_READ | EPT_WRITE | EPT_EXEC
                    | EPT_WB   | EPT_LARGE;
    }

    return STATUS_SUCCESS;
}

// ── VMCS adjust — IA32_VMX_CR0/CR4_FIXED MSR ─────────────────────────────────
static UINT64 adjust_cr(UINT64 val, UINT32 msr_fixed0, UINT32 msr_fixed1) {
    val |=  __readmsr(msr_fixed0); // bit 1 zorunlu
    val &=  __readmsr(msr_fixed1); // bit 0 yasak
    return val;
}

// ── segment selector helpers ──────────────────────────────────────────────────
typedef struct _SEGMENT_DESCRIPTOR {
    UINT16 LimitLow;
    UINT16 BaseLow;
    UINT8  BaseMid;
    UINT8  Attr0;
    UINT8  Attr1LimitHigh;
    UINT8  BaseHigh;
} SEGMENT_DESCRIPTOR;

static UINT32 get_segment_ar(UINT16 selector) {
    if (selector == 0) return 0x10000; // unusable
    SEGMENT_DESCRIPTOR* gdt;
    UINT16 gdtr[5];
    __sgdt(gdtr);
    gdt = (SEGMENT_DESCRIPTOR*)((UINT64)gdtr[1] | ((UINT64)gdtr[2] << 16));
    SEGMENT_DESCRIPTOR* desc = &gdt[selector >> 3];
    UINT32 ar = ((desc->Attr0) | ((UINT32)desc->Attr1LimitHigh << 8)) & 0xF0FF;
    return ar;
}

static UINT32 get_segment_limit(UINT16 selector) {
    return (UINT32)__segmentlimit(selector);
}

static UINT64 get_segment_base(UINT16 selector) {
    if (selector == 0) return 0;
    SEGMENT_DESCRIPTOR* gdt;
    UINT16 gdtr[5];
    __sgdt(gdtr);
    gdt = (SEGMENT_DESCRIPTOR*)((UINT64)gdtr[1] | ((UINT64)gdtr[2] << 16));
    SEGMENT_DESCRIPTOR* desc = &gdt[selector >> 3];
    UINT64 base = desc->BaseLow
                | ((UINT64)desc->BaseMid  << 16)
                | ((UINT64)desc->BaseHigh << 24);
    // system descriptor (64-bit) — upper 32 bit bir sonraki entry'de
    if (!(desc->Attr0 & 0x10))
        base |= (UINT64)(*(UINT32*)(desc + 1)) << 32;
    return base;
}

// ── VM-exit handler — C tarafı ────────────────────────────────────────────────
// asm stub bu fonksiyonu çağırır
VOID VmExitHandler(PVCPU vcpu) {
    UINT32 reason = (UINT32)__vmx_vmread(VMCS_EXIT_REASON) & 0xFFFF;

    switch (reason) {
    case 28: // CR access
    {
        UINT64 qual = __vmx_vmread(VMCS_EXIT_QUALIFICATION);
        UINT32 cr   = qual & 0xF;
        UINT32 type = (qual >> 4) & 3; // 0=MOV to CR, 1=MOV from CR
        UINT32 reg  = (qual >> 8) & 0xF;

        if (cr == 3 && type == 0) {
            // MOV CR3, reg — guest CR3 değişiyor, EPT flush
            // INVEPT single context
            struct { UINT64 EptPtr; UINT64 Reserved; } inv_desc;
            inv_desc.EptPtr   = ept_ptr_encode(g_EptPA);
            inv_desc.Reserved = 0;
            __invept(1, &inv_desc);
        }
        // RIP'i ilerlet
        UINT64 rip   = __vmx_vmread(VMCS_GUEST_RIP);
        UINT64 inslen = __vmx_vmread(0x440C); // VM_EXIT_INSTRUCTION_LEN
        __vmx_vmwrite(VMCS_GUEST_RIP, rip + inslen);
        break;
    }
    case 12: // HLT
        // guest HLT — RIP ilerlet, devam et
    {
        UINT64 rip    = __vmx_vmread(VMCS_GUEST_RIP);
        UINT64 inslen = __vmx_vmread(0x440C);
        __vmx_vmwrite(VMCS_GUEST_RIP, rip + inslen);
        break;
    }
    default:
        // bilinmeyen exit — guest'e devam et
        break;
    }
}

// ── tek CPU için VMCS setup ───────────────────────────────────────────────────
static NTSTATUS setup_vmcs(PVCPU vcpu) {
    // VMCS'yi temizle
    RtlZeroMemory(vcpu->VmcsRegion, PAGE_SIZE);

    // revision ID
    UINT64 vmx_basic = __readmsr(0x480); // IA32_VMX_BASIC
    vcpu->VmcsRegion->RevisionId = (UINT32)(vmx_basic & 0x7FFFFFFF);

    // VMCLEAR + VMPTRLD
    if (__vmx_vmclear(&vcpu->VmcsPA) != 0) return STATUS_UNSUCCESSFUL;
    if (__vmx_vmptrld(&vcpu->VmcsPA) != 0) return STATUS_UNSUCCESSFUL;

    // ── Host state ────────────────────────────────────────────────────────────
    __vmx_vmwrite(VMCS_HOST_CR0, adjust_cr(__readcr0(), 0x486, 0x487));
    __vmx_vmwrite(VMCS_HOST_CR3, __readcr3());
    __vmx_vmwrite(VMCS_HOST_CR4, adjust_cr(__readcr4(), 0x488, 0x489));

    UINT16 gdtr_buf[5]; __sgdt(gdtr_buf);
    UINT16 idtr_buf[5]; __sidt(idtr_buf);

    __vmx_vmwrite(VMCS_HOST_CS_SEL,   __readcs() & ~7);
    __vmx_vmwrite(VMCS_HOST_SS_SEL,   __readss() & ~7);
    __vmx_vmwrite(VMCS_HOST_DS_SEL,   __readds() & ~7);
    __vmx_vmwrite(VMCS_HOST_ES_SEL,   __reades() & ~7);
    __vmx_vmwrite(VMCS_HOST_FS_SEL,   __readfs() & ~7);
    __vmx_vmwrite(VMCS_HOST_GS_SEL,   __readgs() & ~7);
    __vmx_vmwrite(VMCS_HOST_TR_SEL,   __readtr() & ~7);

    __vmx_vmwrite(VMCS_HOST_FS_BASE,   __readmsr(0xC0000100)); // IA32_FS_BASE
    __vmx_vmwrite(VMCS_HOST_GS_BASE,   __readmsr(0xC0000101)); // IA32_GS_BASE
    __vmx_vmwrite(VMCS_HOST_TR_BASE,
        get_segment_base(__readtr()));
    __vmx_vmwrite(VMCS_HOST_GDTR_BASE,
        (UINT64)gdtr_buf[1] | ((UINT64)gdtr_buf[2] << 16));
    __vmx_vmwrite(VMCS_HOST_IDTR_BASE,
        (UINT64)idtr_buf[1] | ((UINT64)idtr_buf[2] << 16));

    // host RSP = VCPU stack'in tepesi
    __vmx_vmwrite(VMCS_HOST_RSP,
        (UINT64)vcpu->HostStack + sizeof(vcpu->HostStack) - 8);

    // host RIP = VM-exit asm stub
    extern VOID VmExitAsmStub(VOID);
    __vmx_vmwrite(VMCS_HOST_RIP, (UINT64)VmExitAsmStub);

    // ── Guest state — şu anki CPU durumunu yakala ─────────────────────────────
    __vmx_vmwrite(VMCS_GUEST_CR0,
        adjust_cr(__readcr0(), 0x486, 0x487));
    __vmx_vmwrite(VMCS_GUEST_CR3, __readcr3());
    __vmx_vmwrite(VMCS_GUEST_CR4,
        adjust_cr(__readcr4(), 0x488, 0x489));
    __vmx_vmwrite(VMCS_GUEST_DR7, __readdr(7));
    __vmx_vmwrite(VMCS_GUEST_RFLAGS, __readeflags());
    __vmx_vmwrite(VMCS_GUEST_VMCS_LINK_PTR, ~0ULL);

    // segment register'lar
    __vmx_vmwrite(VMCS_GUEST_CS_SEL,   __readcs());
    __vmx_vmwrite(VMCS_GUEST_SS_SEL,   __readss());
    __vmx_vmwrite(VMCS_GUEST_DS_SEL,   __readds());
    __vmx_vmwrite(VMCS_GUEST_ES_SEL,   __reades());
    __vmx_vmwrite(VMCS_GUEST_FS_SEL,   __readfs());
    __vmx_vmwrite(VMCS_GUEST_GS_SEL,   __readgs());
    __vmx_vmwrite(VMCS_GUEST_TR_SEL,   __readtr());
    __vmx_vmwrite(VMCS_GUEST_LDTR_SEL, __readldtr());

#define SET_SEG(seg, SEG) \
    __vmx_vmwrite(VMCS_GUEST_##SEG##_BASE,  get_segment_base(__read##seg())); \
    __vmx_vmwrite(VMCS_GUEST_##SEG##_LIMIT, get_segment_limit(__read##seg())); \
    __vmx_vmwrite(VMCS_GUEST_##SEG##_AR,    get_segment_ar(__read##seg()))

    SET_SEG(cs, CS); SET_SEG(ss, SS); SET_SEG(ds, DS);
    SET_SEG(es, ES); SET_SEG(fs, FS); SET_SEG(gs, GS);
    SET_SEG(tr, TR); SET_SEG(ldtr, LDTR);

    __vmx_vmwrite(VMCS_GUEST_GDTR_BASE,
        (UINT64)gdtr_buf[1] | ((UINT64)gdtr_buf[2] << 16));
    __vmx_vmwrite(VMCS_GUEST_IDTR_BASE,
        (UINT64)idtr_buf[1] | ((UINT64)idtr_buf[2] << 16));
    __vmx_vmwrite(VMCS_GUEST_GDTR_LIMIT, gdtr_buf[0]);
    __vmx_vmwrite(VMCS_GUEST_IDTR_LIMIT, idtr_buf[0]);

    __vmx_vmwrite(VMCS_GUEST_ACTIVITY_STATE,   0); // active
    __vmx_vmwrite(VMCS_GUEST_INTERRUPTIBILITY, 0);

    // ── VM-execution controls ──────────────────────────────────────────────────
    UINT64 pin_based = __readmsr(0x48D); // IA32_VMX_TRUE_PINBASED_CTLS
    UINT64 cpu_based = __readmsr(0x48E); // IA32_VMX_TRUE_PROCBASED_CTLS
    UINT64 cpu_based2= __readmsr(0x48F); // IA32_VMX_TRUE_PROCBASED_CTLS2 — bazı CPU'larda 0x48B
    UINT64 exit_ctrl = __readmsr(0x48B); // IA32_VMX_TRUE_EXIT_CTLS
    UINT64 entry_ctrl= __readmsr(0x490); // IA32_VMX_TRUE_ENTRY_CTLS

    UINT32 pin   = (UINT32)(pin_based >> 32)  & (UINT32)(pin_based  & 0xFFFFFFFF);
    UINT32 cpu   = (UINT32)(cpu_based >> 32)  & (UINT32)(cpu_based  & 0xFFFFFFFF);
    UINT32 cpu2  = (UINT32)(cpu_based2 >> 32) & (UINT32)(cpu_based2 & 0xFFFFFFFF);
    UINT32 exits = (UINT32)(exit_ctrl >> 32)  & (UINT32)(exit_ctrl  & 0xFFFFFFFF);
    UINT32 entry = (UINT32)(entry_ctrl >> 32) & (UINT32)(entry_ctrl & 0xFFFFFFFF);

    cpu  |= CPU_BASED_HLT_EXITING
          | CPU_BASED_CR3_LOAD_EXITING
          | CPU_BASED_ACTIVATE_SECONDARY;
    cpu2 |= CPU_BASED2_ENABLE_EPT;
    exits|= VMEXIT_HOST_ADDR_SPACE_SIZE;
    entry|= VMENTRY_IA32E_MODE_GUEST;

    __vmx_vmwrite(VMCS_CTRL_PIN_BASED,    pin);
    __vmx_vmwrite(VMCS_CTRL_CPU_BASED,    cpu);
    __vmx_vmwrite(VMCS_CTRL_CPU_BASED2,   cpu2);
    __vmx_vmwrite(VMCS_CTRL_VMEXIT,       exits);
    __vmx_vmwrite(VMCS_CTRL_VMENTRY,      entry);
    __vmx_vmwrite(VMCS_CTRL_CR3_TARGET_COUNT, 0);

    // EPT pointer
    __vmx_vmwrite(VMCS_CTRL_EPT_PTR, ept_ptr_encode(g_EptPA));

    return STATUS_SUCCESS;
}

// ── tek CPU'yu virtualize et ──────────────────────────────────────────────────
static VOID virtualize_cpu(PVOID ctx) {
    ULONG cpu = KeGetCurrentProcessorNumber();
    PVCPU vcpu = &g_VcpuArray[cpu];

    // VMXON region alloc
    PHYSICAL_ADDRESS pa_max;
    pa_max.QuadPart = MAXLONGLONG;
    vcpu->VmxonRegion = (PVMCS_REGION)MmAllocateContiguousMemory(
        PAGE_SIZE, pa_max);
    if (!vcpu->VmxonRegion) return;
    RtlZeroMemory(vcpu->VmxonRegion, PAGE_SIZE);

    vcpu->VmcsRegion = (PVMCS_REGION)MmAllocateContiguousMemory(
        PAGE_SIZE, pa_max);
    if (!vcpu->VmcsRegion) return;
    RtlZeroMemory(vcpu->VmcsRegion, PAGE_SIZE);

    // revision ID
    UINT64 vmx_basic = __readmsr(0x480);
    UINT32 rev = (UINT32)(vmx_basic & 0x7FFFFFFF);
    vcpu->VmxonRegion->RevisionId = rev;
    vcpu->VmcsRegion->RevisionId  = rev;

    vcpu->VmxonPA = MmGetPhysicalAddress(vcpu->VmxonRegion);
    vcpu->VmcsPA  = MmGetPhysicalAddress(vcpu->VmcsRegion);

    // CR4.VMXE = 1
    __writecr4(__readcr4() | 0x2000);

    // IA32_FEATURE_CONTROL lock + VMXON enable
    UINT64 feat = __readmsr(0x3A);
    if (!(feat & 1)) {
        feat |= (1ULL | (1ULL << 2)); // lock + VMXON outside SMX
        __writemsr(0x3A, feat);
    }

    // VMXON
    if (__vmx_on(&vcpu->VmxonPA) != 0) return;

    // VMCS setup
    if (!NT_SUCCESS(setup_vmcs(vcpu))) {
        __vmx_off();
        return;
    }

    // guest RIP/RSP = VMLAUNCH'tan sonra devam edecek yer
    // bu satırdan sonra guest olarak devam eder
    extern VOID VmLaunchContinue(VOID);
    __vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)VmLaunchContinue);
    __vmx_vmwrite(VMCS_GUEST_RSP, (UINT64)vcpu->GuestRsp);

    // VMLAUNCH
    __vmx_vmlaunch();

    // buraya gelirse VMLAUNCH başarısız
    __vmx_off();
    __writecr4(__readcr4() & ~0x2000ULL);
}

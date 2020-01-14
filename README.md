# Kconfig hardened check

## Motivation

There are plenty of Linux kernel hardening config options. A lot of them are
not enabled by the major distros. We have to enable these options ourselves to
make our systems more secure.

But nobody likes checking configs manually. So let the computers do their job!

__kconfig-hardened-check.py__ helps me to check the Linux kernel Kconfig option list
against my hardening preferences, which are based on the

  - [KSPP recommended settings][1],
  - [CLIP OS kernel configuration][2],
  - last public [grsecurity][3] patch (options which they disable).

I also created [__Linux Kernel Defence Map__][4] that is a graphical representation of the
relationships between these hardening features and the corresponding vulnerability classes
or exploitation techniques.

## Supported microarchitectures

  - X86_64
  - X86_32
  - ARM64
  - ARM

## Script output examples

### Usage
```
usage: kconfig-hardened-check.py [-h] [-p {X86_64,X86_32,ARM64,ARM}]
                                 [-c CONFIG] [--debug] [--json]

Checks the hardening options in the Linux kernel config

optional arguments:
  -h, --help            show this help message and exit
  -p {X86_64,X86_32,ARM64,ARM}, --print {X86_64,X86_32,ARM64,ARM}
                        print hardening preferences for selected architecture
  -c CONFIG, --config CONFIG
                        check the config_file against these preferences
  --debug               enable internal debug mode
  --json                print results in JSON format

```

### Script output for `Ubuntu 18.04 (Bionic Beaver)` kernel config
```
#./kconfig-hardened-check.py -c config_files/distros/ubuntu-bionic-generic.config
[+] Trying to detect architecture in "config_files/distros/ubuntu-bionic-generic.config"...
[+] Detected architecture: X86_64
[+] Checking "config_files/distros/ubuntu-bionic-generic.config" against hardening preferences...
                 option name                 | desired val | decision |       reason       |   check result
=========================================================================================================================
CONFIG_BUG                                   |      y      |defconfig |  self_protection   |   OK
CONFIG_STRICT_KERNEL_RWX                     |      y      |defconfig |  self_protection   |   OK
CONFIG_STACKPROTECTOR_STRONG                 |      y      |defconfig |  self_protection   |   OK: CONFIG_CC_STACKPROTECTOR_STRONG "y"
CONFIG_SLUB_DEBUG                            |      y      |defconfig |  self_protection   |   OK
CONFIG_STRICT_MODULE_RWX                     |      y      |defconfig |  self_protection   |   OK
CONFIG_MICROCODE                             |      y      |defconfig |  self_protection   |   OK
CONFIG_RETPOLINE                             |      y      |defconfig |  self_protection   |   OK
CONFIG_X86_SMAP                              |      y      |defconfig |  self_protection   |   OK
CONFIG_X86_UMIP                              |      y      |defconfig |  self_protection   |   OK: CONFIG_X86_INTEL_UMIP "y"
CONFIG_IOMMU_SUPPORT                         |      y      |defconfig |  self_protection   |   OK
CONFIG_SYN_COOKIES                           |      y      |defconfig |  self_protection   |   OK
CONFIG_PAGE_TABLE_ISOLATION                  |      y      |defconfig |  self_protection   |   OK
CONFIG_RANDOMIZE_MEMORY                      |      y      |defconfig |  self_protection   |   OK
CONFIG_INTEL_IOMMU                           |      y      |defconfig |  self_protection   |   OK
CONFIG_AMD_IOMMU                             |      y      |defconfig |  self_protection   |   OK
CONFIG_VMAP_STACK                            |      y      |defconfig |  self_protection   |   OK
CONFIG_RANDOMIZE_BASE                        |      y      |defconfig |  self_protection   |   OK
CONFIG_THREAD_INFO_IN_TASK                   |      y      |defconfig |  self_protection   |   OK
CONFIG_BUG_ON_DATA_CORRUPTION                |      y      |   kspp   |  self_protection   |   FAIL: "is not set"
CONFIG_DEBUG_WX                              |      y      |   kspp   |  self_protection   |   OK
CONFIG_SCHED_STACK_END_CHECK                 |      y      |   kspp   |  self_protection   |   OK
CONFIG_SLAB_FREELIST_HARDENED                |      y      |   kspp   |  self_protection   |   OK
CONFIG_SLAB_FREELIST_RANDOM                  |      y      |   kspp   |  self_protection   |   OK
CONFIG_SHUFFLE_PAGE_ALLOCATOR                |      y      |   kspp   |  self_protection   |   FAIL: not found
CONFIG_FORTIFY_SOURCE                        |      y      |   kspp   |  self_protection   |   OK
CONFIG_GCC_PLUGINS                           |      y      |   kspp   |  self_protection   |   FAIL: "is not set"
CONFIG_GCC_PLUGIN_RANDSTRUCT                 |      y      |   kspp   |  self_protection   |   FAIL: not found
CONFIG_GCC_PLUGIN_LATENT_ENTROPY             |      y      |   kspp   |  self_protection   |   FAIL: not found
CONFIG_DEBUG_LIST                            |      y      |   kspp   |  self_protection   |   FAIL: "is not set"
CONFIG_DEBUG_SG                              |      y      |   kspp   |  self_protection   |   FAIL: "is not set"
CONFIG_DEBUG_CREDENTIALS                     |      y      |   kspp   |  self_protection   |   FAIL: "is not set"
CONFIG_DEBUG_NOTIFIERS                       |      y      |   kspp   |  self_protection   |   FAIL: "is not set"
CONFIG_HARDENED_USERCOPY                     |      y      |   kspp   |  self_protection   |   OK
CONFIG_HARDENED_USERCOPY_FALLBACK            | is not set  |   kspp   |  self_protection   |   OK: not found
CONFIG_MODULE_SIG                            |      y      |   kspp   |  self_protection   |   OK
CONFIG_MODULE_SIG_ALL                        |      y      |   kspp   |  self_protection   |   OK
CONFIG_MODULE_SIG_SHA512                     |      y      |   kspp   |  self_protection   |   OK
CONFIG_MODULE_SIG_FORCE                      |      y      |   kspp   |  self_protection   |   FAIL: "is not set"
CONFIG_DEFAULT_MMAP_MIN_ADDR                 |    65536    |   kspp   |  self_protection   |   OK
CONFIG_REFCOUNT_FULL                         |      y      |   kspp   |  self_protection   |   FAIL: "is not set"
CONFIG_INIT_STACK_ALL                        |      y      |  clipos  |  self_protection   |   FAIL: not found
CONFIG_INIT_ON_ALLOC_DEFAULT_ON              |      y      |  clipos  |  self_protection   |   FAIL: not found
CONFIG_INIT_ON_FREE_DEFAULT_ON               |      y      |  clipos  |  self_protection   |   FAIL: not found
CONFIG_SECURITY_DMESG_RESTRICT               |      y      |  clipos  |  self_protection   |   FAIL: "is not set"
CONFIG_DEBUG_VIRTUAL                         |      y      |  clipos  |  self_protection   |   FAIL: "is not set"
CONFIG_STATIC_USERMODEHELPER                 |      y      |  clipos  |  self_protection   |   FAIL: "is not set"
CONFIG_SLAB_MERGE_DEFAULT                    | is not set  |  clipos  |  self_protection   |   FAIL: "y"
CONFIG_GCC_PLUGIN_RANDSTRUCT_PERFORMANCE     | is not set  |  clipos  |  self_protection   |   FAIL: CONFIG_GCC_PLUGIN_RANDSTRUCT is needed
CONFIG_GCC_PLUGIN_STACKLEAK                  |      y      |  clipos  |  self_protection   |   FAIL: not found
CONFIG_STACKLEAK_METRICS                     | is not set  |  clipos  |  self_protection   |   FAIL: CONFIG_GCC_PLUGIN_STACKLEAK is needed
CONFIG_STACKLEAK_RUNTIME_DISABLE             | is not set  |  clipos  |  self_protection   |   FAIL: CONFIG_GCC_PLUGIN_STACKLEAK is needed
CONFIG_RANDOM_TRUST_CPU                      | is not set  |  clipos  |  self_protection   |   OK: not found
CONFIG_INTEL_IOMMU_SVM                       |      y      |  clipos  |  self_protection   |   OK
CONFIG_INTEL_IOMMU_DEFAULT_ON                |      y      |  clipos  |  self_protection   |   FAIL: "is not set"
CONFIG_SLUB_DEBUG_ON                         |      y      |    my    |  self_protection   |   FAIL: "is not set"
CONFIG_RESET_ATTACK_MITIGATION               |      y      |    my    |  self_protection   |   OK
CONFIG_AMD_IOMMU_V2                          |      y      |    my    |  self_protection   |   FAIL: "m"
CONFIG_SECURITY                              |      y      |defconfig |  security_policy   |   OK
CONFIG_SECURITY_WRITABLE_HOOKS               | is not set  |defconfig |  security_policy   |   OK
CONFIG_SECURITY_YAMA                         |      y      |   kspp   |  security_policy   |   OK
CONFIG_SECURITY_LOADPIN                      |      y      |    my    |  security_policy   |   FAIL: "is not set"
CONFIG_SECURITY_LOCKDOWN_LSM                 |      y      |    my    |  security_policy   |   FAIL: not found
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY           |      y      |    my    |  security_policy   |   FAIL: not found
CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY|      y      |    my    |  security_policy   |   FAIL: not found
CONFIG_SECURITY_SAFESETID                    |      y      |    my    |  security_policy   |   FAIL: not found
CONFIG_SECCOMP                               |      y      |defconfig | cut_attack_surface |   OK
CONFIG_SECCOMP_FILTER                        |      y      |defconfig | cut_attack_surface |   OK
CONFIG_STRICT_DEVMEM                         |      y      |defconfig | cut_attack_surface |   OK
CONFIG_MODULES                               | is not set  |   kspp   | cut_attack_surface |   FAIL: "y"
CONFIG_DEVMEM                                | is not set  |   kspp   | cut_attack_surface |   FAIL: "y"
CONFIG_IO_STRICT_DEVMEM                      |      y      |   kspp   | cut_attack_surface |   FAIL: "is not set"
CONFIG_ACPI_CUSTOM_METHOD                    | is not set  |   kspp   | cut_attack_surface |   OK
CONFIG_COMPAT_BRK                            | is not set  |   kspp   | cut_attack_surface |   OK
CONFIG_DEVKMEM                               | is not set  |   kspp   | cut_attack_surface |   OK
CONFIG_COMPAT_VDSO                           | is not set  |   kspp   | cut_attack_surface |   OK
CONFIG_BINFMT_MISC                           | is not set  |   kspp   | cut_attack_surface |   FAIL: "m"
CONFIG_INET_DIAG                             | is not set  |   kspp   | cut_attack_surface |   FAIL: "m"
CONFIG_KEXEC                                 | is not set  |   kspp   | cut_attack_surface |   FAIL: "y"
CONFIG_PROC_KCORE                            | is not set  |   kspp   | cut_attack_surface |   FAIL: "y"
CONFIG_LEGACY_PTYS                           | is not set  |   kspp   | cut_attack_surface |   FAIL: "y"
CONFIG_HIBERNATION                           | is not set  |   kspp   | cut_attack_surface |   FAIL: "y"
CONFIG_LEGACY_VSYSCALL_NONE                  |      y      |   kspp   | cut_attack_surface |   FAIL: "is not set"
CONFIG_IA32_EMULATION                        | is not set  |   kspp   | cut_attack_surface |   FAIL: "y"
CONFIG_X86_X32                               | is not set  |   kspp   | cut_attack_surface |   FAIL: "y"
CONFIG_MODIFY_LDT_SYSCALL                    | is not set  |   kspp   | cut_attack_surface |   FAIL: "y"
CONFIG_X86_PTDUMP                            | is not set  |grsecurity| cut_attack_surface |   OK
CONFIG_ZSMALLOC_STAT                         | is not set  |grsecurity| cut_attack_surface |   OK
CONFIG_PAGE_OWNER                            | is not set  |grsecurity| cut_attack_surface |   OK
CONFIG_DEBUG_KMEMLEAK                        | is not set  |grsecurity| cut_attack_surface |   OK
CONFIG_BINFMT_AOUT                           | is not set  |grsecurity| cut_attack_surface |   OK: not found
CONFIG_KPROBES                               | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_UPROBES                               | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_GENERIC_TRACER                        | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_PROC_VMCORE                           | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_PROC_PAGE_MONITOR                     | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_USELIB                                | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_CHECKPOINT_RESTORE                    | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_USERFAULTFD                           | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_HWPOISON_INJECT                       | is not set  |grsecurity| cut_attack_surface |   FAIL: "m"
CONFIG_MEM_SOFT_DIRTY                        | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_DEVPORT                               | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_DEBUG_FS                              | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_NOTIFIER_ERROR_INJECTION              | is not set  |grsecurity| cut_attack_surface |   FAIL: "m"
CONFIG_ACPI_TABLE_UPGRADE                    | is not set  | lockdown | cut_attack_surface |   FAIL: "y"
CONFIG_ACPI_APEI_EINJ                        | is not set  | lockdown | cut_attack_surface |   FAIL: "m"
CONFIG_PROFILING                             | is not set  | lockdown | cut_attack_surface |   FAIL: "y"
CONFIG_BPF_SYSCALL                           | is not set  | lockdown | cut_attack_surface |   FAIL: "y"
CONFIG_MMIOTRACE_TEST                        | is not set  | lockdown | cut_attack_surface |   OK
CONFIG_KSM                                   | is not set  |  clipos  | cut_attack_surface |   FAIL: "y"
CONFIG_KALLSYMS                              | is not set  |  clipos  | cut_attack_surface |   FAIL: "y"
CONFIG_X86_VSYSCALL_EMULATION                | is not set  |  clipos  | cut_attack_surface |   FAIL: "y"
CONFIG_MAGIC_SYSRQ                           | is not set  |  clipos  | cut_attack_surface |   FAIL: "y"
CONFIG_KEXEC_FILE                            | is not set  |  clipos  | cut_attack_surface |   FAIL: "y"
CONFIG_USER_NS                               | is not set  |  clipos  | cut_attack_surface |   FAIL: "y"
CONFIG_LDISC_AUTOLOAD                        | is not set  |  clipos  | cut_attack_surface |   OK: not found
CONFIG_MMIOTRACE                             | is not set  |    my    | cut_attack_surface |   FAIL: "y"
CONFIG_LIVEPATCH                             | is not set  |    my    | cut_attack_surface |   FAIL: "y"
CONFIG_IP_DCCP                               | is not set  |    my    | cut_attack_surface |   FAIL: "m"
CONFIG_IP_SCTP                               | is not set  |    my    | cut_attack_surface |   FAIL: "m"
CONFIG_FTRACE                                | is not set  |    my    | cut_attack_surface |   FAIL: "y"
CONFIG_BPF_JIT                               | is not set  |    my    | cut_attack_surface |   FAIL: "y"
CONFIG_VIDEO_VIVID                           | is not set  |    my    | cut_attack_surface |   FAIL: "m"
CONFIG_ARCH_MMAP_RND_BITS                    |     32      |  clipos  |userspace_hardening |   FAIL: "28"

[+] config check is finished: 'OK' - 49 / 'FAIL' - 74
```

## kconfig-hardened-check versioning

I usually update the kernel hardening recommendations after each Linux kernel release.

So the version of `kconfig-hardened-check` is associated with the corresponding version of the kernel.

The version format is: __[major_number].[kernel_version]__

The current version of `kconfig-hardened-check` is __0.5.3__, it's marked with the git tag.


## Questions and answers

__Q:__ How disabling `CONFIG_USER_NS` cuts the attack surface? It's needed for containers!

__A:__ Yes, the `CONFIG_USER_NS` option provides some isolation between the userspace programs,
but the script recommends disabling it to cut the attack surface __of the kernel__.

The rationale:

  - A nice LWN article about the corresponding LKML discussion: https://lwn.net/Articles/673597/

  - A twitter thread about `CONFIG_USER_NS` and security: https://twitter.com/robertswiecki/status/1095447678949953541

<br />

__Q:__ Why `CONFIG_GCC_PLUGINS` is automatically disabled during the kernel compilation?

__A:__ It means that your gcc doesn't support plugins. For example, if you have `gcc-7` on Ubuntu,
try to install `gcc-7-plugin-dev` package, it should help.

<br />

__Q:__ KSPP and CLIP OS recommend `CONFIG_PANIC_ON_OOPS=y`. Why doesn't this tool do the same?

__A:__ I personally don't support this recommendation because it provides easy denial-of-service
attacks for the whole system (kernel oops is not a rare situation). I think having `CONFIG_BUG` is enough here --
if we have a kernel oops in the process context, the offending/attacking process is killed.

[1]: http://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings
[2]: https://docs.clip-os.org/clipos/kernel.html#configuration
[3]: https://grsecurity.net/
[4]: https://github.com/a13xp0p0v/linux-kernel-defence-map

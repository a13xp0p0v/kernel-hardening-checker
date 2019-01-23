# Kconfig hardened check

## Motivation

There are plenty of Linux kernel hardening config options. A lot of them are
not enabled by the major distros. We have to enable these options ourselves to
make our systems more secure.

But nobody likes checking configs manually. So let the computers do their job!

__kconfig-hardened-check.py__ helps me to check the Linux kernel Kconfig option list
against my hardening preferences for `x86_64`, which are based on the
[KSPP recommended settings][1] and last public [grsecurity][2] patch (options
which they disable).

Please don't cry if my Python code looks like C. I'm just a kernel developer.

__TODO:__ add hardening preferences for ARM.

## Script output examples

### Usage
```
#./kconfig-hardened-check.py
usage: kconfig-hardened-check.py [-h] [-p {X86_64,X86_32,ARM64}] [-c CONFIG]
                                 [--debug]

Checks the hardening options in the Linux kernel config

optional arguments:
  -h, --help            show this help message and exit
  -p {X86_64,X86_32,ARM64}, --print {X86_64,X86_32,ARM64}
                        print hardening preferences for selected architecture
  -c CONFIG, --config CONFIG
                        check the config_file against these preferences
  --debug               enable internal debug mode
```

### Script output for `Ubuntu 18.04 (Bionic Beaver)` kernel config
```
#./kconfig-hardened-check.py -c config_files/distros/ubuntu-bionic-generic.config
[+] Trying to detect architecture in "config_files/distros/ubuntu-bionic-generic.config"...
[+] Detected architecture: X86_64
[+] Checking "config_files/distros/ubuntu-bionic-generic.config" against hardening preferences...
  option name                            | desired val | decision |       reason       ||        check result        
  ===================================================================================================================
  CONFIG_BUG                             |      y      |defconfig |  self_protection   ||             OK             
  CONFIG_STRICT_KERNEL_RWX               |      y      |defconfig |  self_protection   ||             OK             
  CONFIG_STACKPROTECTOR_STRONG           |      y      |defconfig |  self_protection   ||CONFIG_CC_STACKPROTECTOR_STRONG: OK ("y")
  CONFIG_THREAD_INFO_IN_TASK             |      y      |defconfig |  self_protection   ||             OK             
  CONFIG_SLUB_DEBUG                      |      y      |defconfig |  self_protection   ||             OK             
  CONFIG_STRICT_MODULE_RWX               |      y      |defconfig |  self_protection   ||             OK             
  CONFIG_PAGE_TABLE_ISOLATION            |      y      |defconfig |  self_protection   ||             OK             
  CONFIG_RANDOMIZE_MEMORY                |      y      |defconfig |  self_protection   ||             OK             
  CONFIG_RANDOMIZE_BASE                  |      y      |defconfig |  self_protection   ||             OK             
  CONFIG_RETPOLINE                       |      y      |defconfig |  self_protection   ||             OK             
  CONFIG_X86_SMAP                        |      y      |defconfig |  self_protection   ||             OK             
  CONFIG_X86_INTEL_UMIP                  |      y      |defconfig |  self_protection   ||             OK             
  CONFIG_SYN_COOKIES                     |      y      |defconfig |  self_protection   ||             OK             
  CONFIG_VMAP_STACK                      |      y      |defconfig |  self_protection   ||             OK             
  CONFIG_BUG_ON_DATA_CORRUPTION          |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_DEBUG_WX                        |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_SCHED_STACK_END_CHECK           |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_PAGE_POISONING                  |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_SLAB_FREELIST_HARDENED          |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_SLAB_FREELIST_RANDOM            |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_HARDENED_USERCOPY               |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_HARDENED_USERCOPY_FALLBACK      | is not set  |   kspp   |  self_protection   ||       OK: not found        
  CONFIG_FORTIFY_SOURCE                  |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_GCC_PLUGINS                     |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_GCC_PLUGIN_RANDSTRUCT           |      y      |   kspp   |  self_protection   ||      FAIL: not found       
  CONFIG_GCC_PLUGIN_STRUCTLEAK           |      y      |   kspp   |  self_protection   ||      FAIL: not found       
  CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL |      y      |   kspp   |  self_protection   ||      FAIL: not found       
  CONFIG_GCC_PLUGIN_LATENT_ENTROPY       |      y      |   kspp   |  self_protection   ||      FAIL: not found       
  CONFIG_DEBUG_LIST                      |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_DEBUG_SG                        |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_DEBUG_CREDENTIALS               |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_DEBUG_NOTIFIERS                 |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_MODULE_SIG                      |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_MODULE_SIG_ALL                  |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_MODULE_SIG_SHA512               |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_MODULE_SIG_FORCE                |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_DEFAULT_MMAP_MIN_ADDR           |    65536    |   kspp   |  self_protection   ||             OK             
  CONFIG_REFCOUNT_FULL                   |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_GCC_PLUGIN_STACKLEAK            |      y      |    my    |  self_protection   ||      FAIL: not found       
  CONFIG_LOCK_DOWN_KERNEL                |      y      |    my    |  self_protection   ||             OK             
  CONFIG_SLUB_DEBUG_ON                   |      y      |    my    |  self_protection   ||     FAIL: "is not set"     
  CONFIG_SECURITY_DMESG_RESTRICT         |      y      |    my    |  self_protection   ||     FAIL: "is not set"     
  CONFIG_STATIC_USERMODEHELPER           |      y      |    my    |  self_protection   ||     FAIL: "is not set"     
  CONFIG_SECURITY_LOADPIN                |      y      |    my    |  self_protection   ||     FAIL: "is not set"     
  CONFIG_PAGE_POISONING_NO_SANITY        | is not set  |    my    |  self_protection   ||       OK: not found        
  CONFIG_PAGE_POISONING_ZERO             | is not set  |    my    |  self_protection   ||       OK: not found        
  CONFIG_SLAB_MERGE_DEFAULT              | is not set  |    my    |  self_protection   ||         FAIL: "y"          
  CONFIG_SECURITY                        |      y      |defconfig |  security_policy   ||             OK             
  CONFIG_SECURITY_YAMA                   |      y      |   kspp   |  security_policy   ||             OK             
  CONFIG_SECURITY_SELINUX_DISABLE        | is not set  |   kspp   |  security_policy   ||             OK             
  CONFIG_SECCOMP                         |      y      |defconfig | cut_attack_surface ||             OK             
  CONFIG_SECCOMP_FILTER                  |      y      |defconfig | cut_attack_surface ||             OK             
  CONFIG_STRICT_DEVMEM                   |      y      |defconfig | cut_attack_surface ||             OK             
  CONFIG_IO_STRICT_DEVMEM                |      y      |   kspp   | cut_attack_surface ||     FAIL: "is not set"     
  CONFIG_ACPI_CUSTOM_METHOD              | is not set  |   kspp   | cut_attack_surface ||             OK             
  CONFIG_COMPAT_BRK                      | is not set  |   kspp   | cut_attack_surface ||             OK             
  CONFIG_DEVKMEM                         | is not set  |   kspp   | cut_attack_surface ||             OK             
  CONFIG_COMPAT_VDSO                     | is not set  |   kspp   | cut_attack_surface ||             OK             
  CONFIG_BINFMT_MISC                     | is not set  |   kspp   | cut_attack_surface ||         FAIL: "m"          
  CONFIG_INET_DIAG                       | is not set  |   kspp   | cut_attack_surface ||         FAIL: "m"          
  CONFIG_KEXEC                           | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_PROC_KCORE                      | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_LEGACY_PTYS                     | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_HIBERNATION                     | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_LEGACY_VSYSCALL_NONE            |      y      |   kspp   | cut_attack_surface ||     FAIL: "is not set"     
  CONFIG_IA32_EMULATION                  | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_X86_X32                         | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_MODIFY_LDT_SYSCALL              | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_X86_PTDUMP                      | is not set  |grsecurity| cut_attack_surface ||             OK             
  CONFIG_ZSMALLOC_STAT                   | is not set  |grsecurity| cut_attack_surface ||             OK             
  CONFIG_PAGE_OWNER                      | is not set  |grsecurity| cut_attack_surface ||             OK             
  CONFIG_DEBUG_KMEMLEAK                  | is not set  |grsecurity| cut_attack_surface ||             OK             
  CONFIG_BINFMT_AOUT                     | is not set  |grsecurity| cut_attack_surface ||       OK: not found        
  CONFIG_KPROBES                         | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"          
  CONFIG_UPROBES                         | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"          
  CONFIG_GENERIC_TRACER                  | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"          
  CONFIG_PROC_VMCORE                     | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"          
  CONFIG_PROC_PAGE_MONITOR               | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"          
  CONFIG_USELIB                          | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"          
  CONFIG_CHECKPOINT_RESTORE              | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"          
  CONFIG_USERFAULTFD                     | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"          
  CONFIG_HWPOISON_INJECT                 | is not set  |grsecurity| cut_attack_surface ||         FAIL: "m"          
  CONFIG_MEM_SOFT_DIRTY                  | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"          
  CONFIG_DEVPORT                         | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"          
  CONFIG_DEBUG_FS                        | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"          
  CONFIG_NOTIFIER_ERROR_INJECTION        | is not set  |grsecurity| cut_attack_surface ||         FAIL: "m"          
  CONFIG_ACPI_TABLE_UPGRADE              | is not set  | lockdown | cut_attack_surface ||         FAIL: "y"          
  CONFIG_ACPI_APEI_EINJ                  | is not set  | lockdown | cut_attack_surface ||         FAIL: "m"          
  CONFIG_PROFILING                       | is not set  | lockdown | cut_attack_surface ||         FAIL: "y"          
  CONFIG_BPF_SYSCALL                     | is not set  | lockdown | cut_attack_surface ||         FAIL: "y"          
  CONFIG_MMIOTRACE_TEST                  | is not set  | lockdown | cut_attack_surface ||             OK             
  CONFIG_MMIOTRACE                       | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_KEXEC_FILE                      | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_LIVEPATCH                       | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_USER_NS                         | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_IP_DCCP                         | is not set  |    my    | cut_attack_surface ||         FAIL: "m"          
  CONFIG_IP_SCTP                         | is not set  |    my    | cut_attack_surface ||         FAIL: "m"          
  CONFIG_FTRACE                          | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_BPF_JIT                         | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_ARCH_MMAP_RND_BITS              |     32      |    my    |userspace_protection||         FAIL: "28"         

[-] config check is NOT PASSED: 56 errors
```

__Go and fix them all!__


N.B. If `CONFIG_GCC_PLUGIN*` options are automatically disabled during your kernel compilation,
then your gcc doesn't support plugins. For example, if you have `gcc-7` on Ubuntu, try to install
`gcc-7-plugin-dev` package, it should help.


[1]: http://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings
[2]: https://grsecurity.net/

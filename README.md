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

## Script output examples

### Usage
```
#./kconfig-hardened-check.py
usage: kconfig-hardened-check.py [-h] [-p] [-c CONFIG] [--debug]

Checks the hardening options in the Linux kernel config

optional arguments:
  -h, --help            show this help message and exit
  -p, --print           print hardening preferences
  -c CONFIG, --config CONFIG
                        check the config_file against these preferences
  --debug               enable internal debug mode
```

### Script output for `Ubuntu 18.04 (Bionic Beaver)` kernel config
```
#./kconfig-hardened-check.py -c config_files/ubuntu-bionic-generic.config
[+] Checking "config_files/ubuntu-bionic-generic.config" against hardening preferences...
  option name                            | desired val | decision |       reason       ||        check result        
  ===================================================================================================================
  CONFIG_BUG                             |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_PAGE_TABLE_ISOLATION            |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_RETPOLINE                       |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_X86_64                          |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_STRICT_KERNEL_RWX               |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_STRICT_MODULE_RWX               |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_DEBUG_WX                        |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_RANDOMIZE_BASE                  |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_RANDOMIZE_MEMORY                |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_STACKPROTECTOR_STRONG           |      y      | ubuntu18 |  self_protection   ||CONFIG_CC_STACKPROTECTOR_STRONG: OK ("y")
  CONFIG_VMAP_STACK                      |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_THREAD_INFO_IN_TASK             |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_SCHED_STACK_END_CHECK           |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_SLUB_DEBUG                      |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_SLAB_FREELIST_HARDENED          |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_SLAB_FREELIST_RANDOM            |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_HARDENED_USERCOPY               |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_FORTIFY_SOURCE                  |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_MODULE_SIG                      |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_MODULE_SIG_ALL                  |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_MODULE_SIG_SHA512               |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_SYN_COOKIES                     |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_DEFAULT_MMAP_MIN_ADDR           |    65536    | ubuntu18 |  self_protection   ||             OK             
  CONFIG_BUG_ON_DATA_CORRUPTION          |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_PAGE_POISONING                  |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_GCC_PLUGINS                     |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_GCC_PLUGIN_RANDSTRUCT           |      y      |   kspp   |  self_protection   ||      FAIL: not found       
  CONFIG_GCC_PLUGIN_STRUCTLEAK           |      y      |   kspp   |  self_protection   ||      FAIL: not found       
  CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL |      y      |   kspp   |  self_protection   ||      FAIL: not found       
  CONFIG_GCC_PLUGIN_LATENT_ENTROPY       |      y      |   kspp   |  self_protection   ||      FAIL: not found       
  CONFIG_REFCOUNT_FULL                   |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_DEBUG_LIST                      |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_DEBUG_SG                        |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_DEBUG_CREDENTIALS               |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_DEBUG_NOTIFIERS                 |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_MODULE_SIG_FORCE                |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_HARDENED_USERCOPY_FALLBACK      | is not set  |   kspp   |  self_protection   ||       OK: not found        
  CONFIG_GCC_PLUGIN_STACKLEAK            |      y      |    my    |  self_protection   ||      FAIL: not found       
  CONFIG_SLUB_DEBUG_ON                   |      y      |    my    |  self_protection   ||     FAIL: "is not set"     
  CONFIG_SECURITY_DMESG_RESTRICT         |      y      |    my    |  self_protection   ||     FAIL: "is not set"     
  CONFIG_STATIC_USERMODEHELPER           |      y      |    my    |  self_protection   ||     FAIL: "is not set"     
  CONFIG_PAGE_POISONING_NO_SANITY        | is not set  |    my    |  self_protection   ||       OK: not found        
  CONFIG_PAGE_POISONING_ZERO             | is not set  |    my    |  self_protection   ||       OK: not found        
  CONFIG_SECURITY                        |      y      | ubuntu18 |  security_policy   ||             OK             
  CONFIG_SECURITY_YAMA                   |      y      | ubuntu18 |  security_policy   ||             OK             
  CONFIG_SECURITY_SELINUX_DISABLE        | is not set  | ubuntu18 |  security_policy   ||             OK             
  CONFIG_SECCOMP                         |      y      | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_SECCOMP_FILTER                  |      y      | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_STRICT_DEVMEM                   |      y      | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_ACPI_CUSTOM_METHOD              | is not set  | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_COMPAT_BRK                      | is not set  | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_DEVKMEM                         | is not set  | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_COMPAT_VDSO                     | is not set  | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_X86_PTDUMP                      | is not set  | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_ZSMALLOC_STAT                   | is not set  | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_PAGE_OWNER                      | is not set  | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_DEBUG_KMEMLEAK                  | is not set  | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_BINFMT_AOUT                     | is not set  | ubuntu18 | cut_attack_surface ||       OK: not found        
  CONFIG_IO_STRICT_DEVMEM                |      y      |   kspp   | cut_attack_surface ||     FAIL: "is not set"     
  CONFIG_LEGACY_VSYSCALL_NONE            |      y      |   kspp   | cut_attack_surface ||     FAIL: "is not set"     
  CONFIG_BINFMT_MISC                     | is not set  |   kspp   | cut_attack_surface ||         FAIL: "m"          
  CONFIG_INET_DIAG                       | is not set  |   kspp   | cut_attack_surface ||         FAIL: "m"          
  CONFIG_KEXEC                           | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_PROC_KCORE                      | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_LEGACY_PTYS                     | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_IA32_EMULATION                  | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_X86_X32                         | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_MODIFY_LDT_SYSCALL              | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_HIBERNATION                     | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
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
  CONFIG_KEXEC_FILE                      | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_LIVEPATCH                       | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_USER_NS                         | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_IP_DCCP                         | is not set  |    my    | cut_attack_surface ||         FAIL: "m"          
  CONFIG_IP_SCTP                         | is not set  |    my    | cut_attack_surface ||         FAIL: "m"          
  CONFIG_FTRACE                          | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_PROFILING                       | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_BPF_JIT                         | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_BPF_SYSCALL                     | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_ARCH_MMAP_RND_BITS              |     32      |    my    |userspace_protection||         FAIL: "28"         

[-] config check is NOT PASSED: 51 errors
```

__Go and fix them all!__

[1]: http://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings
[2]: https://grsecurity.net/

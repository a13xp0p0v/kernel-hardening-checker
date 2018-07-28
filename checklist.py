from options import OptCheck, OR


class Checklist:
    def __init__(self, debug=False):
        self.debug = debug

        modules_not_set = OptCheck('MODULES',                'is not set', 'kspp', 'cut_attack_surface')
        devmem_not_set = OptCheck('DEVMEM',                  'is not set', 'kspp', 'cut_attack_surface')

        checklist = []
        checklist.append(OptCheck('BUG',                     'y', 'ubuntu18', 'self_protection'))
        checklist.append(OptCheck('PAGE_TABLE_ISOLATION',    'y', 'ubuntu18', 'self_protection'))
        checklist.append(OptCheck('RETPOLINE',               'y', 'ubuntu18', 'self_protection'))
        checklist.append(OptCheck('X86_64',                  'y', 'ubuntu18', 'self_protection'))
        checklist.append(OptCheck('STRICT_KERNEL_RWX',       'y', 'ubuntu18', 'self_protection'))
        checklist.append(OptCheck('STRICT_MODULE_RWX',       'y', 'ubuntu18', 'self_protection'))
        checklist.append(OptCheck('DEBUG_WX',                'y', 'ubuntu18', 'self_protection'))
        checklist.append(OptCheck('RANDOMIZE_BASE',          'y', 'ubuntu18', 'self_protection'))
        checklist.append(OptCheck('RANDOMIZE_MEMORY',        'y', 'ubuntu18', 'self_protection'))
        checklist.append(
            OR(
                OptCheck('STACKPROTECTOR_STRONG','y', 'ubuntu18', 'self_protection'),
                OptCheck('CC_STACKPROTECTOR_STRONG','y', 'ubuntu18', 'self_protection')
             )
        )
        checklist.append(OptCheck('VMAP_STACK',              'y', 'ubuntu18', 'self_protection'))
        checklist.append(OptCheck('THREAD_INFO_IN_TASK',     'y', 'ubuntu18', 'self_protection'))
        checklist.append(OptCheck('SCHED_STACK_END_CHECK',   'y', 'ubuntu18', 'self_protection'))
        checklist.append(OptCheck('SLUB_DEBUG',              'y', 'ubuntu18', 'self_protection'))
        checklist.append(OptCheck('SLAB_FREELIST_HARDENED',  'y', 'ubuntu18', 'self_protection'))
        checklist.append(OptCheck('SLAB_FREELIST_RANDOM',    'y', 'ubuntu18', 'self_protection'))
        checklist.append(OptCheck('HARDENED_USERCOPY',       'y', 'ubuntu18', 'self_protection'))
        checklist.append(OptCheck('FORTIFY_SOURCE',          'y', 'ubuntu18', 'self_protection'))
        checklist.append(OR(OptCheck('MODULE_SIG',           'y', 'ubuntu18', 'self_protection'), modules_not_set))
        checklist.append(OR(OptCheck('MODULE_SIG_ALL',       'y', 'ubuntu18', 'self_protection'), modules_not_set))
        checklist.append(OR(OptCheck('MODULE_SIG_SHA512',    'y', 'ubuntu18', 'self_protection'), modules_not_set))
        checklist.append(OptCheck('SYN_COOKIES',             'y', 'ubuntu18', 'self_protection')) # another reason?
        checklist.append(OptCheck('DEFAULT_MMAP_MIN_ADDR',   '65536', 'ubuntu18', 'self_protection'))

        checklist.append(OptCheck('BUG_ON_DATA_CORRUPTION',           'y', 'kspp', 'self_protection'))
        checklist.append(OptCheck('PAGE_POISONING',                   'y', 'kspp', 'self_protection'))
        checklist.append(OptCheck('GCC_PLUGINS',                      'y', 'kspp', 'self_protection'))
        checklist.append(OptCheck('GCC_PLUGIN_RANDSTRUCT',            'y', 'kspp', 'self_protection'))
        checklist.append(OptCheck('GCC_PLUGIN_STRUCTLEAK',            'y', 'kspp', 'self_protection'))
        checklist.append(OptCheck('GCC_PLUGIN_STRUCTLEAK_BYREF_ALL',  'y', 'kspp', 'self_protection'))
        checklist.append(OptCheck('GCC_PLUGIN_LATENT_ENTROPY',        'y', 'kspp', 'self_protection'))
        checklist.append(OptCheck('REFCOUNT_FULL',                    'y', 'kspp', 'self_protection'))
        checklist.append(OptCheck('DEBUG_LIST',                       'y', 'kspp', 'self_protection'))
        checklist.append(OptCheck('DEBUG_SG',                         'y', 'kspp', 'self_protection'))
        checklist.append(OptCheck('DEBUG_CREDENTIALS',                'y', 'kspp', 'self_protection'))
        checklist.append(OptCheck('DEBUG_NOTIFIERS',                  'y', 'kspp', 'self_protection'))
        checklist.append(OptCheck('MODULE_SIG_FORCE',                 'y', 'kspp', 'self_protection'))
        checklist.append(OptCheck('HARDENED_USERCOPY_FALLBACK',       'is not set', 'kspp', 'self_protection'))

        checklist.append(OptCheck('GCC_PLUGIN_STACKLEAK',             'y', 'my', 'self_protection'))
        checklist.append(OptCheck('SLUB_DEBUG_ON',                    'y', 'my', 'self_protection'))
        checklist.append(OptCheck('SECURITY_DMESG_RESTRICT',          'y', 'my', 'self_protection'))
        checklist.append(OptCheck('STATIC_USERMODEHELPER',            'y', 'my', 'self_protection')) # breaks systemd?
        checklist.append(OptCheck('PAGE_POISONING_NO_SANITY',         'is not set', 'my', 'self_protection'))
        checklist.append(OptCheck('PAGE_POISONING_ZERO',              'is not set', 'my', 'self_protection'))

        checklist.append(OptCheck('SECURITY',                    'y', 'ubuntu18', 'security_policy'))
        checklist.append(OptCheck('SECURITY_YAMA',               'y', 'ubuntu18', 'security_policy'))
        checklist.append(OptCheck('SECURITY_SELINUX_DISABLE',    'is not set', 'ubuntu18', 'security_policy'))

        checklist.append(OptCheck('SECCOMP',              'y', 'ubuntu18', 'cut_attack_surface'))
        checklist.append(OptCheck('SECCOMP_FILTER',       'y', 'ubuntu18', 'cut_attack_surface'))
        checklist.append(OR(OptCheck('STRICT_DEVMEM',     'y', 'ubuntu18', 'cut_attack_surface'), devmem_not_set))
        checklist.append(OptCheck('ACPI_CUSTOM_METHOD',   'is not set', 'ubuntu18', 'cut_attack_surface'))
        checklist.append(OptCheck('COMPAT_BRK',           'is not set', 'ubuntu18', 'cut_attack_surface'))
        checklist.append(OptCheck('DEVKMEM',              'is not set', 'ubuntu18', 'cut_attack_surface'))
        checklist.append(OptCheck('COMPAT_VDSO',          'is not set', 'ubuntu18', 'cut_attack_surface'))
        checklist.append(OptCheck('X86_PTDUMP',           'is not set', 'ubuntu18', 'cut_attack_surface'))
        checklist.append(OptCheck('ZSMALLOC_STAT',        'is not set', 'ubuntu18', 'cut_attack_surface'))
        checklist.append(OptCheck('PAGE_OWNER',           'is not set', 'ubuntu18', 'cut_attack_surface'))
        checklist.append(OptCheck('DEBUG_KMEMLEAK',       'is not set', 'ubuntu18', 'cut_attack_surface'))
        checklist.append(OptCheck('BINFMT_AOUT',          'is not set', 'ubuntu18', 'cut_attack_surface'))

        checklist.append(OR(OptCheck('IO_STRICT_DEVMEM',  'y', 'kspp', 'cut_attack_surface'), devmem_not_set))
        checklist.append(OptCheck('LEGACY_VSYSCALL_NONE', 'y', 'kspp', 'cut_attack_surface')) # 'vsyscall=none'
        checklist.append(OptCheck('BINFMT_MISC',          'is not set', 'kspp', 'cut_attack_surface'))
        checklist.append(OptCheck('INET_DIAG',            'is not set', 'kspp', 'cut_attack_surface'))
        checklist.append(OptCheck('KEXEC',                'is not set', 'kspp', 'cut_attack_surface'))
        checklist.append(OptCheck('PROC_KCORE',           'is not set', 'kspp', 'cut_attack_surface'))
        checklist.append(OptCheck('LEGACY_PTYS',          'is not set', 'kspp', 'cut_attack_surface'))
        checklist.append(OptCheck('IA32_EMULATION',       'is not set', 'kspp', 'cut_attack_surface'))
        checklist.append(OptCheck('X86_X32',              'is not set', 'kspp', 'cut_attack_surface'))
        checklist.append(OptCheck('MODIFY_LDT_SYSCALL',   'is not set', 'kspp', 'cut_attack_surface'))
        checklist.append(OptCheck('HIBERNATION',          'is not set', 'kspp', 'cut_attack_surface'))

        checklist.append(OptCheck('KPROBES',                 'is not set', 'grsecurity', 'cut_attack_surface'))
        checklist.append(OptCheck('UPROBES',                 'is not set', 'grsecurity', 'cut_attack_surface'))
        checklist.append(OptCheck('GENERIC_TRACER',          'is not set', 'grsecurity', 'cut_attack_surface'))
        checklist.append(OptCheck('PROC_VMCORE',             'is not set', 'grsecurity', 'cut_attack_surface'))
        checklist.append(OptCheck('PROC_PAGE_MONITOR',       'is not set', 'grsecurity', 'cut_attack_surface'))
        checklist.append(OptCheck('USELIB',                  'is not set', 'grsecurity', 'cut_attack_surface'))
        checklist.append(OptCheck('CHECKPOINT_RESTORE',      'is not set', 'grsecurity', 'cut_attack_surface'))
        checklist.append(OptCheck('USERFAULTFD',             'is not set', 'grsecurity', 'cut_attack_surface'))
        checklist.append(OptCheck('HWPOISON_INJECT',         'is not set', 'grsecurity', 'cut_attack_surface'))
        checklist.append(OptCheck('MEM_SOFT_DIRTY',          'is not set', 'grsecurity', 'cut_attack_surface'))
        checklist.append(OptCheck('DEVPORT',                 'is not set', 'grsecurity', 'cut_attack_surface'))
        checklist.append(OptCheck('DEBUG_FS',                'is not set', 'grsecurity', 'cut_attack_surface'))
        checklist.append(OptCheck('NOTIFIER_ERROR_INJECTION','is not set', 'grsecurity', 'cut_attack_surface'))

        checklist.append(OptCheck('KEXEC_FILE',           'is not set', 'my', 'cut_attack_surface'))
        checklist.append(OptCheck('LIVEPATCH',            'is not set', 'my', 'cut_attack_surface'))
        checklist.append(OptCheck('USER_NS',              'is not set', 'my', 'cut_attack_surface')) # user.max_user_namespaces=0
        checklist.append(OptCheck('IP_DCCP',              'is not set', 'my', 'cut_attack_surface'))
        checklist.append(OptCheck('IP_SCTP',              'is not set', 'my', 'cut_attack_surface'))
        checklist.append(OptCheck('FTRACE',               'is not set', 'my', 'cut_attack_surface'))
        checklist.append(OptCheck('PROFILING',            'is not set', 'my', 'cut_attack_surface'))
        checklist.append(OptCheck('BPF_JIT',              'is not set', 'my', 'cut_attack_surface'))
        checklist.append(OptCheck('BPF_SYSCALL',          'is not set', 'my', 'cut_attack_surface'))

        checklist.append(OptCheck('ARCH_MMAP_RND_BITS',   '32', 'my', 'userspace_protection'))

        checklist.append(OptCheck('LKDTM',    'm', 'my', 'feature_test'))

        self._checklist = checklist

    def __len__(self):
        return len(self._checklist)

    def __getitem__(self, index):
        return self._checklist[index]

    def check(self, config):
        for opt in self._checklist:
            if hasattr(opt, 'opts'):
                for o in opt.opts:
                    o.state = config.get_option(o.name)
            else:
                opt.state = config.get_option(opt.name)
            opt.check()

        if self.debug:
            known_options = [opt.name for opt in self._checklist]
            for option, value in config.options.items():
                if option not in known_options:
                    print("DEBUG: dunno about option {} ({})".format(option, value))


    def get_errors_count(self):
        return len(list(filter(lambda opt: opt.result.startswith('FAIL'), self._checklist)))


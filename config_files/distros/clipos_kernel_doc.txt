.. Copyright © 2018 ANSSI.
   CLIP OS is a trademark of the French Republic.
   Content licensed under the Open License version 2.0 as published by Etalab
   (French task force for Open Data).

.. _kernel:

Kernel
======

The CLIP OS kernel is based on Linux. It also integrates:

* existing hardening patches that are not upstream yet and that we consider
  relevant to our security model;
* developments made for previous CLIP OS versions that we have not upstreamed
  yet (or that cannot be);
* entirely new functionalities that have not been upstreamed yet (or that
  cannot be).

Objectives
----------

As the core of a hardened operating system, the CLIP OS kernel is particularly
responsible for:

* providing **robust security mechanisms** to higher levels of the operating
  system, such as reliable isolation primitives;
* maintaining maximal **trust in hardware resources**;
* guaranteeing its **own protection** against various threats.

Configuration
-------------

In this section we discuss our security-relevant configuration choices for
the CLIP OS kernel. Before starting, it is worth mentioning that:

* We do our best to **limit the number of kernel modules**.

  In other words, as many modules as possible should be built-in. Modules are
  only used when needed either for the initramfs or to ease the automation of
  the deployment of CLIP OS on multiple different machines (for the moment, we
  only target a QEMU-KVM guest). This is particularly important as module
  loading is disabled after CLIP OS startup.

* We **focus on a secure configuration**. The remaining of the configuration
  is minimal and it is your job to tune it for your machines and use cases.

* CLIP OS only supports the x86-64 architecture for now.

* Running 32-bit programs is voluntarily unsupported. Should you change that
  in your custom kernel, keep in mind that it requires further attention when
  configuring it (e.g., ensure that ``CONFIG_COMPAT_VDSO=n``).

* Many options that are not useful to us are disabled in order to cut attack
  surface. As they are not all detailed below, please see
  ``src/portage/clip/sys-kernel/clipos-kernel/files/config.d/blacklist`` for an
  exhaustive list of the ones we **explicitly** disable.

General setup
~~~~~~~~~~~~~

.. describe:: CONFIG_AUDIT=y

   CLIP OS will need the auditing infrastructure.

.. describe:: CONFIG_IKCONFIG=n
              CONFIG_IKHEADERS=n

   We do not need ``.config`` to be available at runtime, neither do we need
   access to kernel headers through *sysfs*.

.. describe:: CONFIG_KALLSYMS=n

   Symbols are only useful for debug and attack purposes.

.. describe:: CONFIG_USERFAULTFD=n

   The ``userfaultfd()`` system call adds attack surface and can `make heap
   sprays easier <https://duasynt.com/blog/linux-kernel-heap-spray>`_. Note
   that the ``vm.unprivileged_userfaultfd`` sysctl can also be used to restrict
   the use of this system call to privileged users.

.. describe:: CONFIG_EXPERT=y

   This unlocks additional configuration options we need.

.. ---

.. describe:: CONFIG_USER_NS=n

   User namespaces can be useful for some use cases but even more to an
   attacker. We choose to disable them for the moment, but we could also enable
   them and use the ``kernel.unprivileged_userns_clone`` sysctl provided by
   linux-hardened to disable their unprivileged use.

.. ---

.. describe:: CONFIG_SLUB_DEBUG=y

   Allow allocator validation checking to be enabled.

.. describe:: CONFIG_SLAB_MERGE_DEFAULT=n

   Merging SLAB caches can make heap exploitation easier.

.. describe:: CONFIG_SLAB_FREELIST_RANDOM=y

   Randomize allocator freelists

.. describe:: CONFIG_SLAB_FREELIST_HARDENED=y

   Harden slab metadata

.. describe:: CONFIG_SLAB_CANARY=y

   Place canaries at the end of slab allocations. [linux-hardened]_

.. ---

.. describe:: CONFIG_SHUFFLE_PAGE_ALLOCATOR=y

   Page allocator randomization is primarily a performance improvement for
   direct-mapped memory-side-cache utilization, but it does reduce the
   predictability of page allocations and thus complements
   ``SLAB_FREELIST_RANDOM``. The ``page_alloc.shuffle=1`` parameter needs to be
   added to the kernel command line.

.. ---

.. describe:: CONFIG_COMPAT_BRK=n

   Enabling this would disable brk ASLR.

.. ---

.. describe:: CONFIG_GCC_PLUGINS=y

   Enable GCC plugins, some of which are security-relevant; GCC 4.7 at least is
   required.

   .. describe:: CONFIG_GCC_PLUGIN_LATENT_ENTROPY=y

      Instrument some kernel code to gather additional (but not
      cryptographically secure) entropy at boot time.

   .. describe:: CONFIG_GCC_PLUGIN_STRUCTLEAK=y
                 CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL=y

      Prevent potential information leakage by forcing zero-initialization of:

        - structures on the stack containing userspace addresses;
        - any stack variable (thus including structures) that may be passed by
          reference and has not already been explicitly initialized.

      This is particularly important to prevent trivial bypassing of KASLR.

   .. describe:: CONFIG_GCC_PLUGIN_RANDSTRUCT=y

      Randomize layout of sensitive kernel structures. Exploits targeting such
      structures then require an additional information leak vulnerability.

   .. describe:: CONFIG_GCC_PLUGIN_RANDSTRUCT_PERFORMANCE=n

      Do not weaken structure randomization

.. ---

.. describe:: CONFIG_ARCH_MMAP_RND_BITS=32

   Use maximum number of randomized bits for the mmap base address on x86_64.
   Note that thanks to a linux-hardened patch, this also impacts the number of
   randomized bits for the stack base address.

.. ---

.. describe:: CONFIG_STACKPROTECTOR=y
              CONFIG_STACKPROTECTOR_STRONG=y

   Use ``-fstack-protector-strong`` for best stack canary coverage; GCC 4.9 at
   least is required.

.. describe:: CONFIG_VMAP_STACK=y

   Virtually-mapped stacks benefit from guard pages, thus making kernel stack
   overflows harder to exploit.

.. describe:: CONFIG_REFCOUNT_FULL=y

   Do extensive checks on reference counting to prevent use-after-free
   conditions. Without this option, on x86, there already is a fast
   assembly-based protection based on the PaX implementation but it does not
   cover all cases.

.. ---

.. describe:: CONFIG_STRICT_MODULE_RWX=y

   Enforce strict memory mappings permissions for loadable kernel modules.

.. ---

Although CLIP OS stores kernel modules in a read-only rootfs whose integrity is
guaranteed by dm-verity, we still enable and enforce module signing as an
additional layer of security:

 .. describe:: CONFIG_MODULE_SIG=y
               CONFIG_MODULE_SIG_FORCE=y
               CONFIG_MODULE_SIG_ALL=y
               CONFIG_MODULE_SIG_SHA512=y
               CONFIG_MODULE_SIG_HASH="sha512"

.. ---

.. describe:: CONFIG_INIT_STACK_ALL=n

   This option requires compiler support that is currently only available in
   Clang.

Processor type and features
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. describe:: CONFIG_RETPOLINE=y

   Retpolines are needed to protect against Spectre v2. GCC 7.3.0 or higher is
   required.

.. describe:: CONFIG_LEGACY_VSYSCALL_NONE=y
              CONFIG_LEGACY_VSYSCALL_EMULATE=n
              CONFIG_LEGACY_VSYSCALL_XONLY=n
              CONFIG_X86_VSYSCALL_EMULATION=n

   The vsyscall table is not required anymore by libc and is a fixed-position
   potential source of ROP gadgets.

.. describe:: CONFIG_MICROCODE=y

   Needed to benefit from microcode updates and thus security fixes (e.g.,
   additional Intel pseudo-MSRs to be used by the kernel as a mitigation for
   various speculative execution vulnerabilities).

.. describe:: CONFIG_X86_MSR=n
              CONFIG_X86_CPUID=n

   Enabling those features would only present userspace with more attack
   surface.

.. describe:: CONFIG_KSM=n

   Enabling this feature can make cache side-channel attacks such as
   FLUSH+RELOAD much easier to carry out.

.. ---

.. describe:: CONFIG_DEFAULT_MMAP_MIN_ADDR=65536

   This should in particular be non-zero to prevent the exploitation of kernel
   NULL pointer bugs.

.. describe:: CONFIG_MTRR=y

   Memory Type Range Registers can make speculative execution bugs a bit harder
   to exploit.

.. describe:: CONFIG_X86_PAT=y

   Page Attribute Tables are the modern equivalents of MTRRs, which we
   described above.

.. describe:: CONFIG_ARCH_RANDOM=y

   Enable the RDRAND instruction to benefit from a secure hardware RNG if
   supported. See also ``CONFIG_RANDOM_TRUST_CPU``.

.. describe:: CONFIG_X86_SMAP=y

   Enable Supervisor Mode Access Prevention to prevent ret2usr exploitation
   techniques.

.. describe:: CONFIG_X86_INTEL_UMIP=y

   Enable User Mode Instruction Prevention. Note that hardware supporting this
   feature is not common yet.

.. describe:: CONFIG_X86_INTEL_MPX=n

   Intel Memory Protection Extensions (MPX) add hardware assistance to memory
   protection. Compiler support is required but was deprecated in GCC 8 and
   removed from GCC 9. Moreover, MPX kernel support is `being dropped
   <MPX_dropped_>`_.

   .. _MPX_dropped: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f240652b6032b48ad7fa35c5e701cc4c8d697c0b

.. describe:: CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS=n

   Memory Protection Keys are a promising feature but they are still not
   supported on current hardware.

.. describe:: CONFIG_X86_INTEL_TSX_MODE_OFF=y

   Set the default value of the ``tsx`` kernel parameter to ``off``.

.. ---

Enable the **seccomp** BPF userspace API for syscall attack surface reduction:

  .. describe:: CONFIG_SECCOMP=y
                CONFIG_SECCOMP_FILTER=y

.. ---

.. describe:: CONFIG_RANDOMIZE_BASE=y

   While this may be seen as a `controversial
   <https://grsecurity.net/kaslr_an_exercise_in_cargo_cult_security.php>`_
   feature, it makes sense for CLIP OS. Indeed, KASLR may be defeated thanks to
   the kernel interfaces that are available to an attacker, or through attacks
   leveraging hardware vulnerabilities such as speculative and out-of-order
   execution ones. However, CLIP OS follows the *defense in depth* principle
   and an attack surface reduction approach. Thus, the following points make
   KASLR relevant in the CLIP OS kernel:

   * KASLR was initially designed to counter remote attacks but the strong
     security model of CLIP OS (e.g., no sysfs mounts in most containers,
     minimal procfs, no arbitrary code execution) makes a local attack
     more complex to carry out.
   * STRUCTLEAK, STACKLEAK, kptr_restrict and
     ``CONFIG_SECURITY_DMESG_RESTRICT`` are enabled in CLIP OS.
   * The CLIP OS kernel is custom-compiled (at least for a given deployment),
     its image is unreadable to all users including privileged ones and updates
     are end-to-end encrypted. This makes both the content and addresses of the
     kernel image secret. Note that, however, the production kernel image is
     currently part of an EFI binary and is not encrypted, causing it to be
     accessible to a physical attacker. This will change in the future as we
     will only use the kernel included in the EFI binary to boot and then
     *kexec* to the real production kernel whose image will be located on an
     encrypted disk partition.
   * We enable ``CONFIG_PANIC_ON_OOPS`` by default so that the kernel
     cannot recover from failed exploit attempts, thus preventing any brute
     forcing.
   * We enable Kernel Page Table Isolation, mitigating Meltdown and potential
     other hardware information leakage. Variante 3a (Rogue System Register
     Read) however remains an important threat to KASLR.

.. ---

.. describe:: CONFIG_RANDOMIZE_MEMORY=y

   Most of the above explanations stand for that feature.

.. describe:: CONFIG_KEXEC=n
              CONFIG_KEXEC_FILE=n

   Disable the ``kexec()`` system call to prevent an already-root attacker from
   rebooting on an untrusted kernel.

.. describe:: CONFIG_CRASH_DUMP=n

   A crash dump can potentially provide an attacker with useful information.
   However we disabled ``kexec()`` syscalls above thus this configuration
   option should have no impact anyway.

.. ---

.. describe:: CONFIG_MODIFY_LDT_SYSCALL=n

   This is not supposed to be needed by userspace applications and only
   increases the kernel attack surface.

Power management and ACPI options
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. describe:: CONFIG_HIBERNATION=n

   The CLIP OS swap partition is encrypted with an ephemeral key and thus
   cannot support suspend to disk.

Firmware Drivers
~~~~~~~~~~~~~~~~

.. describe:: CONFIG_RESET_ATTACK_MITIGATION=n

   In order to work properly, this mitigation requires userspace support that
   is currently not available in CLIP OS. Moreover, due to our use of Secure
   Boot, Trusted Boot and the fact that machines running CLIP OS are expected
   to lock their BIOS with a password, the type of *cold boot attacks* this
   mitigation is supposed to thwart should not be an issue.

Executable file formats / Emulations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. describe:: CONFIG_BINFMT_MISC=n

   We do not want our kernel to support miscellaneous binary classes. ELF
   binaries and interpreted scripts starting with a shebang are enough.

.. describe:: CONFIG_COREDUMP=n

   Core dumps can provide an attacker with useful information.

Networking support
~~~~~~~~~~~~~~~~~~

.. describe:: CONFIG_SYN_COOKIES=y

   Enable TCP syncookies.

Device Drivers
~~~~~~~~~~~~~~

.. describe:: CONFIG_HW_RANDOM_TPM=y

   Expose the TPM's Random Number Generator (RNG) as a Hardware RNG (HWRNG)
   device, allowing the kernel to collect randomness from it. See documentation
   of ``CONFIG_RANDOM_TRUST_CPU`` and the ``rng_core.default_quality`` command
   line parameter for supplementary information.

.. describe:: CONFIG_TCG_TPM=y

   CLIP OS leverages the TPM to ensure :ref:`boot integrity <trusted_boot>`.

.. describe:: CONFIG_DEVMEM=n

   The ``/dev/mem`` device should not be required by any user application
   nowadays.

   .. note::

      If you must enable it, at least enable ``CONFIG_STRICT_DEVMEM`` and
      ``CONFIG_IO_STRICT_DEVMEM`` to restrict at best access to this device.

.. describe:: CONFIG_DEVKMEM=n

   This virtual device is only useful for debug purposes and is very dangerous
   as it allows direct kernel memory writing (particularly useful for
   rootkits).

.. describe:: CONFIG_LEGACY_PTYS=n

   Use the modern PTY interface only.

.. describe:: CONFIG_LDISC_AUTOLOAD=n

   Do not automatically load any line discipline that is in a kernel module
   when an unprivileged user asks for it.

.. describe:: CONFIG_DEVPORT=n

   The ``/dev/port`` device should not be used anymore by userspace, and it
   could increase the kernel attack surface.

.. describe:: CONFIG_RANDOM_TRUST_CPU=n
              CONFIG_RANDOM_TRUST_BOOLOADER=n

   Do not **credit** entropy generated by the CPU manufacturer's HWRNG nor
   provided by the booloader, and included in Linux's entropy pool. Fast and
   robust initialization of Linux's CSPRNG is instead achieved thanks to the
   TPM's HWRNG (see documentation of ``CONFIG_HW_RANDOM_TPM`` and the
   ``rng_core.default_quality`` command line parameter).

.. describe:: CONFIG_STAGING=n

   *Staging* drivers are typically of lower quality and under heavy
   development. They are thus more likely to contain bugs, including security
   vulnerabilities, and should be avoided.

The IOMMU allows for protecting the system's main memory from arbitrary
accesses from devices (e.g., DMA attacks). Note that this is related to
hardware features. On a recent Intel machine, we enable the following:

  .. describe:: CONFIG_IOMMU_SUPPORT=y
                CONFIG_INTEL_IOMMU=y
                CONFIG_INTEL_IOMMU_SVM=y
                CONFIG_INTEL_IOMMU_DEFAULT_ON=y

File systems
~~~~~~~~~~~~

.. describe:: CONFIG_PROC_KCORE=n

   Enabling this would provide an attacker with precious information on the
   running kernel.

Kernel hacking
~~~~~~~~~~~~~~

.. describe:: CONFIG_MAGIC_SYSRQ=n

   This should only be needed for debugging.

.. describe:: CONFIG_DEBUG_KERNEL=y

   This is useful even in a production kernel to enable further configuration
   options that have security benefits.

.. describe:: CONFIG_DEBUG_VIRTUAL=y

   Enable sanity checks in virtual to page code.

.. describe:: CONFIG_STRICT_KERNEL_RWX=y

   Ensure kernel page tables have strict permissions.

.. describe:: CONFIG_DEBUG_WX=y

   Check and report any dangerous memory mapping permissions, i.e., both
   writable and executable kernel pages.

.. describe:: CONFIG_DEBUG_FS=n

   The debugfs virtual file system is only useful for debugging and protecting
   it would require additional work.

.. describe:: CONFIG_SLUB_DEBUG_ON=n

   Using the ``slub_debug`` command line parameter provides more fine grained
   control.

.. describe:: CONFIG_PANIC_ON_OOPS=y
              CONFIG_PANIC_TIMEOUT=-1

   Prevent potential further exploitation of a bug by immediately panicking the
   kernel.

The following options add additional checks and validation for various
commonly targeted kernel structures:

  .. describe:: CONFIG_DEBUG_CREDENTIALS=y
                CONFIG_DEBUG_NOTIFIERS=y
                CONFIG_DEBUG_LIST=y
                CONFIG_DEBUG_SG=y
  .. describe:: CONFIG_BUG_ON_DATA_CORRUPTION=y

     Note that linux-hardened patches add more places where this configuration
     option has an impact.

  .. describe:: CONFIG_SCHED_STACK_END_CHECK=y
  .. describe:: CONFIG_PAGE_POISONING=n

     We choose to poison pages with zeroes and thus prefer using
     ``init_on_free`` in combination with linux-hardened's
     ``PAGE_SANITIZE_VERIFY``.

Security
~~~~~~~~

.. describe:: CONFIG_SECURITY_DMESG_RESTRICT=y

   Prevent unprivileged users from gathering information from the kernel log
   buffer via ``dmesg(8)``. Note that this still can be overridden through the
   ``kernel.dmesg_restrict`` sysctl.

.. describe:: CONFIG_PAGE_TABLE_ISOLATION=y

   Enable KPTI to prevent Meltdown attacks and, more generally, reduce the
   number of hardware side channels.

.. ---

.. describe:: CONFIG_INTEL_TXT=n

   CLIP OS does not use Intel Trusted Execution Technology.

.. ---

.. describe:: CONFIG_HARDENED_USERCOPY=y

   Harden data copies between kernel and user spaces, preventing classes of
   heap overflow exploits and information leaks.

.. describe:: CONFIG_HARDENED_USERCOPY_FALLBACK=n

   Use strict whitelisting mode, i.e., do not ``WARN()``.

.. describe:: CONFIG_FORTIFY_SOURCE=y

   Leverage compiler to detect buffer overflows.

.. describe:: CONFIG_FORTIFY_SOURCE_STRICT_STRING=n

   This extends ``FORTIFY_SOURCE`` to intra-object overflow checking. It is
   useful to find bugs but not recommended for a production kernel yet.
   [linux-hardened]_

.. describe:: CONFIG_STATIC_USERMODEHELPER=y

   This makes the kernel route all usermode helper calls to a single binary
   that cannot have its name changed. Without this, the kernel can be tricked
   into calling an attacker-controlled binary (e.g. to bypass SMAP, cf.
   `exploitation <https://seclists.org/oss-sec/2016/q4/621>`_ of
   CVE-2016-8655).

   .. describe:: CONFIG_STATIC_USERMODEHELPER_PATH=""

      Currently, we have no need for usermode helpers therefore we simply
      disable them. If we ever need some, this path will need to be set to a
      custom trusted binary in charge of filtering and choosing what real
      helpers should then be called.

.. ---

.. describe:: CONFIG_SECURITY=y

   Enable us to choose different security modules.

.. describe:: CONFIG_SECURITY_SELINUX=y

   CLIP OS intends to leverage SELinux in its security model.

.. describe:: CONFIG_SECURITY_SELINUX_BOOTPARAM=n

   We do not need SELinux to be disableable.

.. describe:: CONFIG_SECURITY_SELINUX_DISABLE=n

   We do not want SELinux to be disabled. In addition, this would prevent LSM
   structures such as security hooks from being marked as read-only.

.. describe:: CONFIG_SECURITY_SELINUX_DEVELOP=y

   For now, but will eventually be ``n``.

.. describe:: CONFIG_SECURITY_LOCKDOWN_LSM=y
              CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y
              CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y

   Basically, the *lockdown* LSM tries to strengthen the boundary between the
   superuser and the kernel. The *integrity* mode thus restricts access to
   features that would allow userland to modify the running kernel, and the
   *confidentiality* mode extends these restrictions to features that would
   allow userland to extract confidential information held inside the kernel.
   Note that a significant portion of such features is already disabled in the
   CLIP OS kernel due to our custom configuration. The *lockdown* functionality
   is important for CLIP OS as we want to prevent an attacker, be he highly
   privileged, from persisting on a compromised machine.

.. ---

.. describe:: CONFIG_LSM="yama"

   SELinux shall be stacked too once CLIP OS uses it.

.. ---

.. describe:: CONFIG_SECURITY_YAMA=y

   The Yama LSM currently provides ptrace scope restriction (which might be
   redundant with CLIP-LSM in the future).

.. ---

.. describe:: CONFIG_INTEGRITY=n

   The integrity subsystem provides several components, the security benefits
   of which are already enforced by CLIP OS (e.g., read-only mounts for all
   parts of the system containing executable programs).

.. ---

.. describe:: CONFIG_SECURITY_PERF_EVENTS_RESTRICT=y

   See documentation about the ``kernel.perf_event_paranoid`` sysctl below.
   [linux-hardened]_

.. ---

.. describe:: CONFIG_SECURITY_TIOCSTI_RESTRICT=y

   This prevents unprivileged users from using the TIOCSTI ioctl to inject
   commands into other processes that share a tty session. [linux-hardened]_

.. ---

.. describe:: CONFIG_GCC_PLUGIN_STACKLEAK=y
              CONFIG_STACKLEAK_TRACK_MIN_SIZE=100
              CONFIG_STACKLEAK_METRICS=n
              CONFIG_STACKLEAK_RUNTIME_DISABLE=n

``STACKLEAK`` erases the kernel stack before returning from system calls,
leaving it initialized to a poison value. This both reduces the information
that kernel stack leak bugs can reveal and the exploitability of uninitialized
stack variables. However, it does not cover functions reaching the same stack
depth as prior functions during the same system call.

It used to also block kernel stack depth overflows caused by ``alloca()``, such
as Stack Clash attacks. We maintained this functionality for our kernel for a
while but eventually `dropped it
<https://github.com/clipos/src_external_linux/commit/3e5f9114fc2f70f6d2ae5d10db10869e0564eb03>`_.

.. describe:: CONFIG_INIT_ON_FREE_DEFAULT_ON=y
              CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y

   These set ``init_on_free=1`` and ``init_on_alloc=1`` on the kernel command
   line. See the documentation of these kernel parameters for details.

.. describe:: CONFIG_PAGE_SANITIZE_VERIFY=y
              CONFIG_SLAB_SANITIZE_VERIFY=y

   Verify that newly allocated pages and slab allocations are zeroed to detect
   write-after-free bugs. This works in concert with ``init_on_free`` and is
   adjusted to not be redundant with ``init_on_alloc``.
   [linux-hardened]_

.. ---


Compilation
-----------

GCC version 7.3.0 or higher is required to fully benefit from retpolines
(``-mindirect-branch=thunk-extern``).


Sysctl Security Tuning
----------------------

Many sysctls are not security-relevant or only play a role if some kernel
configuration options are enabled/disabled. In other words, the following is
tightly related to the CLIP OS kernel configuration detailed above.

.. describe:: dev.tty.ldisc_autoload = 0

   See ``CONFIG_LDISC_AUTOLOAD`` above, which serves as a default value for
   this sysctl.

.. describe:: kernel.kptr_restrict = 2

   Hide kernel addresses in ``/proc`` and other interfaces, even to privileged
   users.

.. describe:: kernel.yama.ptrace_scope = 3

   Enable the strictest ptrace scope restriction provided by the Yama LSM.

.. describe:: kernel.perf_event_paranoid = 3

   This completely disallows unprivileged access to the ``perf_event_open()``
   system call. This is actually not needed as we already enable
   ``CONFIG_SECURITY_PERF_EVENTS_RESTRICT``. [linux-hardened]_

   Note that this requires a patch included in linux-hardened (see `here
   <https://lwn.net/Articles/696216/>`_ for the reason why it is not upstream).
   Indeed, on a mainline kernel without such a patch, the above is equivalent
   to setting this sysctl to ``2``, which would still allow the profiling of
   user processes.

.. describe:: kernel.tiocsti_restrict = 1

   This is already forced by the ``CONFIG_SECURITY_TIOCSTI_RESTRICT`` kernel
   configuration option that we enable. [linux-hardened]_

The following two sysctls help mitigating TOCTOU vulnerabilities by preventing
users from creating symbolic or hard links to files they do not own or have
read/write access to:

  .. describe:: fs.protected_symlinks = 1
                fs.protected_hardlinks = 1

In addition, the following other two sysctls impose restrictions on the opening
of FIFOs and regular files in order to make similar spoofing attacks harder
(note however that `these restrictions currently do not apply to networked
filesystems, among others <sysctl_protected_limitations_>`_):

  .. describe:: fs.protected_fifos = 2
                fs.protected_regular = 2

.. _sysctl_protected_limitations: https://www.openwall.com/lists/oss-security/2020/01/28/2

We do not simply disable the BPF Just in Time compiler as CLIP OS plans on
using it:

  .. describe:: kernel.unprivileged_bpf_disabled = 1

     Prevent unprivileged users from using BPF.

  .. describe:: net.core.bpf_jit_harden = 2

     Trades off performance but helps mitigate JIT spraying.

.. describe:: kernel.deny_new_usb = 0

   The management of USB devices is handled at a higher level by CLIP OS.
   [linux-hardened]_

.. describe:: kernel.device_sidechannel_restrict = 1

   Restrict device timing side channels. [linux-hardened]_

.. describe:: fs.suid_dumpable = 0

   Do not create core dumps of setuid executables.  Note that we already
   disable all core dumps by setting ``CONFIG_COREDUMP=n``.

.. describe:: kernel.pid_max = 65536

   Increase the space for PID values.

.. describe:: kernel.modules_disabled = 1

   Disable module loading once systemd has loaded the ones required for the
   running machine according to a profile (i.e., a predefined and
   hardware-specific list of modules).

Pure network sysctls (``net.ipv4.*`` and ``net.ipv6.*``) will be detailed in a
separate place.


Command line parameters
-----------------------

We pass the following command line parameters to the kernel:

.. describe:: extra_latent_entropy

   This parameter provided by a linux-hardened patch (based on the PaX
   implementation) enables a very simple form of latent entropy extracted
   during system start-up and added to the entropy obtained with
   ``GCC_PLUGIN_LATENT_ENTROPY``. [linux-hardened]_

.. describe:: pti=on

   This force-enables KPTI even on CPUs claiming to be safe from Meltdown.

.. describe:: spectre_v2=on

   Same reasoning as above but for the Spectre v2 vulnerability. Note that this
   implies ``spectre_v2_user=on``, which enables the mitigation against user
   space to user space task attacks (namely IBPB and STIBP when available and
   relevant).

.. describe:: spec_store_bypass_disable=seccomp

   Same reasoning as above but for the Spectre v4 vulnerability. Note that this
   mitigation requires updated microcode for Intel processors.


.. describe:: mds=full,nosmt

   This parameter controls optional mitigations for the Microarchitectural Data
   Sampling (MDS) class of Intel CPU vulnerabilities. Not specifying this
   parameter is equivalent to setting ``mds=full``, which leaves SMT enabled
   and therefore is not a complete mitigation. Note that this mitigation
   requires an Intel microcode update and also addresses the TSX Asynchronous
   Abort (TAA) Intel CPU vulnerability on systems that are affected by MDS.

.. describe:: iommu=force

   Even if we correctly enable the IOMMU in the kernel configuration, the
   kernel can still decide for various reasons to not initialize it at boot.
   Therefore, we force it with this parameter. Note that with some Intel
   chipsets, you may need to add ``intel_iommu=igfx_off`` to allow your GPU to
   access the physical memory directly without going through the DMA Remapping.

.. describe:: slub_debug=F

   The ``F`` option adds many sanity checks to various slab operations. Other
   interesting options that we considered but eventually chose to not use are:

    * The ``P`` option, which enables poisoning on slab cache allocations,
      disables the ``init_on_free`` and ``SLAB_SANITIZE_VERIFY`` features. As
      they respectively poison with zeroes on object freeing and check the
      zeroing on object allocations, we prefer enabling them instead of using
      ``slub_debug=P``.
    * The ``Z`` option enables red zoning, i.e., it adds extra areas around
      slab objects that detect when one is overwritten past its real size.
      This can help detect overflows but we already rely on ``SLAB_CANARY``
      provided by linux-hardened. A canary is much better than a simple red
      zone as it is supposed to be random.

.. describe:: page_alloc.shuffle=1

   See ``CONFIG_SHUFFLE_PAGE_ALLOCATOR``.

.. describe:: rng_core.default_quality=512

   Increase trust in the TPM's HWRNG to robustly and fastly initialize Linux's
   CSPRNG by **crediting** half of the entropy it provides.

Also, note that:

* ``slub_nomerge`` is not used as we already set
  ``CONFIG_SLAB_MERGE_DEFAULT=n`` in the kernel configuration.
* ``l1tf``: The built-in PTE Inversion mitigation is sufficient to mitigate
  the L1TF vulnerability as long as CLIP OS is not used as an hypervisor with
  untrusted guest VMs. If it were to be someday, ``l1tf=full,force`` should be
  used to force-enable VMX unconditional cache flushes and force-disable SMT
  (note that an Intel microcode update is not required for this mitigation to
  work but improves performance by providing a way to invalidate caches with a
  finer granularity).
* ``tsx=off``: This parameter is already set by default thanks to
  ``CONFIG_X86_INTEL_TSX_MODE_OFF``. It deactivates the Intel TSX feature on
  CPUs that support TSX control (i.e. are recent enough or received a microcode
  update) and that are not already vulnerable to MDS, therefore mitigating the
  TSX Asynchronous Abort (TAA) Intel CPU vulnerability.
* ``tsx_async_abort``: This parameter controls optional mitigations for the TSX
  Asynchronous Abort (TAA) Intel CPU vulnerability. Due to our use of
  ``mds=full,nosmt`` in addition to ``CONFIG_X86_INTEL_TSX_MODE_OFF``, CLIP OS
  is already protected against this vulnerability as long as the CPU microcode
  has been updated, whether or not the CPU is affected by MDS. For the record,
  if we wanted to keep TSX activated, we could specify
  ``tsx_async_abort=full,nosmt``. Not specifying this parameter is equivalent
  to setting ``tsx_async_abort=full``, which leaves SMT enabled and therefore
  is not a complete mitigation. Note that this mitigation requires an Intel
  microcode update and has no effect on systems that are already affected by
  MDS and enable mitigations against it, nor on systems that disable TSX.
* ``kvm.nx_huge_pages``: This parameter allows to control the KVM hypervisor
  iTLB multihit mitigations. Such mitigations are not needed as long as CLIP OS
  is not used as an hypervisor with untrusted guest VMs. If it were to be
  someday, ``kvm.nx_huge_pages=force`` should be used to ensure that guests
  cannot exploit the iTLB multihit erratum to crash the host.
* ``mitigations``: This parameter controls optional mitigations for CPU
  vulnerabilities in an arch-independent and more coarse-grained way. For now,
  we keep using arch-specific options for the sake of explicitness. Not setting
  this parameter equals setting it to ``auto``, which itself does not update
  anything.
* ``init_on_free=1`` is automatically set due to ``INIT_ON_FREE_DEFAULT_ON``. It
  zero-fills page and slab allocations on free to reduce risks of information
  leaks and help mitigate a subset of use-after-free vulnerabilities.
* ``init_on_alloc=1`` is automatically set due to ``INIT_ON_ALLOC_DEFAULT_ON``.
  The purpose of this functionality is to eliminate several kinds of
  *uninitialized heap memory* flaws by zero-filling:

  * all page allocator and slab allocator memory when allocated: this is
    already guaranteed by our use of ``init_on_free`` in combination with
    ``PAGE_SANITIZE_VERIFY`` and ``SLAB_SANITIZE_VERIFY`` from linux-hardened,
    and thus has no effect;
  * a few more *special* objects when allocated: these are the ones for which
    we enable ``init_on_alloc`` as they are not covered by the aforementioned
    combination of ``init_on_free`` and ``SANITIZE_VERIFY`` features.

.. rubric:: Citations and origin of some items

.. [linux-hardened]
   This item is provided by the ``linux-hardened`` patches.

.. vim: set tw=79 ts=2 sts=2 sw=2 et:

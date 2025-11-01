Export of Github issues for [a13xp0p0v/kernel-hardening-checker](https://github.com/a13xp0p0v/kernel-hardening-checker).

# [\#205 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/205) `open`: feedback wanted
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/21078693?u=ea6720d19e50301f32cdbbf74ef758cbc41d6cad&v=4" width="50">[alexmyczko](https://github.com/alexmyczko) opened issue at [2025-10-29 18:51](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/205):

I had a look at the things it is reporting and this came out:
 
What are your thoughts about it? DISCLAIMER, only apply settings you understand and have tested.
 
First I check the outputs of all three categories: sysctl kernel settings, cmdline options, and kernel configuration:

https://github.com/alexmyczko/autoexec.bat/blob/master/config.sys/debian-kernel-hardening-checker
 
Then this helper script helps with the kernel .config:

https://github.com/alexmyczko/autoexec.bat/blob/master/config.sys/install-1up-kernel

How are others using this?

^ I have only tested this with Debian. It is likely to work with Ubuntu too. No idea about non-deb based systems...

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-11-01 18:05](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/205#issuecomment-3476633314):

Hello @alexmyczko,

I agree with your point "`only apply settings you understand and have tested`".
That's why I think that changing these settings automatically may be dangerous.
Let me quote the man page of `kernel-hardening-checker`:
> Please note that changing the Linux kernel security parameters may also affect system performance and functionality of userspace software. Therefore, when setting these parameters, consider the threat model of your Linux-based information system and thoroughly test its typical workload.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-11-01 18:22](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/205#issuecomment-3476648764):

> How are others using this?

I think many system administrators and developers use `kernel-hardening-checker` for security compliance: they get the report from the tool and decide which parameters should be fixed.

I also know some GNU/Linux distro maintainers that use `kernel-hardening-checker` for improving the configuration of the distro kernels. I guess they make these changes manually and carefully. To help with such decisions, I've created the Linux Kernel Defence Map https://github.com/a13xp0p0v/linux-kernel-defence-map -- it shows the relationships between various security hardening features, vulnerabilities and exploit technique. 

Anyway, some users asked for a json mode in `kernel-hardening-checker` for integration it with other tools: https://github.com/a13xp0p0v/kernel-hardening-checker/issues/20.
So this feature has been added and it works fine: `/bin/kernel-hardening-checker -a -m json`.


-------------------------------------------------------------------------------

# [\#204 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/204) `merged`: Update README with link to package manager versions

#### <img src="https://avatars.githubusercontent.com/u/21078693?u=ea6720d19e50301f32cdbbf74ef758cbc41d6cad&v=4" width="50">[alexmyczko](https://github.com/alexmyczko) opened issue at [2025-10-28 12:58](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/204):

Added a link to the package manager versions for kernel-hardening-checker.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-10-29 18:29](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/204#issuecomment-3463104677):

Cool, I didn't know about repology.org!
Thanks for the contribution. Merged!


-------------------------------------------------------------------------------

# [\#203 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/203) `merged`: New tests and code refactoring

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) opened issue at [2025-10-27 12:45](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/203):

Hello, I have worked on all types of tests and some code improvements. Unit tests now provide 100% coverage, functional tests 99% (we don't have enough checks for more).

I tried to submit the tests atomically, indicating a link to the specific line of code that it covers to make it easier for you to review.

Implemented a couple of hacky tricks to mask the PATH and rename a number of files. For unit tests, I wrote a series of test scenarios that now cover the entire code.

While developing the tests, I improved the list processing mechanism a bit. It could fail for two reasons:
- the presence of spaces after a comma
- the presence of quotes in the list during complex verification

Now these cases are handled correctly with only a few lines changed.

In addition, I decided to rework the `override_expected_value()` function. Managed to make it more compact and functional: now it doesn't matter where the check we need is located (at the beginning, in the middle, or in another complex check). I implemented this through a simple recursive decomposition mechanism.

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) commented at [2025-10-27 13:29](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/203#issuecomment-3451299849):

Unfortunately, here:

https://github.com/a13xp0p0v/kernel-hardening-checker/pull/203/commits/349a00515c5c486e12d68185dedf9ad054d0fc1d

Since we have `VersionCheck` in `.opts` which I simply skip, I had to cast one data type to another, otherwise the idea wouldn't pass mypy. I understand that this is not a good solution, but doing it the right way would require rewriting the huge part of the engine. I leave it up to you to decide whether the functionality is necessary or not (I just find it more functional and compact in the same time). If not, I can remove it and adjust the tests.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-10-27 17:34](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/203#issuecomment-3452527362):

Hello @Willenst, thanks!
Let me give some ideas what to improve.

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) commented at [2025-10-28 12:23](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/203#issuecomment-3456208726):

Thanks for the review, I've made corrections. I think a number of points are worth discussing further :)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-10-28 13:55](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/203#issuecomment-3456600719):

@Willenst, thanks for the fixes!

After fixing the last things that are not resolved, could you please reorganize this branch (incorporating the fixes into your initial commits)?

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) commented at [2025-10-28 14:52](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/203#issuecomment-3456902119):

I fixed the remaining issues and squashed fix-commits with the existing ones. Please check if everything is correct. I tried to make everything as atomic as it was originally.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-10-29 13:19](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/203#issuecomment-3461478857):

Nice! Thanks for the collaboration, @Willenst.

Please see some additional fixes that I've added to your pull request.

Merged!


-------------------------------------------------------------------------------

# [\#202 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/202) `open`: Add special comment to bypass specific parameters analysis
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/38216788?v=4" width="50">[dakrup](https://github.com/dakrup) opened issue at [2025-09-29 10:29](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/202):

Sometimes some parameters (as IOMMU-related, for instance) are in config file for a reason. So it may be valuable to have a documented comment, so we could put it into kernel config file and checker would bypass analysis of a config parameter below, so to limit a number of warnings and/or errors.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-10-18 10:15](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/202#issuecomment-3418168112):

Hello @dakrup.

Thanks for sharing your thoughts.

I think adding some comments to the analyzed Kconfig file would not work well (Kconfig files are auto-generated).

There is another approach to mute some checks, see the discussion in https://github.com/a13xp0p0v/kernel-hardening-checker/issues/50.

It would also allow to add custom extra checks.

What do you think?


-------------------------------------------------------------------------------

# [\#201 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/201) `merged`: `/proc/<pid>/mem` hardenings

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) opened issue at [2025-09-22 13:56](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/201):

According to #173 and #170 

**Option 1: Never Allow `FOLL_FORCE` Bypass**
*   **Kconfig:** `CONFIG_PROC_MEM_NO_FORCE=y`
*   **Command-line:** `proc_mem.force_override=never`

This option completely disables the use of the `FOLL_FORCE` flag within the specific function that handles `/proc/<pid>/mem` (see [fs/proc/base.c, line 877](https://elixir.bootlin.com/linux/v6.16.7/source/fs/proc/base.c#L877)). Normally, `FOLL_FORCE` allows writing to a process's memory via `/proc/<pid>/mem` even if the target memory region has protection flags that would typically prevent writing (e.g., read-only memory or even executable functions).

**Option 2: Allow `FOLL_FORCE` Only for Ptrace-Attached Processes**
*   **Kconfig:** `CONFIG_PROC_MEM_FORCE_PTRACE=y`
*   **Command-line:** `proc_mem.force_override=ptrace`

This option permits the use of `FOLL_FORCE` only when a process has legitimately attached to the target process via `ptrace` (as debuggers do).

**Option 3: Always Allow `FOLL_FORCE` Bypass (Default, Least Secure)**
*   **Kconfig:** `CONFIG_PROC_MEM_ALWAYS_FORCE=y`
*   **Command-line:** `proc_mem.force_override=always`
This is the most permissive and least secure setting. It allows any process with the appropriate permissions (typically the same UID/GID) to write to any memory region of another process via `/proc/<pid>/mem`. From a security perspective, if an attacker compromises any process running as a user, they can potentially manipulate any other process owned by same user.

---

#### **Interaction with `kernel.yama.ptrace_scope`**

Initially, I assumed that sysctl `kernel.yama.ptrace_scope` would achieve a similar level of protection, as it restricts access to all `/proc/<pid>/*` files. For instance, the function `proc_map_files_readdir` (see [fs/proc/base.c, line 2421](https://elixir.bootlin.com/linux/v6.16.7/source/fs/proc/base.c#L2421)) checks `ptrace_scope` before allowing a process to list another process's `/proc` entries. This led me to believe that `yama` hardening (which is already recommended) might make additional `proc_mem` hardening useless -- until I conducted further tests.

---

#### **Demonstration with a Minimal PoC**

Consider the following Proof-of-Concept (PoC) program:
```c
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

void target_func() {
    printf("Target\n");
}

int main() {
    int value = 5;
    void *exec_mem = mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

    while(1) {
	    printf("PID: %d\n", getpid());
        printf("Stack: %p\nExec: %p\nText: %p\nValue: %d\n", 
               &value, exec_mem, target_func, value);
        target_func();
        sleep(10);
    }

    return 0;
}
```

**Example 1: `yama.ptrace_scope=0` or `1`**
```
$ ./poc
PID: 1508
Stack: 0x7fff89013e1c
Exec: 0x7fdcf5ab2000
Text: 0x5562071b11c9
Value: 5

...
$ echo '0x2a000000' | xxd -p -r | dd of=/proc/1508/mem bs=1 seek=$((0x7fff89013e1c)) count=4 conv=notrunc
4+0 records in
4+0 records out
4 bytes copied, 0.000316429 s, 12.6 kB/s
# ... similar commands succeed for the exec and text addresses ...
...

PID: 1508
Stack: 0x7fff89013e1c
Exec: 0x7fdcf5ab2000
Text: 0x5562071b11c9
Value: 42
Segmentation fault (core dumped)
```

Without any defenses, an attacker can overwrite even executable memory (text and exec pages), leading to a crash.

**Example 2: `yama.ptrace_scope=2` or `3` (Restrictive)**
```
$ sudo sysctl -w kernel.yama.ptrace_scope=2
kernel.yama.ptrace_scope = 2
$ ./poc
PID: 1508
...

$ echo '0x2a000000' | xxd -p -r | dd of=/proc/584/mem bs=1 seek=$((0x7ffdfb484b1c)) count=4 conv=notrunc
dd: failed to open '/proc/584/mem': Permission denied
```
As expected, `yama` effectively blocks access to other processes' memory. However, a process can still attempt to modify its *own* memory via `/proc/self/mem`:
```
$ echo '0x2a000000' | xxd -p -r | dd of=/proc/self/mem bs=1 seek=$((0x7fff79030120)) count=4 conv=notrunc
dd: error writing '/proc/self/mem': Input/output error
1+0 records in
0+0 records out
0 bytes copied, 0.000389125 s, 0.0 kB/s
```

This fails with an "Input/output error" because address doesn't exist, but we don't have any 'Permission denied' warnings.

**Example 3: With `CONFIG_PROC_MEM_NO_FORCE=y` (`force_override=never`) and yama.ptrace_scope=0**
```
$ ./poc &
[1] 1310
PID: 1310
Stack: 0x7fff4c04c02c
Exec: 0x7fd55e06e000
Text: 0x5565f9ec31c9
Value: 5

# Writing to writable stack memory still works:
$ echo '0x2a000000' | xxd -p -r | dd of=/proc/1310/mem bs=1 seek=$((0x7fff4c04c02c)) count=4 conv=notrunc
4+0 records in
4+0 records out
4 bytes copied, 0.000447966 s, 8.9 kB/s

# Writing to protected (executable) memory now fails:
$ echo '0x2a000000' | xxd -p -r | dd of=/proc/1310/mem bs=1 seek=$((0x5565f9ec31c9)) count=4 conv=notrunc
dd: error writing '/proc/1310/mem': Input/output error
1+0 records in
0+0 records out
0 bytes copied, 0.000521603 s, 0.0 kB/s
```
With `force_override=never`, the kernel now correctly prevents writes to non-writable memory regions (like the text section) **even within the access permissions, so it will work for self process!**.

---

#### **The Security Gap and the Necessity of `proc_mem.force_override`**

While `kernel.yama.ptrace_scope` effectively protects *other* processes, it does not prevent a compromised process from modifying its *own* protected memory pages. This creates a security gap, as self-modification can be exploited to trigger race condition vulnerabilities (e.g., [CVE-2022-2590](https://github.com/hyeonjun17/CVE-2022-2590-analysis/tree/main))!

Therefore, for comprehensive protection, you must either:
1.  Set `force_override=ptrace` and completely disable unprivileged ptrace (which is often impractical), or
2.  Set `force_override=never` OR `CONFIG_PROC_MEM_NO_FORCE` to fully disable the `FOLL_FORCE`, ensuring the kernel enforces memory protection flags under all circumstances.

The `proc_mem.force_override` setting provides finer-grained control over userspace memory write permissions.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-10-18 06:10](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/201#issuecomment-3417854957):

@Willenst, excellent contribution, thanks!
Merged.


-------------------------------------------------------------------------------

# [\#200 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/200) `open`: Prepare a new release of the tool corresponding to Linux v6.17
**Labels**: `planned_before_release`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2025-09-20 06:13](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/200):

It's time to do that.




-------------------------------------------------------------------------------

# [\#199 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/199) `merged`: Add recommendations from the CIS Benchmark
**Labels**: `new_check`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2025-09-13 19:00](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/199):

This pull request starts from a patch prepared by Shashank Wankhade and Vikas Mittal from Samsung Delhi. We discussed it via email. I've added some fixes and improvements in separate commits to avoid changing this original patch.

This pull request adds the recommendations from the CIS Benchmark.
I've introduced a new `OptCheck.reason` value for them: `network_security`.
CIS Benchmark recommendations that may impact normal network functionality are commented out.

This pull request also adds the `LSM_MMAP_MIN_ADDR` check.

This work refers to the issue #189 where @AlmirST mentioned some of the CIS recommendations. 

Nice!




-------------------------------------------------------------------------------

# [\#198 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/198) `merged`: Add ZERO_CALL_USED_REGS for side channel mitigation instead of CFI

#### <img src="https://avatars.githubusercontent.com/u/1202023?u=598ebb36aedeae0e25c3167bc26c754c3a185efb&v=4" width="50">[citypw](https://github.com/citypw) opened issue at [2025-08-15 15:00](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/198):

This option was removed because it's not worth for ROP mitigation, but it's still can be part of side channel mitigation to those doesn't have hardware mitigation.

Reference:
https://www.amd.com/content/dam/amd/en/documents/resources/technical-guidance-for-mitigating-branch-type-confusion.pdf https://bughunters.google.com/blog/6243730100977664/exploiting-retbleed-in-the-real-world

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-09-13 14:02](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/198#issuecomment-3288408759):

Hello @citypw, 

I've added a comment: https://github.com/a13xp0p0v/kernel-hardening-checker/commit/8c55d04c9825295b7d9bbe8dd63d7339d555d0fd

And merged the branch containing your commit:
<img width="1060" height="63" alt="image" src="https://github.com/user-attachments/assets/06ea3ba3-c245-406f-a0e6-6e8bd6dee5b5" />

Thanks!


-------------------------------------------------------------------------------

# [\#197 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/197) `merged`: Extend perf_event_paranoid comment

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) opened issue at [2025-07-14 12:29](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/197):

Hi, looked into the parameter `perf_event_paranoid` and it seems that a value of 2 behaves like 3 in the vast majority of cases. 

Based on https://github.com/a13xp0p0v/kernel-hardening-checker/tree/master/kernel_hardening_checker/config_files/distros and CONFIG_SECURITY_PERF_EVENTS_RESTRICT (see https://lkml.org/lkml/2016/1/11/587) kconfig presence: the unique value 3 is common mostle for Debian family.

So, I think it is better to make more detailed comment

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-19 21:21](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/197#issuecomment-3092579305):

Thanks for the clarifications, @Willenst! I've fixed the style a bit and merged this.


-------------------------------------------------------------------------------

# [\#196 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/196) `merged`: CI: Introduce the package test

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2025-07-01 19:57](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/196):



#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-01 22:24](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/196#issuecomment-3025701261):

Thanks to @sobolevn for the ideas!


-------------------------------------------------------------------------------

# [\#195 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/195) `merged`: man: add kernel-hardening-checker.1 manual
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/148225969?u=a0386c1aaaf5d51f94578df1b459ea6c15e858c5&v=4" width="50">[krekhovx](https://github.com/krekhovx) opened issue at [2025-06-23 15:13](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/195):

Hi, I want to add your software to Debian, after building the package I checked it with Lintian and it said:
`W: kernel-hardening-checker: no-manual-page [usr/bin/kernel-hardening-checker]`
This is a violation for Debian, so it is important to add manual.
Have a good day!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-02 13:24](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/195#issuecomment-3027881062):

@krekhovx, thanks a lot for your contribution!

I've made some improvements and merged this pull request.

> Hi, I want to add your software to Debian

That's great, thank you!
Where can I find the detailed info about this package when it appears in Debian?

#### <img src="https://avatars.githubusercontent.com/u/148225969?u=a0386c1aaaf5d51f94578df1b459ea6c15e858c5&v=4" width="50">[krekhovx](https://github.com/krekhovx) commented at [2025-07-02 16:10](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/195#issuecomment-3028445573):

@a13xp0p0v 

> I've made some improvements and merged this pull request.

Great! Thank you!

> Where can I find the detailed info about this package when it appears in Debian?

You can find detailed information about the package on the official Debian package tracker once it appears in the archive. The package tracker provides descriptions, version history, dependencies, changelogs, and other relevant details.

https://tracker.debian.org/

Or, after the package is available in the repositories, you can run:
`$ apt show kernel-hardening-checker`
on your system to see its details.

Currently, the package is in a "confirmed" state and is waiting for a sponsor. Since Debian is currently in the freeze stage, I expect that the `kernel-hardening-checker` package will be included in Debian 13 (Trixie):
https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1108225
https://salsa.debian.org/krekhov/kernel-hardening-checker

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-04 17:45](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/195#issuecomment-3036956477):

@krekhovx 
Thanks for the information :+1: 

After fixing the man page, I published a new release `v0.6.10.2`:
https://github.com/a13xp0p0v/kernel-hardening-checker/tags

Could you use it instead of the previous version?

#### <img src="https://avatars.githubusercontent.com/u/148225969?u=a0386c1aaaf5d51f94578df1b459ea6c15e858c5&v=4" width="50">[krekhovx](https://github.com/krekhovx) commented at [2025-07-05 13:47](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/195#issuecomment-3038962244):

@a13xp0p0v 
Sure, sure, I see it, I'll update the Salsa repository in the future 👍


-------------------------------------------------------------------------------

# [\#194 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/194) `open`: README: Add a chapter "What Can Go Wrong" about problematic security hardening options
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2025-06-18 18:00](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/194):

To make it more visible, add a table of contents at the beginning of the README.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-02 14:53](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/194#issuecomment-3028180961):

Refers to #69.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-13 20:19](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/194#issuecomment-3067280357):

Refers to #144.


-------------------------------------------------------------------------------

# [\#193 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/193) `merged`: pyproject.toml: add file
**Labels**: `bug/fix`


#### <img src="https://avatars.githubusercontent.com/u/46938494?v=4" width="50">[priv-kweihmann](https://github.com/priv-kweihmann) opened issue at [2025-06-12 05:53](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/193):

as setuptools 80.x deprecated easy_install module, so setup.py can't be used after the deadline of end of October 2025.
Add a pyproject.toml created using setuptools-py2cfg and ini2toml with manually added build-system
section

#### <img src="https://avatars.githubusercontent.com/u/46938494?v=4" width="50">[priv-kweihmann](https://github.com/priv-kweihmann) commented at [2025-06-12 05:54](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/193#issuecomment-2965212864):

Ways to reproduce the original issue

```
python -m venv .env
. .env/bin/activate
pip3 install --upgrade setuptools
python3 setup.py build
```

That will show warnings about the deprecation of the entire easy_install module

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-06-14 23:10](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/193#issuecomment-2973325974):

Hello @priv-kweihmann,

Thanks for your pull request!

1) Could you please fix the broken CI script?

2) It looks like the package version is broken. Could you please fix it? 
![image](https://github.com/user-attachments/assets/485f5424-2d6f-47ad-af2f-2f0bb786c71e)

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/46938494?v=4" width="50">[priv-kweihmann](https://github.com/priv-kweihmann) commented at [2025-06-15 07:51](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/193#issuecomment-2973569084):

> Hello @priv-kweihmann,
> 
> Thanks for your pull request!
> 
> 1. Could you please fix the broken CI script?
> 2. It looks like the package version is broken. Could you please fix it?
>    ![image](https://private-user-images.githubusercontent.com/1419667/455213715-485f5424-2d6f-47ad-af2f-2f0bb786c71e.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NDk5NzM2MjgsIm5iZiI6MTc0OTk3MzMyOCwicGF0aCI6Ii8xNDE5NjY3LzQ1NTIxMzcxNS00ODVmNTQyNC0yZDZmLTQ3YWQtYWYyZi0yZjBiYjc4NmM3MWUucG5nP1gtQW16LUFsZ29yaXRobT1BV1M0LUhNQUMtU0hBMjU2JlgtQW16LUNyZWRlbnRpYWw9QUtJQVZDT0RZTFNBNTNQUUs0WkElMkYyMDI1MDYxNSUyRnVzLWVhc3QtMSUyRnMzJTJGYXdzNF9yZXF1ZXN0JlgtQW16LURhdGU9MjAyNTA2MTVUMDc0MjA4WiZYLUFtei1FeHBpcmVzPTMwMCZYLUFtei1TaWduYXR1cmU9MTE1OTE1NDIxY2YyNmJiMzM4YWE0YzJkNTA4MTA1YTU3ODdmNTExOWFiNzkzNjMxM2MzZjM5ZjA1OTg5ODQ3MiZYLUFtei1TaWduZWRIZWFkZXJzPWhvc3QifQ.CTEQVLHNyffSH1V0ttHwZLVHUwPAlg4L3t6Zixq2mg0)
> 
> Thanks!

@a13xp0p0v both fixed

#### <img src="https://avatars.githubusercontent.com/u/109767616?u=a50adf33a8e6bb8d44eb7749db65ff9b3fc7c8c3&v=4" width="50">[chirizxc](https://github.com/chirizxc) commented at [2025-06-29 10:52](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/193#issuecomment-3016587143):

```toml
[build-system]
requires = ["setuptools == 80.9.0"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["."]

[tool.setuptools.dynamic]
version = {attr = "kernel_hardening_checker.__version__"}

[project]
name = "kernel-hardening-checker"
dynamic = ["version"]
description = "A tool for checking the security hardening options of the Linux kernel"
readme = "README.md"
license = { file = "LICENSE.txt" }
authors = [
  {name = "Alexander Popov", email = "alex.popov@linux.com"},
]
maintainers = [
  {name = "Alexander Popov", email = "alex.popov@linux.com"},
]
classifiers = [
    "Development Status :: 5 - Production/Stable",
    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    "Topic :: Security",
    "Operating System :: POSIX :: Linux",
    "Environment :: Console",
    "Programming Language :: Python :: 3",
]

[project.scripts]
kernel-hardening-checker = "kernel_hardening_checker:main"

[project.urls]
Homepage = "https://github.com/a13xp0p0v/kernel-hardening-checker"
Source = "https://github.com/a13xp0p0v/kernel-hardening-checker"
Download = "https://github.com/a13xp0p0v/kernel-hardening-checker#files"
"Bug Tracker" = "https://github.com/a13xp0p0v/kernel-hardening-checker/issues"
```
maybe something like that?

#### <img src="https://avatars.githubusercontent.com/u/46938494?v=4" width="50">[priv-kweihmann](https://github.com/priv-kweihmann) commented at [2025-06-29 11:43](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/193#issuecomment-3016622589):

> ```toml
> [build-system]
> requires = ["setuptools == 80.9.0"]
> build-backend = "setuptools.build_meta"
> 
> [tool.setuptools.packages.find]
> where = ["."]
> 
> [tool.setuptools.dynamic]
> version = {attr = "kernel_hardening_checker.__version__"}
> 
> [project]
> name = "kernel-hardening-checker"
> dynamic = ["version"]
> description = "A tool for checking the security hardening options of the Linux kernel"
> readme = "README.md"
> license = { file = "LICENSE.txt" }
> authors = [
>   {name = "Alexander Popov", email = "alex.popov@linux.com"},
> ]
> maintainers = [
>   {name = "Alexander Popov", email = "alex.popov@linux.com"},
> ]
> classifiers = [
>     "Development Status :: 5 - Production/Stable",
>     "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
>     "Topic :: Security",
>     "Operating System :: POSIX :: Linux",
>     "Environment :: Console",
>     "Programming Language :: Python :: 3",
> ]
> 
> [project.scripts]
> kernel-hardening-checker = "kernel_hardening_checker:main"
> 
> [project.urls]
> Homepage = "https://github.com/a13xp0p0v/kernel-hardening-checker"
> Source = "https://github.com/a13xp0p0v/kernel-hardening-checker"
> Download = "https://github.com/a13xp0p0v/kernel-hardening-checker#files"
> "Bug Tracker" = "https://github.com/a13xp0p0v/kernel-hardening-checker/issues"
> ```
> 
> maybe something like that?

Took over most of the suggestions.
license needs to be a SPDX conform string, but license-files does add the exact file to the build.
Kept out authors, as the project currently has 74 (and counting) contributors which IMO would need to be mentioned here, so skipping the entire setting should be okay.
Also readme.md is a dynamic setting taking the actual file and uses that for the metadata

#### <img src="https://avatars.githubusercontent.com/u/109767616?u=a50adf33a8e6bb8d44eb7749db65ff9b3fc7c8c3&v=4" width="50">[chirizxc](https://github.com/chirizxc) commented at [2025-06-29 11:50](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/193#issuecomment-3016626098):

> ```toml
> license = { file = "LICENSE.txt" }
> ```

u can use `license = { text = "MIT or something", file = "LICENSE.txt" }`

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-06-30 06:55](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/193#issuecomment-3018013703):

@priv-kweihmann @chirizxc thanks again, merged!


-------------------------------------------------------------------------------

# [\#192 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/192) `closed`: Failure to parse wildcards in sysctl configuration file.
**Labels**: `bug/fix`


#### <img src="https://avatars.githubusercontent.com/u/90906486?v=4" width="50">[WavyEbuilder](https://github.com/WavyEbuilder) opened issue at [2025-06-08 16:08](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/192):

Take a sysctl configuration file with the following contents:
```
net.ipv4.conf.*.accept_source_route = 0
```

Before:
```
rsandhu@graphite ~ $ cat /proc/sys/net/ipv4/conf/wlan0/accept_source_route
1
```
And after applying the sysctl file with `sysctl -p /etc/sysctl.d/00-test`:
```
rsandhu@graphite ~ $ cat /proc/sys/net/ipv4/conf/wlan0/accept_source_route
0
```

This seems to imply `sysctl(1)` supports wildcards. However, KHC fails with:
```
[-] ERROR: unexpected line in sysctl file: "net.ipv4.conf.*.accept_source_route = 0"
```

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-06-28 22:07](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/192#issuecomment-3016087426):

Hello @WavyEbuilder, thanks for creating this report!

Fixed in https://github.com/a13xp0p0v/kernel-hardening-checker/commit/1a230d7fb3abc77333f61fbcc24a2127099c53ce.

Feel free to reopen it if the fix doesn't work for you.

By the way, I would recommend checking a file with the output of `sysctl -a` (instead of the `sysctl.conf` config), because it contains all sysctl parameters.

#### <img src="https://avatars.githubusercontent.com/u/90906486?v=4" width="50">[WavyEbuilder](https://github.com/WavyEbuilder) commented at [2025-06-28 23:21](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/192#issuecomment-3016144524):

Thanks! And noted


-------------------------------------------------------------------------------

# [\#191 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/191) `closed`: disable CONFIG_VT causes INIT: Id "1" respawning too fast: disabled for 5 minutes
**Labels**: `idea_for_the_future`


#### <img src="https://avatars.githubusercontent.com/u/4224783?u=46feb013caaa72f8af1d9d3db11d0d629b74df0d&v=4" width="50">[RobertBerger](https://github.com/RobertBerger) opened issue at [2025-06-06 08:29](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/191):

kernel: 6.14.5
kernel-hardening-checker: 0.6.10
arm32

```
CONFIG_VT                               |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "y"
```

I'm getting `INIT: Id "1" respawning too fast: disabled for 5 minutes`

Here is my inittab:

```
# /etc/inittab: init(8) configuration.
# $Id: inittab,v 1.91 2002/01/25 13:35:21 miquels Exp $

# The default runlevel.
id:3:initdefault:

# Boot-time system configuration/initialization script.
# This is run first except when booting in emergency (-b) mode.
si::sysinit:/etc/init.d/rcS

# What to do in single-user mode.
~~:S:wait:/sbin/sulogin

# /etc/init.d executes the S and K scripts upon change
# of runlevel.
#
# Runlevel 0 is halt.
# Runlevel 1 is single-user.
# Runlevels 2-5 are multi-user.
# Runlevel 6 is reboot.

l0:0:wait:/etc/init.d/rc 0
l1:1:wait:/etc/init.d/rc 1
l2:2:wait:/etc/init.d/rc 2
l3:3:wait:/etc/init.d/rc 3
l4:4:wait:/etc/init.d/rc 4
l5:5:wait:/etc/init.d/rc 5
l6:6:wait:/etc/init.d/rc 6
# Normally not reached, but fallthrough in case of emergency.
z6:6:respawn:/sbin/sulogin
mxc1:12345:respawn:/usr/sbin/ttyrun ttymxc1 /sbin/getty 115200 ttymxc1 vt102
# /sbin/getty invocations for the runlevels.
#
# The "id" field MUST be the same as the last
# characters of the device (after "tty").
#
# Format:
#  <id>:<runlevels>:<action>:<process>
#

1:12345:respawn:/sbin/getty 38400 tty1
```

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-13 21:49](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/191#issuecomment-3067319880):

Hello @RobertBerger, thanks for creating this issue!

Please have a look at the issue https://github.com/a13xp0p0v/kernel-hardening-checker/issues/38. Linux kernel maintainer @danvet gave technical details about `CONFIG_VT`.

Do you see there any clue or solution for the bug you encountered?

#### <img src="https://avatars.githubusercontent.com/u/5088003?v=4" width="50">[danvet](https://github.com/danvet) commented at [2025-07-14 06:32](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/191#issuecomment-3068011425):

Yeah if you just disable CONFIG_VT without at least disabling the login getty then this will happen. Unless you really know what you're doing you need to wait for your distro to do all the plumbing to make this happen.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-19 21:02](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/191#issuecomment-3092570436):

Thank you 👍 

We will add this information while implementing #194 and #144.


-------------------------------------------------------------------------------

# [\#190 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/190) `closed`: CONFIG_WERROR on arm32 with 6.14.x kernel does not compile: -Werror=unterminated-string-initialization
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/4224783?u=46feb013caaa72f8af1d9d3db11d0d629b74df0d&v=4" width="50">[RobertBerger](https://github.com/RobertBerger) opened issue at [2025-06-06 08:09](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/190):

kernel: 6.14.5
kernel-hardening-checker: 0.6.10

``
CONFIG_WERROR                           |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
``

The kernel does not compile with `CONFIG_WERROR=y`.

See log here:

https://pastebin.com/igV2tq6S

The problem here is:

```
| /workdir/build/imx6q-phytec-mira-rdk-nand-wic-master/tmp/work-shared/imx6q-phytec-mira-rdk-nand/kernel-source/drivers/pmdomain/imx/gpc.c:227:11: error: initializer-string for array of 'char' truncates NUL terminator but destination lacks 'nonstring' attribute (21 chars into 20 available) [-Werror=unterminated-string-initialization] 
|   227 |         { "imx-pgc-power-domain"}, 
|       |           ^~~~~~~~~~~~~~~~~~~~~~ 
```


#### <img src="https://avatars.githubusercontent.com/u/4224783?u=46feb013caaa72f8af1d9d3db11d0d629b74df0d&v=4" width="50">[RobertBerger](https://github.com/RobertBerger) commented at [2025-06-10 18:24](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/190#issuecomment-2960225796):

From here:

https://web.git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=9d7a0577c9db35c4cc52db90bc415ea248446472

A possible workaround might be something like this:

```
git show 1baf00eef11fdd0b89a229416504f9a3326d68e1
commit 1baf00eef11fdd0b89a229416504f9a3326d68e1
Author: Robert Berger <Robert.Berger@ReliableEmbeddedSystems.com>
Date:   Tue Jun 10 17:51:58 2025 +0000

    disable -Wunterminated-string-initialization as broken
    
    Signed-off-by: Robert Berger <Robert.Berger@ReliableEmbeddedSystems.com>

diff --git a/Makefile b/Makefile
index 87835d7abbce..d272cc13e964 100644
--- a/Makefile
+++ b/Makefile
@@ -1053,6 +1053,9 @@ KBUILD_CFLAGS += $(call cc-option, -fstrict-flex-arrays=3)
 KBUILD_CFLAGS-$(CONFIG_CC_NO_STRINGOP_OVERFLOW) += $(call cc-option, -Wno-stringop-overflow)
 KBUILD_CFLAGS-$(CONFIG_CC_STRINGOP_OVERFLOW) += $(call cc-option, -Wstringop-overflow)
 
+#Currently, disable -Wunterminated-string-initialization as broken
+KBUILD_CFLAGS += $(call cc-option, -Wno-unterminated-string-initialization)
+
 # disable invalid "can't wrap" optimizations for signed / pointers
 KBUILD_CFLAGS  += -fno-strict-overflow

```

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-13 21:13](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/190#issuecomment-3067304456):

Thanks for the info, @RobertBerger!

It looks like this kernel issue needed an additional fix for Clang:
https://web.git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id=4f79eaa2ceac86a0e0f304b0bab556cca5bf4f30

👍


-------------------------------------------------------------------------------

# [\#189 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/189) `open`: Find out which security hardening recommendations affect or disrupt microservices on Kubernetes
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2025-06-04 19:19](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/189):



#### <img src="https://avatars.githubusercontent.com/u/46416435?v=4" width="50">[AlmirST](https://github.com/AlmirST) commented at [2025-06-18 18:11](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/189#issuecomment-2985261129):

# How kernel hardening parameters influence containers

---

## `kernel.kptr_restrict=1/2`

- **Kernel version:** Introduced in Linux 2.6.38 (`1`); value `2` supported since Linux 4.0

### Purpose
Hide kernel symbol addresses — setting `1` or `2` prevents reading kernel symbols from `/proc/kallsyms` inside containers.

### Behavior
- `1`: Kernel symbols are visible only to the root user.
- `2`: Kernel symbols are hidden even from root inside user namespaces (e.g., containers).

### Observed Effect
Inside containers, tools like `perf` or flame graph scripts show no kernel symbols:

### Risks
- Profiling and tracing tools running inside containers can no longer resolve kernel symbols.

### Affected Services/Tools
- `perf`
- `Sysdig`
- `Falco`
- Flame graph generators

### Note
This setting strengthens kernel hardening and container isolation but may hinder observability in containerized environments. Consider implications for debugging and monitoring workflows.

---

## `kernel.unprivileged_bpf_disabled=1`

- **Kernel version:** Introduced in Linux 5.8

### Purpose
Prevents unprivileged processes (i.e., those without `CAP_BPF` or `CAP_SYS_ADMIN`) from using the `bpf()` system call.

### Behavior
- Unprivileged users and containers cannot load or run eBPF programs.
- Attempts to invoke `bpf()` without proper capabilities will fail with a permission error.

### Risks
- eBPF programs can't be used by non-privileged users.
- Tools like XDPFail2ban and eBPF-based filters will break in unprivileged containers.

### Affected Services/Tools
- `Cilium`
- `Falco`
- `Sysdig Secure` (without `CAP_BPF`)
- Custom eBPF-based tools

### Note
Increases system security but breaks eBPF usage in unprivileged environments. Requires granting capabilities explicitly.

---

## `user.max_user_namespaces=0`

- **Kernel version:** Introduced in Linux 3.8; tunable via sysctl since Linux 4.9

### Purpose
Disables the creation of user namespaces, reducing attack surface.

### Behavior
- Blocks `unshare(CLONE_NEWUSER)` and rootless container execution.
- Affects sandboxing tools relying on user namespaces.

### Risks
- Breaks rootless Docker/Podman.
- Disrupts tools using user or network namespaces.
- Incompatible with older `bpftrace`, `bcc-tools` relying on user namespaces or fixed memory layouts.

### Affected Services/Tools
- Rootless Docker/Podman
- Sandbox-based apps
- Older versions of `bpftrace`, `bcc-tools`
- eBPF programs needing fixed address access

### Note
Security gain at the cost of compatibility. Avoid if rootless/container isolation is needed.

---

## `net.ipv4.ip_forward=0`

- **Kernel version:** Available since early Linux 2.x kernels

### Purpose
Disables IPv4 packet forwarding — stops the host from routing traffic between interfaces.

### Behavior
- Disables inter-container, inter-pod, and cross-node routing.

### Risks
- Breaks Kubernetes (Flannel, Calico).
- Breaks Docker NAT and bridge networking.

### Affected Services/Tools
- Kubernetes container networking (Flannel, Calico)
- Docker bridge networks
- Any IP forwarding-dependent service

### Note
Required (`=1`) for proper container networking unless using eBPF-based networking like Cilium.

---

## `kernel.modules_disabled=1`

- **Kernel version:** Available since Linux 2.6.31

### Purpose
Disables runtime loading of kernel modules — once set, cannot be reverted without reboot.

### Behavior
- Prevents `insmod`, `modprobe`, etc., from loading any module after boot.
- Preloaded modules remain functional.

### Risks
- Breaks Falco (in LKM mode) and other tools depending on loadable modules.
- No dynamic module support after boot.

### Affected Services/Tools
- `Falco` (kernel module mode)
- Custom or legacy kernel module tools
- eBPF-based tools like `Cilium` are unaffected if BPF support is built-in

### Note
Useful for hardened environments. Preload all required modules if this is enabled.

---

## `net.ipv4.conf.all.rp_filter=1`  
## `net.ipv4.conf.default.rp_filter=1`

- **Kernel version:** Available since Linux 2.2

### Purpose
Enable Reverse Path Filtering (RPF) — drops spoofed or misrouted packets.

### Behavior
- `1` (strict mode): Accept packets only if they come in on the interface used to reach their source.
- Affects all interfaces and defaults.

### Risks
- Breaks overlay networks, policy routing (e.g., VXLAN).
- Causes connectivity issues in Kubernetes and CNI plugins.

### Affected Services/Tools
- `Calico`, `Cilium` (with policy routing)
- Docker bridge/host networking
- Kubernetes overlay networks

### Note
Improves anti-spoofing security, but generally incompatible with complex container networking. Use `rp_filter=0` or `2` in such environments.

---

## `CONFIG_DEBUG_INFO_BTF = not set`

- **Kernel version:** Available since Linux 5.2

### Purpose
Controls generation of BTF (BPF Type Format) metadata in the kernel — critical for eBPF CO-RE support.

### Behavior
- Without BTF, many eBPF tools relying on type introspection will fail or require manual kernel headers.

### Impact
- Enables modern eBPF observability  
- Improves portability  
- Increases kernel binary size  
- May expose internal structures to attackers with access

### Risks
- Kernel image becomes larger.
- Potential information exposure in compromised systems.

### Recommendations
- Enable on observability nodes running `Cilium`, `Falco`, `bpftrace`, `bcc`.
- Disable on hardened or minimal systems.

### Affected Services/Tools
- `Cilium`, `Falco`, `bcc-tools`, `bpftrace`
- Any eBPF CO-RE program relying on kernel type metadata

---

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-06-19 05:44](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/189#issuecomment-2986684003):

Great, @AlmirST, thanks a lot for your contribution ⭐️

Refers to #194.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-06-24 12:34](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/189#issuecomment-3000251882):

@AlmirST, a question about user namespaces.

Does the Debian-specific sysctl `kernel.unprivileged_userns_clone=0` break containers as well?

It doesn't disable user namespaces like `user.max_user_namespaces=0`, but requires additional privileges to work with them.

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-19 21:04](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/189#issuecomment-3092571420):

Also refers to #144.

#### <img src="https://avatars.githubusercontent.com/u/46416435?v=4" width="50">[AlmirST](https://github.com/AlmirST) commented at [2025-08-01 12:35](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/189#issuecomment-3144437486):

## `kernel.unprivileged_userns_clone=0`

- **Kernel version:** Debian-specific patch, available since Debian 9 (kernel 4.9 Stretch) and Ubuntu 16.04 (kernel 4.4 Canonical)

### Purpose
Prevents unprivileged processes from using the `CLONE_NEWUSER` system call to create new user namespaces, reducing the risk of local privilege escalation via vulnerabilities in the user namespace implementation.

### Behavior
- `0`: Only processes with `CAP_SYS_ADMIN` are allowed to create user namespaces.
- `1`: All users are allowed to create user namespaces (Linux kernel default behavior).

### Observed Effect
- **Docker (rootful)** – Works as expected because the daemon has the privileges to create user namespaces.
- **Docker rootless** – Fails to start, returns `operation not permitted` when attempting to create a user namespace.
- **Podman (rootful)** – Works as expected.
- **Podman rootless** – Fails to start, same behavior as Docker rootless.
- **Kubernetes (rootful kubelet)** – Functions normally.
- **Kubernetes rootless, Kind, k3s** – Fail to start, require unprivileged user namespaces to be enabled.

### Risks
- Breaks all rootless containerization scenarios.
- May affect third-party applications that create user namespaces without elevated privileges.

### Affected Services/Tools
- `Docker rootless`
- `Podman rootless`
- `Kind`, `k3s`
- Any sandboxing tools or testing utilities that attempt to create user namespaces as unprivileged users.

### Note
Serves as a softer and more compatible alternative to `user.max_user_namespaces=0`, preserving user namespace functionality for privileged processes while having minimal impact on standard rootful Docker and Kubernetes environments.






> [@AlmirST](https://github.com/AlmirST), a question about user namespaces.
> 
> Does the Debian-specific sysctl `kernel.unprivileged_userns_clone=0` break containers as well?
> 
> It doesn't disable user namespaces like `user.max_user_namespaces=0`, but requires additional privileges to work with them.
> 
> Thanks!


-------------------------------------------------------------------------------

# [\#188 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/188) `closed`: License classifiers are deprecated
**Labels**: `bug/fix`


#### <img src="https://avatars.githubusercontent.com/u/4741819?v=4" width="50">[asarubbo](https://github.com/asarubbo) opened issue at [2025-06-03 15:07](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/188):

Hello,

during the packaging of 0.6.10.1 on Gentoo Linux I discovered the following warning:

```
 * QA Notice: setuptools warnings detected:
 * 
 *      License classifiers are deprecated.
```

This happens with setuptools-80.4.0

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-06-04 19:28](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/188#issuecomment-2941190819):

Thanks for noticing this @asarubbo!

Would you like to send a pull request with a fix? I would appreciate it!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-06-28 22:10](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/188#issuecomment-3016089113):

Refers to #193.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-06-30 21:04](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/188#issuecomment-3020720466):

Fixed in #193. Closing.

Thanks!


-------------------------------------------------------------------------------

# [\#187 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/187) `merged`: Add new cmdline checks
**Labels**: `new_check`


#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) opened issue at [2025-06-02 12:20](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/187):

Hello, I've released some new cmdlines, according to this issue #169 ! Waiting for your review!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-06-14 11:01](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/187#issuecomment-2972614174):

Hello @Willenst,

Thanks for your pull request!

Your changes allowed me to spot some semantic errors in `kernel_hardening_checker/checks.py`.

I've fixed them in the commit https://github.com/a13xp0p0v/kernel-hardening-checker/commit/8256e96d6e31786c035dd82a7a7438bc3476e031.

Please rebase your branch above the fresh `master`.

And also please see my review comments.

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) commented at [2025-06-17 15:36](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/187#issuecomment-2980861305):

Hello,
Thank you for your review and work. I just applied all the fixes.

I hope it's okay that I included them in a single commit, since they're all relatively small. I'm looking forward to the next iteration!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-13 19:51](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/187#issuecomment-3067268458):

@Willenst, thanks for the second version.

I've fixed some bugs in this branch and merged it.

You can see my commits on the top of this branch to inspect what I fixed.


-------------------------------------------------------------------------------

# [\#186 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/186) `closed`: BLK_DEV_WRITE_MOUNTED preventing fsck from running at boot

#### <img src="https://avatars.githubusercontent.com/u/174261768?v=4" width="50">[raffaele-ghb](https://github.com/raffaele-ghb) opened issue at [2025-05-22 17:39](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/186):

The system is Gentoo with OpenRC init, x86_64, kernel 6.14.7 (but also earlier versions), GCC 15. The kernel-hardening-checker is version 0.6.10.
After disabling the kernel option as suggested by the tool I systematically got this error on boot:

fsck: checking local filesystem
fsck: fsck.ext4 device or resource busy while trying to open /dev/nvme0n1p6
fsck: filesystem mounted or opened exclusively by another program?
fsck: operational error

Note that the device contains the root filesystem.
According to the option help this behavior is expected:

"there are some setups that need this capability like running fsck on read-only mounted root device"

I suppose the problem is in some way related to the usage of the not-so-common OpenRC init system. I just wanted the issue to be logged somewhere.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-31 13:50](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/186#issuecomment-2925214607):

Thanks for the info @raffaele-ghb!

I've added this to the comment: https://github.com/a13xp0p0v/kernel-hardening-checker/commit/48b1e3f270d196ab83795299da936b699f021b5f:

```
# 1) bdev_allow_write_mounted=0 may break snap and its applications on Ubuntu,
# since snap uses the squashfs filesystem and creates loop devices.
# 2) On Gentoo with openrc-init, bdev_allow_write_mounted=0 makes fsck fail
# on boot during the root filesystem check.
```


-------------------------------------------------------------------------------

# [\#185 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/185) `closed`: Update get_kconfigs.sh to fetch Oracle configs dynamically + update kernel configs 
**Labels**: `planned_before_release`, `config_update`


#### <img src="https://avatars.githubusercontent.com/u/84989429?u=0f9ba34cfa38ee1e11d4948f6c04e6d9c4383e44&v=4" width="50">[xgloom](https://github.com/xgloom) opened issue at [2025-05-05 15:36](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/185):

## Summary
This PR updates [get_kconfigs.sh](https://github.com/a13xp0p0v/kernel-hardening-checker/blob/master/kernel_hardening_checker/config_files/distros/get_kconfigs.sh) to dynamically fetch Oracle kernel config names from `summary.json` on the same Github pages, removing the need for a hardcoded list. 

It also refreshes existing .config files to reflect the latest changes of the distros, as well as adding 83 new .config files.

## Changes
- Fetch kconfigs_from_oracle dynamically via summary.json ([7e80870](https://github.com/a13xp0p0v/kernel-hardening-checker/commit/7e80870d40bcfdba312f29e35cc8dbb5bb72aa99)).
- Update existing kernel configs to latest versions ([5e3ab3c](https://github.com/a13xp0p0v/kernel-hardening-checker/commit/5e3ab3c938a8cf14aa64dd0922cf73d1c328a59c), [c59848d](https://github.com/a13xp0p0v/kernel-hardening-checker/commit/c59848d084c7c81999075424ae80f9fba4b6fcf6)).

## Related issue
Addresses outdated/missing kconfigs discussed in issue #184 .



#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-08 08:41](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/185#issuecomment-2862243913):

Hello @xgloom,

Thanks for coming back with a pull request :+1: 

Let's think about how to improve it. Several considerations:
 - Collecting all the kconfig files available at https://github.com/oracle/kconfigs is not necessary, because that would make the [CI script](https://github.com/a13xp0p0v/kernel-hardening-checker/actions/workflows/functional_test.yml) work for a very very long time.
 - Also, collecting all those kconfig files in `kernel-hardening-checker` would make the repository and install package size much larger, which we don't need.
 - The original idea was to have two versions of kconfig files for each distro for different architectures: the oldest and the newest. That's why we have such a list:
    ```
    "Android 15 (6.6) aarch64"
    "Arch x86_64"
    "CentOS 9 Stream aarch64"
    "CentOS 9 Stream x86_64"
    "Debian 10 Buster x86_64"
    "Debian 13 Trixie aarch64"
    "Debian 13 Trixie x86_64"
    "Fedora 41 Updates aarch64"
    "Fedora 41 Updates x86_64"
    "Oracle Linux 7 (UEK 4) x86_64"
    "Oracle Linux 9 (UEK-NEXT) aarch64"
    "Oracle Linux 9 (UEK-NEXT) x86_64"
    "Ubuntu 20.04 LTS Focal x86_64"
    "Ubuntu 24.04 LTS Noble aarch64"
    "Ubuntu 24.04 LTS Noble x86_64"
    ```

So the easiest way is to manually update the numbers in this list, download the kconfig files and update them in the repository.

What do you think of this?

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/84989429?u=0f9ba34cfa38ee1e11d4948f6c04e6d9c4383e44&v=4" width="50">[xgloom](https://github.com/xgloom) commented at [2025-05-24 16:21](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/185#issuecomment-2906912904):

Ah ok, thank you. Makes sense and didn't know about the CI script, I don't have much time on me right now, but just work sounds straight forward and good.

I'll see if I can do it these upcoming weeks, otherwise someone else may be able to? Thanks!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-31 13:39](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/185#issuecomment-2925202891):

Hi @xgloom!

Closing this pull request. Solved in https://github.com/a13xp0p0v/kernel-hardening-checker/commit/a263e3847f38f24c459881c1b650d377466500c3 and https://github.com/a13xp0p0v/kernel-hardening-checker/commit/6d9270cda2e3a6ffb361a62aa77c870f1f7acb18.

Thanks!


-------------------------------------------------------------------------------

# [\#184 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/184) `closed`: Sharing Azure Linux config for 6.8.0-1021 & question
**Labels**: `good_first_issue`, `planned_before_release`


#### <img src="https://avatars.githubusercontent.com/u/84989429?u=0f9ba34cfa38ee1e11d4948f6c04e6d9c4383e44&v=4" width="50">[xgloom](https://github.com/xgloom) opened issue at [2025-04-11 22:07](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/184):

Hey, 

I checked the Azure Linux file and was surprised by some of the kconfigs here [1]. 
How was this generated?

I created an Azure VM today

```
root@azure-vm-ubuntu:/boot# uname -a
Linux azure-vm-ubuntu 6.8.0-1021-azure #25-Ubuntu SMP Wed Jan 15 20:45:09 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
```

Find different results, for 6.8.0-1021-azure. Might be nice to add to the configs. 
I have attached it, didn't want to PR [2].

Thanks!
 
[1] [Azure_Linux_x86_64.config](https://github.com/a13xp0p0v/kernel-hardening-checker/blob/dd028a2fd49ce5f25f05cdbec91958022c2a3dc2/kernel_hardening_checker/config_files/distros/Azure_Linux_x86_64.config)
[2]  [Azure_Linux_x86_64_6.8.0-1021.config.txt](https://github.com/user-attachments/files/19714572/Azure_Linux_x86_64_6.8.0-1021.config.txt)

#### <img src="https://avatars.githubusercontent.com/u/84989429?u=0f9ba34cfa38ee1e11d4948f6c04e6d9c4383e44&v=4" width="50">[xgloom](https://github.com/xgloom) commented at [2025-04-12 00:33](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/184#issuecomment-2798260593):

Fwiw, here's CentOS Stream 10 (Coughlan) [3]. Downloaded from the official 20250331.0 x86-64 iso (`d494416122e6d31a04545467111cea29`) [4].

```
$ cat /proc/version
Linux version 6.12.0-66.el10.x86_64 (mockbuild@694f893baa82435fb52e73f7c6675ecf) (gcc (GCC) 14.2.1 20250110 (Red Hat 14.2.1-7), GNU ld version 2.41-52.el10) #1 SMP PREEMPT_DYNAMIC Thu Mar 20 13:49:55 UTC 2025
```

[3] [CentOS_10_Stream_x86_64.config.txt](https://github.com/user-attachments/files/19715363/CentOS_10_Stream_x86_64.config.txt)
[4] [CentOS-Stream-10-20250331.0-x86_64-dvd1.iso](https://mirrors.centos.org/mirrorlist?path=/10-stream/BaseOS/x86_64/iso/CentOS-Stream-10-latest-x86_64-dvd1.iso&redirect=1&protocol=https)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-05 00:01](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/184#issuecomment-2849597836):

Hello @xgloom,

Thanks for creating this issue.

> I checked the Azure Linux file and was surprised by some of the kconfigs here [1].
> How was this generated?

We have this script for updating the distro configs: [get_kconfigs.sh](https://github.com/a13xp0p0v/kernel-hardening-checker/blob/master/kernel_hardening_checker/config_files/distros/get_kconfigs.sh). Quoting:
```
wget -O Azure_Linux_x86_64.config https://raw.githubusercontent.com/microsoft/azurelinux/refs/heads/3.0/SPECS/kernel/config
```
Is this link relevant?

And where did you get your config for Azure?

> Fwiw, here's CentOS Stream 10 (Coughlan) [3]. Downloaded from the official 20250331.0 x86-64 iso

Yes, some distros have published new releases since the last update of kconfig files in `kernel_hardening_checker/config_files/distros/`.

By the way, would you like to do a small contribution? 
I'll describe it step by step:
 - Update the distro release numbers in [get_kconfigs.sh](https://github.com/a13xp0p0v/kernel-hardening-checker/blob/master/kernel_hardening_checker/config_files/distros/get_kconfigs.sh) (it's simple),
 - Run that script,
 - And create a pull request with the updated kconfig files.

Thank you!

#### <img src="https://avatars.githubusercontent.com/u/84989429?u=0f9ba34cfa38ee1e11d4948f6c04e6d9c4383e44&v=4" width="50">[xgloom](https://github.com/xgloom) commented at [2025-05-05 15:10](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/184#issuecomment-2851319971):

Hi @a13xp0p0v 

1. 
> Is this link relevant? And where did you get your config for Azure?

I got mine from a live actual Azure VM on https://portal.azure.com/. I guess that means that their actual Azure Linux kconfig differs from their Github repo.

2. 
`get_kconfigs.sh` is nice. Looking at it, I believe that we can automate this completely for all oracle distro's by fetching the distro `unique_names` from the oracle gh-pages URL too. There are 98 of them, so then we have a complete list and also something that doesn't require periodic text updates (of course unless Oracle's git pages changes drastically).

```bash
$ wget -qO- https://raw.githubusercontent.com/oracle/kconfigs/gh-pages/docs/summary.json | jq '.distros[].unique_name' | wc -l
98
```

Like this:

```bash
oracle_git_url="https://raw.githubusercontent.com/oracle/kconfigs/refs/heads/gh-pages/"

readarray -t kconfigs_from_oracle < <(
  # wget output could alternatively be piped to jq -r '.distros[].unique_name'
  wget -qO- "${oracle_git_url}docs/summary.json" | grep -o '"unique_name": "[^"]*"' |  awk -F'"' '{print $4}'
)
```

Would you like me to include this in the PR, or only update the configs I fetched?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-31 13:53](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/184#issuecomment-2925215926):

Distro kconfigs updated in https://github.com/a13xp0p0v/kernel-hardening-checker/commit/a263e3847f38f24c459881c1b650d377466500c3 and https://github.com/a13xp0p0v/kernel-hardening-checker/commit/6d9270cda2e3a6ffb361a62aa77c870f1f7acb18.

Closing this issue for now.


-------------------------------------------------------------------------------

# [\#183 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/183) `merged`: Reorder output tables
**Labels**: `new_feature`, `planned_before_release`


#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) opened issue at [2025-04-11 09:00](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/183):

Hi, I think it's a good idea to reorder the `reason` and `desired_val` tables, because `desired_val` is mostly unpredictable and there can be really long option names, for exaple cmdline parameter `lockdown=confidentiality` or `efi=disable_early_pci_dma` would tear up the output table like this:

![image](https://github.com/user-attachments/assets/9b89a120-6924-4156-b494-7f4089fec348)

After reordering the tables it would look a bit better:

![image](https://github.com/user-attachments/assets/def87443-4b79-4854-af21-c859a8fccdb1)

 By the way, having the desired value close to the check result seems a bit more convenient :)
 
 I hope you will find this addition as a great one, waiting for your review!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-04 23:39](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/183#issuecomment-2849499390):

Hello @Willenst,

Nice, I like this idea.

Could you please rebase this branch on the fresh `master` and also update the README?

Thank you!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-05 00:22](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/183#issuecomment-2849612422):

I would also ask you to make the `option_name` column smaller by 2 symbols.

That will make the table look much better in the README.

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) commented at [2025-05-06 08:00](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/183#issuecomment-2853624033):

Hello, I reduced the `option_name` by 2 characters:
https://github.com/a13xp0p0v/kernel-hardening-checker/pull/183/commits/6608130b270f70304afd8e0d4bbd042c8d8e11ef

And also updated the README:
https://github.com/a13xp0p0v/kernel-hardening-checker/pull/183/commits/a0a9e578ed4b7a88ee0884428574c13a2788ba8b

Rebased on a fresh master and haven't squashed commits yet to simplify the review

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-08 00:42](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/183#issuecomment-2860952829):

Applied, thanks @Willenst!


-------------------------------------------------------------------------------

# [\#182 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/182) `open`: Add new checks related to IOMMU configuration (Kconfig and cmdline)
**Labels**: `question`, `new_check`


#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) opened issue at [2025-04-07 17:33](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/182):

Hello,

While working on Issue #169 , I came across several kernel configuration and command-line options that could potentially enhance the security posture of a system by reducing its attack surface. I'd like to propose adding checks for the following options:

### Kconfig Checks
`CONFIG_IOMMU_DEFAULT_DMA_LAZY`

Why it matters: According to the documentation (https://cateee.net/lkddb/web-lkddb/IOMMU_DEFAULT_DMA_LAZY.html),  this option enables lazy DMA domain allocation, which may result in reduced isolation between devices.

Currently, it is enabled on actual (6.11.7) defconfig and in some distributions. It may be worth adding this as a potential `cut attack surface` option.

### Cmdline Parameter Checks
`intel_iommu=sp_off,sm_off`
	`sp_off`: Disables superpages (hugepages).
	`sm_off`: Disables scalable mode.

Reason: Disabling these features can help reduce attack surface, especially in scenarios where large mappings and scalability speedups are not required.
CVE examples:
https://cisoclub.ru/bdu2019-01306
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-33972
https://nvd.nist.gov/vuln/detail/CVE-2022-48916

`amd_iommu=irtcachedis, nohugepages`

Reason: Basically the same as for Intel, but for AMD - to cut off attack surface by trading some speed.

`amd_iommu=force_isolation`
Reason: Just in case some additional layer of security is required

All cases may be marked as `cut attack surface`

### Additional info

If you're interested in learning more about these options, you can find documentation for AMD here: https://elixir.bootlin.com/linux/v6.13.4/source/Documentation/admin-guide/kernel-parameters.txt#L325

And for Intel, you can find documentation here: https://elixir.bootlin.com/linux/v6.13.4/source/Documentation/admin-guide/kernel-parameters.txt#L2218

If you'd like to take a look at the source code for these options, you're welcome to do so.
If I'm not mistaken, Intel can be found here: https://elixir.bootlin.com/linux/v6.13.4/source/drivers/iommu/intel/iommu.c#L240.
As for AMD, it can be found here: https://elixir.bootlin.com/linux/v6.13.4/source/drivers/iommu/amd/init.c#L3455.

Let me know if this aligns with the vision of the tool. I’d be happy to help contribute implementation if the proposed checks make sense.

Thanks for your time and work on this project!




-------------------------------------------------------------------------------

# [\#181 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/181) `closed`: Allow using `-v, --kernel-version KERNEL_VERSION` for sysctl checking
**Labels**: `bug/fix`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2025-03-24 08:32](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/181):

This will help for `RISC-V` without `kernel.arch` sysctl.

Refers to #172.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-03-24 13:06](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/181#issuecomment-2748074882):

![Image](https://github.com/user-attachments/assets/e80963cb-3e37-480f-a51f-29b8fc856ccd)

Unfortunately, this looks like a part of Fedora kernel naming, so it will not work in general.


-------------------------------------------------------------------------------

# [\#180 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/180) `merged`: Improved some comments-warnings
**Labels**: `bug/fix`, `planned_before_release`


#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) opened issue at [2025-03-18 14:39](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/180):

hello, @a13xp0p0v 

i recently created a VM to test my hardening, after which i found that some of the checks have a bigger effect than expected

- `bdev_allow_write_mounted=0`
since snap uses the squashfs filesystem and creates loop devices, enabling this line may crash snap and its applications

![image](https://github.com/user-attachments/assets/9ee1b670-583e-40b7-b322-6f239234fdb9)

- `kernel.modules_disabled=1`
it interrupts system startup. it should be installed only after the kernel is loaded (e.g. with systemd).

![image](https://github.com/user-attachments/assets/c37db1b9-6de6-4431-ba1c-1e5867df572f)


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-03-24 06:46](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/180#issuecomment-2747054275):

Nice, thanks @d1sgr4c3 !

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-04 23:32](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/180#issuecomment-2849496936):

Hello @d1sgr4c3, thanks again for your pull request.

I've just tested your error with `bdev_allow_write_mounted`: I can't reproduce it on Fedora 41.

![image](https://github.com/user-attachments/assets/055994c9-f2f9-4409-9da6-066396844a29)

Could you double-check it please?

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2025-05-07 10:51](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/180#issuecomment-2858100809):

hello, @a13xp0p0v !

> :I can't reproduce it on Fedora 41.

this is because of Fedora: since snap depends on AppArmor (`dmesg | grep -i AppArmor`), there is no sandboxing implemented because Fedora uses another LSM

__Do you think maybe the comment should describe the problem for Ubuntu?__

```diff
- # enabling this kernel's command-line parameter can break snap and its applications,
+ # enabling this kernel's command-line parameter can break snap and its applications on Ubuntu,
```

--- 

>The snap daemon uses AppArmor and Seccomp to create a security policy that 
is linked to a specific snap revision. This governs what a snap can 
access on your system. AppArmor profiles and Seccomp filters are created
 for each command, and while AppArmor profiles can be changed and 
reloaded while a process is running, Seccomp filters cannot.

https://ubuntu.com/core/docs/security-and-sandboxing

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-07 23:55](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/180#issuecomment-2860850965):

Applied, thanks @d1sgr4c3!


-------------------------------------------------------------------------------

# [\#179 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/179) `closed`: Add a check for CONFIG_ARM_KERNMEM_PERMS for kernel 3.19, 4.0–4.5
**Labels**: `question`, `new_check`


#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2025-02-18 14:35](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/179):

See https://cateee.net/lkddb/web-lkddb/ARM_KERNMEM_PERMS.html and https://www.kernelconfig.io/config_arm_kernmem_perms?q=&kernelversion=%205.4.229&arch=arm

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-02-23 11:03](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/179#issuecomment-2676776894):

Hi @jvoisin, 

Thanks for creating the issue.
 
Was this feature enabled by default?

How about distros, which existed that time?

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2025-02-23 11:55](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/179#issuecomment-2676816141):

I don't think it was ever set by default, and I don't know about distributions making use of it :<

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-03-09 15:27](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/179#issuecomment-2708915229):

Ok, thanks for the info.

Looks like we don't have enough confidence to recommend it for everybody.

However, this case reminds me about the feature https://github.com/a13xp0p0v/kernel-hardening-checker/issues/50, which would allow to add various custom checks.

Closing for now.


-------------------------------------------------------------------------------

# [\#178 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/178) `closed`: KCFI Configurations May Require Excluding FineIBT Depending on FRED Hardware Presence
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/158655396?v=4" width="50">[wryMitts](https://github.com/wryMitts) opened issue at [2025-02-18 04:24](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/178):

Seems that the patch is still being discussed, but wanted to raise awareness:

> However, micro-architecturally, FineIBT is still far better than simple
> IBT for speculation issue, seeing as Intel keep on staunchly refusing to
> turn off the indirect predictors by default like AMD do.
> 
> A security conscious user ought to be using FineIBT for this, given a
> choice, even if it's not perfect in other regards.

-Andrew Cooper

> A security conscious user should use kCFI without FineIBT. :) But I
> think we might be thinking about different elements of security. I am
> focusing on control flow, and I think you're considering speculation?

-Kees Cook


> True.  The security realist knows they're dammed either way, and gets a
> stiff drink instead.

-Andrew Cooper



Appears to be related to:
- Hardware Support of FRED
- FineIBT presence
- Normal IBT Presence?

Enabling FineIBT causes:
Increased speculation attack mitigations? (Andrew Cooper)

Disabling FineIBT:
Better control flow integrity attack mitigations? (Kees Cook)



https://lore.kernel.org/r/20250214192210.work.253-kees@kernel.org 
https://patchwork.kernel.org/project/linux-hardening/patch/20250214192210.work.253-kees@kernel.org/

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-02-23 10:44](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/178#issuecomment-2676766062):

Thanks for the info @wryMitts.

Yes, Kees says:

> But kCFI (with or without IBT, but without FineIBT) will do hash checking at the call site, which
> should make it impossible to reach the entrypoints from an indirect call
> in the first place, as they have no hash preceding them

So KSPP recommends this:
```
# Disable FineIBT since it is weaker than pure KCFI.
cfi=kcfi
```

That's why `kernel-hardening-checker` performs this check:
```
if arch == 'X86_64':
    l += [OR(CmdlineCheck('self_protection', 'kspp', 'cfi', 'kcfi'),
             AND(KconfigCheck('self_protection', 'a13xp0p0v', 'CFI_AUTO_DEFAULT', 'is not set'),
                 KconfigCheck('self_protection', 'a13xp0p0v', 'CFI_AUTO_DEFAULT', 'is present'),
                 CmdlineCheck('self_protection', 'kspp', 'cfi', 'is not set')))]
```

Looks like this check is correct.

Thanks!


-------------------------------------------------------------------------------

# [\#177 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/177) `closed`: Bug with `sysctl` on Android
**Labels**: `bug/fix`


#### <img src="https://avatars.githubusercontent.com/u/3126033?u=da7babdfdf6deb9a767d9862abc9442edeb605a7&v=4" width="50">[Fi5t](https://github.com/Fi5t) opened issue at [2025-02-01 19:20](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/177):

I've tried to run this tool in Android and faced some strange problem. I ran script `kernel-hardening-checker` with autodetect and saw the following error in the terminal:
```shell
# python3 kernel-hardening-checker -a
[+] Going to autodetect and check the security hardening options of the running kernel
[+] Detected version of the running kernel: (5, 10, 177)
[+] Detected kconfig file of the running kernel: /proc/config.gz
[+] Detected cmdline parameters of the running kernel: /proc/cmdline
[!] ERROR: sysctl command returned 1
```
After a bit research I understood that root cause of this problem is `sysctl` binary from `toybox`. It returns non-zero code if I run it. Your tool uses the same binary and this leads to the bug.

I also tried to run `sysctl` from termux packages and it works like a charm:

![Image](https://github.com/user-attachments/assets/d3389cc3-79cb-4d64-b210-79cf80afb8f5)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-02-01 21:42](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/177#issuecomment-2629127134):

Hi @Fi5t, thanks a lot for the report.

I tried to fix this in https://github.com/a13xp0p0v/kernel-hardening-checker/commit/0c00f3fa766496d221ae3b79ce3f6730468f3641.

Could you please check the tool again on your devices?

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/3126033?u=da7babdfdf6deb9a767d9862abc9442edeb605a7&v=4" width="50">[Fi5t](https://github.com/Fi5t) commented at [2025-02-03 08:45](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/177#issuecomment-2630306916):

I've checked it and now everything works fine. I still see the warning in the log, but not the error.

<img width="1226" alt="Image" src="https://github.com/user-attachments/assets/6bc2482e-aa72-4d1c-9329-88dc0c34aaf1" />

Nevertheless, `sysctl` checks also work. Thank you!

<img width="1190" alt="Image" src="https://github.com/user-attachments/assets/bdb5358e-b2d5-462f-830c-4c5bb07ef968" />


-------------------------------------------------------------------------------

# [\#176 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/176) `closed`: ti-sgx-ddk-km driver fails to compile

#### <img src="https://avatars.githubusercontent.com/u/86064602?v=4" width="50">[Sujjan19](https://github.com/Sujjan19) opened issue at [2025-01-30 12:12](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/176):

After merging the ARM's config fragment with TI Sitara yocto build's config using merge_config.sh, the ti-sgx-ddk-km driver fails to compile. 

Is there any config which has been disabled, which is required by this ti-sgx-ddk-km driver ? 

#### <img src="https://avatars.githubusercontent.com/u/86064602?v=4" width="50">[Sujjan19](https://github.com/Sujjan19) commented at [2025-01-31 09:38](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/176#issuecomment-2626764889):

The tool disabled the DRM_LEGACY option which was required by the driver, since the driver is not up-to-date.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-02-01 22:34](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/176#issuecomment-2629143972):

Thanks for the info, @Sujjan19


-------------------------------------------------------------------------------

# [\#175 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/175) `closed`: 64-bit ARM MMAP_MIN_ADDR recommendation should be based on whether CONFIG_COMPAT is enabled
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) opened issue at [2025-01-13 03:34](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/175):

This is meant to be 32768 not only on 32-bit ARM but also 64-bit ARM when 32-bit process compatibility is enabled. It should check for 32-bit compatibility and make the recommendation based on it. There's already a recommendation to disable 32-bit support for attack surface reduction and being able to raise MMAP_MIN_ADDR one a tiny, largely insignificant side benefit.

Here's a relevant snippet from `security/Kconfig`:

```
config LSM_MMAP_MIN_ADDR
	int "Low address space for LSM to protect from user allocation"
	depends on SECURITY && SECURITY_SELINUX
	default 32768 if ARM || (ARM64 && COMPAT)
	default 65536
```

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-01-22 15:24](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/175#issuecomment-2607543775):

Hello @thestinger,

Thanks for creating the issue!

Yes, `kernel-hardening-checker` recommends to disable `CONFIG_COMPAT` according to the KSPP recommendations:
```
    l += [KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT', 'is not set')]
```

So it would be strange if we change the `MMAP_MIN_ADDR` check for `ARM64` depending on the unwanted option and turn `FAIL` into `OK` if `CONFIG_COMPAT` is enabled.

Would you agree?

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2025-01-22 15:28](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/175#issuecomment-2607554762):

> Would you agree?

No, I think CONFIG_COMPAT being enabled should cause 1 failure. Right now, it's causing a 2nd one even when that's already set to what it should be when it's enabled. The recommendation also means encouraging people to set a broken configuration since 32-bit ARM is recommended to have a lower value for compatibility. I don't know how much that's actually needed in practice but it's what they recommended.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-01-22 15:45](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/175#issuecomment-2607597894):

I think we should not turn `FAIL` into `OK` depending on the `CONFIG_COMPAT` option that is not recommended.

But I also agree with your statement:
```
The recommendation also means encouraging people to set a broken configuration
since 32-bit ARM is recommended to have a lower value for compatibility. 
``` 

What if we modify it this way for `ARM64`?
```
        l += [AND(KconfigCheck('self_protection', 'kspp', 'DEFAULT_MMAP_MIN_ADDR', '65536'),
                  KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT', 'is not set'))]
```
The output for Pixel 3a would look this way:
```
CONFIG_DEFAULT_MMAP_MIN_ADDR            |kconfig|   65536    |   kspp   | self_protection  | FAIL: CONFIG_COMPAT is not "is not set"
```

With this approach, we:

- Don't say `OK` for the not recommended option 
- And also avoid encouraging people to set wrong value of `CONFIG_DEFAULT_MMAP_MIN_ADDR` if they have `CONFIG_COMPAT` enabled.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-31 15:21](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/175#issuecomment-2925325883):

The solution https://github.com/a13xp0p0v/kernel-hardening-checker/issues/175#issuecomment-2607597894 is implemented in https://github.com/a13xp0p0v/kernel-hardening-checker/commit/6a209abf269d2797fd8240beb9243de7ec361a28.

Thanks!


-------------------------------------------------------------------------------

# [\#174 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/174) `closed`: Ignore kernel.modules_disabled if CONFIG_MODULES is not set
**Labels**: `bug/fix`


#### <img src="https://avatars.githubusercontent.com/u/23032146?u=b7f1c1c76eb3090e07f73ed855b136435d577db6&v=4" width="50">[jo-so](https://github.com/jo-so) opened issue at [2025-01-10 12:05](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/174):

We are using no modules for our kernel (CONFIG_MODULES=n) which removes /proc/sys/kernel/modules_disabled. This makes this check fail:

```
+kernel.modules_disabled                 |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: is not found
```

We are using version f4dbe258ff3d37489962ea9cf210192ae7ff9280.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-01-22 15:14](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/174#issuecomment-2607516191):

Hello @jo-so, 

It looks like `v0.6.10` contains the commit 7a85a7fddae52572d2cc3f51b7d2f1696b69b94a, which solves your issue.

But it can work only if you check `sysctl` together with `kconfig`. Without the `kconfig` file, `kernel-hardening-checker` can't know that your kernel has disabled `CONFIG_MODULES`.

Could you please try the tool both with `-c` and `-s`?

I guess in this case there is no false check.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-03-09 15:16](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/174#issuecomment-2708909419):

Double-checked `kernel-hardening-checker` for the kernel with disabled `CONFIG_MODULES`:
```
$ ./bin/kernel-hardening-checker -c ~/linux-stable/linux-stable/.config -s /tmp/s |grep modules
kernel.modules_disabled                 |sysctl |     1      |   kspp   |cut_attack_surface| OK: CONFIG_MODULES is "is not set"
```

Checked on the commit: https://github.com/a13xp0p0v/kernel-hardening-checker/commit/dd028a2fd49ce5f25f05cdbec91958022c2a3dc2

Closing this issue.


-------------------------------------------------------------------------------

# [\#173 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/173) `closed`: What are the opinions about: "Allow /proc/pid/mem access override"
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/163189276?v=4" width="50">[migrgh](https://github.com/migrgh) opened issue at [2024-12-31 20:26](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/173):

```
CONFIG_PROC_MEM_ALWAYS_FORCE:
This allows /proc/pid/mem accesses to override memory mapping
permissions if you have ptrace access rights. 
```

```
CONFIG_PROC_MEM_FORCE_PTRACE: 
This allows /proc/pid/mem accesses to override memory mapping                                
permissions for active ptracers like gdb. 
```

```
CONFIG_PROC_MEM_NO_FORCE: 
Never override memory mapping permissions
```

https://github.com/a13xp0p0v/kernel-hardening-checker/issues/147


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-01-22 14:55](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/173#issuecomment-2607465726):

#170

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-10-18 06:11](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/173#issuecomment-3417856097):

Implemented in https://github.com/a13xp0p0v/kernel-hardening-checker/pull/201.
Thanks!


-------------------------------------------------------------------------------

# [\#172 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172) `merged`: Add support for RISC-V
**Labels**: `new_feature`, `planned_before_release`


#### <img src="https://avatars.githubusercontent.com/u/434827?u=1fe0601f243e1627c6f738027d2e71b90dad989d&v=4" width="50">[bcoles](https://github.com/bcoles) opened issue at [2024-12-27 11:00](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172):

This PR adds support for RISC-V. Fixes #56.


## generate defconfig

The provided kernel config files were generated using the RISC-V toolchain (gcc):

```sh
git checkout v6.10
PATH="/home/user/Desktop/riscv/bin:$PATH" ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- make defconfig
mv .config ../kernel-hardening-checker/kernel_hardening_checker/config_files/defconfigs/riscv_defconfig_6.10.config
```

(I can also provide configs built with `musl` if that would be of any use.)


## detect_arch_by_kconfig()

Kernel configs for both 32-bit and 64-bit RISC-V systems use `CONFIG_RISCV_*`.

`detect_arch_by_kconfig()` uses `"RISCV"` for architecture detection, ignoring bit-width.



## detect_arch_by_sysctl()

I examined multiple Linux RISC-V systems, many of which did not populate the `kernel.arch` sysctl.

`detect_arch_by_sysctl()` uses `riscv32` and `riscv64` for 32-bit and 64-bit respectively. `uname -m` provides the same values. Perhaps a new `detect_arch_by_uname()` function should be added as a fallback.



## Example Output

Example output on `debian-20240128-convert_riscv64-virt` in Qemu:

<details>
<p>

```
#!/bin/sh
# https://wiki.debian.org/RISC-V
# https://wiki.qemu.org/Documentation/Platforms/RISCV
# https://gitlab.com/api/v4/projects/giomasce%2Fdqib/jobs/artifacts/master/download?job=convert_riscv64-virt

/home/user/qemu/build/qemu-system-riscv64 \
  -nographic \
  -cpu rv64 \
  -nographic \
  -M virt \
  -m 1G \
  -smp 2 \
  -bios /usr/lib/riscv64-linux-gnu/opensbi/generic/fw_jump.elf \
  -kernel /usr/lib/u-boot/qemu-riscv64_smode/uboot.elf \
  -object rng-random,filename=/dev/urandom,id=rng \
  -device virtio-rng-device,rng=rng \
  -device virtio-blk-device,drive=hd -drive file=image.qcow2,if=none,id=hd \
  -device virtio-net-device,netdev=net -netdev user,id=net,hostfwd=tcp::2222-:22 \
  -append "root=LABEL=rootfs console=ttyS0" \
  -no-reboot
```
</p>
</details>


Output:

<details>
<p>

```
user@debian:~/kernel-hardening-checker$ python3 ./bin/kernel-hardening-checker -a
[+] Going to autodetect and check the security hardening options of the running kernel
[+] Detected version of the running kernel: (6, 6, 13)
[+] Detected kconfig file of the running kernel: /boot/config-6.6.13-riscv64
[+] Detected cmdline parameters of the running kernel: /proc/cmdline
Traceback (most recent call last):
  File "/home/user/kernel-hardening-checker/./bin/kernel-hardening-checker", line 22, in <module>
    kernel_hardening_checker.main()
  File "/home/user/kernel-hardening-checker/kernel_hardening_checker/__init__.py", line 441, in main
    ret = subprocess.run(['sysctl', '-a'], check=False, stdout=f, stderr=subprocess.DEVNULL, shell=False).returncode
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/subprocess.py", line 548, in run
    with Popen(*popenargs, **kwargs) as process:
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/subprocess.py", line 1026, in __init__
    self._execute_child(args, executable, preexec_fn, close_fds,
  File "/usr/lib/python3.12/subprocess.py", line 1955, in _execute_child
    raise child_exception_type(errno_num, err_msg, err_filename)
FileNotFoundError: [Errno 2] No such file or directory: 'sysctl'  
```

```
user@debian:~/kernel-hardening-checker$ PATH="/sbin:$PATH" ./bin/kernel-hardening-checker -a
[+] Going to autodetect and check the security hardening options of the running kernel
[+] Detected version of the running kernel: (6, 6, 13)
[+] Detected kconfig file of the running kernel: /boot/config-6.6.13-riscv64
[+] Detected cmdline parameters of the running kernel: /proc/cmdline
[+] Saved sysctl output to /tmp/sysctl-65u_jxyb
[+] Detected microarchitecture: RISCV
[+] Detected compiler: GCC 130200
[!] WARNING: cmdline option "root" is found multiple times
[!] WARNING: sysctl options available for root are not found in /tmp/sysctl-65u_jxyb, try checking the output of `sudo sysctl -a`
=========================================================================================================================
              option_name               | type  |desired_val | decision |      reason      | check_result
=========================================================================================================================
CONFIG_BUG                              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_SLUB_DEBUG                       |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_THREAD_INFO_IN_TASK              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_IOMMU_SUPPORT                    |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STACKPROTECTOR                   |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STACKPROTECTOR_STRONG            |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STRICT_KERNEL_RWX                |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STRICT_MODULE_RWX                |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_REFCOUNT_FULL                    |kconfig|     y      |defconfig | self_protection  | OK: version >= (5, 4, 208)
CONFIG_INIT_STACK_ALL_ZERO              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_CPU_MITIGATIONS                  |kconfig|     y      |defconfig | self_protection  | FAIL: is not found
CONFIG_RANDOMIZE_BASE                   |kconfig|     y      |defconfig | self_protection  | FAIL: "is not set"
CONFIG_VMAP_STACK                       |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_RANDOM_KMALLOC_CACHES            |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SLAB_MERGE_DEFAULT               |kconfig| is not set |   kspp   | self_protection  | FAIL: "y"
CONFIG_BUG_ON_DATA_CORRUPTION           |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SLAB_FREELIST_HARDENED           |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SLAB_FREELIST_RANDOM             |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SHUFFLE_PAGE_ALLOCATOR           |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_FORTIFY_SOURCE                   |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_DEBUG_VIRTUAL                    |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_DEBUG_SG                         |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_INIT_ON_ALLOC_DEFAULT_ON         |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_STATIC_USERMODEHELPER            |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SCHED_CORE                       |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_SECURITY_LOCKDOWN_LSM            |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY      |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY|kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_LIST_HARDENED                    |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_DEBUG_CREDENTIALS                |kconfig|     y      |   kspp   | self_protection  | OK: version >= (6, 6, 8)
CONFIG_DEBUG_NOTIFIERS                  |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SCHED_STACK_END_CHECK            |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_KFENCE                           |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_KFENCE_SAMPLE_INTERVAL           |kconfig|    100     |   kspp   | self_protection  | FAIL: "0"
CONFIG_RANDSTRUCT_FULL                  |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_HARDENED_USERCOPY                |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_HARDENED_USERCOPY_FALLBACK       |kconfig| is not set |   kspp   | self_protection  | OK: is not found
CONFIG_HARDENED_USERCOPY_PAGESPAN       |kconfig| is not set |   kspp   | self_protection  | OK: is not found
CONFIG_GCC_PLUGIN_LATENT_ENTROPY        |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_MODULE_SIG                       |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_MODULE_SIG_ALL                   |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_MODULE_SIG_SHA512                |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_MODULE_SIG_FORCE                 |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_INIT_ON_FREE_DEFAULT_ON          |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_EFI_DISABLE_PCI_DMA              |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_RESET_ATTACK_MITIGATION          |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_UBSAN_BOUNDS                     |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_UBSAN_LOCAL_BOUNDS               |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_UBSAN_TRAP                       |kconfig|     y      |   kspp   | self_protection  | FAIL: CONFIG_UBSAN_BOUNDS is not "y"
CONFIG_UBSAN_SANITIZE_ALL               |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_SECURITY_YAMA                    |kconfig|     y      |   kspp   | security_policy  | OK
CONFIG_SECURITY_LANDLOCK                |kconfig|     y      |   kspp   | security_policy  | OK
CONFIG_SECURITY_SELINUX_DISABLE         |kconfig| is not set |   kspp   | security_policy  | OK: is not found
CONFIG_SECURITY_SELINUX_BOOTPARAM       |kconfig| is not set |   kspp   | security_policy  | OK
CONFIG_SECURITY_SELINUX_DEVELOP         |kconfig| is not set |   kspp   | security_policy  | FAIL: "y"
CONFIG_SECURITY_WRITABLE_HOOKS          |kconfig| is not set |   kspp   | security_policy  | OK: is not found
CONFIG_SECURITY_SELINUX_DEBUG           |kconfig| is not set |   kspp   | security_policy  | OK
CONFIG_SECURITY_SELINUX                 |kconfig|     y      |a13xp0p0v | security_policy  | OK
CONFIG_SECCOMP                          |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_SECCOMP_FILTER                   |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_BPF_UNPRIV_DEFAULT_OFF           |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_SECURITY_DMESG_RESTRICT          |kconfig|     y      |   kspp   |cut_attack_surface| OK
CONFIG_ACPI_CUSTOM_METHOD               |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_COMPAT_BRK                       |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_DEVKMEM                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_BINFMT_MISC                      |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "m"
CONFIG_INET_DIAG                        |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "m"
CONFIG_KEXEC                            |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_PROC_KCORE                       |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_LEGACY_PTYS                      |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_HIBERNATION                      |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_COMPAT                           |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_IA32_EMULATION                   |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_X86_X32                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_X86_X32_ABI                      |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_MODIFY_LDT_SYSCALL               |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_OABI_COMPAT                      |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_X86_MSR                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_LEGACY_TIOCSTI                   |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_MODULE_FORCE_LOAD                |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_MODULES                          |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_DEVMEM                           |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_IO_STRICT_DEVMEM                 |kconfig|     y      |   kspp   |cut_attack_surface| OK
CONFIG_LDISC_AUTOLOAD                   |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_X86_VSYSCALL_EMULATION           |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_DRM_LEGACY                       |kconfig| is not set |maintainer|cut_attack_surface| OK
CONFIG_FB                               |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "y"
CONFIG_VT                               |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "y"
CONFIG_BLK_DEV_FD                       |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_BLK_DEV_FD_RAWCMD                |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT       |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_N_GSM                            |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "m"
CONFIG_ZSMALLOC_STAT                    |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_DEBUG_KMEMLEAK                   |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_BINFMT_AOUT                      |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_KPROBE_EVENTS                    |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_UPROBE_EVENTS                    |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_GENERIC_TRACER                   |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_FUNCTION_TRACER                  |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_STACK_TRACER                     |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_HIST_TRIGGERS                    |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_BLK_DEV_IO_TRACE                 |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_PROC_VMCORE                      |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PROC_PAGE_MONITOR                |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_USELIB                           |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_CHECKPOINT_RESTORE               |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_USERFAULTFD                      |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_HWPOISON_INJECT                  |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_MEM_SOFT_DIRTY                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DEVPORT                          |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_DEBUG_FS                         |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_NOTIFIER_ERROR_INJECTION         |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_FAIL_FUTEX                       |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PUNIT_ATOM_DEBUG                 |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_ACPI_CONFIGFS                    |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_EDAC_DEBUG                       |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DRM_I915_DEBUG                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DVB_C8SECTPFE                    |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_MTD_SLRAM                        |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_MTD_PHRAM                        |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_IO_URING                         |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_KCMP                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_RSEQ                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_LATENCYTOP                       |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_KCOV                             |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_PROVIDE_OHCI1394_DMA_INIT        |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_SUNRPC_DEBUG                     |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_X86_16BIT                        |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_BLK_DEV_UBLK                     |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_SMB_SERVER                       |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_XFS_ONLINE_SCRUB_STATS           |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_CACHESTAT_SYSCALL                |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_PREEMPTIRQ_TRACEPOINTS           |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_ENABLE_DEFAULT_TRACERS           |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PROVE_LOCKING                    |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_TEST_DEBUG_VIRTUAL               |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_MPTCP                            |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_TLS                              |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_TIPC                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_IP_SCTP                          |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_KGDB                             |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_PTDUMP_DEBUGFS                   |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_X86_PTDUMP                       |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DEBUG_CLOSURES                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_BCACHE_CLOSURES_DEBUG            |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_STAGING                          |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KSM                              |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KALLSYMS                         |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KEXEC_FILE                       |kconfig| is not set |  clipos  |cut_attack_surface| OK
CONFIG_CRASH_DUMP                       |kconfig| is not set |  clipos  |cut_attack_surface| OK
CONFIG_USER_NS                          |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_X86_CPUID                        |kconfig| is not set |  clipos  |cut_attack_surface| OK: is not found
CONFIG_X86_IOPL_IOPERM                  |kconfig| is not set |  clipos  |cut_attack_surface| OK: is not found
CONFIG_ACPI_TABLE_UPGRADE               |kconfig| is not set |  clipos  |cut_attack_surface| OK: is not found
CONFIG_EFI_CUSTOM_SSDT_OVERLAYS         |kconfig| is not set |  clipos  |cut_attack_surface| OK
CONFIG_AIO                              |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_MAGIC_SYSRQ                      |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_MAGIC_SYSRQ_SERIAL               |kconfig| is not set |grapheneos|cut_attack_surface| FAIL: "y"
CONFIG_EFI_TEST                         |kconfig| is not set | lockdown |cut_attack_surface| OK
CONFIG_MMIOTRACE_TEST                   |kconfig| is not set | lockdown |cut_attack_surface| OK: is not found
CONFIG_KPROBES                          |kconfig| is not set | lockdown |cut_attack_surface| FAIL: "y"
CONFIG_BPF_SYSCALL                      |kconfig| is not set | lockdown |cut_attack_surface| FAIL: "y"
CONFIG_MMIOTRACE                        |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_LIVEPATCH                        |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_IP_DCCP                          |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "m"
CONFIG_FTRACE                           |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "y"
CONFIG_VIDEO_VIVID                      |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "m"
CONFIG_INPUT_EVBUG                      |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_CORESIGHT                        |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_XFS_SUPPORT_V4                   |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "y"
CONFIG_BLK_DEV_WRITE_MOUNTED            |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_FAULT_INJECTION                  |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_ARM_PTDUMP_DEBUGFS               |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_ARM_PTDUMP                       |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_SECCOMP_CACHE_DEBUG              |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_LKDTM                            |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_TRIM_UNUSED_KSYMS                |kconfig|     y      |a13xp0p0v |cut_attack_surface| FAIL: "is not set"
CONFIG_COREDUMP                         |kconfig| is not set |  clipos  | harden_userspace | FAIL: "y"
CONFIG_ARCH_MMAP_RND_BITS               |kconfig|     24     |a13xp0p0v | harden_userspace | FAIL: "18"
CONFIG_ARCH_MMAP_RND_COMPAT_BITS        |kconfig|     17     |a13xp0p0v | harden_userspace | FAIL: is not found
nosmep                                  |cmdline| is not set |defconfig | self_protection  | OK: is not found
nosmap                                  |cmdline| is not set |defconfig | self_protection  | OK: is not found
nokaslr                                 |cmdline| is not set |defconfig | self_protection  | OK: is not found
nopti                                   |cmdline| is not set |defconfig | self_protection  | OK: is not found
nospectre_v1                            |cmdline| is not set |defconfig | self_protection  | OK: is not found
nospectre_v2                            |cmdline| is not set |defconfig | self_protection  | OK: is not found
nospectre_bhb                           |cmdline| is not set |defconfig | self_protection  | OK: is not found
nospec_store_bypass_disable             |cmdline| is not set |defconfig | self_protection  | OK: is not found
dis_ucode_ldr                           |cmdline| is not set |defconfig | self_protection  | OK: is not found
arm64.nobti                             |cmdline| is not set |defconfig | self_protection  | OK: is not found
arm64.nopauth                           |cmdline| is not set |defconfig | self_protection  | OK: is not found
arm64.nomte                             |cmdline| is not set |defconfig | self_protection  | OK: is not found
rodata                                  |cmdline|     on     |defconfig | self_protection  | OK: rodata is not found
slab_merge                              |cmdline| is not set |   kspp   | self_protection  | OK: is not found
slub_merge                              |cmdline| is not set |   kspp   | self_protection  | OK: is not found
page_alloc.shuffle                      |cmdline|     1      |   kspp   | self_protection  | FAIL: is not found
slab_nomerge                            |cmdline| is present |   kspp   | self_protection  | FAIL: is not present
init_on_alloc                           |cmdline|     1      |   kspp   | self_protection  | OK: CONFIG_INIT_ON_ALLOC_DEFAULT_ON is "y"
init_on_free                            |cmdline|     1      |   kspp   | self_protection  | FAIL: is not found
hardened_usercopy                       |cmdline|     1      |   kspp   | self_protection  | OK: CONFIG_HARDENED_USERCOPY is "y"
slab_common.usercopy_fallback           |cmdline| is not set |   kspp   | self_protection  | OK: is not found
kfence.sample_interval                  |cmdline|    100     |   kspp   | self_protection  | FAIL: is not found
nosmt                                   |cmdline| is present |   kspp   |cut_attack_surface| FAIL: is not present
debugfs                                 |cmdline|    off     |  grsec   |cut_attack_surface| FAIL: is not found
sysrq_always_enabled                    |cmdline| is not set |grapheneos|cut_attack_surface| OK: is not found
bdev_allow_write_mounted                |cmdline|     0      |a13xp0p0v |cut_attack_surface| OK: CONFIG_BLK_DEV_WRITE_MOUNTED is not found
norandmaps                              |cmdline| is not set |defconfig | harden_userspace | OK: is not found
net.core.bpf_jit_harden                 |sysctl |     2      |   kspp   | self_protection  | FAIL: is not found
kernel.oops_limit                       |sysctl |    100     |a13xp0p0v | self_protection  | FAIL: "10000"
kernel.warn_limit                       |sysctl |    100     |a13xp0p0v | self_protection  | FAIL: "0"
kernel.dmesg_restrict                   |sysctl |     1      |   kspp   |cut_attack_surface| OK
kernel.perf_event_paranoid              |sysctl |     3      |   kspp   |cut_attack_surface| OK
user.max_user_namespaces                |sysctl |     0      |   kspp   |cut_attack_surface| FAIL: "3618"
dev.tty.ldisc_autoload                  |sysctl |     0      |   kspp   |cut_attack_surface| FAIL: "1"
kernel.kptr_restrict                    |sysctl |     2      |   kspp   |cut_attack_surface| FAIL: "0"
dev.tty.legacy_tiocsti                  |sysctl |     0      |   kspp   |cut_attack_surface| OK
kernel.kexec_load_disabled              |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: "0"
kernel.unprivileged_bpf_disabled        |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: "2"
vm.unprivileged_userfaultfd             |sysctl |     0      |   kspp   |cut_attack_surface| OK
kernel.modules_disabled                 |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: "0"
kernel.io_uring_disabled                |sysctl |     2      |  grsec   |cut_attack_surface| FAIL: "0"
kernel.sysrq                            |sysctl |     0      |a13xp0p0v |cut_attack_surface| FAIL: "438"
fs.protected_symlinks                   |sysctl |     1      |   kspp   | harden_userspace | OK
fs.protected_hardlinks                  |sysctl |     1      |   kspp   | harden_userspace | OK
fs.protected_fifos                      |sysctl |     2      |   kspp   | harden_userspace | FAIL: "1"
fs.protected_regular                    |sysctl |     2      |   kspp   | harden_userspace | OK
fs.suid_dumpable                        |sysctl |     0      |   kspp   | harden_userspace | OK
kernel.randomize_va_space               |sysctl |     2      |   kspp   | harden_userspace | OK
kernel.yama.ptrace_scope                |sysctl |     3      |   kspp   | harden_userspace | FAIL: "0"
vm.mmap_rnd_bits                        |sysctl |     24     |a13xp0p0v | harden_userspace | FAIL: is not found
vm.mmap_rnd_compat_bits                 |sysctl |     17     |a13xp0p0v | harden_userspace | FAIL: is not found

[+] Config check is finished: 'OK' - 135 / 'FAIL' - 96
```
</p>
</details>


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-01-22 14:10](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2607351305):

Hello @bcoles,

Cool, thanks for your work and interest to this project!

Some thoughts for the beginning:

- Looks like the Linux kernel has a single `arch/riscv/` directory in the source code. Do we really need to add three more arches `'RISCV', 'RISCV32', 'RISCV64'` for `kernel-hardening-checker`?
- Did you try to compare the `defconfig` checks for the latest `RISC-V` defconfig file? They should be adapted not to give the `FAIL` results.
- How about adding `Ubuntu for RISC-V` config to the distros collection?

#### <img src="https://avatars.githubusercontent.com/u/434827?u=1fe0601f243e1627c6f738027d2e71b90dad989d&v=4" width="50">[bcoles](https://github.com/bcoles) commented at [2025-01-24 13:56](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2612590842):

>     * Looks like the Linux kernel has a single `arch/riscv/` directory in the source code. Do we really need to add three more arches `'RISCV', 'RISCV32', 'RISCV64'` for `kernel-hardening-checker`?

No, we don't need all three. I have replaced these with one: `RISCV`.


>     * Did you try to compare the `defconfig` checks for the latest `RISC-V` defconfig file? They should be adapted not to give the `FAIL` results.

I thought the included defconf files were supposed to represent the mainline defaults. The other defconf files in the repository certainly do not pass - they result in multiple failures.

Perhaps I misunderstand. Can you elaborate?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-01-25 12:32](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2613951564):

> I thought the included defconf files were supposed to represent the mainline defaults. The other defconf files in the repository certainly do not pass - they result in multiple failures.

I mean `kernel_hardening_checker/checks.py` contains checks with the `defconfig` value in the `reason` field, and they represent the kernel hardening features that are enabled on supported microarchitectures by default.

For example, `PAGE_TABLE_ISOLATION` is enabled in `defconfig` for `X86_64`.
But on `X86_32` it's off by default and we mark it as recommended by KSPP.
So we have these checks with the corresponding `if arch`:
```
    if arch == 'X86_64':
        l += [OR(KconfigCheck('self_protection', 'defconfig', 'MITIGATION_PAGE_TABLE_ISOLATION', 'y'),
                 KconfigCheck('self_protection', 'defconfig', 'PAGE_TABLE_ISOLATION', 'y'))]
...
    if arch == 'X86_32':
        l += [OR(KconfigCheck('self_protection', 'kspp', 'MITIGATION_PAGE_TABLE_ISOLATION', 'y'),
                 KconfigCheck('self_protection', 'kspp', 'PAGE_TABLE_ISOLATION', 'y'))]
```

It's the first thing that we need to fix in this pull request:
1) please fix `if arch` for the `defconfig` checks that show FAIL on the RISC-V `defconfig` file.
2) please change the `reason` field to `defconfig` for other kernel hardening features that are enabled by default on RISC-V kernel v0.6.10.

After this work, our `defconfig` checks in `kernel-hardening-checker` will show truth and we could go further.

Thank you!

#### <img src="https://avatars.githubusercontent.com/u/434827?u=1fe0601f243e1627c6f738027d2e71b90dad989d&v=4" width="50">[bcoles](https://github.com/bcoles) commented at [2025-01-25 14:24](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2613982790):

Thanks.

>     1. please fix `if arch` for the `defconfig` checks that show FAIL on the RISC-V `defconfig` file.

That makes sense. I have implemented these changes.

>     2. please change the `reason` field to `defconfig` for other kernel hardening features that are enabled by default on RISC-V kernel v0.6.10.

I have implemented these changes for `defconfig` and `self_protection` checks (using the provided kernel 6.9.0 `defconfig` file), presuming you meant `decision` rather than `reason`.

Output:

<details>

```
$ ./bin/kernel-hardening-checker -c kernel_hardening_checker/config_files/defconfigs/riscv_defconfig_6.9.config  
[+] Kconfig file to check: kernel_hardening_checker/config_files/defconfigs/riscv_defconfig_6.9.config
[+] Detected kernel version: (6, 9, 0)
[+] Detected microarchitecture: RISCV
[+] Detected compiler: GCC 130200
=========================================================================================================================
              option_name               | type  |desired_val | decision |      reason      | check_result
=========================================================================================================================
CONFIG_BUG                              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_SLUB_DEBUG                       |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_THREAD_INFO_IN_TASK              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_IOMMU_SUPPORT                    |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STACKPROTECTOR                   |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STACKPROTECTOR_STRONG            |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STRICT_KERNEL_RWX                |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STRICT_MODULE_RWX                |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_REFCOUNT_FULL                    |kconfig|     y      |defconfig | self_protection  | OK: version >= (5, 4, 208)
CONFIG_INIT_STACK_ALL_ZERO              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_CPU_MITIGATIONS                  |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_VMAP_STACK                       |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_DEBUG_SG                         |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_LIST_HARDENED                    |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_SCHED_STACK_END_CHECK            |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_RANDOM_KMALLOC_CACHES            |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SLAB_MERGE_DEFAULT               |kconfig| is not set |   kspp   | self_protection  | FAIL: "y"
CONFIG_BUG_ON_DATA_CORRUPTION           |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SLAB_FREELIST_HARDENED           |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SLAB_FREELIST_RANDOM             |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SHUFFLE_PAGE_ALLOCATOR           |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_FORTIFY_SOURCE                   |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_DEBUG_VIRTUAL                    |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_INIT_ON_ALLOC_DEFAULT_ON         |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_STATIC_USERMODEHELPER            |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SCHED_CORE                       |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_SECURITY_LOCKDOWN_LSM            |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY      |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY|kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_DEBUG_CREDENTIALS                |kconfig|     y      |   kspp   | self_protection  | OK: version >= (6, 6, 8)
CONFIG_DEBUG_NOTIFIERS                  |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_KFENCE                           |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_KFENCE_SAMPLE_INTERVAL           |kconfig|    100     |   kspp   | self_protection  | FAIL: CONFIG_KFENCE is not "y"
CONFIG_RANDSTRUCT_FULL                  |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_HARDENED_USERCOPY                |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_HARDENED_USERCOPY_FALLBACK       |kconfig| is not set |   kspp   | self_protection  | FAIL: CONFIG_HARDENED_USERCOPY is not "y"
CONFIG_HARDENED_USERCOPY_PAGESPAN       |kconfig| is not set |   kspp   | self_protection  | FAIL: CONFIG_HARDENED_USERCOPY is not "y"
CONFIG_GCC_PLUGIN_LATENT_ENTROPY        |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_MODULE_SIG                       |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_MODULE_SIG_ALL                   |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_MODULE_SIG_SHA512                |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_MODULE_SIG_FORCE                 |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_INIT_ON_FREE_DEFAULT_ON          |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_EFI_DISABLE_PCI_DMA              |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_RESET_ATTACK_MITIGATION          |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_UBSAN_BOUNDS                     |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_UBSAN_LOCAL_BOUNDS               |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_UBSAN_TRAP                       |kconfig|     y      |   kspp   | self_protection  | FAIL: CONFIG_UBSAN_BOUNDS is not "y"
CONFIG_UBSAN_SANITIZE_ALL               |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_SECURITY_YAMA                    |kconfig|     y      |   kspp   | security_policy  | FAIL: "is not set"
CONFIG_SECURITY_LANDLOCK                |kconfig|     y      |   kspp   | security_policy  | FAIL: "is not set"
CONFIG_SECURITY_SELINUX_DISABLE         |kconfig| is not set |   kspp   | security_policy  | OK: is not found
CONFIG_SECURITY_SELINUX_BOOTPARAM       |kconfig| is not set |   kspp   | security_policy  | OK
CONFIG_SECURITY_SELINUX_DEVELOP         |kconfig| is not set |   kspp   | security_policy  | FAIL: "y"
CONFIG_SECURITY_WRITABLE_HOOKS          |kconfig| is not set |   kspp   | security_policy  | OK: is not found
CONFIG_SECURITY_SELINUX_DEBUG           |kconfig| is not set |   kspp   | security_policy  | OK
CONFIG_SECURITY_SELINUX                 |kconfig|     y      |a13xp0p0v | security_policy  | OK
CONFIG_SECCOMP                          |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_SECCOMP_FILTER                   |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_BPF_UNPRIV_DEFAULT_OFF           |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_STRICT_DEVMEM                    |kconfig|     y      |defconfig |cut_attack_surface| FAIL: "is not set"
CONFIG_SECURITY_DMESG_RESTRICT          |kconfig|     y      |   kspp   |cut_attack_surface| FAIL: "is not set"
CONFIG_ACPI_CUSTOM_METHOD               |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_COMPAT_BRK                       |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_DEVKMEM                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_BINFMT_MISC                      |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_INET_DIAG                        |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_KEXEC                            |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_PROC_KCORE                       |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_LEGACY_PTYS                      |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_HIBERNATION                      |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_COMPAT                           |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_IA32_EMULATION                   |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_X86_X32                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_X86_X32_ABI                      |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_MODIFY_LDT_SYSCALL               |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_OABI_COMPAT                      |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_X86_MSR                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_LEGACY_TIOCSTI                   |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_MODULE_FORCE_LOAD                |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_MODULES                          |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_DEVMEM                           |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_IO_STRICT_DEVMEM                 |kconfig|     y      |   kspp   |cut_attack_surface| FAIL: is not found
CONFIG_LDISC_AUTOLOAD                   |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_X86_VSYSCALL_EMULATION           |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_DRM_LEGACY                       |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_FB                               |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "y"
CONFIG_VT                               |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "y"
CONFIG_BLK_DEV_FD                       |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_BLK_DEV_FD_RAWCMD                |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT       |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_N_GSM                            |kconfig| is not set |maintainer|cut_attack_surface| OK
CONFIG_ZSMALLOC_STAT                    |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DEBUG_KMEMLEAK                   |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_BINFMT_AOUT                      |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_KPROBE_EVENTS                    |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_UPROBE_EVENTS                    |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_GENERIC_TRACER                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_FUNCTION_TRACER                  |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_STACK_TRACER                     |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_HIST_TRIGGERS                    |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_BLK_DEV_IO_TRACE                 |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PROC_VMCORE                      |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PROC_PAGE_MONITOR                |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_USELIB                           |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_CHECKPOINT_RESTORE               |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_USERFAULTFD                      |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_HWPOISON_INJECT                  |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_MEM_SOFT_DIRTY                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DEVPORT                          |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_DEBUG_FS                         |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_NOTIFIER_ERROR_INJECTION         |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_FAIL_FUTEX                       |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PUNIT_ATOM_DEBUG                 |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_ACPI_CONFIGFS                    |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_EDAC_DEBUG                       |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DRM_I915_DEBUG                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DVB_C8SECTPFE                    |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_MTD_SLRAM                        |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_MTD_PHRAM                        |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_IO_URING                         |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_KCMP                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_RSEQ                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_LATENCYTOP                       |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_KCOV                             |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_PROVIDE_OHCI1394_DMA_INIT        |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_SUNRPC_DEBUG                     |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_X86_16BIT                        |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_BLK_DEV_UBLK                     |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_SMB_SERVER                       |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_XFS_ONLINE_SCRUB_STATS           |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_CACHESTAT_SYSCALL                |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_PREEMPTIRQ_TRACEPOINTS           |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_ENABLE_DEFAULT_TRACERS           |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PROVE_LOCKING                    |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_TEST_DEBUG_VIRTUAL               |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_MPTCP                            |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_TLS                              |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_TIPC                             |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_IP_SCTP                          |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_KGDB                             |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_PTDUMP_DEBUGFS                   |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_X86_PTDUMP                       |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DEBUG_CLOSURES                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_BCACHE_CLOSURES_DEBUG            |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_STAGING                          |kconfig| is not set |  clipos  |cut_attack_surface| OK
CONFIG_KSM                              |kconfig| is not set |  clipos  |cut_attack_surface| OK
CONFIG_KALLSYMS                         |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KEXEC_FILE                       |kconfig| is not set |  clipos  |cut_attack_surface| OK
CONFIG_CRASH_DUMP                       |kconfig| is not set |  clipos  |cut_attack_surface| OK: is not found
CONFIG_USER_NS                          |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_X86_CPUID                        |kconfig| is not set |  clipos  |cut_attack_surface| OK: is not found
CONFIG_X86_IOPL_IOPERM                  |kconfig| is not set |  clipos  |cut_attack_surface| OK: is not found
CONFIG_ACPI_TABLE_UPGRADE               |kconfig| is not set |  clipos  |cut_attack_surface| OK: is not found
CONFIG_EFI_CUSTOM_SSDT_OVERLAYS         |kconfig| is not set |  clipos  |cut_attack_surface| OK
CONFIG_AIO                              |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_MAGIC_SYSRQ                      |kconfig| is not set |  clipos  |cut_attack_surface| OK
CONFIG_MAGIC_SYSRQ_SERIAL               |kconfig| is not set |grapheneos|cut_attack_surface| OK: is not found
CONFIG_EFI_TEST                         |kconfig| is not set | lockdown |cut_attack_surface| OK
CONFIG_MMIOTRACE_TEST                   |kconfig| is not set | lockdown |cut_attack_surface| OK: is not found
CONFIG_KPROBES                          |kconfig| is not set | lockdown |cut_attack_surface| OK
CONFIG_BPF_SYSCALL                      |kconfig| is not set | lockdown |cut_attack_surface| FAIL: "y"
CONFIG_MMIOTRACE                        |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_LIVEPATCH                        |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_IP_DCCP                          |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_FTRACE                           |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_VIDEO_VIVID                      |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_INPUT_EVBUG                      |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_CORESIGHT                        |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_XFS_SUPPORT_V4                   |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_BLK_DEV_WRITE_MOUNTED            |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "y"
CONFIG_FAULT_INJECTION                  |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_ARM_PTDUMP_DEBUGFS               |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_ARM_PTDUMP                       |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_SECCOMP_CACHE_DEBUG              |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_LKDTM                            |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_TRIM_UNUSED_KSYMS                |kconfig|     y      |a13xp0p0v |cut_attack_surface| FAIL: "is not set"
CONFIG_COREDUMP                         |kconfig| is not set |  clipos  | harden_userspace | FAIL: "y"
CONFIG_ARCH_MMAP_RND_BITS               |kconfig|     24     |a13xp0p0v | harden_userspace | FAIL: "18"
CONFIG_ARCH_MMAP_RND_COMPAT_BITS        |kconfig|     17     |a13xp0p0v | harden_userspace | FAIL: "8"

[+] Config check is finished: 'OK' - 114 / 'FAIL' - 66
```

</details>

#### <img src="https://avatars.githubusercontent.com/u/434827?u=1fe0601f243e1627c6f738027d2e71b90dad989d&v=4" width="50">[bcoles](https://github.com/bcoles) commented at [2025-01-25 14:34](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2613985762):

As for the checks, [KSPP Recommended Settings](https://kspp.github.io/Recommended_Settings) does not currently have recommendations for RISC-V, but some of the existing recommendations for other architectures are likely to be applicable. These may need to be assessed individually.

For example:

* [KASLR is supported](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f57805555834494e8cad729d01d86ba326d64959) (`CONFIG_RELOCATABLE`, `RANDOMIZE_BASE`), but not enabled by default.
* `DEFAULT_MMAP_MIN_ADDR` is `4096` in defconfig, but could likely be bumped up to `32768` per [KConfig documentation](https://elixir.bootlin.com/linux/v6.12.6/source/mm/Kconfig#L754).

Do you have a suggestion for the `decision` value to use for these? `kspp` or `a13xp0p0v` ?

#### <img src="https://avatars.githubusercontent.com/u/434827?u=1fe0601f243e1627c6f738027d2e71b90dad989d&v=4" width="50">[bcoles](https://github.com/bcoles) commented at [2025-01-25 15:14](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2613998260):

> How about adding Ubuntu for RISC-V config to the distros collection?

Sure, I can add config files for a few distros.

Unfortunately https://github.com/oracle/kconfigs does not have KConfig files for RISC-V systems.

Is there a better approach than pulling the config from `/usr/src/*$(uname -r)/.config` on a live system?

#### <img src="https://avatars.githubusercontent.com/u/434827?u=1fe0601f243e1627c6f738027d2e71b90dad989d&v=4" width="50">[bcoles](https://github.com/bcoles) commented at [2025-01-26 03:40](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2614196586):

> > How about adding Ubuntu for RISC-V config to the distros collection?
> 
> Sure, I can add config files for a few distros.
> 
> Unfortunately https://github.com/oracle/kconfigs does not have KConfig files for RISC-V systems.
> 
> Is there a better approach than pulling the config from `/usr/src/*$(uname -r)/.config` on a live system?

I've added OpenSUSE to the `get_kconfigs.sh` script and added a `OpenSUSE_riscv64.config` config file.

I've added a `Ubuntu_24.04_LTS_Noble_riscv64.config` config file for [Ubuntu 24.0.4.1 (RISC-V)](https://ubuntu.com/download/risc-v) kernel `6.8.0-41-generic`.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-02-01 16:06](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2629008933):

Hi @bcoles !

First of all, thanks for showing the autodetect bug on Debian.

I've fixed it:

```
deb@debian:~/kernel-hardening-checker$ which sysctl
deb@debian:~/kernel-hardening-checker$ cat /etc/issue
Debian GNU/Linux 11 \n \l

deb@debian:~/kernel-hardening-checker$ which sysctl
deb@debian:~/kernel-hardening-checker$ ./bin/kernel-hardening-checker -a
[+] Going to autodetect and check the security hardening options of the running kernel
[+] Detected version of the running kernel: (5, 10, 0)
[+] Detected kconfig file of the running kernel: /boot/config-5.10.0-32-amd64
[+] Detected cmdline parameters of the running kernel: /proc/cmdline
[+] Saved sysctls to a temporary file /tmp/sysctl-ktlabxv2
[+] Detected microarchitecture: X86_64
[+] Detected compiler: GCC 100201
...
```

Could you check that the latest `master` works fine for you?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-02-01 22:25](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2629141449):

And thanks for your fixes.
The first step with the `defconfig` checks looks good. 

> As for the checks, [KSPP Recommended Settings](https://kspp.github.io/Recommended_Settings) does not currently have recommendations for RISC-V, but some of the existing recommendations for other architectures are likely to be applicable. These may need to be assessed individually.
> 
> For example:
> 
> * [KASLR is supported](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f57805555834494e8cad729d01d86ba326d64959) (`CONFIG_RELOCATABLE`, `RANDOMIZE_BASE`), but not enabled by default.
> * `DEFAULT_MMAP_MIN_ADDR` is `4096` in defconfig, but could likely be bumped up to `32768` per [KConfig documentation](https://elixir.bootlin.com/linux/v6.12.6/source/mm/Kconfig#L754).
> 
> Do you have a suggestion for the `decision` value to use for these? `kspp` or `a13xp0p0v` ?

Yes, I think, this is the second step.

KSPP recommendations in the beginning contain a lot of settings that are universal for all microarchitectures.
However, not all of them are supported on RISC-V.

So we need to take those checks which are applicable to RISC-V. We can still use the `kspp` `decision` for them.

For other recommendations that can't be satisfied on RISC-V, we need to add `if arch` disabling them on RISC-V.

In other words, please try to enable all known hardening features in RISC-V kernel using `make menuconfig` and then mute the unsupported ones using the `if arch` trick in `kernel-hardening-checker`.

By the way, could you please use Linux kernel v6.10 to be consistent with the `kernel-hardening-checker` release?

#### <img src="https://avatars.githubusercontent.com/u/434827?u=1fe0601f243e1627c6f738027d2e71b90dad989d&v=4" width="50">[bcoles](https://github.com/bcoles) commented at [2025-02-02 01:28](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2629192673):

> Hi @bcoles !
> 
> First of all, thanks for showing the autodetect bug on Debian.
> 
> I've fixed it:
> 
> ```
> deb@debian:~/kernel-hardening-checker$ which sysctl
> deb@debian:~/kernel-hardening-checker$ cat /etc/issue
> Debian GNU/Linux 11 \n \l
> 
> deb@debian:~/kernel-hardening-checker$ which sysctl
> deb@debian:~/kernel-hardening-checker$ ./bin/kernel-hardening-checker -a
> [+] Going to autodetect and check the security hardening options of the running kernel
> [+] Detected version of the running kernel: (5, 10, 0)
> [+] Detected kconfig file of the running kernel: /boot/config-5.10.0-32-amd64
> [+] Detected cmdline parameters of the running kernel: /proc/cmdline
> [+] Saved sysctls to a temporary file /tmp/sysctl-ktlabxv2
> [+] Detected microarchitecture: X86_64
> [+] Detected compiler: GCC 100201
> ...
> ```
> 
> Could you check that the latest `master` works fine for you?

The `sysctl` path issue is resolved on `debian-20240128-convert_riscv64-virt` as `root` and low-privileged user:

```
# ./bin/kernel-hardening-checker -a
[+] Going to autodetect and check the security hardening options of the running kernel
[+] Detected version of the running kernel: (6, 6, 13)
[+] Detected kconfig file of the running kernel: /boot/config-6.6.13-riscv64
[+] Detected cmdline parameters of the running kernel: /proc/cmdline
[+] Saved sysctls to a temporary file /tmp/sysctl-na9x7j6n
[+] Detected microarchitecture: RISCV
[+] Detected compiler: GCC 130200
[!] WARNING: cmdline option "root" is found multiple times

[...]

net.core.bpf_jit_harden                 |sysctl |     2      |   kspp   | self_protection  | FAIL: "0"
kernel.oops_limit                       |sysctl |    100     |a13xp0p0v | self_protection  | FAIL: "10000"
kernel.warn_limit                       |sysctl |    100     |a13xp0p0v | self_protection  | FAIL: "0"
kernel.dmesg_restrict                   |sysctl |     1      |   kspp   |cut_attack_surface| OK
kernel.perf_event_paranoid              |sysctl |     3      |   kspp   |cut_attack_surface| OK
dev.tty.ldisc_autoload                  |sysctl |     0      |   kspp   |cut_attack_surface| FAIL: "1"
kernel.kptr_restrict                    |sysctl |     2      |   kspp   |cut_attack_surface| FAIL: "0"
dev.tty.legacy_tiocsti                  |sysctl |     0      |   kspp   |cut_attack_surface| OK
user.max_user_namespaces                |sysctl |     0      |   kspp   |cut_attack_surface| FAIL: "3613"
kernel.kexec_load_disabled              |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: "0"
kernel.unprivileged_bpf_disabled        |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: "2"
vm.unprivileged_userfaultfd             |sysctl |     0      |   kspp   |cut_attack_surface| OK
kernel.modules_disabled                 |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: "0"
kernel.io_uring_disabled                |sysctl |     2      |  grsec   |cut_attack_surface| FAIL: "0"
kernel.sysrq                            |sysctl |     0      |a13xp0p0v |cut_attack_surface| FAIL: "438"
fs.protected_symlinks                   |sysctl |     1      |   kspp   | harden_userspace | OK
fs.protected_hardlinks                  |sysctl |     1      |   kspp   | harden_userspace | OK
fs.protected_fifos                      |sysctl |     2      |   kspp   | harden_userspace | FAIL: "1"
fs.protected_regular                    |sysctl |     2      |   kspp   | harden_userspace | OK
fs.suid_dumpable                        |sysctl |     0      |   kspp   | harden_userspace | OK
kernel.randomize_va_space               |sysctl |     2      |   kspp   | harden_userspace | OK
kernel.yama.ptrace_scope                |sysctl |     3      |   kspp   | harden_userspace | FAIL: "0"
vm.mmap_rnd_bits                        |sysctl |     24     |a13xp0p0v | harden_userspace | FAIL: "18"
vm.mmap_rnd_compat_bits                 |sysctl |     17     |a13xp0p0v | harden_userspace | FAIL: is not found
[...]
```

The `cmdline` warning is valid:

```
$ cat /proc/cmdline 
root=LABEL=rootfs rw noquiet root=LABEL=rootfs
```

#### <img src="https://avatars.githubusercontent.com/u/434827?u=1fe0601f243e1627c6f738027d2e71b90dad989d&v=4" width="50">[bcoles](https://github.com/bcoles) commented at [2025-02-02 01:34](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2629194279):

> By the way, could you please use Linux kernel v6.10 to be consistent with the `kernel-hardening-checker` release?

I have added a 6.10 defconfig. Are the other defconfigs in this PR (versions 4.20, 5.0, 5.17, and 6.0 - 6.9) of use or should I remove them?

As this PR may take a while to merge, can we merge the changes to `config_files` first as a separate PR? This will save having to frequently rebase these changes.

#### <img src="https://avatars.githubusercontent.com/u/434827?u=1fe0601f243e1627c6f738027d2e71b90dad989d&v=4" width="50">[bcoles](https://github.com/bcoles) commented at [2025-02-02 12:45](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2629382247):

> KSPP recommendations in the beginning contain a lot of settings that are universal for all microarchitectures. However, not all of them are supported on RISC-V.
> 
> So we need to take those checks which are applicable to RISC-V. We can still use the `kspp` `decision` for them.

Done, with `kspp`.

> For other recommendations that can't be satisfied on RISC-V, we need to add `if arch` disabling them on RISC-V.
> 
> In other words, please try to enable all known hardening features in RISC-V kernel using `make menuconfig` and then mute the unsupported ones using the `if arch` trick in `kernel-hardening-checker`.

**Kernel Configs**

I have updated all RISC-V kernel config checks. All kernel configuration options which are not supported by RISC-V should now be excluded by an `if arch` check, with some caveats:

* I have left the `grsec` tests untouched (ie, not behind a `if arch` check). I do not have access to modern `grsec` source.

* I have left many `cut_attack_surface` checks which require `is not set` untouched (ie, not behind a `if arch` check). For example, the floppy driver checks:

```
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'BLK_DEV_FD', 'is not set')] # recommended by Denis Efremov in /pull/54
    l += [KconfigCheck('cut_attack_surface', 'maintainer', 'BLK_DEV_FD_RAWCMD', 'is not set')] # recommended by Denis Efremov in /pull/62
```

No RISC-V kernel configs support these options going back as far as 4.20 kernel, so these options will never realistically be enabled, and thus these checks should always pass. Leaving these checks enabled for all architectures should cause no harm.


**Cmdline**

I have updated RISC-V cmdline checks. RISC-V does not have any unique cmdline options with obvious security impact.

```
$ grep -rn early_param arch/riscv/
arch/riscv/kernel/setup.c:259:	parse_early_param();
arch/riscv/kernel/cpufeature.c:652:early_param("riscv_isa_fallback", riscv_isa_fallback_setup);
arch/riscv/kernel/acpi.c:52:early_param("acpi", parse_acpi);
arch/riscv/kernel/paravirt.c:42:early_param("no-steal-acc", parse_no_stealacc);
arch/riscv/mm/init.c:209:early_param("mem", early_mem);
arch/riscv/mm/init.c:777:early_param("no4lvl", print_no4lvl);
arch/riscv/mm/init.c:784:early_param("no5lvl", print_no5lvl);
arch/riscv/mm/init.c:1052:early_param("nokaslr", print_nokaslr);
```

RISC-V does support `nokaslr`, for which there is already a `"is not set"` check. Given that the majority of the `cmdline` checks are for `is not set`, I have left these checks largely unchanged.


**Sysctl**

I have perused the `sysctl` settings and left these largely unchanged, as the exsiting checks seems reasonable (and the userland checks are architecture-agnostic).


---

Example output on `debian-20240128-convert_riscv64-virt` in Qemu:

<details>
<p>

```
# ./bin/kernel-hardening-checker -a
[+] Going to autodetect and check the security hardening options of the running kernel
[+] Detected version of the running kernel: (6, 6, 13)
[+] Detected kconfig file of the running kernel: /boot/config-6.6.13-riscv64
[+] Detected cmdline parameters of the running kernel: /proc/cmdline
[+] Saved sysctls to a temporary file /tmp/sysctl-leu02jtj
[+] Detected microarchitecture: RISCV
[+] Detected compiler: GCC 130200
[!] WARNING: cmdline option "root" is found multiple times
=========================================================================================================================
              option_name               | type  |desired_val | decision |      reason      | check_result
=========================================================================================================================
CONFIG_BUG                              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_SLUB_DEBUG                       |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_THREAD_INFO_IN_TASK              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_IOMMU_SUPPORT                    |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STACKPROTECTOR                   |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STACKPROTECTOR_STRONG            |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STRICT_KERNEL_RWX                |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STRICT_MODULE_RWX                |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_REFCOUNT_FULL                    |kconfig|     y      |defconfig | self_protection  | OK: version >= (5, 4, 208)
CONFIG_INIT_STACK_ALL_ZERO              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_CPU_MITIGATIONS                  |kconfig|     y      |defconfig | self_protection  | FAIL: is not found
CONFIG_VMAP_STACK                       |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_RANDOM_KMALLOC_CACHES            |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SLAB_MERGE_DEFAULT               |kconfig| is not set |   kspp   | self_protection  | FAIL: "y"
CONFIG_BUG_ON_DATA_CORRUPTION           |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SLAB_FREELIST_HARDENED           |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SLAB_FREELIST_RANDOM             |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SHUFFLE_PAGE_ALLOCATOR           |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_FORTIFY_SOURCE                   |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_DEBUG_VIRTUAL                    |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_DEBUG_SG                         |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_INIT_ON_ALLOC_DEFAULT_ON         |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_STATIC_USERMODEHELPER            |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SECURITY_LOCKDOWN_LSM            |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY      |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY|kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_LIST_HARDENED                    |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_DEBUG_CREDENTIALS                |kconfig|     y      |   kspp   | self_protection  | OK: version >= (6, 6, 8)
CONFIG_DEBUG_NOTIFIERS                  |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SCHED_STACK_END_CHECK            |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_KFENCE                           |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_RANDSTRUCT_FULL                  |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_HARDENED_USERCOPY                |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_HARDENED_USERCOPY_FALLBACK       |kconfig| is not set |   kspp   | self_protection  | OK: is not found
CONFIG_HARDENED_USERCOPY_PAGESPAN       |kconfig| is not set |   kspp   | self_protection  | OK: is not found
CONFIG_GCC_PLUGIN_LATENT_ENTROPY        |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_MODULE_SIG                       |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_MODULE_SIG_ALL                   |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_MODULE_SIG_SHA512                |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_MODULE_SIG_FORCE                 |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_INIT_ON_FREE_DEFAULT_ON          |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_EFI_DISABLE_PCI_DMA              |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_RESET_ATTACK_MITIGATION          |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_UBSAN_BOUNDS                     |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_UBSAN_LOCAL_BOUNDS               |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_UBSAN_TRAP                       |kconfig|     y      |   kspp   | self_protection  | FAIL: CONFIG_UBSAN_BOUNDS is not "y"
CONFIG_UBSAN_SANITIZE_ALL               |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_DEFAULT_MMAP_MIN_ADDR            |kconfig|   32768    |   kspp   | self_protection  | FAIL: "4096"
CONFIG_RANDOMIZE_BASE                   |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_STACKPROTECTOR_PER_TASK          |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SECURITY                         |kconfig|     y      |defconfig | security_policy  | OK
CONFIG_SECURITY_YAMA                    |kconfig|     y      |   kspp   | security_policy  | OK
CONFIG_SECURITY_LANDLOCK                |kconfig|     y      |   kspp   | security_policy  | OK
CONFIG_SECURITY_SELINUX_DISABLE         |kconfig| is not set |   kspp   | security_policy  | OK: is not found
CONFIG_SECURITY_SELINUX_BOOTPARAM       |kconfig| is not set |   kspp   | security_policy  | OK
CONFIG_SECURITY_SELINUX_DEVELOP         |kconfig| is not set |   kspp   | security_policy  | FAIL: "y"
CONFIG_SECURITY_WRITABLE_HOOKS          |kconfig| is not set |   kspp   | security_policy  | OK: is not found
CONFIG_SECURITY_SELINUX_DEBUG           |kconfig| is not set |   kspp   | security_policy  | OK
CONFIG_SECURITY_SELINUX                 |kconfig|     y      |a13xp0p0v | security_policy  | OK
CONFIG_SECCOMP                          |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_SECCOMP_FILTER                   |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_BPF_UNPRIV_DEFAULT_OFF           |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_SECURITY_DMESG_RESTRICT          |kconfig|     y      |   kspp   |cut_attack_surface| OK
CONFIG_ACPI_CUSTOM_METHOD               |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_COMPAT_BRK                       |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_DEVKMEM                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_BINFMT_MISC                      |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "m"
CONFIG_INET_DIAG                        |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "m"
CONFIG_KEXEC                            |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_PROC_KCORE                       |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_LEGACY_PTYS                      |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_HIBERNATION                      |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_COMPAT                           |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_IA32_EMULATION                   |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_X86_X32                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_X86_X32_ABI                      |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_MODIFY_LDT_SYSCALL               |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_OABI_COMPAT                      |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_X86_MSR                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_LEGACY_TIOCSTI                   |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_MODULE_FORCE_LOAD                |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_MODULES                          |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_DEVMEM                           |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_IO_STRICT_DEVMEM                 |kconfig|     y      |   kspp   |cut_attack_surface| OK
CONFIG_LDISC_AUTOLOAD                   |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_X86_VSYSCALL_EMULATION           |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_STRICT_DEVMEM                    |kconfig|     y      |   kspp   |cut_attack_surface| OK
CONFIG_DRM_LEGACY                       |kconfig| is not set |maintainer|cut_attack_surface| OK
CONFIG_FB                               |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "y"
CONFIG_VT                               |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "y"
CONFIG_BLK_DEV_FD                       |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_BLK_DEV_FD_RAWCMD                |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT       |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_N_GSM                            |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "m"
CONFIG_ZSMALLOC_STAT                    |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_DEBUG_KMEMLEAK                   |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_BINFMT_AOUT                      |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_KPROBE_EVENTS                    |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_UPROBE_EVENTS                    |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_GENERIC_TRACER                   |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_FUNCTION_TRACER                  |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_STACK_TRACER                     |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_HIST_TRIGGERS                    |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_BLK_DEV_IO_TRACE                 |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_PROC_VMCORE                      |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PROC_PAGE_MONITOR                |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_USELIB                           |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_CHECKPOINT_RESTORE               |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_USERFAULTFD                      |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_HWPOISON_INJECT                  |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_MEM_SOFT_DIRTY                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DEVPORT                          |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_DEBUG_FS                         |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_NOTIFIER_ERROR_INJECTION         |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_FAIL_FUTEX                       |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PUNIT_ATOM_DEBUG                 |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_ACPI_CONFIGFS                    |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_EDAC_DEBUG                       |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DRM_I915_DEBUG                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DVB_C8SECTPFE                    |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_MTD_SLRAM                        |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_MTD_PHRAM                        |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_IO_URING                         |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_KCMP                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_RSEQ                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_LATENCYTOP                       |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_KCOV                             |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_PROVIDE_OHCI1394_DMA_INIT        |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_SUNRPC_DEBUG                     |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_X86_16BIT                        |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_BLK_DEV_UBLK                     |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_SMB_SERVER                       |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_XFS_ONLINE_SCRUB_STATS           |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_CACHESTAT_SYSCALL                |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_PREEMPTIRQ_TRACEPOINTS           |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_ENABLE_DEFAULT_TRACERS           |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PROVE_LOCKING                    |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_TEST_DEBUG_VIRTUAL               |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_MPTCP                            |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_TLS                              |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_TIPC                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_IP_SCTP                          |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_KGDB                             |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_PTDUMP_DEBUGFS                   |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_X86_PTDUMP                       |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DEBUG_CLOSURES                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_BCACHE_CLOSURES_DEBUG            |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_STAGING                          |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KSM                              |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KALLSYMS                         |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KEXEC_FILE                       |kconfig| is not set |  clipos  |cut_attack_surface| OK
CONFIG_CRASH_DUMP                       |kconfig| is not set |  clipos  |cut_attack_surface| OK
CONFIG_USER_NS                          |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_X86_CPUID                        |kconfig| is not set |  clipos  |cut_attack_surface| OK: is not found
CONFIG_X86_IOPL_IOPERM                  |kconfig| is not set |  clipos  |cut_attack_surface| OK: is not found
CONFIG_ACPI_TABLE_UPGRADE               |kconfig| is not set |  clipos  |cut_attack_surface| OK: is not found
CONFIG_EFI_CUSTOM_SSDT_OVERLAYS         |kconfig| is not set |  clipos  |cut_attack_surface| OK
CONFIG_AIO                              |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_MAGIC_SYSRQ                      |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_MAGIC_SYSRQ_SERIAL               |kconfig| is not set |grapheneos|cut_attack_surface| FAIL: "y"
CONFIG_EFI_TEST                         |kconfig| is not set | lockdown |cut_attack_surface| OK
CONFIG_MMIOTRACE_TEST                   |kconfig| is not set | lockdown |cut_attack_surface| OK: is not found
CONFIG_KPROBES                          |kconfig| is not set | lockdown |cut_attack_surface| FAIL: "y"
CONFIG_BPF_SYSCALL                      |kconfig| is not set | lockdown |cut_attack_surface| FAIL: "y"
CONFIG_MMIOTRACE                        |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_LIVEPATCH                        |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_IP_DCCP                          |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "m"
CONFIG_FTRACE                           |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "y"
CONFIG_VIDEO_VIVID                      |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "m"
CONFIG_INPUT_EVBUG                      |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_CORESIGHT                        |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_XFS_SUPPORT_V4                   |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "y"
CONFIG_BLK_DEV_WRITE_MOUNTED            |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_FAULT_INJECTION                  |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_ARM_PTDUMP_DEBUGFS               |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_ARM_PTDUMP                       |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_SECCOMP_CACHE_DEBUG              |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_LKDTM                            |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_TRIM_UNUSED_KSYMS                |kconfig|     y      |a13xp0p0v |cut_attack_surface| FAIL: "is not set"
CONFIG_COREDUMP                         |kconfig| is not set |  clipos  | harden_userspace | FAIL: "y"
CONFIG_ARCH_MMAP_RND_BITS               |kconfig|     24     |a13xp0p0v | harden_userspace | FAIL: "18"
CONFIG_ARCH_MMAP_RND_COMPAT_BITS        |kconfig|     17     |a13xp0p0v | harden_userspace | FAIL: is not found
nosmep                                  |cmdline| is not set |defconfig | self_protection  | OK: is not found
nosmap                                  |cmdline| is not set |defconfig | self_protection  | OK: is not found
nokaslr                                 |cmdline| is not set |defconfig | self_protection  | OK: is not found
nopti                                   |cmdline| is not set |defconfig | self_protection  | OK: is not found
nospectre_v1                            |cmdline| is not set |defconfig | self_protection  | OK: is not found
nospectre_v2                            |cmdline| is not set |defconfig | self_protection  | OK: is not found
nospectre_bhb                           |cmdline| is not set |defconfig | self_protection  | OK: is not found
nospec_store_bypass_disable             |cmdline| is not set |defconfig | self_protection  | OK: is not found
dis_ucode_ldr                           |cmdline| is not set |defconfig | self_protection  | OK: is not found
arm64.nobti                             |cmdline| is not set |defconfig | self_protection  | OK: is not found
arm64.nopauth                           |cmdline| is not set |defconfig | self_protection  | OK: is not found
arm64.nomte                             |cmdline| is not set |defconfig | self_protection  | OK: is not found
rodata                                  |cmdline|     on     |defconfig | self_protection  | OK: rodata is not found
slab_merge                              |cmdline| is not set |   kspp   | self_protection  | OK: is not found
slub_merge                              |cmdline| is not set |   kspp   | self_protection  | OK: is not found
page_alloc.shuffle                      |cmdline|     1      |   kspp   | self_protection  | FAIL: is not found
slab_nomerge                            |cmdline| is present |   kspp   | self_protection  | FAIL: is not present
init_on_alloc                           |cmdline|     1      |   kspp   | self_protection  | OK: CONFIG_INIT_ON_ALLOC_DEFAULT_ON is "y"
init_on_free                            |cmdline|     1      |   kspp   | self_protection  | FAIL: is not found
hardened_usercopy                       |cmdline|     1      |   kspp   | self_protection  | OK: CONFIG_HARDENED_USERCOPY is "y"
slab_common.usercopy_fallback           |cmdline| is not set |   kspp   | self_protection  | OK: is not found
debugfs                                 |cmdline|    off     |  grsec   |cut_attack_surface| FAIL: is not found
sysrq_always_enabled                    |cmdline| is not set |grapheneos|cut_attack_surface| OK: is not found
bdev_allow_write_mounted                |cmdline|     0      |a13xp0p0v |cut_attack_surface| OK: CONFIG_BLK_DEV_WRITE_MOUNTED is not found
norandmaps                              |cmdline| is not set |defconfig | harden_userspace | OK: is not found
net.core.bpf_jit_harden                 |sysctl |     2      |   kspp   | self_protection  | FAIL: "0"
kernel.oops_limit                       |sysctl |    100     |a13xp0p0v | self_protection  | FAIL: "10000"
kernel.warn_limit                       |sysctl |    100     |a13xp0p0v | self_protection  | FAIL: "0"
vm.mmap_min_addr                        |sysctl |   32768    |   kspp   | self_protection  | FAIL: "4096"
kernel.dmesg_restrict                   |sysctl |     1      |   kspp   |cut_attack_surface| OK
kernel.perf_event_paranoid              |sysctl |     3      |   kspp   |cut_attack_surface| OK
dev.tty.ldisc_autoload                  |sysctl |     0      |   kspp   |cut_attack_surface| FAIL: "1"
kernel.kptr_restrict                    |sysctl |     2      |   kspp   |cut_attack_surface| FAIL: "0"
dev.tty.legacy_tiocsti                  |sysctl |     0      |   kspp   |cut_attack_surface| OK
user.max_user_namespaces                |sysctl |     0      |   kspp   |cut_attack_surface| FAIL: "3613"
kernel.kexec_load_disabled              |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: "0"
kernel.unprivileged_bpf_disabled        |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: "2"
vm.unprivileged_userfaultfd             |sysctl |     0      |   kspp   |cut_attack_surface| OK
kernel.modules_disabled                 |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: "0"
kernel.io_uring_disabled                |sysctl |     2      |  grsec   |cut_attack_surface| FAIL: "0"
kernel.sysrq                            |sysctl |     0      |a13xp0p0v |cut_attack_surface| FAIL: "438"
fs.protected_symlinks                   |sysctl |     1      |   kspp   | harden_userspace | OK
fs.protected_hardlinks                  |sysctl |     1      |   kspp   | harden_userspace | OK
fs.protected_fifos                      |sysctl |     2      |   kspp   | harden_userspace | FAIL: "1"
fs.protected_regular                    |sysctl |     2      |   kspp   | harden_userspace | OK
fs.suid_dumpable                        |sysctl |     0      |   kspp   | harden_userspace | OK
kernel.randomize_va_space               |sysctl |     2      |   kspp   | harden_userspace | OK
kernel.yama.ptrace_scope                |sysctl |     3      |   kspp   | harden_userspace | FAIL: "0"
vm.mmap_rnd_bits                        |sysctl |     24     |a13xp0p0v | harden_userspace | FAIL: "18"
vm.mmap_rnd_compat_bits                 |sysctl |     17     |a13xp0p0v | harden_userspace | FAIL: is not found

[+] Config check is finished: 'OK' - 138 / 'FAIL' - 94
```

</p>
</details>


Example output on `ubuntu-24.04.1-preinstalled-server-riscv64` in Qemu:

<details>
<p>

```
# ./bin/kernel-hardening-checker -a
[+] Going to autodetect and check the security hardening options of the running kernel
[+] Detected version of the running kernel: (6, 8, 0)
[+] Detected kconfig file of the running kernel: /boot/config-6.8.0-41-generic
[+] Detected cmdline parameters of the running kernel: /proc/cmdline
[+] Saved sysctls to a temporary file /tmp/sysctl-rpma167k
[+] Detected microarchitecture: RISCV
[+] Detected compiler: GCC 130200
=========================================================================================================================
              option_name               | type  |desired_val | decision |      reason      | check_result
=========================================================================================================================
CONFIG_BUG                              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_SLUB_DEBUG                       |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_THREAD_INFO_IN_TASK              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_IOMMU_SUPPORT                    |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STACKPROTECTOR                   |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STACKPROTECTOR_STRONG            |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STRICT_KERNEL_RWX                |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STRICT_MODULE_RWX                |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_REFCOUNT_FULL                    |kconfig|     y      |defconfig | self_protection  | OK: version >= (5, 4, 208)
CONFIG_INIT_STACK_ALL_ZERO              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_CPU_MITIGATIONS                  |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_VMAP_STACK                       |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_RANDOM_KMALLOC_CACHES            |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SLAB_MERGE_DEFAULT               |kconfig| is not set |   kspp   | self_protection  | FAIL: "y"
CONFIG_BUG_ON_DATA_CORRUPTION           |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SLAB_FREELIST_HARDENED           |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SLAB_FREELIST_RANDOM             |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SHUFFLE_PAGE_ALLOCATOR           |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_FORTIFY_SOURCE                   |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_DEBUG_VIRTUAL                    |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_DEBUG_SG                         |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_INIT_ON_ALLOC_DEFAULT_ON         |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_STATIC_USERMODEHELPER            |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SECURITY_LOCKDOWN_LSM            |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY      |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY|kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_LIST_HARDENED                    |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_DEBUG_CREDENTIALS                |kconfig|     y      |   kspp   | self_protection  | OK: version >= (6, 6, 8)
CONFIG_DEBUG_NOTIFIERS                  |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SCHED_STACK_END_CHECK            |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_KFENCE                           |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_RANDSTRUCT_FULL                  |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_HARDENED_USERCOPY                |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_HARDENED_USERCOPY_FALLBACK       |kconfig| is not set |   kspp   | self_protection  | OK: is not found
CONFIG_HARDENED_USERCOPY_PAGESPAN       |kconfig| is not set |   kspp   | self_protection  | OK: is not found
CONFIG_GCC_PLUGIN_LATENT_ENTROPY        |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_MODULE_SIG                       |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_MODULE_SIG_ALL                   |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_MODULE_SIG_SHA512                |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_MODULE_SIG_FORCE                 |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_INIT_ON_FREE_DEFAULT_ON          |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_EFI_DISABLE_PCI_DMA              |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_RESET_ATTACK_MITIGATION          |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_UBSAN_BOUNDS                     |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_UBSAN_LOCAL_BOUNDS               |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_UBSAN_TRAP                       |kconfig|     y      |   kspp   | self_protection  | FAIL: CONFIG_UBSAN_BOUNDS is not "y"
CONFIG_UBSAN_SANITIZE_ALL               |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_DEFAULT_MMAP_MIN_ADDR            |kconfig|   32768    |   kspp   | self_protection  | FAIL: "65536"
CONFIG_RANDOMIZE_BASE                   |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_STACKPROTECTOR_PER_TASK          |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SECURITY                         |kconfig|     y      |defconfig | security_policy  | OK
CONFIG_SECURITY_YAMA                    |kconfig|     y      |   kspp   | security_policy  | OK
CONFIG_SECURITY_LANDLOCK                |kconfig|     y      |   kspp   | security_policy  | OK
CONFIG_SECURITY_SELINUX_DISABLE         |kconfig| is not set |   kspp   | security_policy  | OK: is not found
CONFIG_SECURITY_SELINUX_BOOTPARAM       |kconfig| is not set |   kspp   | security_policy  | FAIL: "y"
CONFIG_SECURITY_SELINUX_DEVELOP         |kconfig| is not set |   kspp   | security_policy  | FAIL: "y"
CONFIG_SECURITY_WRITABLE_HOOKS          |kconfig| is not set |   kspp   | security_policy  | OK: is not found
CONFIG_SECURITY_SELINUX_DEBUG           |kconfig| is not set |   kspp   | security_policy  | OK
CONFIG_SECURITY_SELINUX                 |kconfig|     y      |a13xp0p0v | security_policy  | OK
CONFIG_SECCOMP                          |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_SECCOMP_FILTER                   |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_BPF_UNPRIV_DEFAULT_OFF           |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_SECURITY_DMESG_RESTRICT          |kconfig|     y      |   kspp   |cut_attack_surface| OK
CONFIG_ACPI_CUSTOM_METHOD               |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_COMPAT_BRK                       |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_DEVKMEM                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_BINFMT_MISC                      |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "m"
CONFIG_INET_DIAG                        |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "m"
CONFIG_KEXEC                            |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_PROC_KCORE                       |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_LEGACY_PTYS                      |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_HIBERNATION                      |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_COMPAT                           |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_IA32_EMULATION                   |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_X86_X32                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_X86_X32_ABI                      |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_MODIFY_LDT_SYSCALL               |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_OABI_COMPAT                      |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_X86_MSR                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_LEGACY_TIOCSTI                   |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_MODULE_FORCE_LOAD                |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_MODULES                          |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_DEVMEM                           |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_IO_STRICT_DEVMEM                 |kconfig|     y      |   kspp   |cut_attack_surface| FAIL: "is not set"
CONFIG_LDISC_AUTOLOAD                   |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_X86_VSYSCALL_EMULATION           |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_STRICT_DEVMEM                    |kconfig|     y      |   kspp   |cut_attack_surface| OK
CONFIG_DRM_LEGACY                       |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_FB                               |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "y"
CONFIG_VT                               |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "y"
CONFIG_BLK_DEV_FD                       |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_BLK_DEV_FD_RAWCMD                |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT       |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_N_GSM                            |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "m"
CONFIG_ZSMALLOC_STAT                    |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_DEBUG_KMEMLEAK                   |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_BINFMT_AOUT                      |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_KPROBE_EVENTS                    |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_UPROBE_EVENTS                    |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_GENERIC_TRACER                   |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_FUNCTION_TRACER                  |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_STACK_TRACER                     |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_HIST_TRIGGERS                    |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_BLK_DEV_IO_TRACE                 |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_PROC_VMCORE                      |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_PROC_PAGE_MONITOR                |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_USELIB                           |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_CHECKPOINT_RESTORE               |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_USERFAULTFD                      |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_HWPOISON_INJECT                  |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_MEM_SOFT_DIRTY                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DEVPORT                          |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_DEBUG_FS                         |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_NOTIFIER_ERROR_INJECTION         |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_FAIL_FUTEX                       |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PUNIT_ATOM_DEBUG                 |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_ACPI_CONFIGFS                    |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_EDAC_DEBUG                       |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_DRM_I915_DEBUG                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DVB_C8SECTPFE                    |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_MTD_SLRAM                        |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_MTD_PHRAM                        |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_IO_URING                         |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_KCMP                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_RSEQ                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_LATENCYTOP                       |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_KCOV                             |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_PROVIDE_OHCI1394_DMA_INIT        |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_SUNRPC_DEBUG                     |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_X86_16BIT                        |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_BLK_DEV_UBLK                     |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_SMB_SERVER                       |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_XFS_ONLINE_SCRUB_STATS           |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_CACHESTAT_SYSCALL                |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_PREEMPTIRQ_TRACEPOINTS           |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_ENABLE_DEFAULT_TRACERS           |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PROVE_LOCKING                    |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_TEST_DEBUG_VIRTUAL               |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_MPTCP                            |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_TLS                              |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_TIPC                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_IP_SCTP                          |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_KGDB                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_PTDUMP_DEBUGFS                   |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_X86_PTDUMP                       |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DEBUG_CLOSURES                   |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_BCACHE_CLOSURES_DEBUG            |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_STAGING                          |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KSM                              |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KALLSYMS                         |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KEXEC_FILE                       |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_CRASH_DUMP                       |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_USER_NS                          |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_X86_CPUID                        |kconfig| is not set |  clipos  |cut_attack_surface| OK: is not found
CONFIG_X86_IOPL_IOPERM                  |kconfig| is not set |  clipos  |cut_attack_surface| OK: is not found
CONFIG_ACPI_TABLE_UPGRADE               |kconfig| is not set |  clipos  |cut_attack_surface| OK: is not found
CONFIG_EFI_CUSTOM_SSDT_OVERLAYS         |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_AIO                              |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_MAGIC_SYSRQ                      |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_MAGIC_SYSRQ_SERIAL               |kconfig| is not set |grapheneos|cut_attack_surface| FAIL: "y"
CONFIG_EFI_TEST                         |kconfig| is not set | lockdown |cut_attack_surface| FAIL: "m"
CONFIG_MMIOTRACE_TEST                   |kconfig| is not set | lockdown |cut_attack_surface| OK: is not found
CONFIG_KPROBES                          |kconfig| is not set | lockdown |cut_attack_surface| FAIL: "y"
CONFIG_BPF_SYSCALL                      |kconfig| is not set | lockdown |cut_attack_surface| FAIL: "y"
CONFIG_MMIOTRACE                        |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_LIVEPATCH                        |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_IP_DCCP                          |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "m"
CONFIG_FTRACE                           |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "y"
CONFIG_VIDEO_VIVID                      |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "m"
CONFIG_INPUT_EVBUG                      |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "m"
CONFIG_CORESIGHT                        |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_XFS_SUPPORT_V4                   |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "y"
CONFIG_BLK_DEV_WRITE_MOUNTED            |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "y"
CONFIG_FAULT_INJECTION                  |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_ARM_PTDUMP_DEBUGFS               |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_ARM_PTDUMP                       |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_SECCOMP_CACHE_DEBUG              |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_LKDTM                            |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_TRIM_UNUSED_KSYMS                |kconfig|     y      |a13xp0p0v |cut_attack_surface| FAIL: "is not set"
CONFIG_COREDUMP                         |kconfig| is not set |  clipos  | harden_userspace | FAIL: "y"
CONFIG_ARCH_MMAP_RND_BITS               |kconfig|     24     |a13xp0p0v | harden_userspace | OK
CONFIG_ARCH_MMAP_RND_COMPAT_BITS        |kconfig|     17     |a13xp0p0v | harden_userspace | FAIL: is not found
nosmep                                  |cmdline| is not set |defconfig | self_protection  | OK: is not found
nosmap                                  |cmdline| is not set |defconfig | self_protection  | OK: is not found
nokaslr                                 |cmdline| is not set |defconfig | self_protection  | OK: is not found
nopti                                   |cmdline| is not set |defconfig | self_protection  | OK: is not found
nospectre_v1                            |cmdline| is not set |defconfig | self_protection  | OK: is not found
nospectre_v2                            |cmdline| is not set |defconfig | self_protection  | OK: is not found
nospectre_bhb                           |cmdline| is not set |defconfig | self_protection  | OK: is not found
nospec_store_bypass_disable             |cmdline| is not set |defconfig | self_protection  | OK: is not found
dis_ucode_ldr                           |cmdline| is not set |defconfig | self_protection  | OK: is not found
arm64.nobti                             |cmdline| is not set |defconfig | self_protection  | OK: is not found
arm64.nopauth                           |cmdline| is not set |defconfig | self_protection  | OK: is not found
arm64.nomte                             |cmdline| is not set |defconfig | self_protection  | OK: is not found
rodata                                  |cmdline|     on     |defconfig | self_protection  | OK: rodata is not found
slab_merge                              |cmdline| is not set |   kspp   | self_protection  | OK: is not found
slub_merge                              |cmdline| is not set |   kspp   | self_protection  | OK: is not found
page_alloc.shuffle                      |cmdline|     1      |   kspp   | self_protection  | FAIL: is not found
slab_nomerge                            |cmdline| is present |   kspp   | self_protection  | FAIL: is not present
init_on_alloc                           |cmdline|     1      |   kspp   | self_protection  | OK: CONFIG_INIT_ON_ALLOC_DEFAULT_ON is "y"
init_on_free                            |cmdline|     1      |   kspp   | self_protection  | FAIL: is not found
hardened_usercopy                       |cmdline|     1      |   kspp   | self_protection  | OK: CONFIG_HARDENED_USERCOPY is "y"
slab_common.usercopy_fallback           |cmdline| is not set |   kspp   | self_protection  | OK: is not found
debugfs                                 |cmdline|    off     |  grsec   |cut_attack_surface| FAIL: is not found
sysrq_always_enabled                    |cmdline| is not set |grapheneos|cut_attack_surface| OK: is not found
bdev_allow_write_mounted                |cmdline|     0      |a13xp0p0v |cut_attack_surface| FAIL: is not found
norandmaps                              |cmdline| is not set |defconfig | harden_userspace | OK: is not found
net.core.bpf_jit_harden                 |sysctl |     2      |   kspp   | self_protection  | FAIL: "0"
kernel.oops_limit                       |sysctl |    100     |a13xp0p0v | self_protection  | FAIL: "10000"
kernel.warn_limit                       |sysctl |    100     |a13xp0p0v | self_protection  | FAIL: "0"
vm.mmap_min_addr                        |sysctl |   32768    |   kspp   | self_protection  | FAIL: "65536"
kernel.dmesg_restrict                   |sysctl |     1      |   kspp   |cut_attack_surface| OK
kernel.perf_event_paranoid              |sysctl |     3      |   kspp   |cut_attack_surface| FAIL: "4"
dev.tty.ldisc_autoload                  |sysctl |     0      |   kspp   |cut_attack_surface| FAIL: "1"
kernel.kptr_restrict                    |sysctl |     2      |   kspp   |cut_attack_surface| FAIL: "1"
dev.tty.legacy_tiocsti                  |sysctl |     0      |   kspp   |cut_attack_surface| OK
user.max_user_namespaces                |sysctl |     0      |   kspp   |cut_attack_surface| FAIL: "15226"
kernel.kexec_load_disabled              |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: "0"
kernel.unprivileged_bpf_disabled        |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: "2"
vm.unprivileged_userfaultfd             |sysctl |     0      |   kspp   |cut_attack_surface| OK
kernel.modules_disabled                 |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: "0"
kernel.io_uring_disabled                |sysctl |     2      |  grsec   |cut_attack_surface| FAIL: "0"
kernel.sysrq                            |sysctl |     0      |a13xp0p0v |cut_attack_surface| FAIL: "176"
fs.protected_symlinks                   |sysctl |     1      |   kspp   | harden_userspace | OK
fs.protected_hardlinks                  |sysctl |     1      |   kspp   | harden_userspace | OK
fs.protected_fifos                      |sysctl |     2      |   kspp   | harden_userspace | FAIL: "1"
fs.protected_regular                    |sysctl |     2      |   kspp   | harden_userspace | OK
fs.suid_dumpable                        |sysctl |     0      |   kspp   | harden_userspace | FAIL: "2"
kernel.randomize_va_space               |sysctl |     2      |   kspp   | harden_userspace | OK
kernel.yama.ptrace_scope                |sysctl |     3      |   kspp   | harden_userspace | FAIL: "1"
vm.mmap_rnd_bits                        |sysctl |     24     |a13xp0p0v | harden_userspace | OK
vm.mmap_rnd_compat_bits                 |sysctl |     17     |a13xp0p0v | harden_userspace | FAIL: is not found

[+] Config check is finished: 'OK' - 127 / 'FAIL' - 105
```

</p>
</details>


Example output on `t2-24.5-riscv64-base-wayland-glibc-gcc` in Qemu:

<details>
<p>

```
bash-5.2# ./bin/kernel-hardening-checker -a
[+] Going to autodetect and check the security hardening options of the running kernel
[+] Detected version of the running kernel: (6, 8, 7)
[!] ERROR: detecting kconfig file failed: didn't find /proc/config.gz or /boot/config-6.8.7-t2
```

```
bash-5.2# ./bin/kernel-hardening-checker -c /boot/kconfig-6.8.7-t2 
[+] Kconfig file to check: /boot/kconfig-6.8.7-t2
[+] Detected kernel version: (6, 8, 7)
[+] Detected microarchitecture: RISCV
[+] Detected compiler: GCC 130201
=========================================================================================================================
              option_name               | type  |desired_val | decision |      reason      | check_result
=========================================================================================================================
CONFIG_BUG                              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_SLUB_DEBUG                       |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_THREAD_INFO_IN_TASK              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_IOMMU_SUPPORT                    |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STACKPROTECTOR                   |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STACKPROTECTOR_STRONG            |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STRICT_KERNEL_RWX                |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_STRICT_MODULE_RWX                |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_REFCOUNT_FULL                    |kconfig|     y      |defconfig | self_protection  | OK: version >= (5, 4, 208)
CONFIG_INIT_STACK_ALL_ZERO              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_CPU_MITIGATIONS                  |kconfig|     y      |defconfig | self_protection  | FAIL: is not found
CONFIG_VMAP_STACK                       |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_RANDOM_KMALLOC_CACHES            |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SLAB_MERGE_DEFAULT               |kconfig| is not set |   kspp   | self_protection  | FAIL: "y"
CONFIG_BUG_ON_DATA_CORRUPTION           |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SLAB_FREELIST_HARDENED           |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SLAB_FREELIST_RANDOM             |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SHUFFLE_PAGE_ALLOCATOR           |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_FORTIFY_SOURCE                   |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_DEBUG_VIRTUAL                    |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_DEBUG_SG                         |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_INIT_ON_ALLOC_DEFAULT_ON         |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_STATIC_USERMODEHELPER            |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_SECURITY_LOCKDOWN_LSM            |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY      |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY|kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_LIST_HARDENED                    |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_DEBUG_CREDENTIALS                |kconfig|     y      |   kspp   | self_protection  | OK: version >= (6, 6, 8)
CONFIG_DEBUG_NOTIFIERS                  |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_SCHED_STACK_END_CHECK            |kconfig|     y      |   kspp   | self_protection  | OK: CONFIG_VMAP_STACK is "y"
CONFIG_KFENCE                           |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_RANDSTRUCT_FULL                  |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_HARDENED_USERCOPY                |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_HARDENED_USERCOPY_FALLBACK       |kconfig| is not set |   kspp   | self_protection  | FAIL: CONFIG_HARDENED_USERCOPY is not "y"
CONFIG_HARDENED_USERCOPY_PAGESPAN       |kconfig| is not set |   kspp   | self_protection  | FAIL: CONFIG_HARDENED_USERCOPY is not "y"
CONFIG_GCC_PLUGIN_LATENT_ENTROPY        |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_MODULE_SIG                       |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_MODULE_SIG_ALL                   |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_MODULE_SIG_SHA512                |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_MODULE_SIG_FORCE                 |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_INIT_ON_FREE_DEFAULT_ON          |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_EFI_DISABLE_PCI_DMA              |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_RESET_ATTACK_MITIGATION          |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_UBSAN_BOUNDS                     |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_UBSAN_LOCAL_BOUNDS               |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_UBSAN_TRAP                       |kconfig|     y      |   kspp   | self_protection  | FAIL: CONFIG_UBSAN_BOUNDS is not "y"
CONFIG_UBSAN_SANITIZE_ALL               |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_DEFAULT_MMAP_MIN_ADDR            |kconfig|   32768    |   kspp   | self_protection  | FAIL: "4096"
CONFIG_RANDOMIZE_BASE                   |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_STACKPROTECTOR_PER_TASK          |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_SECURITY                         |kconfig|     y      |defconfig | security_policy  | FAIL: "is not set"
CONFIG_SECURITY_YAMA                    |kconfig|     y      |   kspp   | security_policy  | FAIL: is not found
CONFIG_SECURITY_LANDLOCK                |kconfig|     y      |   kspp   | security_policy  | FAIL: is not found
CONFIG_SECURITY_SELINUX_DISABLE         |kconfig| is not set |   kspp   | security_policy  | OK: is not found
CONFIG_SECURITY_SELINUX_BOOTPARAM       |kconfig| is not set |   kspp   | security_policy  | OK: is not found
CONFIG_SECURITY_SELINUX_DEVELOP         |kconfig| is not set |   kspp   | security_policy  | OK: is not found
CONFIG_SECURITY_WRITABLE_HOOKS          |kconfig| is not set |   kspp   | security_policy  | OK: is not found
CONFIG_SECURITY_SELINUX_DEBUG           |kconfig| is not set |   kspp   | security_policy  | OK: is not found
CONFIG_SECURITY_SELINUX                 |kconfig|     y      |a13xp0p0v | security_policy  | FAIL: is not found
CONFIG_SECCOMP                          |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_SECCOMP_FILTER                   |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_BPF_UNPRIV_DEFAULT_OFF           |kconfig|     y      |defconfig |cut_attack_surface| OK
CONFIG_SECURITY_DMESG_RESTRICT          |kconfig|     y      |   kspp   |cut_attack_surface| FAIL: "is not set"
CONFIG_ACPI_CUSTOM_METHOD               |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_COMPAT_BRK                       |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_DEVKMEM                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_BINFMT_MISC                      |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "m"
CONFIG_INET_DIAG                        |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "m"
CONFIG_KEXEC                            |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_PROC_KCORE                       |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_LEGACY_PTYS                      |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_HIBERNATION                      |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_COMPAT                           |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_IA32_EMULATION                   |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_X86_X32                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_X86_X32_ABI                      |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_MODIFY_LDT_SYSCALL               |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_OABI_COMPAT                      |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_X86_MSR                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_LEGACY_TIOCSTI                   |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_MODULE_FORCE_LOAD                |kconfig| is not set |   kspp   |cut_attack_surface| OK
CONFIG_MODULES                          |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_DEVMEM                           |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_IO_STRICT_DEVMEM                 |kconfig|     y      |   kspp   |cut_attack_surface| FAIL: is not found
CONFIG_LDISC_AUTOLOAD                   |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
CONFIG_X86_VSYSCALL_EMULATION           |kconfig| is not set |   kspp   |cut_attack_surface| OK: is not found
CONFIG_STRICT_DEVMEM                    |kconfig|     y      |   kspp   |cut_attack_surface| FAIL: "is not set"
CONFIG_DRM_LEGACY                       |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_FB                               |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "y"
CONFIG_VT                               |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "y"
CONFIG_BLK_DEV_FD                       |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_BLK_DEV_FD_RAWCMD                |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_NOUVEAU_LEGACY_CTX_SUPPORT       |kconfig| is not set |maintainer|cut_attack_surface| OK: is not found
CONFIG_N_GSM                            |kconfig| is not set |maintainer|cut_attack_surface| FAIL: "m"
CONFIG_ZSMALLOC_STAT                    |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_DEBUG_KMEMLEAK                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_BINFMT_AOUT                      |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_KPROBE_EVENTS                    |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_UPROBE_EVENTS                    |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_GENERIC_TRACER                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_FUNCTION_TRACER                  |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_STACK_TRACER                     |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_HIST_TRIGGERS                    |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_BLK_DEV_IO_TRACE                 |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PROC_VMCORE                      |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PROC_PAGE_MONITOR                |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_USELIB                           |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_CHECKPOINT_RESTORE               |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_USERFAULTFD                      |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_HWPOISON_INJECT                  |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_MEM_SOFT_DIRTY                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DEVPORT                          |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_DEBUG_FS                         |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_NOTIFIER_ERROR_INJECTION         |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_FAIL_FUTEX                       |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PUNIT_ATOM_DEBUG                 |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_ACPI_CONFIGFS                    |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_EDAC_DEBUG                       |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_DRM_I915_DEBUG                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DVB_C8SECTPFE                    |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_MTD_SLRAM                        |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_MTD_PHRAM                        |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_IO_URING                         |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_KCMP                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_RSEQ                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_LATENCYTOP                       |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_KCOV                             |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_PROVIDE_OHCI1394_DMA_INIT        |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_SUNRPC_DEBUG                     |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_X86_16BIT                        |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_BLK_DEV_UBLK                     |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_SMB_SERVER                       |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_XFS_ONLINE_SCRUB_STATS           |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_CACHESTAT_SYSCALL                |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_PREEMPTIRQ_TRACEPOINTS           |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_ENABLE_DEFAULT_TRACERS           |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PROVE_LOCKING                    |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_TEST_DEBUG_VIRTUAL               |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_MPTCP                            |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_TLS                              |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_TIPC                             |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_IP_SCTP                          |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "m"
CONFIG_KGDB                             |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_PTDUMP_DEBUGFS                   |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_X86_PTDUMP                       |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_DEBUG_CLOSURES                   |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_BCACHE_CLOSURES_DEBUG            |kconfig| is not set |  grsec   |cut_attack_surface| OK: is not found
CONFIG_STAGING                          |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KSM                              |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KALLSYMS                         |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_KEXEC_FILE                       |kconfig| is not set |  clipos  |cut_attack_surface| OK
CONFIG_CRASH_DUMP                       |kconfig| is not set |  clipos  |cut_attack_surface| OK
CONFIG_USER_NS                          |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_X86_CPUID                        |kconfig| is not set |  clipos  |cut_attack_surface| OK: is not found
CONFIG_X86_IOPL_IOPERM                  |kconfig| is not set |  clipos  |cut_attack_surface| OK: is not found
CONFIG_ACPI_TABLE_UPGRADE               |kconfig| is not set |  clipos  |cut_attack_surface| OK: is not found
CONFIG_EFI_CUSTOM_SSDT_OVERLAYS         |kconfig| is not set |  clipos  |cut_attack_surface| OK
CONFIG_AIO                              |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_MAGIC_SYSRQ                      |kconfig| is not set |  clipos  |cut_attack_surface| FAIL: "y"
CONFIG_MAGIC_SYSRQ_SERIAL               |kconfig| is not set |grapheneos|cut_attack_surface| FAIL: "y"
CONFIG_EFI_TEST                         |kconfig| is not set | lockdown |cut_attack_surface| FAIL: "m"
CONFIG_MMIOTRACE_TEST                   |kconfig| is not set | lockdown |cut_attack_surface| OK: is not found
CONFIG_KPROBES                          |kconfig| is not set | lockdown |cut_attack_surface| OK
CONFIG_BPF_SYSCALL                      |kconfig| is not set | lockdown |cut_attack_surface| FAIL: "y"
CONFIG_MMIOTRACE                        |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_LIVEPATCH                        |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_IP_DCCP                          |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "m"
CONFIG_FTRACE                           |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_VIDEO_VIVID                      |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_INPUT_EVBUG                      |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_CORESIGHT                        |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_XFS_SUPPORT_V4                   |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "y"
CONFIG_BLK_DEV_WRITE_MOUNTED            |kconfig| is not set |a13xp0p0v |cut_attack_surface| FAIL: "y"
CONFIG_FAULT_INJECTION                  |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_ARM_PTDUMP_DEBUGFS               |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_ARM_PTDUMP                       |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_SECCOMP_CACHE_DEBUG              |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK
CONFIG_LKDTM                            |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
CONFIG_TRIM_UNUSED_KSYMS                |kconfig|     y      |a13xp0p0v |cut_attack_surface| FAIL: is not found
CONFIG_COREDUMP                         |kconfig| is not set |  clipos  | harden_userspace | FAIL: "y"
CONFIG_ARCH_MMAP_RND_BITS               |kconfig|     24     |a13xp0p0v | harden_userspace | FAIL: "18"
CONFIG_ARCH_MMAP_RND_COMPAT_BITS        |kconfig|     17     |a13xp0p0v | harden_userspace | FAIL: "8"

[+] Config check is finished: 'OK' - 96 / 'FAIL' - 86


```
</p>
</details>

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-02-23 11:07](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2676778359):

Hi @bcoles,

Excuse me for the delay, I was travelling.

Now I've returned and going to spend some weekends on your pull request and this feature
(I'm working on this project in my spare time).

I'll return with comments / additional commits to this branch.

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-03-10 10:15](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2710069927):

Hello @bcoles,

I've installed the RISC-V virtual machine in QEMU:
![Снимок экрана от 2025-03-10 12-25-08](https://github.com/user-attachments/assets/c5c4d578-15d8-44b6-baf3-9002cc22b629)
![Снимок экрана от 2025-03-10 12-31-42](https://github.com/user-attachments/assets/89a34324-0d03-4f1e-b0e8-1af18c30cbc9)

Arch detection from kconfig on your branch works fine:
```
$ ./bin/kernel-hardening-checker -c riscv-kconfig.out -l riscv-cmdline.out -s riscv-sysctl.out 
[+] Kconfig file to check: riscv-kconfig.out
[+] Kernel cmdline file to check: riscv-cmdline.out
[+] Sysctl output file to check: riscv-sysctl.out
[+] Detected kernel version: (6, 12, 7)
[+] Detected microarchitecture: RISCV
[+] Detected compiler: GCC 140201
...
```

Arch detection from sysctl also works fine:
```
$ ./bin/kernel-hardening-checker  -s riscv-sysctl.out 
[+] Sysctl output file to check: riscv-sysctl.out
[+] Detected microarchitecture: RISCV (riscv64)
[-] Can't check vm.mmap_rnd_bits without CONFIG_ARCH_MMAP_RND_BITS_MAX
[-] Can't check vm.mmap_rnd_compat_bits without CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX
...
```

Cool!

> I have added a 6.10 defconfig. Are the other defconfigs in this PR (versions 4.20, 5.0, 5.17, and 6.0 - 6.9) of use or should I remove them?

I think it's fine to have previous versions of RISC-V configs as well. The CI script will test the tool on them. 

> As this PR may take a while to merge, can we merge the changes to config_files first as a separate PR? This will save having to frequently rebase these changes.

Unfortunately, merging RISC-V kconfig files separately without the main functionality will break the CI.
That's how the current master branch fails:
```
$ ./bin/kernel-hardening-checker -c riscv-kconfig.out 
[+] Kconfig file to check: riscv-kconfig.out
[+] Detected kernel version: (6, 12, 7)
[!] ERROR: failed to detect microarchitecture in kconfig
```

Currently, I'm going to focus on your pull request before any other feature. So, I hope, merging it will not take that long. 

Could you please rebase this branch onto the current master and give me an ability to add commits to this branch?

Thank you again!

#### <img src="https://avatars.githubusercontent.com/u/434827?u=1fe0601f243e1627c6f738027d2e71b90dad989d&v=4" width="50">[bcoles](https://github.com/bcoles) commented at [2025-03-10 13:06](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2710540152):

> Could you please rebase this branch onto the current master and give me an ability to add commits to this branch?

Rebased. You should have permissions.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-03-22 17:55](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2745387652):

I've added `RISC-V` support in `kernel-build-containers` (https://github.com/a13xp0p0v/kernel-build-containers/issues/34):

https://github.com/a13xp0p0v/kernel-build-containers/commit/76fc4010b9c1c272cb079950edb7d6a418fda24a 

It is useful for this work.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-03-22 21:34](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2745827577):

@bcoles, I've created a branch https://github.com/a13xp0p0v/kernel-hardening-checker/tree/riscv-prev,
it contains your commit https://github.com/a13xp0p0v/kernel-hardening-checker/commit/224970f553a3012c0a63484463f0689e2b8bbc7c.

I removed that commit from this pull request, because reviewing these changes in kconfig checks all together is a pain.

I'm going to split them and apply carefully here in separate commits.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-03-24 08:10](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2747240527):

Hi @bcoles,

You can see, I've added some missing `defconfig` checks.

What did I do? I removed arch-independent checks from `kernel_hardening_checker/checks.py`, and then inverted the `if arch` conditions this way:
```
-    if arch == 'ARM64':
+    if not arch == 'ARM64':
```

After that I examined the `OK` results of checking kconfigs in `kernel_hardening_checker/config_files/defconfigs/`. And I've made some missing fixes that you see in the commits. Finally, there were no OK results except for the duplicate checks.

Good. It means that now `defconfig` checks for RISCV are ready. So we can revisit the `kspp` and other checks.

Would you like to proceed this work?

If you do, I would ask you to repeat the procedure that I described in https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2629141449:
> So we need to take those checks which are applicable to RISC-V. We can still use the kspp decision for them.
> For other recommendations that can't be satisfied on RISC-V, we need to add if arch disabling them on RISC-V.

For that you can use my trick with temporary removing `if arch` condition and enabling everything possible for RISCV in `menuconfig`.

By the way, I've saved your previous commit https://github.com/a13xp0p0v/kernel-hardening-checker/commit/224970f553a3012c0a63484463f0689e2b8bbc7c in a separate branch.

But I would ask you to split the changes in multiple commits (one for each check). That would make my review easier.

Thanks again!
Please ask if you have questions.

#### <img src="https://avatars.githubusercontent.com/u/434827?u=1fe0601f243e1627c6f738027d2e71b90dad989d&v=4" width="50">[bcoles](https://github.com/bcoles) commented at [2025-03-24 08:22](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2747269691):

> Arch detection from sysctl also works fine:
> 
> ```
> $ ./bin/kernel-hardening-checker  -s riscv-sysctl.out 
> [+] Sysctl output file to check: riscv-sysctl.out
> [+] Detected microarchitecture: RISCV (riscv64)
> [-] Can't check vm.mmap_rnd_bits without CONFIG_ARCH_MMAP_RND_BITS_MAX
> [-] Can't check vm.mmap_rnd_compat_bits without CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX
> ...
> ```

Milk-V kernels (and others IIRC) do not populate `kernel.arch`.

#### <img src="https://avatars.githubusercontent.com/u/434827?u=1fe0601f243e1627c6f738027d2e71b90dad989d&v=4" width="50">[bcoles](https://github.com/bcoles) commented at [2025-03-24 08:25](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2747275394):

> So we can revisit the `kspp` and other checks.

I do not have time to work on this feature for the foreseeable future.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-03-24 08:36](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2747303742):

> Milk-V kernels (and others IIRC) do not populate kernel.arch.

I see a solution, we can also use `-v, --kernel-version KERNEL_VERSION` for checking sysctl.
Created an issue #181.

> I do not have time to work on this feature for the foreseeable future.

@bcoles, thank you very much anyway 👍

I'll continue working on it after my talk at Zer0Con https://zer0con.org/

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-03-24 13:20](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2748115693):

> Milk-V kernels (and others IIRC) do not populate kernel.arch.

@bcoles, unfortunately, #181 is not a solution (closing it):
![image](https://github.com/user-attachments/assets/1abb7e0c-2bc1-485e-a7aa-777f466a1492)
Here `riscv64` is a part of Fedora kernel naming. It will not work for general case.

So on boards without `kernel.arch` sysctl, we have this output for separate sysctl checking:
```
$ ./bin/kernel-hardening-checker -s riscv-sysctl.out
[+] Sysctl output file to check: riscv-sysctl.out
[!] WARNING: failed to detect microarchitecture in sysctl, arch-dependent checks will be dropped
[-] Can't check vm.mmap_rnd_bits without CONFIG_ARCH_MMAP_RND_BITS_MAX
[-] Can't check vm.mmap_rnd_compat_bits without CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX
=========================================================================================================================
              option_name               | type  |desired_val | decision |      reason      | check_result
=========================================================================================================================
net.core.bpf_jit_harden                 |sysctl |     2      |   kspp   | self_protection  | FAIL: "0"
...
```

The only arch-dependent sysctl check, which is dropped, is  `vm.mmap_min_addr`. Not good, but not critical as well.

But if sysctls are checked together with kconfig, this issue disappears.
```
$ ./bin/kernel-hardening-checker -s riscv-sysctl.out -c riscv-kconfig.out 
[+] Kconfig file to check: riscv-kconfig.out
[+] Sysctl output file to check: riscv-sysctl.out
[+] Detected kernel version: (6, 12, 7)
[+] Detected microarchitecture: RISCV
[+] Detected compiler: GCC 140201
=========================================================================================================================
              option_name               | type  |desired_val | decision |      reason      | check_result
=========================================================================================================================
CONFIG_BUG                              |kconfig|     y      |defconfig | self_protection  | OK
...
```
Here arch is detected in kconfig.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-04-27 00:02](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2832800505):

Hello @bcoles,
I've done another big amount of work:
 - Added the KSPP recommendations for RISCV (arch-independent)
 - Developed many KSPP checks for RISCV
 - Improved `override_expected_value()`
 - Fixed some mistakes in the checks along the way

I think this feature will be finished soon.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-04 23:16](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/172#issuecomment-2849491389):

Hello @bcoles,

I've finished this big work.
Now `RISC-V` is officially supported in `kernel-hardening-checker`.
The tool properly checks:
 - Security hardening options enabled in the `RISC-V` defconfig,
 - KSPP recommendations applicable for `RISC-V`.

Thank you for initializing this task :)

During this work I also:
 - Fixed some mistakes in the checks,
 - Cleaned up the kconfig collection,
 - Improved the `kernel-hardening-checker` engine a bit.

Cool!


-------------------------------------------------------------------------------

# [\#171 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/171) `closed`: 2 Checks Recommended by Timesys Hardening Guide CONFIG_DEBUG_BUGVERBOSE & CONFIG_ZSMALLOC
**Labels**: `question`, `new_check`


#### <img src="https://avatars.githubusercontent.com/u/158655396?v=4" width="50">[wryMitts](https://github.com/wryMitts) opened issue at [2024-12-27 04:31](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/171):

Found here: 
https://timesys.com/pdf/Timesys-kernel-hardening-guide.pdf Dated 2022
https://web.archive.org/web/20241227042743/https://timesys.com/pdf/Timesys-kernel-hardening-guide.pdf

This seems useful for the project:
`DEBUG_BUGVERBOSE=is not set`

> Make sure this is not enabled, as it could provide an attacker
> sensitive kernel backtrace information on BUG() conditions

Not sure on this one?:
`ZSMALLOC=is not set`

> Do not enable memory allocator for compressed pages (slab-based
> memory allocator designed to store compressed RAM pages via
> virtual memory mapping

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2025-01-13 03:29](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/171#issuecomment-2586110194):

Not enabling ZSMALLOC does technically reduce attack surface just like disabling lots of other kernel functionality but it's unclear why they're specifically recommending disabling it. I don't think it makes sense to include as a recommendation without specific reasoning for it.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-31 15:48](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/171#issuecomment-2925354563):

@wryMitts, thanks for sharing this.

Looks like this **Timesys Corporation** did amazing job [SARCASM] selling their **Timesys Kernel Hardening Analysis Tool**, which simply provides the recommendations from `kernel-hardening-checker`.

They don't even mention `kernel-hardening-checker`. Shame on them:
https://www.timesys.com/security/securing-your-linux-configuration-kernel-hardening/

![Image](https://github.com/user-attachments/assets/a77f97cb-3646-460b-a574-64dd89702430)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-31 15:59](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/171#issuecomment-2925368604):

I agree with @thestinger, their rationale behind disabling `ZSMALLOC` is not very convincing.

I'm also not sure about disabling `DEBUG_BUGVERBOSE`.
All Linux distros rely on this. Maybe it's better to restrict unprivileged access to the kernel log (`CONFIG_SECURITY_DMESG_RESTRICT` and the `kernel.dmesg_restrict` sysctl)?

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2025-06-02 10:02](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/171#issuecomment-2929795410):

> I'm also not sure about disabling DEBUG_BUGVERBOSE.
All Linux distros rely on this. Maybe it's better to restrict unprivileged access to the kernel log (CONFIG_SECURITY_DMESG_RESTRICT and the kernel.dmesg_restrict sysctl)?

I agree, it's better to have the admin have access to verbose logs.

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2025-06-02 13:15](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/171#issuecomment-2930666217):

> All Linux distros rely on this. Maybe it's better to restrict unprivileged access to the kernel log (CONFIG_SECURITY_DMESG_RESTRICT and the kernel.dmesg_restrict sysctl)?

It's better to restrict access to the kernel logs but there are multiple ways of doing that. There are some existing checks for things like this but it's a bit problematic for Android where SELinux is used instead, and for Android that makes a lot more sense and is stricter than giving our CAP_SYSLOG or using the io_uring gid for exceptions, etc. Maybe there could be an Android mode which takes this into account instead of it recommending enabling things which will be incompatible and won't improve security avoid the fully static SELinux policy verified via verified boot and loaded very early before any data partition is mounted.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-13 22:04](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/171#issuecomment-3067327652):

> Maybe there could be an Android mode which takes this into account instead of it recommending enabling things which will be incompatible 

@thestinger, we have already considered having some special recommendations for Android in `kernel-hardening-checker`: https://github.com/a13xp0p0v/kernel-hardening-checker/pull/91

However, I don't know how to distinguish between kernel configs for GNU/Linux and Android: https://github.com/a13xp0p0v/kernel-hardening-checker/pull/142#issuecomment-2206492055

Do you have any suggestions?

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2025-07-14 16:01](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/171#issuecomment-3070123585):

I was thinking that there should just be a switch to enable it. In the Android mode, it can take into account how Android uses SELinux and avoid suggesting things such as DMESG_RESTRICT which are redundant. I don't think it should avoid suggesting things which are currently incompatible, just ones which are done another way that's comparable in security.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-19 21:33](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/171#issuecomment-3092583429):

@thestinger, thanks for sharing your thoughts.

There is also another more general idea about how to enable customization of the checks: https://github.com/a13xp0p0v/kernel-hardening-checker/issues/50

Thinking about the proper design of this feature.


-------------------------------------------------------------------------------

# [\#170 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/170) `closed`: proc mem force
**Labels**: `good_first_issue`, `new_check`


#### <img src="https://avatars.githubusercontent.com/u/41237666?u=828cced2fb07ceee3bc23fda3ce10320076e79e5&v=4" width="50">[rusty-snake](https://github.com/rusty-snake) opened issue at [2024-12-18 17:51](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/170):

Linux 6.12 added proc mem force, see https://lwn.net/Articles/983169/

- Kconfig: `CONFIG_PROC_MEM_NO_FORCE=y`
- command-line: `proc_mem.force_override=never`

or

- Kconfig: `CONFIG_PROC_MEM_FORCE_PTRACE=y`
- command-line: `proc_mem.force_override=ptrace`

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-10-18 06:11](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/170#issuecomment-3417856523):

Implemented in https://github.com/a13xp0p0v/kernel-hardening-checker/pull/201.
Thanks!


-------------------------------------------------------------------------------

# [\#169 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/169) `closed`: More Kernel command-line checks
**Labels**: `good_first_issue`, `new_check`


#### <img src="https://avatars.githubusercontent.com/u/41237666?u=828cced2fb07ceee3bc23fda3ce10320076e79e5&v=4" width="50">[rusty-snake](https://github.com/rusty-snake) opened issue at [2024-12-09 12:13](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/169):

- `intel_iommu=on`
  - pass if value is `on`
  - pass if `CONFIG_INTEL_IOMMU_DEFAULT_ON` is `y`
  - skip if non-intel?
  - fail otherwise
- `lockdown=confidentiality`
  - pass if value is `confidentiality`
  - pass if `CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY` is `y`
  - fail otherwise
- `module.sig_enforce=1`
  - pass if value is `1`
  - pass if `CONFIG_MODULE_SIG_FORCE` is `y`
  - fail otherwise
- `efi=disable_early_pci_dma`
  - pass if value is `disable_early_pci_dma`
  - pass if `CONFIG_EFI_DISABLE_PCI_DMA` is `y` and value is not `no_disable_early_pci_dma`
  - fail otherwise

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-13 19:52](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/169#issuecomment-3067268710):

Implemented in #187.

Thanks @rusty-snake and @Willenst for the collaboration.


-------------------------------------------------------------------------------

# [\#168 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/168) `closed`: Add another name for STRICT_MODULE_RWX

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-12-05 14:57](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/168):

Apparently, this was a thing between `STRICT_MODULE_RWX` and `DEBUG_SET_MODULE_RONX`.

Source: https://www.youtube.com/watch?v=n7oUA2b15P8

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-12-09 05:32](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/168#issuecomment-2526971601):

Hello @jvoisin.

Interesting, thanks.

I've found this [patch](https://patchwork.kernel.org/project/linux-arm-kernel/patch/1484789346-21012-3-git-send-email-labbott@redhat.com/).

Looks like it didn't find a way to the upstream kernel, so `CONFIG_DEBUG_MODULE_RONX` was directly changed to `STRICT_MODULE_RWX` in [this commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0f5bf6d0afe4be6e1391908ff2d6dc9730e91550).

So we don't really need to check the additional name `CONFIG_HARDENED_MODULE_MAPPINGS`.


-------------------------------------------------------------------------------

# [\#167 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/167) `merged`: parsing CONFIG_LSM option implementation
**Labels**: `new_feature`, `new_check`


#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) opened issue at [2024-11-22 00:36](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/167):

hello, @a13xp0p0v
this PR refers to #151

i have a few theses 
## checks design
may be we shoould use this design
```Python
lsm_modules = ['module1', 'module2' ... 'moduleN']
for module in lsm_modules:
    l += [KconfigCheck('self_protection', 'kspp', 'LSM', module)]
```
instead of
```Python
l += [KconfigCheck('self_protection', 'kspp', 'LSM', 'landlock')]
l += [KconfigCheck('self_protection', 'kspp', 'LSM', 'lockdown')]
l += [KconfigCheck('self_protection', 'kspp', 'LSM', 'yama')]
```
> but if we iterate this, we cant past author (kspp, a13xp0p0v, or anyone else) easily. so, its not a suggestion, just a little question

## modules
may be you meant some modules which i not commited?

## grenerate option
how to be with `-g X86_64` ?

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2024-12-08 01:59](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/167#issuecomment-2525377831):

@a13xp0p0v, done with advices

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2024-12-22 04:24](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/167#issuecomment-2558326227):

hello, @a13xp0p0v 
i've done requested changes exept two things:
- i think that typo fix in `test_engine.py` dont needed because i wrote it to simulate **lsm list** like in kconfig
- there is much `if`'s in engine, so i need your advice to make it more beautiful

in an any case, i re-wrote code, excluded bugs and made all like you wrote in review + it works

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2024-12-28 03:42](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/167#issuecomment-2564158586):

hello, @a13xp0p0v 
please have a look at checks we wrote
here is a hitch: `CONFIG_LSM` only provides order of modules, but, in fact, even if LSM contain some module, it can be even not compiled, so, wont work at all

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-01-22 13:14](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/167#issuecomment-2607220316):

Hello @d1sgr4c3,

Thanks for your previous fixes and please see my commits:

- I did some refactoring,
- Improved the verdicts,
- Fixed the assertion failures in `AND` & `OR`.

These assertion failures appeared because, unfortunately, you didn't test the new `*value*` check with `AND` & `OR`.
Could you please finish the engine unit test and check the coverage?

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2025-02-10 05:51](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/167#issuecomment-2646980943):

hello, @a13xp0p0v 
seems like i'm done with engine unit test

also i checked the coverage. looks kinda ok
![image](https://github.com/user-attachments/assets/1dd424b7-54c8-4e98-b0eb-933f797cd94a)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-02-23 10:31](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/167#issuecomment-2676761705):

Hello @d1sgr4c3,

I reorganized the commits and merged the branch.

Thanks for collaboration!


-------------------------------------------------------------------------------

# [\#166 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/166) `closed`: LIST_HARDENED and DEBUG_LIST should be handled differently since the security properties are the same

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) opened issue at [2024-10-26 03:17](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/166):

LIST_HARDENED exists as a higher performance alternative to DEBUG_LIST providing the same security benefits with lower performance cost. DEBUG_LIST selects LIST_HARDENED since it implies the security properties of LIST_HARDENED. If DEBUG_LIST is enabled, the LIST_HARDENED checks aren't actually used but rather are provided by DEBUG_LIST. Therefore, on recent kernels, you could simply check for LIST_HARDENED and ignore DEBUG_LIST but the script supports the LTS branches so that can't be done as a simplification yet.

The check should look for **either** DEBUG_LIST or LIST_HARDENED rather than checking for both. Older kernels don't have LIST_HARDENED but have the same security hardening available via DEBUG_LIST. Newer kernels can use LIST_HARDENED instead of DEBUG_LIST for the same security properties with lower overhead.

Also see https://x.com/grsecurity/status/1745862639362715988, grsecurity moved to this too.

cc @kees

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-11-09 17:47](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/166#issuecomment-2466311385):

Thank you @thestinger.

Done in https://github.com/a13xp0p0v/kernel-hardening-checker/commit/24c1a906d96f77202837e90d4b1f9f5d9933e1b9.


-------------------------------------------------------------------------------

# [\#165 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/165) `merged`: Integration with oracle/kconfigs

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) opened issue at [2024-10-22 09:20](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/165):

I've added a script for integration with oracle/kconfigs #119  and updated several old links, incorporating them into the same script. Now all kconfigs can be fetched automatically. For now, I’ve committed everything that gets fetched by the script, but I haven't touched the old kconfigs yet. I believe they can be removed eventually.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-11-16 19:02](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/165#issuecomment-2480738076):

Hello @Willenst,
Thanks for your prototype!
Please see my review.

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) commented at [2024-11-17 15:39](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/165#issuecomment-2481320210):

Hi, I'm really sorry, but I think I made a mistake somewhere during rebase and your commits were overwritten. I tried to reconstruct them from memory, but I'm not 100% sure it worked. 

Also, updated some kconfigs with the help of tool:
https://github.com/a13xp0p0v/kernel-hardening-checker/pull/165/commits/04c4c31e424190d7b0b224488a7369a9fdd4bbc5

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) commented at [2024-11-21 13:30](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/165#issuecomment-2491161883):

Added some kconfigs for older kernels, also, should I replace all the old kconfigs with the ones added by my script?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-11-23 17:00](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/165#issuecomment-2495540506):

@Willenst, thanks for the fixes!

Please remove all changes in kconfigs and squash all the commits to a single one, which adds `get_kconfigs.sh` and removes `links.txt`.

Then I'll add some changes on top and carefully update `config_files/distros/`.

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) commented at [2024-11-23 18:03](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/165#issuecomment-2495562460):

Re-formatted the commits, since you asked to discard the added configs, I also discarded a small CI test addition (it's made for the new config file), I'm attaching it here separately, since it might be helpful:

```
@@ -109,7 +109,7 @@ cat /etc/sysctl.conf
 coverage run -a --branch bin/kernel-hardening-checker -s /etc/sysctl.conf
 
 echo ">>>>> test -v (kernel version detection) <<<<<"
-cp kernel_hardening_checker/config_files/distros/fedora_34.config ./test.config
+cp kernel_hardening_checker/config_files/distros/Fedora_39_Core_x86_64.config ./test.config
 coverage run -a --branch bin/kernel-hardening-checker -c ./test.config -v /proc/version
 
 echo "Collect coverage for error handling"
@@ -179,7 +179,7 @@ sed '3d' test.config > error.config
 coverage run -a --branch bin/kernel-hardening-checker -c error.config -v /proc/cmdline && exit 1
 
 echo ">>>>> no arch <<<<<"
-sed '305d' test.config > error.config
+sed '/CONFIG_X86_64/d; /CONFIG_ARM64/d' test.config > error.config
 coverage run -a --branch bin/kernel-hardening-checker -c error.config && exit 1
 
 echo ">>>>> more than one arch <<<<<"
 ```

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-11-23 20:14](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/165#issuecomment-2495642350):

@Willenst,

-  I've added some fixes to the `get_kconfigs.sh` script 
- Cleaned up the distro kconfigs
- Improved the functional test a bit

Merged!

Thanks for the collaboration!


-------------------------------------------------------------------------------

# [\#164 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/164) `merged`: implementation of `arch_mmap_rnd` checks

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) opened issue at [2024-10-13 09:21](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/164):

reffering to #146, i implemented this cheks
we cant check maximum and minimum random offets through `sysctl` (please, see [my comments here](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/146))

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-10-23 06:51](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/164#issuecomment-2431068464):

Hello @d1sgr4c3, 

Thanks for your work!

I would recommend to leave `override_expected_value()` in `engine.py`, it will be needed for #50.

How about adding `refine_check(mode, checklist, parsed_options, target, source)` in `__init__.py`?

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2024-10-23 10:18](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/164#issuecomment-2431631932):

sure, @a13xp0p0v 
that is easy. w8 for commit please, i think ill done with a few hours

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2024-10-27 06:49](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/164#issuecomment-2439877873):

i re-created my branch, take a look pleasde

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-11-09 17:28](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/164#issuecomment-2466306184):

Hello @d1sgr4c3,

I've improved your pull request a bit: dropped some code, improved code style and fixed a mistake.

Now it's merged! 

Thanks for your work!


-------------------------------------------------------------------------------

# [\#163 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/163) `merged`: Add an --autodetect option
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-10-08 20:33](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/163):

Instead of having to specify Kconfig file and `/proc/cmdline`, `--autodetect` will try to infer them.

This is related to #129, and replaces #130.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-10-09 05:57](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/163#issuecomment-2401379628):

Thanks @jvoisin!
What do you think about calling `sysctl -a` here from the tool?

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-10-09 11:07](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/163#issuecomment-2402017316):

As issuing `sysctl -a` to get full coverage requires elevated privileges, I'd like to (maybe) add it in a followup PR, since it'll add some complexity to properly handle this.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-10-12 20:49](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/163#issuecomment-2408696486):

> As issuing sysctl -a to get full coverage requires elevated privileges, I'd like to (maybe) add it in a followup PR, since it'll add some complexity to properly handle this.

I think we should simply avoid elevating privileges in the autodetect mode.

In that case checking the output of `sysctl -a` will give a warning:
```
[!] WARNING: sysctl options available for root are not found in {fname}, please use the output of `sudo sysctl -a`
```
I thinks it's not a problem, in that case only the `net.core.bpf_jit_harden` check will show `FAIL: is not found`.

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-10-15 12:52](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/163#issuecomment-2413833357):

Done :)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-11-09 21:08](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/163#issuecomment-2466460314):

Hello @jvoisin,

I've worked on your prototype, now it doesn't import glob.

Please see the commit https://github.com/a13xp0p0v/kernel-hardening-checker/pull/163/commits/f54d736904785b1ebc0350f8da763d6ff1e3badb.

What do you think?

Thanks a lot!

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-11-10 12:45](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/163#issuecomment-2466721446):

LGTM, albeit you might want to sprinkle some `os.access(file_path, os.R_OK)` just in case.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-11-16 15:36](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/163#issuecomment-2480618672):

Hello @jvoisin,
I've added some improvements and CI tests for the autodetection.
Merged!
Thanks, it's a pleasure to collaborate with you.


-------------------------------------------------------------------------------

# [\#162 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/162) `closed`: Add PTDUMP_DEBUGFS (arm64)

#### <img src="https://avatars.githubusercontent.com/u/1202023?u=598ebb36aedeae0e25c3167bc26c754c3a185efb&v=4" width="50">[citypw](https://github.com/citypw) opened issue at [2024-09-26 15:46](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/162):

Hey @a13xp0p0v , PTDUMP_DEBUGFS for arm64 seems missing.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-10-06 16:06](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/162#issuecomment-2395491580):

Hi @citypw,

This check already exists:
```
$ grep \'PTDUMP_DEBUGFS kernel_hardening_checker/checks.py 
    l += [KconfigCheck('cut_attack_surface', 'grsec', 'PTDUMP_DEBUGFS', 'is not set')]
```
```
$ ./bin/kernel-hardening-checker -c kernel_hardening_checker/config_files/distros/android_pixel-7.config |grep PTDUMP_DEBUGFS
CONFIG_PTDUMP_DEBUGFS                   |kconfig| is not set |  grsec   |cut_attack_surface| OK
CONFIG_ARM_PTDUMP_DEBUGFS               |kconfig| is not set |a13xp0p0v |cut_attack_surface| OK: is not found
```
Thanks!

#### <img src="https://avatars.githubusercontent.com/u/1202023?u=598ebb36aedeae0e25c3167bc26c754c3a185efb&v=4" width="50">[citypw](https://github.com/citypw) commented at [2024-10-07 09:58](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/162#issuecomment-2396467439):

The option name in x86 is same as arm64. Only the arm32 is using CONFIG_ARM_PTDUMP_DEBUGFS. It seems the current version working fine. Closing the PR. Thanks @a13xp0p0v


-------------------------------------------------------------------------------

# [\#161 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/161) `merged`:  implementation of `detect_arch_sysctl()`

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) opened issue at [2024-09-05 16:38](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/161):

implementation of of issue #158 

some **sysct** checks depend on the microarchitecture,
for example: #157 

what i did: 
- renamed the existing `detect_arch()` into `detect_arch_kconfig()` 
- implemented `detect_arch_sysctl()`.

now we can parse the `kernel.arch` **sysctl** to determine the arch.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-09-07 18:12](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/161#issuecomment-2336383118):

Hello @flipthewho,

Thanks for your pull request!

Please see my review below.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-09-15 19:16](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/161#issuecomment-2351753389):

@flipthewho, it would be nice if you provide the testcases for your arch detection.

You can add them to the functional test [.github/workflows/functional_test.sh](https://github.com/a13xp0p0v/kernel-hardening-checker/blob/master/.github/workflows/functional_test.sh).

Testing `detect_arch_kconfig()` would be appreciated as well.

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2024-09-27 02:43](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/161#issuecomment-2378301190):

hello, @a13xp0p0v!
i guess i`m done

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-10-03 08:55](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/161#issuecomment-2390878797):

Excellent! Thank you @flipthewho.
Merged.

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2024-10-03 09:38](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/161#issuecomment-2390964899):

much thanks, @a13xp0p0v!
had an interesting case)


-------------------------------------------------------------------------------

# [\#160 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/160) `merged`: sysctl parsing fixes
**Labels**: `bug/fix`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2024-09-04 13:39](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/160):

It solves #159, reported by @hyder365.




-------------------------------------------------------------------------------

# [\#159 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/159) `closed`: sysctl parsing has a small problem
**Labels**: `bug/fix`


#### <img src="https://avatars.githubusercontent.com/u/67167176?v=4" width="50">[hyder365](https://github.com/hyder365) opened issue at [2024-09-02 17:37](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/159):

When using -s sysctl.conf, the formatting of the file seems to break kernel-hardening-checker. 

For example:

- "net.ipv4.conf.all.rp_filter = 2" works
- "net.ipv4.conf.all.rp_filter=2" doesn't work
- "net.ipv4.conf.all.rp_filter= 2" doesn't work

It's too strict on the formatting. Could you please allow it to work with the more normal spacing we use in config files? (I know sysctl -a does the double space)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-09-04 13:46](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/159#issuecomment-2329116386):

Hello @hyder365,

Thanks for creating this issue.
Please try this branch: https://github.com/a13xp0p0v/kernel-hardening-checker/tree/sysctl-fixes.

Example usage for sysctl.conf:
```
$ ./bin/kernel-hardening-checker -s sysctl.conf 
[+] Sysctl output file to check: sysctl.conf
[!] WARNING: ancient sysctl options are not found in sysctl.conf, please use the output of `sudo sysctl -a`
[!] WARNING: sysctl options available for root are not found in sysctl.conf, please use the output of `sudo sysctl -a`
=========================================================================================================================
              option_name               | type  |desired_val | decision |      reason      | check_result
=========================================================================================================================
net.core.bpf_jit_harden                 |sysctl |     2      |   kspp   | self_protection  | FAIL: is not found
kernel.oops_limit                       |sysctl |    100     |a13xp0p0v | self_protection  | FAIL: is not found
kernel.warn_limit                       |sysctl |    100     |a13xp0p0v | self_protection  | FAIL: is not found
kernel.dmesg_restrict                   |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: is not found
kernel.perf_event_paranoid              |sysctl |     3      |   kspp   |cut_attack_surface| FAIL: is not found
user.max_user_namespaces                |sysctl |     0      |   kspp   |cut_attack_surface| FAIL: is not found
dev.tty.ldisc_autoload                  |sysctl |     0      |   kspp   |cut_attack_surface| FAIL: is not found
kernel.kptr_restrict                    |sysctl |     2      |   kspp   |cut_attack_surface| FAIL: is not found
dev.tty.legacy_tiocsti                  |sysctl |     0      |   kspp   |cut_attack_surface| FAIL: is not found
kernel.kexec_load_disabled              |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: is not found
kernel.unprivileged_bpf_disabled        |sysctl |     1      |   kspp   |cut_attack_surface| OK
vm.unprivileged_userfaultfd             |sysctl |     0      |   kspp   |cut_attack_surface| FAIL: is not found
kernel.modules_disabled                 |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: is not found
kernel.io_uring_disabled                |sysctl |     2      |  grsec   |cut_attack_surface| FAIL: is not found
kernel.sysrq                            |sysctl |     0      |a13xp0p0v |cut_attack_surface| FAIL: is not found
fs.protected_symlinks                   |sysctl |     1      |   kspp   | harden_userspace | FAIL: is not found
fs.protected_hardlinks                  |sysctl |     1      |   kspp   | harden_userspace | FAIL: is not found
fs.protected_fifos                      |sysctl |     2      |   kspp   | harden_userspace | FAIL: is not found
fs.protected_regular                    |sysctl |     2      |   kspp   | harden_userspace | FAIL: is not found
fs.suid_dumpable                        |sysctl |     0      |   kspp   | harden_userspace | FAIL: is not found
kernel.randomize_va_space               |sysctl |     2      |   kspp   | harden_userspace | FAIL: is not found
kernel.yama.ptrace_scope                |sysctl |     3      |   kspp   | harden_userspace | FAIL: is not found

[+] Config check is finished: 'OK' - 1 / 'FAIL' - 21
```

Please pay attention to the warnings at the beginning.
Using the `kernel-hardening-checker` for `sysctl.conf` does not give the complete and correct result.

Is it fine for you?

#### <img src="https://avatars.githubusercontent.com/u/67167176?v=4" width="50">[hyder365](https://github.com/hyder365) commented at [2024-09-04 14:08](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/159#issuecomment-2329173339):

Thanks for the quick work. I think the warning is fine.


-------------------------------------------------------------------------------

# [\#158 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/158) `closed`: Implement `detect_arch_sysctl()`
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2024-08-28 18:52](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/158):

Some sysctl checks depend on the microarchitecture.

Example: #157.

So we need to rename the existing `detect_arch()` into `detect_arch_kconfig()` and then implement `detect_arch_sysctl()`.

We can parse the `kernel.arch` sysctl to determine the arch.





-------------------------------------------------------------------------------

# [\#157 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/157) `merged`: implementation of `vm.mmap_min_addr = 65536` sysctl check
**Labels**: `new_check`


#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) opened issue at [2024-08-25 10:58](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/157):

realised issue #153 

tested on `bullseye` image, also there is an default option for my ubutu. didnt cause any issuses with booting or something
this option can reduces chances to local privelege escalation using null-pntr

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-08-25 13:24](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/157#issuecomment-2308837635):

Hello @flipthewho, thanks for your pull request!

There are still several things to fix:

1) static analysys CI failure

2) this check is not for `harden_userspace`, it's for the kernel self protection. It prevents kernel null pointer dereference exploitation.

3) the `decision` is not `a13xp0p0v`, since the KSPP recommends the corresponding kconfig option. Please use `kspp` and add the comment like `compatible with the 'DEFAULT_MMAP_MIN_ADDR' kconfig check by KSPP`

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-08-28 18:54](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/157#issuecomment-2316045208):

Hello @flipthewho,

Hmm, unfortunately, not so easy ;)

Please see: `DEFAULT_MMAP_MIN_ADDR` should have different values for different architectures.

So you need to add `if arch` here.

But!

There is no arch detection for separate sysctl checking.

So we need to rename the existing `detect_arch()` into `detect_arch_kconfig()` and then implement `detect_arch_sysctl()`.

I've created the issue #158 for that.

Would you like to develop this feature? That would allow to finish this pull request.

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2024-10-04 01:19](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/157#issuecomment-2392602754):

@a13xp0p0v, now we done with the sysctl arch detection
in my implementation i followed by KSPP recommendations:

**X86_64** : `CONFIG_DEFAULT_MMAP_MIN_ADDR=65536`
**X86_32** : `CONFIG_DEFAULT_MMAP_MIN_ADDR=65536`
**ARM64** : `CONFIG_DEFAULT_MMAP_MIN_ADDR=32768`
**ARM** : `CONFIG_DEFAULT_MMAP_MIN_ADDR=32768`

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2024-10-04 02:01](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/157#issuecomment-2392646990):

@a13xp0p0v, ~i guess we need to review tests bc my assert causes error in tests~
```python
def add_sysctl_checks(l: List[ChecklistObjType], arch: StrOrNone) -> None:
    assert(arch), 'empty arch'
```
here is a crashlog
```
>>>>> check sysctl separately <<<<<
+ coverage run -a --branch bin/kernel-hardening-checker -s ./kernel_hardening_checker/config_files/distros/example_sysctls.txt
[+] Sysctl output file to check: ./kernel_hardening_checker/config_files/distros/example_sysctls.txt
[!] WARNING: failed to detect microarchitecture in sysctl, arch-dependent checks will be dropped
Traceback (most recent call last):
  File "/home/vyashnikov/tools/kernel-hardening-checker/bin/kernel-hardening-checker", line 22, in <module>
    kernel_hardening_checker.main()
  File "/home/vyashnikov/tools/kernel-hardening-checker/kernel_hardening_checker/__init__.py", line 397, in main
    add_sysctl_checks(config_checklist, arch)
  File "/home/vyashnikov/tools/kernel-hardening-checker/kernel_hardening_checker/checks.py", line 730, in add_sysctl_checks
    assert(arch), 'empty arch'
AssertionError: empty arch
``` 

upd: we dont need to review checks or something else bc there is only this check with arch. so, assertion is useless cause we drop most of checks

i commented this line, waiting for your reply to make decision and make commented line more beautiful

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-10-06 15:58](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/157#issuecomment-2395488558):

Hello @flipthewho, 

Yes, the assertion that you are adding is not needed:
if `detect_arch_sysctl()` fails, `__init__.py` only prints a warning and continues.

And please see my review https://github.com/a13xp0p0v/kernel-hardening-checker/pull/157#issuecomment-2316045208, some fixes are still mising.

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2024-10-07 03:33](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/157#issuecomment-2395825520):

@a13xp0p0v, sure, agree with assertion
also `self_protection` is the reason for this option

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-10-08 17:29](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/157#issuecomment-2400438926):

Excellent, thanks @flipthewho.
Merged.

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2024-10-08 22:41](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/157#issuecomment-2400943031):

much thanks, @a13xp0p0v 
glad to see a merge!


-------------------------------------------------------------------------------

# [\#156 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/156) `merged`: implementation of `CONFIG_CFI_AUTO_DEFAULT `
**Labels**: `new_check`


#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) opened issue at [2024-08-25 10:01](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/156):

there is an implementation of #149

a few words about logic: `OK` is `cfi=kcfi` in __cmdline__. if this parameter is not set, we looking for `CONFIG_CFI_AUTO_DEFAULT` which should be off, it is equals to  `cfi=kcfi`([reference](https://patchew.org/linux/20240501000218.work.998-kees@kernel.org/))
also for kCFI options we have some dependences, they are also added to check.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-09-07 18:05](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/156#issuecomment-2336342046):

Hello @flipthewho,

Thanks for your pull request!

I see a mistake: this recommendation for `x86_64` can't be satisfied on `arm64`:
```
$ ./bin/kernel-hardening-checker -c kernel_hardening_checker/config_files/distros/android_pixel-7.config -l /tmp/l |grep -i cfi
CONFIG_DEBUG_NOTIFIERS                  |kconfig|     y      |   kspp   | self_protection  | OK: CONFIG_CFI_CLANG is "y"
CONFIG_CFI_CLANG                        |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_CFI_PERMISSIVE                   |kconfig| is not set |   kspp   | self_protection  | OK
CONFIG_CFI_AUTO_DEFAULT                 |kconfig| is not set |a13xp0p0v | self_protection  | FAIL: CONFIG_CFI_AUTO_DEFAULT is not present
```
Please check the arch.

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2024-09-09 06:00](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/156#issuecomment-2337193600):

checked arch in cmdline, but forgot bout kconfig, my bad
pushed it with arch checking

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-09-10 19:25](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/156#issuecomment-2341848721):

Thanks, @flipthewho.
I added a commit with minor style fixes.
Merged!


-------------------------------------------------------------------------------

# [\#155 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/155) `merged`: Unitest addons
**Labels**: `bug/fix`


#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) opened issue at [2024-08-22 21:01](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/155):

Hello, some new unittest code for #145 , now it must must cover almost 100%! I've added tests for `print_unknown_options()` and `colorize_result()`. Also, I had an interesting experience with _object-oriented programming, pylint, mypy, and unittest_, which are all new to me, hope everything works fine. Waiting for your feedback!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-08-25 12:37](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/155#issuecomment-2308816977):

@Willenst, thanks a lot for your work!

I've added some fixes to this PR.
Please check them one by one. Feel free to squash them into your version.

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) commented at [2024-08-27 13:47](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/155#issuecomment-2312613741):

@a13xp0p0v, thanks a lot for your fixes, good additions with a great code practice, I've learned a lot! 
All commits were squashed for a beautiful push request, so, just in case, they will be stored for some time here
https://github.com/Willenst/kernel-hardening-checker/tree/test_CI

Also, I've made a littler code refactor of my print_unknown_options (1-st commit), so it will be nice if you check it again.

Since you've said that additional debug info is unneeded in one of your additions (_unittest_ prints all the info if test fails), debug info from `run_engine` was also deleted.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-08-28 18:03](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/155#issuecomment-2315961283):

Excellent, thanks @Willenst.
Merged.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-08-28 18:23](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/155#issuecomment-2315995921):

I added one more test to cover this:
![image](https://github.com/user-attachments/assets/8d5b26bd-25d1-482b-9b4a-a2875908f729)

The details: https://app.codecov.io/gh/a13xp0p0v/kernel-hardening-checker/blob/master/kernel_hardening_checker%2Fengine.py?flags%5B0%5D=engine_unit-test

The commit: https://github.com/a13xp0p0v/kernel-hardening-checker/commit/f866b3686068ada2556aa773d6c06c691e2df9ad


-------------------------------------------------------------------------------

# [\#154 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/154) `closed`: Add kconfig option `CONFIG_CFI_AUTO_DEFAULT` which is twin of `cfi=kcfi`

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) opened issue at [2024-08-22 18:53](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/154):

this release commit is an implementation of #149 

basic things: `OK`is `cfi=kcfi` in __cmdline__. if this parameter is not set, we looking for `CONFIG_CFI_AUTO_DEFAULT` which should be off, it is equals to  `cfi=kcfi`, see [reference](https://patchew.org/linux/20240501000218.work.998-kees@kernel.org/)
also for this Kconfig options we have some dependences, they are also added to check.

important thing: we should specify compiler (From Kees Cook's [slides](https://outflux.net/slides/2020/lca/cfi.pdf))




-------------------------------------------------------------------------------

# [\#153 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/153) `closed`: Implement the `vm.mmap_min_addr = 65536` sysctl check
**Labels**: `good_first_issue`, `new_check`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2024-08-21 15:32](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/153):



#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-10-08 17:29](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/153#issuecomment-2400439553):

Implemented by @flipthewho.
Closing.


-------------------------------------------------------------------------------

# [\#152 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/152) `merged`: Add io_uring_disabled similar to CONFIG_IO_URING in kconfig
**Labels**: `new_check`


#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) opened issue at [2024-08-17 11:22](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/152):

References #109 

Added a sysctl io_uring_disabled check, which I believe should be set to 2 for complete disabling. Fully disabling this option reduces the attack surface, as a limited io_uring could still be exploited from rooted namespaces, such as unsecured Docker containers for example. Also, this approach is recommended by Grsecurity and has been implemented in kconfig as fully disabled.





#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-08-18 15:03](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/152#issuecomment-2295292750):

Hello @Willenst, 

Thanks a lot for your pull request!

I have some tips for you:

1) Please move this check below the kspp checks to keep the order similar to `add_kconfig_checks()` and `add_cmdline_checks()`.

2) Please use the `have_kconfig` trick. Without it, the tool gives the false positive error if you check only the sysctls:
```
$ ./bin/kernel-hardening-checker  -s /tmp/s
[+] Sysctl output file to check: /tmp/s
=========================================================================================================================
              option_name               | type  |desired_val | decision |      reason      | check_result
=========================================================================================================================
net.core.bpf_jit_harden                 |sysctl |     2      |   kspp   | self_protection  | FAIL: "0"
kernel.oops_limit                       |sysctl |    100     |a13xp0p0v | self_protection  | FAIL: "10000"
kernel.warn_limit                       |sysctl |    100     |a13xp0p0v | self_protection  | FAIL: "0"
kernel.io_uring_disabled                |sysctl |     2      |  grsec   |cut_attack_surface| OK: CONFIG_IO_URING is not found
...
```

3) For this check, please add the comment like this:
```
# This check is compatible with the 'IO_URING' check by grsecurity
```

And I would also ask you to rebase the PR branch onto the fresh master.

Thank you!

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) commented at [2024-08-19 15:09](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/152#issuecomment-2296813220):

Thanks a lot for the detailed reply! This is my first experience working on a public opensource project, I apologize for the mistakes, seems like now this check works fine. I've merged my PR with the current master, also moved  `io_uring_disabled` check below the kspp ones, and added the comment about kconfig `IO_URING` compatibility. 
```
$ ./kernel-hardening-checker -s /tmp/file1
[+] Sysctl output file to check: /tmp/file1
=========================================================================================================================
              option_name               | type  |desired_val | decision |      reason      | check_result
=========================================================================================================================
vm.unprivileged_userfaultfd             |sysctl |     0      |   kspp   |cut_attack_surface| OK
kernel.modules_disabled                 |sysctl |     1      |   kspp   |cut_attack_surface| FAIL: "0"
kernel.io_uring_disabled                |sysctl |     2      |  grsec   |cut_attack_surface| FAIL: "0"
```

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-08-25 13:05](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/152#issuecomment-2308828638):

@Willenst, thanks! 

The false positive error is fixed:
1) with kconfig
```
$ ./bin/kernel-hardening-checker -c kconfig -s /tmp/s -m verbose
...
-------------------------------------------------------------------------------------------------------------------------
    <<< OR >>>                                                                             | FAIL: "0"
kernel.io_uring_disabled                |sysctl |     2      |  grsec   |cut_attack_surface| FAIL: "0"
    <<< AND >>>                                                                            | FAIL: "y"
CONFIG_IO_URING                         |kconfig| is not set |  grsec   |cut_attack_surface| FAIL: "y"
CONFIG_LOCALVERSION                     |kconfig| is present |    -     |        -         | OK: is present
-------------------------------------------------------------------------------------------------------------------------
```
2) without kconfig
```
$ ./bin/kernel-hardening-checker  -s /tmp/s -m verbose
...
-------------------------------------------------------------------------------------------------------------------------
    <<< OR >>>                                                                             | FAIL: "0"
kernel.io_uring_disabled                |sysctl |     2      |  grsec   |cut_attack_surface| FAIL: "0"
    <<< AND >>>                                                                            | FAIL: CONFIG_LOCALVERSION is not present
CONFIG_IO_URING                         |kconfig| is not set |  grsec   |cut_attack_surface| None
CONFIG_LOCALVERSION                     |kconfig| is present |    -     |        -         | FAIL: is not present
-------------------------------------------------------------------------------------------------------------------------
```
Good.

Now we need some minor style fixes:
1) please check the static analysis CI failure
2) please add missing spaces absolutely similar to the `kernel.modules_disabled` check
3) please fix the word order in the comment, like this: `# compatible with the 'IO_URING' kconfig check by grsecurity`

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) commented at [2024-08-26 09:05](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/152#issuecomment-2309718581):

@a13xp0p0v, Changes made based on your comments:

1. Static analysis CI should work fine:

```
$ pylint --recursive=y kernel_hardening_checker setup.py 

--------------------------------------------------------------------
Your code has been rated at 10.00/10 (previous run: 10.00/10, +0.00)
```

I also verified it in the fork's workflow:

![image](https://github.com/user-attachments/assets/08e35f46-b78c-4199-8327-02b7e5dc53aa)

2. Missing spaces added, similar to `kernel.modules_disabled` 
3. Word order corrected as suggested

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-08-29 06:35](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/152#issuecomment-2316820274):

Thanks, @Willenst.
Merged!


-------------------------------------------------------------------------------

# [\#151 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/151) `closed`: Implement parsing of the `CONFIG_LSM` kconfig option
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2024-08-10 11:41](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/151):

The `CONFIG_LSM` kconfig option contains a list of LSM modules loaded by the kernel.
Let's create a simple mechanism for checking that it contains the needed LSM module.

The checking rule might look like this:
```
l += [KconfigCheck('self_protection', 'kspp', 'LSM', '*lockdown*')]
``` 
Here `'*lockdown*'` means that `lockdown` is in the comma-separated list.




-------------------------------------------------------------------------------

# [\#150 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/150) `merged`: Add ARM SMMU check options
**Labels**: `new_check`


#### <img src="https://avatars.githubusercontent.com/u/1202023?u=598ebb36aedeae0e25c3167bc26c754c3a185efb&v=4" width="50">[citypw](https://github.com/citypw) opened issue at [2024-08-06 16:06](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/150):

Threat model:
https://github.com/hardenedlinux/grsecurity-101-tutorials/blob/master/embedded_platform_security.md

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-08-11 18:19](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/150#issuecomment-2282845748):

Welcome @citypw,
Thanks for the pull request!

I noticed, that these options are not in defconfig for arm (32 bit):
```
$ grep ARM_SMMU kernel_hardening_checker/config_files/defconfigs/arm_defconfig_6.10.config
# CONFIG_ARM_SMMU is not set
```

Please move these checks under `if arch == 'ARM64':`.

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/1202023?u=598ebb36aedeae0e25c3167bc26c754c3a185efb&v=4" width="50">[citypw](https://github.com/citypw) commented at [2024-08-11 18:56](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/150#issuecomment-2282855498):

@a13xp0p0v It's been a while and it's good to see this project keep going on. 

Thanks for the review. Moved them into "ARM64". I don't have knowledge about if all armv7 hardware shipped SMMU by default or only the specific hardware like [ Exynos5 SoC]( https://genode.org/documentation/articles/arm_virtualization ) . I've only seen it's been deployed in arm64 at the moment.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-08-18 14:37](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/150#issuecomment-2295285335):

Thank you, @citypw.
Merged!


-------------------------------------------------------------------------------

# [\#149 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/149) `closed`: Add kconfig option `CONFIG_CFI_AUTO_DEFAULT`
**Labels**: `good_first_issue`, `new_check`


#### <img src="https://avatars.githubusercontent.com/u/107318481?u=7423ac118deca5f7f745e28ac2e3f6a487465973&v=4" width="50">[winterknife](https://github.com/winterknife) opened issue at [2024-07-22 20:16](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/149):

This kconfig option is an alternative to the `cfi=kcfi` kernel command-line parameter check that's already implemented.

Reference: https://www.phoronix.com/news/Linux-6.11-Hardening


#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2024-08-22 18:57](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/149#issuecomment-2305433182):

hello, @winterknife, @a13xp0p0v 
i implemented this ussue in my fork and merged all commits from test branch to release
now there is a #154 pull request into main repo

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-09-10 19:25](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/149#issuecomment-2341849357):

Implemented by @flipthewho.
Closing.


-------------------------------------------------------------------------------

# [\#148 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/148) `merged`: Simplify a bit the detect_arch function

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-07-16 23:40](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/148):

- Use a regex to extract the arch instead of doing the extraction "by hand".
- Reduce nested indentation.
- Reduce the amount of code in the loop.
- Remove a forceful `re.compile`: python will cache regex in a compiled form if necessary.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-28 17:52](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/148#issuecomment-2254594341):

Looks good to me.
Thanks, @jvoisin.
Merged!


-------------------------------------------------------------------------------

# [\#147 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/147) `closed`: New kconfig SECURITY_PROC_MEM_RESTRICT_WRITES

#### <img src="https://avatars.githubusercontent.com/u/77795961?v=4" width="50">[osevan](https://github.com/osevan) opened issue at [2024-07-15 06:58](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/147):

The new SECURITY_PROC_MEM_RESTRICT_WRITES Kconfig option allows restricting writes to the mem file of processes unless the current process ptraces to that given task. 

https://lore.kernel.org/lkml/20240712-vfs-procfs-ce7e6c7cf26b@brauner/

#### <img src="https://avatars.githubusercontent.com/u/107318481?u=7423ac118deca5f7f745e28ac2e3f6a487465973&v=4" width="50">[winterknife](https://github.com/winterknife) commented at [2024-07-22 20:06](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/147#issuecomment-2243724842):

Another reference: https://www.phoronix.com/news/Linux-6.11-Tightens-Mem-Access

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-29 16:19](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/147#issuecomment-2256365491):

@osevan, @winterknife, thanks for creating the issue!

Looks like the proposed version of this feature is not accepted:
https://lore.kernel.org/lkml/CAHk-=wiGWLChxYmUA5HrT5aopZrB7_2VTa0NLZcxORgkUe5tEQ@mail.gmail.com/

So let's wait and see.
Closing this issue for now.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-10-18 06:12](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/147#issuecomment-3417859211):

Implemented in https://github.com/a13xp0p0v/kernel-hardening-checker/pull/201.
Thanks!


-------------------------------------------------------------------------------

# [\#146 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/146) `closed`: Implement the `CONFIG_ARCH_MMAP_RND_COMPAT_BITS` check
**Labels**: `good_first_issue`, `new_check`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2024-07-07 15:32](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/146):

`CONFIG_ARCH_MMAP_RND_COMPAT_BITS` should be equal to `CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX` or not set at all (if `CONFIG_COMPAT` is not set).

See `CONFIG_ARCH_MMAP_RND_BITS` as an example.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-08-11 11:10](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/146#issuecomment-2282721362):

Also need to check the `vm.mmap_rnd_bits` and `vm.mmap_rnd_compat_bits` sysctl options.

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2024-10-09 21:29](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/146#issuecomment-2403462670):

hello, @a13xp0p0v
i'd like to take over the implementation of this issue.
____
>See CONFIG_ARCH_MMAP_RND_BITS as an example.

did you talk about this?
```python
    if kconfig:
        # populate the checklist with the parsed Kconfig data
        parsed_kconfig_options = {} # type: Dict[str, str]
        parse_kconfig_file(mode, parsed_kconfig_options, kconfig)
        populate_with_data(config_checklist, parsed_kconfig_options, 'kconfig')

        # hackish refinement of the CONFIG_ARCH_MMAP_RND_BITS check
        mmap_rnd_bits_max = parsed_kconfig_options.get('CONFIG_ARCH_MMAP_RND_BITS_MAX', None)
        if mmap_rnd_bits_max:
            override_expected_value(config_checklist, 'CONFIG_ARCH_MMAP_RND_BITS', mmap_rnd_bits_max)
        else:
            # remove the CONFIG_ARCH_MMAP_RND_BITS check to avoid false results
            if mode != 'json':
                print('[-] Can\'t check CONFIG_ARCH_MMAP_RND_BITS without CONFIG_ARCH_MMAP_RND_BITS_MAX')
            config_checklist[:] = [o for o in config_checklist if o.name != 'CONFIG_ARCH_MMAP_RND_BITS']
```
and
```python
for opt in config_checklist:
    opt.name == 'CONFIG_ARCH_MMAP_RND_BITS':
    # don't add CONFIG_ARCH_MMAP_RND_BITS because its value needs refinement
```
and, finally 
```Python
l += [KconfigCheck('harden_userspace', 'a13xp0p0v', 'ARCH_MMAP_RND_BITS', 'MAX')] # 'MAX' value is refined using ARCH_MMAP_RND_BITS_MAX
```

should i use these references to implement an issue?

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2024-10-10 02:24](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/146#issuecomment-2403790357):

>  Also need to check the vm.mmap_rnd_bits and vm.mmap_rnd_compat_bits sysctl options.

i found, that this value can be changed after boot using the `/proc/sys/vm/mmap_rnd_compat_bits` tunable.

so, we should  implement sysctl check separately, right?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-10-10 16:46](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/146#issuecomment-2405597519):

> should i use these references to implement an issue?

Yes, certainly.

> so, we should implement sysctl check separately, right?

Yes. And this may require some creative approach to do the refinement.

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2024-10-13 09:08](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/146#issuecomment-2408894748):

hello, @a13xp0p0v 
there some oopses: we cant implement sysct checks from userspace.
according to sources, we have the following:
```C
#ifdef CONFIG_HAVE_ARCH_MMAP_RND_BITS
const int mmap_rnd_bits_min = CONFIG_ARCH_MMAP_RND_BITS_MIN;
int mmap_rnd_bits_max __ro_after_init = CONFIG_ARCH_MMAP_RND_BITS_MAX;
int mmap_rnd_bits __read_mostly = CONFIG_ARCH_MMAP_RND_BITS;
#endif
#ifdef CONFIG_HAVE_ARCH_MMAP_RND_COMPAT_BITS
const int mmap_rnd_compat_bits_min = CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MIN;
const int mmap_rnd_compat_bits_max = CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MAX;
int mmap_rnd_compat_bits __read_mostly = CONFIG_ARCH_MMAP_RND_COMPAT_BITS;
#endif
```
and this structure
```C
#ifdef CONFIG_HAVE_ARCH_MMAP_RND_BITS
 {
  .procname = "mmap_rnd_bits",
  .data  = &mmap_rnd_bits,
  .maxlen  = sizeof(mmap_rnd_bits),
  .mode  = 0600,
  .proc_handler = proc_dointvec_minmax,
  .extra1  = (void *)&mmap_rnd_bits_min,
  .extra2  = (void *)&mmap_rnd_bits_max,
 },
```
here `.extra1  = (void *)&mmap_rnd_bits_min,` equals to
`const int mmap_rnd_bits_min = CONFIG_ARCH_MMAP_RND_BITS_MIN;`, like an `.extra2`
lets look for `.proc_handler` 
using `cscope` i found
```C
int proc_dointvec_minmax(const struct ctl_table *table, int write,
    void *buffer, size_t *lenp, loff_t *ppos)
{
 struct do_proc_dointvec_minmax_conv_param param = {
  .min = (int *) table->extra1,
  .max = (int *) table->extra2,
 };
 return do_proc_dointvec(table, write, buffer, lenp, ppos,
    do_proc_dointvec_minmax_conv, &param);
}
```
here we can see only pointers, so we cant even parse this opts from userspace, they are defined with **Kconfig**

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2024-10-13 09:16](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/146#issuecomment-2408897356):

so, in our case, we can rely only on theesee sources (`arch/<architecture>/Kconfig)
for  `x86`
```C
config ARCH_MMAP_RND_BITS_MAX
	default 32 if 64BIT
	default 16

config ARCH_MMAP_RND_COMPAT_BITS_MIN
	default 8

config ARCH_MMAP_RND_COMPAT_BITS_MAX
	default 16
```
for `aarch64`
```C
config ARCH_MMAP_RND_BITS_MIN
	default 14 if PAGE_SIZE_64KB
	default 16 if PAGE_SIZE_16KB
	default 18

# max bits determined by the following formula:
#  VA_BITS - PAGE_SHIFT - 3
config ARCH_MMAP_RND_BITS_MAX
	default 19 if ARM64_VA_BITS=36
	default 24 if ARM64_VA_BITS=39
	default 27 if ARM64_VA_BITS=42
	default 30 if ARM64_VA_BITS=47
	default 29 if ARM64_VA_BITS=48 && ARM64_64K_PAGES
	default 31 if ARM64_VA_BITS=48 && ARM64_16K_PAGES
	default 33 if ARM64_VA_BITS=48
	default 14 if ARM64_64K_PAGES
	default 16 if ARM64_16K_PAGES
	default 18

config ARCH_MMAP_RND_COMPAT_BITS_MIN
	default 7 if ARM64_64K_PAGES
	default 9 if ARM64_16K_PAGES
	default 11

config ARCH_MMAP_RND_COMPAT_BITS_MAX
	default 16
```
and for `arm`
```C
config ARCH_MMAP_RND_BITS_MIN
	default 8

config ARCH_MMAP_RND_BITS_MAX
	default 14 if PAGE_OFFSET=0x40000000
	default 15 if PAGE_OFFSET=0x80000000
	default 16
```
as you can see, here is a lot of additional parameters in `arm` and `arm64`
so, i decided to check only `x86` family in sysctl checks

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-10-16 13:50](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/146#issuecomment-2416908224):

Thanks for the analysis, @d1sgr4c3.

I would recommend setting these sysctls to `MAX` and then using `override_expected_value()` to do the refinement.

#### <img src="https://avatars.githubusercontent.com/u/121037831?u=fc711d33e89e67f8ad3094527177769eba26ba18&v=4" width="50">[d1sgr4c3](https://github.com/d1sgr4c3) commented at [2024-10-20 04:17](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/146#issuecomment-2424563952):

@a13xp0p0v, i need your help and review, can we discuss this issue right in merge request? i have something new

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-11-09 17:30](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/146#issuecomment-2466306529):

Done by @d1sgr4c3, closing.


-------------------------------------------------------------------------------

# [\#145 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/145) `closed`: Relatively low code coverage in the engine unit test
**Labels**: `bug/fix`, `good_first_issue`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2024-07-07 14:55](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/145):

Need to add tests for `print_unknown_options()` and `colorize_result()` at [kernel_hardening_checker/test_engine.py](https://github.com/a13xp0p0v/kernel-hardening-checker/blob/master/kernel_hardening_checker/test_engine.py)

More details [here](https://app.codecov.io/gh/a13xp0p0v/kernel-hardening-checker/blob/master/kernel_hardening_checker%2Fengine.py?flags%5B0%5D=engine_unit-test).

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-08-28 18:24](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/145#issuecomment-2315997263):

Closing. Thanks to @Willenst.


-------------------------------------------------------------------------------

# [\#144 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/144) `open`: Add the `with care` column
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2024-07-03 15:21](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/144):

I have an idea: to add a column `|with care|` for the options that may break some kernel functionality or introduce significant performance impact. 

(refers to #137)




-------------------------------------------------------------------------------

# [\#143 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/143) `closed`: __init__.py: do not exit on unexpected line
**Labels**: `bug/fix`


#### <img src="https://avatars.githubusercontent.com/u/1485263?v=4" width="50">[ffontaine](https://github.com/ffontaine) opened issue at [2024-07-02 12:59](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/143):

Display a warning instead of exiting on unexpected line such as: `CONFIG_BCM_OTP_IMPL=`

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-03 13:03](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/143#issuecomment-2206031021):

Hello @ffontaine,
Could you please give more information about this option and give the example kconfig.
I don't see it in the upstream kernel.
Thanks.

#### <img src="https://avatars.githubusercontent.com/u/1485263?v=4" width="50">[ffontaine](https://github.com/ffontaine) commented at [2024-07-03 13:11](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/143#issuecomment-2206045829):

Hello,

I made a typo (BMC -> BCM).
I don't have a lot of information, it seems a proprietary option: https://dev.iopsys.eu/broadcom/bcmlinux/-/blame/master/Kconfig.bcm#L713

It is probably wrong to have an empty value, nevertheless, the rest of the file seems to be ok.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-03 13:16](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/143#issuecomment-2206056526):

Ok, thanks!
And why does it break the logic in `parse_kconfig_file()`?
Maybe we can adapt the parsing code instead of changing the error to warning.

#### <img src="https://avatars.githubusercontent.com/u/1485263?v=4" width="50">[ffontaine](https://github.com/ffontaine) commented at [2024-07-03 13:22](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/143#issuecomment-2206067945):

The logic is broken because the line doesn't match any of this regex:

```
        opt_is_on = re.compile(r"CONFIG_[a-zA-Z0-9_]+=.+$")
        opt_is_off = re.compile(r"# CONFIG_[a-zA-Z0-9_]+ is not set$")
```

Indeed, there is no character after `=`. 
An other option would be to replace
```
opt_is_on = re.compile(r"CONFIG_[a-zA-Z0-9_]+=.+$")
```
by
```
opt_is_on = re.compile(r"CONFIG_[a-zA-Z0-9_]+=.*$")
```

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-03 15:02](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/143#issuecomment-2206444720):

That is strange.

Kconfig should generate only two variants:
`CONFIG_LOCK_DEBUGGING_SUPPORT=y`
or
`# CONFIG_PROVE_LOCKING is not set`.

Are you sure that your kconfig file is not corrupted?

Can you run `make` in the kernel source code do double-check that?

#### <img src="https://avatars.githubusercontent.com/u/1485263?v=4" width="50">[ffontaine](https://github.com/ffontaine) commented at [2024-07-03 16:30](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/143#issuecomment-2206755047):

Unfortunately, I can't run make. Actually, I have no access to the source code. I'm running kernel-hardening-checker on the `/proc/config.gz` extracted from the device.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-03 16:43](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/143#issuecomment-2206776994):

I see.
Could you share this config?
I'll think how to fix it better.

#### <img src="https://avatars.githubusercontent.com/u/1485263?v=4" width="50">[ffontaine](https://github.com/ffontaine) commented at [2024-07-03 16:52](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/143#issuecomment-2206790033):

I'm not allowed to provide you this file however I would be happy to test your fix :-).

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-03 17:16](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/143#issuecomment-2206838870):

You make my task a bit harder :)

Okay, a did the following:
```
git clone https://dev.iopsys.eu/broadcom/bcmlinux.git
cd bcmlinux/
git checkout master
make defconfig
cat .config |grep "=$"
```

It gives the following:
```
CONFIG_BCM_CHIP_NUMBER=
CONFIG_BCM_SCHED_RT_PERIOD=
CONFIG_BCM_SCHED_RT_RUNTIME=
CONFIG_BCM_DEFAULT_CONSOLE_LOGLEVEL=
CONFIG_BCM_RDP_IMPL=
```

Yes, it's a strange vendor behaviour.

Anyway, let's think what to do with it.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-06 21:30](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/143#issuecomment-2211974882):

@ffontaine, I adapted the tool.

See the output for the Broadcom config:
```
[+] Kconfig file to check: bad_config
[+] Detected microarchitecture: X86_64
[+] Detected kernel version: (3, 4, 11)
[-] Can't detect the compiler: no CONFIG_GCC_VERSION or CONFIG_CLANG_VERSION
[!] WARNING: found strange Kconfig option CONFIG_BCM_CHIP_NUMBER with empty value
[!] WARNING: found strange Kconfig option CONFIG_BCM_SCHED_RT_PERIOD with empty value
[!] WARNING: found strange Kconfig option CONFIG_BCM_SCHED_RT_RUNTIME with empty value
[!] WARNING: found strange Kconfig option CONFIG_BCM_DEFAULT_CONSOLE_LOGLEVEL with empty value
[!] WARNING: found strange Kconfig option CONFIG_BCM_RDP_IMPL with empty value
[-] Can't check CONFIG_ARCH_MMAP_RND_BITS without CONFIG_ARCH_MMAP_RND_BITS_MAX
=========================================================================================================================
              option_name               | type  |desired_val | decision |      reason      | check_result
=========================================================================================================================
CONFIG_BUG                              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_SLUB_DEBUG                       |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_THREAD_INFO_IN_TASK              |kconfig|     y      |defconfig | self_protection  | FAIL: is not found
```

Now you can test `kernel-hardening-checker` with your config.

#### <img src="https://avatars.githubusercontent.com/u/1485263?v=4" width="50">[ffontaine](https://github.com/ffontaine) commented at [2024-07-07 08:22](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/143#issuecomment-2212367681):

Thanks, it works, I'm closing this PR.


-------------------------------------------------------------------------------

# [\#142 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/142) `closed`: Tweak the checks for android

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-06-28 14:14](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/142):

> Android configs require various things that are currently disallowed in this
> tool. We can use CONFIG_ANDROID to detect Android configs and generate reports with fewer positives that cannot/should not be changed.

Based on #91

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-03 15:13](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/142#issuecomment-2206492055):

Hi @jvoisin,

Thanks for your work!

We need to improve it somehow.
This branch introduces faults, because `CONFIG_ANDROID` is enabled for some general-purpose distros.
For example, Ubuntu and Debian enable it.

Please see the wrong results:
```bash
$ ./bin/kernel-hardening-checker -c kernel_hardening_checker/config_files/distros/ubuntu-22.04.config |grep ANDROID
CONFIG_MODULES                          |kconfig| is not set |   kspp   |cut_attack_surface| OK: CONFIG_ANDROID is "y"
CONFIG_MAGIC_SYSRQ                      |kconfig| is not set |  clipos  |cut_attack_surface| OK: CONFIG_ANDROID is "y"
CONFIG_BPF_SYSCALL                      |kconfig| is not set | lockdown |cut_attack_surface| OK: CONFIG_ANDROID is "y"
CONFIG_TRIM_UNUSED_KSYMS                |kconfig|     y      |a13xp0p0v |cut_attack_surface| OK: CONFIG_ANDROID is "y"
```

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-07-03 15:49](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/142#issuecomment-2206639081):

Sigh, why can't we have nice things…
I don't see a straightforward way to detect [android kernel config](https://android.googlesource.com/kernel/configs/+/refs/heads/main/w/android-6.next/android-base.config) :/

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-03 16:49](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/142#issuecomment-2206786273):

Sigh. Agree.

But I see an alternative approach here: to implement #50: `Allow redefining rules and expanding rule sets`.

Please see this discussion, maybe you'll have some thoughts.

For now, closing this pull request.


-------------------------------------------------------------------------------

# [\#141 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/141) `closed`: Use a proper regex to extract kernel version

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-06-14 16:09](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/141):

Instead of spaghetti ad-hoc string manipulation.




-------------------------------------------------------------------------------

# [\#140 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/140) `merged`: Add two PAGE_TABLE_CHECK related checks from kspp

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-05-22 20:04](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/140):

Newly added in https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=87caef42200cd44f8b808ec2f8ac2257f3e0a8c1

cc @kees

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-06-09 09:03](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/140#issuecomment-2156401859):

Thanks @jvoisin.
Merged!


-------------------------------------------------------------------------------

# [\#139 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/139) `closed`: Tweak the checks for android

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-05-17 18:47](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/139):

> Android configs require various things that are currently disallowed in this
tool. We can use CONFIG_ANDROID to detect Android configs and generate reports with fewer positives that cannot/should not be changed.

Based on https://github.com/a13xp0p0v/kernel-hardening-checker/pull/91

cc @strcat @jduck @sempervictus

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2024-05-17 21:54](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/139#issuecomment-2118425858):

It's still possible to use a kernel with dynamic kernel module support disabled on Android, so I think that one is questionable. They require using dynamic kernel modules as part of Generic Kernel Image support but there's no real technical requirement to use them if you build a kernel specifically for the device. The requirement is part of requiring that the device can boot with a Generic Kernel Image via the stable ABI for out-of-tree modules. We used to disable dynamic kernel modules for GrapheneOS but it got too hard to maintain since both in-tree and out-of-tree driver modules are only really tested as dynamic kernel modules in practice so we started running into far many initialization order issues where they don't delay loading firmware, etc.

Android fully requires `/proc/sysrq-trigger` interface so it makes sense not to ask to disable MAGIC_SYSRQ but you **can** set the default `kernel.sysrq` to 0 and can disable serial sysrq support.

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2024-05-17 21:54](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/139#issuecomment-2118426271):

BPF is also a hard requirement and Android deals with the attack surface aspect itself by fully limiting it to `bpfloader` via SELinux which can only be used via netd.

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-05-17 22:05](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/139#issuecomment-2118434161):

> It's still possible to use a kernel with dynamic kernel module support disabled on Android, so I think that one is questionable. They require using dynamic kernel modules as part of Generic Kernel Image support but there's no real technical requirement to use them if you build a kernel specifically for the device. The requirement is part of requiring that the device can boot with a Generic Kernel Image via the stable ABI for out-of-tree modules. We used to disable dynamic kernel modules for GrapheneOS but it got too hard to maintain since both in-tree and out-of-tree driver modules are only really tested as dynamic kernel modules in practice so we started running into far many initialization order issues where they don't delay loading firmware, etc.

Well, if GrapheneOS can't manage to do it, I don't think it's really questionable nor realistic to expect anyone to do it :)

> Android fully requires /proc/sysrq-trigger interface so it makes sense not to ask to disable MAGIC_SYSRQ but you can set the default kernel.sysrq to 0 and can disable serial sysrq support.

There is a [note/todo](https://github.com/a13xp0p0v/kernel-hardening-checker/blob/master/kernel_hardening_checker/checks.py#L655) about this.

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2024-05-17 22:09](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/139#issuecomment-2118437811):

> Well, if GrapheneOS can't manage to do it, I don't think it's really questionable nor realistic to expect anyone to do it :)

We could do it, but it doesn't provide any significant security benefits so it's not worth the significant hassle to get it working and keep it working. It can break things in a subtle way. The same thing applies to many in-tree modules.

> There is a [note/todo](https://github.com/a13xp0p0v/kernel-hardening-checker/blob/master/kernel_hardening_checker/checks.py#L655) about this.

You can set `kernel.sysrq` via the kernel configuration rather than only sysctl:

https://github.com/a13xp0p0v/kernel-hardening-checker/issues/104

Better to change the default in kernel configuration to avoid a race window where it's not disabled yet in early boot.

#### <img src="https://avatars.githubusercontent.com/u/1331084?v=4" width="50">[sempervictus](https://github.com/sempervictus) commented at [2024-05-18 01:28](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/139#issuecomment-2118548598):

Firmware load races on built-in init don't sound fun, but kicking off an async waiter in init to complete fw load when a condition is met might be a way to go. Benefits to lto and therefore kcfi might be worth it.

Re eBPF - given the load restriction its a bit of a chicken and egg thing (as using it to alter selinux context seems a good way to go but itself likely requires a bypass), but it might be worth trying to understand how someone other than the loading role could impact what the JIT does to it by control of context which the eBPF code accesses.

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-06-28 14:14](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/139#issuecomment-2197037110):

Superseded by #142


-------------------------------------------------------------------------------

# [\#138 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/138) `merged`: Add a couple of grsecurity disabled options
**Labels**: `new_feature`, `planned_before_release`


#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-05-17 00:21](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/138):

This is based on a grsecurity 6.6 patch

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-05-17 00:21](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/138#issuecomment-2116417004):

It might be nice to alphabetically sort the options at some point.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-08-19 15:15](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/138#issuecomment-2296827406):

@jvoisin, thanks for your work.
I've finished it and merged the branch.


-------------------------------------------------------------------------------

# [\#137 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/137) `closed`: Add Google's kernelctf attack surface reduction
**Labels**: `idea_for_the_future`


#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-05-16 23:57](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/137):



#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-06-09 08:50](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/137#issuecomment-2156397087):

Hi @jvoisin, 

Thanks for the idea!

Does disabling `CONFIG_NF_TABLES` break anything vital for general-purpose GNU/Linux distros?

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-06-09 13:14](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/137#issuecomment-2156602761):

If they're using nftables, yes :o)
Otherwise, if the *old* iptables interface is used, nothing should break, no.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-03 15:17](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/137#issuecomment-2206511977):

Ok, let's save it as an idea for the future.

I have an idea: to add a column `|with care|` for dangerous options that may break something or introduce significant performance impact.


-------------------------------------------------------------------------------

# [\#136 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/136) `merged`: CI: Add pylint

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2024-05-14 13:18](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/136):






-------------------------------------------------------------------------------

# [\#135 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/135) `closed`: Put two x86-related checks behind an arch check

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-05-12 15:24](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/135):






-------------------------------------------------------------------------------

# [\#134 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/134) `merged`: Add a check to `_open`

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-05-12 15:00](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/134):

This shall transform ugly stacktraces into aesthetically pleasant error messages.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-06-02 17:38](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/134#issuecomment-2143960990):

Hello @jvoisin,
Thanks for the pull request.
I've finished the implementation:
 - merged the recent `master` into this branch,
 - added similar checks for the `cmdline` and `sysctl` files,
 - added the check that the `cmdline` file is not empty,
 - added the corresponding CI tests (to avoid loosing the test coverage).
 
Merged!


-------------------------------------------------------------------------------

# [\#133 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/133) `closed`: Which Python versions should `kernel-hardening-checker` support?
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2024-05-12 12:30](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/133):

The CI scripts of `kernel-hardening-checker` run on Python versions that are currently officially supported:
![CI](https://github.com/a13xp0p0v/kernel-hardening-checker/assets/1419667/4a628a03-f5ab-4aaf-9e14-0a75680616fa)
![Python versions](https://github.com/a13xp0p0v/kernel-hardening-checker/assets/1419667/66c799ce-ed19-4d68-90e8-636d686d4b89)
(from https://devguide.python.org/versions/)

**Question**
Should `kernel-hardening-checker` also work on some older Python versions?
Is it needed on old machines?
What do you think?



#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-05-12 14:03](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/133#issuecomment-2106257563):

I don't think that kernel-hardening-checker depends on ultra-modern python features, so supporting old-ish-but-still-maintained python version shouldn't add any overhead.

#### <img src="https://avatars.githubusercontent.com/u/10352354?u=97ab0d446ea4204b959ae74734f8436c78de18e7&v=4" width="50">[egberts](https://github.com/egberts) commented at [2024-07-05 00:19](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/133#issuecomment-2209661494):

`os.path` is going away soon.  `pathlib.Path` is the new "path"

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-07-05 14:32](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/133#issuecomment-2210986094):

`os.path` isn't going anywhere soon, according to the [documentation](https://docs.python.org/3/library/os.path.html)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-28 19:04](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/133#issuecomment-2254612721):

`from __future__ import annotations` is supported since Python 3.7.
It is used in `./kernel_hardening_checker/engine.py`.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-28 19:12](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/133#issuecomment-2254616562):

Assignment expression or "walrus operator” `NAME := expr` has been supported since Python 3.8.
It is used in `./kernel_hardening_checker/__init__.py`.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-09-04 12:55](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/133#issuecomment-2328948921):

Closing this question for now.
Supporting Python starting from v3.8 looks reasonable.


-------------------------------------------------------------------------------

# [\#132 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/132) `closed`: Add CONFIG_AMD_MEM_ENCRYPT
**Labels**: `idea_for_the_future`


#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-05-03 13:54](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/132):

Encrypted RAM is a security mechanism, if only against forensic.




-------------------------------------------------------------------------------

# [\#131 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/131) `merged`: Add a check for CONFIG_UNWIND_PATCH_PAC_INTO_SCS

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-05-03 13:44](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/131):

It allows to fallback to a shadow call stack on aarch64 if PAC isn't supported.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-06-09 20:57](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/131#issuecomment-2156786298):

@jvoisin, thanks!
Merged!


-------------------------------------------------------------------------------

# [\#130 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/130) `closed`: Add a --autodetect option
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-04-30 14:42](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/130):

Instead of having to specify Kconfig file and /proc/cmdline, --autodetect will try to infer them.

This is related to #129

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-03 16:59](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/130#issuecomment-2206800334):

It's a big nice feature that needs careful testing.
Let's return to this work after releasing a fresh version of kernel-hardening-checker.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-09-15 19:20](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/130#issuecomment-2351755200):

Hello @jvoisin,
The new version of the tool is released.
Would you like to restart this feature?
Thank you very much!

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-09-16 12:28](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/130#issuecomment-2352778966):

The red CI is unrelated to this PR

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-10-06 23:21](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/130#issuecomment-2395626954):

Hello @jvoisin,

I've made some code refactoring to make your work easier (and the patch smaller):
https://github.com/a13xp0p0v/kernel-hardening-checker/commit/ae0e9b61a00b00b5157c1fc2781c5c4f3f6b3aab
https://github.com/a13xp0p0v/kernel-hardening-checker/commit/c577892112b1692ea53d251268d18217a18bf8a8
https://github.com/a13xp0p0v/kernel-hardening-checker/commit/0155202dbbacf5dab5002ef2a220bc58ae184172
https://github.com/a13xp0p0v/kernel-hardening-checker/commit/d6533504ff61a92145640c73f0d3c4a611330319
https://github.com/a13xp0p0v/kernel-hardening-checker/commit/df50315e63cdf13bfe111f74a81d124f291a7349
https://github.com/a13xp0p0v/kernel-hardening-checker/commit/b882a2b6c72b711159a73cc1bba82d1da6bc19c8

Please rebase onto the fresh `master`. You can use the new `perform_checking()` function.

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-10-08 20:33](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/130#issuecomment-2400769252):

Superseded by #163


-------------------------------------------------------------------------------

# [\#129 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/129) `closed`: Improve --kernel-version and --cmdline 
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-04-30 14:20](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/129):

```console
$ python3 ./bin/kernel-hardening-checker -h
usage: kernel-hardening-checker [-h] [--version] [-m {verbose,json,show_ok,show_fail}] [-c CONFIG] [-l CMDLINE] [-s SYSCTL] [-v KERNEL_VERSION] [-p {X86_64,X86_32,ARM64,ARM}] [-g {X86_64,X86_32,ARM64,ARM}]

A tool for checking the security hardening options of the Linux kernel

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -m {verbose,json,show_ok,show_fail}, --mode {verbose,json,show_ok,show_fail}
                        choose the report mode
  -c CONFIG, --config CONFIG
                        check the security hardening options in the kernel Kconfig file (also supports *.gz files)
  -l CMDLINE, --cmdline CMDLINE
                        check the security hardening options in the kernel cmdline file (contents of /proc/cmdline)
  -s SYSCTL, --sysctl SYSCTL
                        check the security hardening options in the sysctl output file (`sudo sysctl -a > file`)
  -v KERNEL_VERSION, --kernel-version KERNEL_VERSION
                        extract the version from the kernel version file (contents of /proc/version)
  -p {X86_64,X86_32,ARM64,ARM}, --print {X86_64,X86_32,ARM64,ARM}
                        print the security hardening recommendations for the selected microarchitecture
  -g {X86_64,X86_32,ARM64,ARM}, --generate {X86_64,X86_32,ARM64,ARM}
                        generate a Kconfig fragment with the security hardening options for the selected microarchitecture
$
```

It would be nice to have `--cmdline` and `--kernel-version` use default values when not provided with one.

```console
$  # current behaviour
$ python3 ./bin/kernel-hardening-checker -c /boot/config-* --kernel-version 
usage: kernel-hardening-checker [-h] [--version] [-m {verbose,json,show_ok,show_fail}] [-c CONFIG] [-l CMDLINE] [-s SYSCTL] [-v KERNEL_VERSION] [-p {X86_64,X86_32,ARM64,ARM}] [-g {X86_64,X86_32,ARM64,ARM}]
kernel-hardening-checker: error: argument -v/--kernel-version: expected one argument
$  # desired behaviour
$ python3 ./bin/kernel-hardening-checker -c /boot/config-6.6.3-414.asahi.fc39.aarch64+16k --kernel-version
[+] Kconfig file to check: /boot/config-6.6.3-414.asahi.fc39.aarch64+16k
[+] Detected microarchitecture: ARM64
[+] Detected kernel version: (6, 6, 3) from /proc/version
[+] Detected compiler: GCC 130201
$ # heck, detecting the current kernel and config would be even better:
$ python3 ./bin/kernel-hardening-checker --autodetect
[+] Detected kernel version: (6, 6, 3) from /proc/version
[+] Detected microarchitecture: ARM64
[+] Found corresponding Kconfig file to check: /boot/config-6.6.3-414.asahi.fc39.aarch64+16k
[+] Detected compiler: GCC 130201
```

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-06-02 21:07](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/129#issuecomment-2144021266):

Hi @jvoisin,

I like this idea.

I see 2 additional features for `--autodetect`:
 - Try using `/proc/config.gz` before searching in `/boot/`.
 - Also check the current sysctl state.

What do you think?

Thank you!

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-06-06 15:41](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/129#issuecomment-2152845045):

Yup, those were on my todo-list (I should have mentioned it here tbh), but I wanted to see if you'd be interested in this before adding them.

I think I'd make sense to get this one merged, and then pile features on top of it :)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-06-09 06:48](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/129#issuecomment-2156353061):

Hi @jvoisin,

The `--autodetect` mode is incompatible with others and requires something like this:
```
assert(args.config is None and
       args.cmdline is None and
       args.sysctl is None and
       args.print is None and
       args.generate is None), \
       'unexpected args'
```

So I think the `--autodetect` mode checking kconfig, cmdline, and sysctls should be implemented in separate `if` block, similarly to `if args.print` and `if args.generate` in the current code.

I would propose reimplementing it in the current PR and get the final `--autodetect` argument behavior before merging.

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-06-09 14:34](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/129#issuecomment-2156633455):

Done in #130.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-11-16 15:38](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/129#issuecomment-2480620233):

Done! Closing.


-------------------------------------------------------------------------------

# [\#128 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/128) `closed`: Add an add_x86_only_kconfig_checks and an add_arm_only_kconfig_checks function
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-04-30 13:55](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/128):

Splitting the checks by arch family makes the code a tad more readable and self-contains, and makes it easier to inspect what checks are architecture-specific, instead of having the read the whole file.

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-05-03 12:52](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/128#issuecomment-2092958026):

Is this something you're interested in @a13xp0p0v? Otherwise, I won't spend time resolving conflicts :)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-06-09 10:36](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/128#issuecomment-2156435483):

Hello @jvoisin,

This branch breaks the current order of the checks.

Let me describe the rationale, maybe we will create a better solution.

First, all checks in `config_checklist` are ordered by `type`:
1. kconfig checks
2. cmdline checks
3. sysctl checks

In each `type`, the checks are ordered by `reason`:
1. self_protection
2. security_policy
3. cut_attack_surface 
4. harden_userspace

In each `reason`, the checks are ordered by `decision` **starting from the most credible**:
1. defconfig
2. kspp
3. grsec
4. maintainer
5. clipos
6. lockdown
7. a13xp0p0v

This ordering of the checks in `kernel_hardening_checker/checks.py` makes maintaining them much easier.

We also discussed this with @asarubbo in #113.

Does it sound reasonable?
Do you see how to improve the sorting of the checks?

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-06-09 13:40](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/128#issuecomment-2156611214):

I think it depends what we want to optimize for, code-wise: do we think it's easier to group checks by reason, or by architecture. I think the latter is more desirable, grouping by reason also makes sense.

What would be nice would be to actually group the checks, either in `add_arm_only_kconfig_checks`/`add_x86_only_kconfig_checks`/…, or in `add_defconfig_kconfig_checks`/`add_kssp_kconfig_checks`/… to make the grouping explicit and reduce the length of `add_kconfig_checks`. Happy to send a pull-request if you agree :)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-06-10 13:56](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/128#issuecomment-2158448230):

Thanks @jvoisin!

Explicit grouping by `type` + `reason` is a good idea.

We will return to this work when I update the checks according to the recent KSPP changes (https://github.com/a13xp0p0v/kernel-hardening-checker/commit/b22708589a1f4138db2fbb192cd28b00d046cdaa, thanks to Kees for the collaboration).

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-06-10 13:59](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/128#issuecomment-2158456145):

By the way, I guess this refactoring will allow to do easy alphabetical sorting inside each group.

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-06-10 14:02](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/128#issuecomment-2158463774):

> By the way, I guess this refactoring will allow to do easy alphabetical sorting inside each group.

That's the plan :>

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-03 16:54](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/128#issuecomment-2206793698):

It's a big and important refactoring.
Let's return to this work after releasing a fresh version of `kernel-hardening-checker`.


-------------------------------------------------------------------------------

# [\#127 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/127) `closed`: Handle the CPU side-channels 6.9 renaming

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-04-30 13:12](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/127):

Some mitigations are missing and should be added, but this should/will be done in another commit.

This should close #117

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-06-02 13:13](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/127#issuecomment-2143849449):

Implemented in:
https://github.com/a13xp0p0v/kernel-hardening-checker/commit/9d1c4cf0068065842f838125245ead146bf247b6
https://github.com/a13xp0p0v/kernel-hardening-checker/commit/86b67f39d3846fddb4419689c0e2d3ff35876cc5
https://github.com/a13xp0p0v/kernel-hardening-checker/commit/78f559541028faaa02884f0fd9cc955fbbf4ca47

Closing.
Thanks!


-------------------------------------------------------------------------------

# [\#126 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/126) `closed`: Disable codecov upload for pull-requests
**Labels**: `bug/fix`


#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-04-30 13:09](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/126):

It makes the CI unhappy:

```
==> Uploader SHASUM verified (e70beb7c9e3d894678e7d4d0fcb94e59133212dbda5ca7406b625a0167ce4ca8  codecov)
==> Running version v0.5.2
==> Running git config --global --add safe.directory /home/runner/work/kernel-hardening-checker/kernel-hardening-checker
/usr/bin/git config --global --add safe.directory /home/runner/work/kernel-hardening-checker/kernel-hardening-checker
==> Running command '/home/runner/work/_actions/codecov/codecov-action/v4/dist/codecov -v create-commit'
/home/runner/work/_actions/codecov/codecov-action/v4/dist/codecov -v create-commit --git-service github -C 616d9f017fb5c87f466b6766e15a497308770b02 -Z
info - 2024-04-30 13:02:31,335 -- ci service found: github-actions
debug - 2024-04-30 13:02:31,338 -- versioning system found: <class 'codecov_cli.helpers.versioning_systems.GitVersioningSystem'>
debug - 2024-04-30 13:02:31,340 -- versioning system found: <class 'codecov_cli.helpers.versioning_systems.GitVersioningSystem'>
warning - 2024-04-30 13:02:31,343 -- No config file could be found. Ignoring config.
debug - 2024-04-30 13:02:31,343 -- No codecov_yaml found
debug - 2024-04-30 13:02:31,343 -- Starting create commit process --- {"commit_sha": "616d9f017fb5c87f466b6766e15a497308770b02", "parent_sha": null, "pr": "121", "branch": "typing", "slug": "a13xp0p0v/kernel-hardening-checker", "token": null, "service": "github", "enterprise_url": null}
info - 2024-04-30 13:02:31,725 -- The PR is happening in a forked repo. Using tokenless upload.
info - 2024-04-30 13:02:33,996 -- Process Commit creating complete
debug - 2024-04-30 13:02:33,996 -- Commit creating result --- {"result": "RequestResult(error=RequestError(code='HTTP Error 500', params={}, description='{\"error\": \"Server Error (500)\"}'), warnings=[], status_code=500, text='{\"error\": \"Server Error (500)\"}')"}
error - 2024-04-30 13:02:33,996 -- Commit creating failed: {"error": "Server Error (500)"}
```

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-05-02 14:07](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/126#issuecomment-2090590112):

Yes, tired of various `codecov` failures, just like everyone else :)

Currently, `codecov` version 4 requires a secret token for uploading the coverage reports.
That's why the pull requests from forked repositories can't use `codecov` and CI fails.

As a compromise, I've created two separate GitHub Actions without coverage control:
https://github.com/a13xp0p0v/kernel-hardening-checker/actions/workflows/engine_unit-test_no-coverage.yml
https://github.com/a13xp0p0v/kernel-hardening-checker/actions/workflows/functional_test_no-coverage.yml
These should work for each pull request.

But the original actions with the coverage control will fail anyway. 

What do you think about that?

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-05-02 15:12](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/126#issuecomment-2090777163):

Another way would be simply have a [condition](https://docs.github.com/en/actions/using-jobs/using-conditions-to-control-job-execution) in the codecov job, to prevent it from running in pull-requests,

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-05-03 11:44](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/126#issuecomment-2092837916):

Cool, thanks!
I've added such a condition.

Could you please rebase any pull request?
We should see only no-codecov tests working.

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-05-03 12:59](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/126#issuecomment-2092968369):

It's working \o/

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-05-03 22:54](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/126#issuecomment-2093861525):

Nice, thanks, Julien!

By the way, excuse me for not-so-fast handling of issues and pull requests.
I'm working on this project in my spare time (however very regularly).

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-05-06 13:40](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/126#issuecomment-2096047092):

> By the way, excuse me for not-so-fast handling of issues and pull requests.
I'm working on this project in my spare time (however very regularly).

No need to apologise :)


-------------------------------------------------------------------------------

# [\#125 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/125) `merged`: Don't fail some sysctl checks if a config option already takes care of it

#### <img src="https://avatars.githubusercontent.com/u/35331380?u=72faa041753d4499058882bd8da1efb708e555d7&v=4" width="50">[cotequeiroz](https://github.com/cotequeiroz) opened issue at [2024-04-23 20:29](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/125):

Don't fail some sysctl checks if a config option already takes care of it
If called with both a kernel config file and a sysctl file, we can check the former to skip some sysctl checks that are not present because a config option has disabled it.

While at it, let `dev.tty.legacy_tiocsti` not be a failure if not found.  It was added in linux-6.2, so earlier versions will not have it.  Its absence alone is a soft indication that it can't be set.

It could be argued that any of the sysctl checks can be skipped if not found, but I still left the config checks in place, as an extra safeguard.

Switch the symbol used to check a root-generated sysctl file from `net.core.bpf_jit_harden` to `kernel.cad_pid` as the former is not present if JIT is disabled.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-04-30 18:11](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/125#issuecomment-2086363630):

Hi, @cotequeiroz,
Thanks a lot for your pull request!
Let's discuss some details.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-05-02 09:52](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/125#issuecomment-2090054224):

I've also rebased this branch.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-05-02 12:26](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/125#issuecomment-2090373742):

@cotequeiroz, the branch is merged.

Thanks for the collaboration!

Please see the final changes and comment if you have any questions or arguments.


-------------------------------------------------------------------------------

# [\#124 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/124) `closed`: Skip clang specific tests when using gcc

#### <img src="https://avatars.githubusercontent.com/u/35331380?u=72faa041753d4499058882bd8da1efb708e555d7&v=4" width="50">[cotequeiroz](https://github.com/cotequeiroz) opened issue at [2024-04-23 20:29](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/124):

`CFI_CLANG` and `CFI_PERMISSIVE` will never be present when compiling with gcc.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-05-02 10:15](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/124#issuecomment-2090097562):

@cotequeiroz, please feel free to reopen the pull request, if you have arguments on this.
Thanks again!


-------------------------------------------------------------------------------

# [\#123 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/123) `merged`: Skip CPU-dependent checks if CPU is not supported

#### <img src="https://avatars.githubusercontent.com/u/35331380?u=72faa041753d4499058882bd8da1efb708e555d7&v=4" width="50">[cotequeiroz](https://github.com/cotequeiroz) opened issue at [2024-04-23 20:29](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/123):

This checks `CPU_SUP_INTEL` symbols not set to skip Intel-only symbols:
  - `X86_MCE_INTEL`
  - `MICROCODE_INTEL`
  - `X86_INTEL_TSX_MODE_OFF`
  - `tsx` command line option

Conversely, `CPU_SUP_AMD` not set avoids:
 - `MICROCODE_AMD`
 - `CPU_SRSO`




-------------------------------------------------------------------------------

# [\#122 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/122) `closed`: Disable `CONFIG_N_GSM`
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/6131885?v=4" width="50">[cgzones](https://github.com/cgzones) opened issue at [2024-04-18 15:19](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/122):

For attack surface reduction one might want to disable `CONFIG_N_GSM`.
See also: https://www.openwall.com/lists/oss-security/2024/04/17/1

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-04-20 22:36](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/122#issuecomment-2067805077):

Hi @cgzones.
Thanks for the info.
It looks like the existing recommendation `sysctl dev.tty.ldisc_autoload = 0` solves this, doesn't it?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-07 13:52](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/122#issuecomment-2212458641):

Yes,  `sysctl dev.tty.ldisc_autoload = 0` is another solution.
But I added the `CONFIG_N_GSM` check anyway.
Thanks.


-------------------------------------------------------------------------------

# [\#121 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/121) `merged`: Add some lightweight typing
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-04-15 12:53](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/121):

This is a first quick pass over the codebase. If having better typing is something desirable, I'll do another more comprehensive one.

Having typing makes it easier to understand what's going on in the code, eg. "this function called `colorize_result` it taking either a `str` or `None`, and is returning either a `str` or `None`, so odds are that it's handling error conditions properly." It also makes the life of IDE/static analyzers/… easier.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-04-17 18:02](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/121#issuecomment-2061903203):

Hi @jvoisin, 
Thanks for the pull request! I like the idea.
There is a CI error, could you have a look, please?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-04-17 18:07](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/121#issuecomment-2061911998):

> Hi @jvoisin, Thanks for the pull request! I like the idea. There is a CI error, could you have a look, please?

I mean this error:
```
Traceback (most recent call last):
  File "bin/kernel-hardening-checker", line 13, in <module>
    import kernel_hardening_checker
  File "/home/runner/work/kernel-hardening-checker/kernel-hardening-checker/kernel_hardening_checker/__init__.py", line 32, in <module>
    def detect_arch(fname: str, archs: list[str]) -> tuple:
TypeError: 'type' object is not subscriptable
Error: Process completed with exit code 1.
```

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-04-30 12:56](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/121#issuecomment-2085255768):

The error is because I didn't realise Python ≤3.9 was supported

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-05-12 12:32](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/121#issuecomment-2106231646):

@jvoisin, thanks!
 
The CI scripts of `kernel-hardening-checker` run on Python versions that are currently officially supported.
Should `kernel-hardening-checker` also support some older Python versions?

I've added a separate issue for this discussion: https://github.com/a13xp0p0v/kernel-hardening-checker/issues/133

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-05-13 17:34](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/121#issuecomment-2108366345):

Hi @jvoisin,

Thank you for starting this work!

In this branch, I added the detailed static typing, which is checked with the `mypy` tool in CI.

Would you like to have a look and do a brief review?

I separated the commits that:
 - add typing,
 - fix mypy warnings,
 - do refactoring,
 - improve CI.
 
There should be no functional changes in this branch.
The `kernel-hardening-checker` output should be the same before these changes and after them.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-05-13 17:39](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/121#issuecomment-2108387839):

By the way, I just learned that `mypy` has the `--strict` mode and can generate the html report with coverage.

Do we need this, how do you think?

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-05-13 20:51](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/121#issuecomment-2108778214):

Wow, you really went all-in!

- I'm not sure it's worth duplicating the type checking step in several jobs. In fact, having it into its own job would make sense, so that it could be parallelized with the others.
- `-> None` is implicit, but I guess having it explicitly doesn't hurt.
- I don't think we really care about coverage: I added the typing annotations as always-up-to-date-comments, so that it's more clean what every function is doing/expecting. Reaching 100% typing information coverage will likely add way to many useless bloat.

Otherwise, LGTM :)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-05-13 23:45](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/121#issuecomment-2109008338):

> Wow, you really went all-in!
> 
> * I'm not sure it's worth duplicating the type checking step in several jobs. In fact, having it into its own job would make sense, so that it could be parallelized with the others.

Agree, fixed in https://github.com/a13xp0p0v/kernel-hardening-checker/pull/121/commits/dda21ff0d50bbe01acf7305946124e5d13d1bb3b

> * `-> None` is implicit, but I guess having it explicitly doesn't hurt.
> * I don't think we really care about coverage: I added the typing annotations as always-up-to-date-comments, so that it's more clean what every function is doing/expecting. Reaching 100% typing information coverage will likely add way to many useless bloat.
> 
> Otherwise, LGTM :)

Cool, thanks!


-------------------------------------------------------------------------------

# [\#120 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/120) `merged`: Add a check for X86_USER_SHADOW_STACK

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2024-04-15 12:06](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/120):

This should close #114

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-04-17 16:14](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/120#issuecomment-2061687030):

Hey @jvoisin,
Thanks for the pull request!
As I see, `X86_USER_SHADOW_STACK` is not enabled by `defconfig`. I'll fix the `decision` field and push to your branch.


-------------------------------------------------------------------------------

# [\#119 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/119) `closed`: Integration with oracle/kconfigs
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/150761?u=f98bb82be5009ecefd6ee9bc3d60fcf082f8cf49&v=4" width="50">[evdenis](https://github.com/evdenis) opened issue at [2024-03-29 10:32](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/119):

There is a collection of kconfigs which are automatically updated in https://github.com/oracle/kconfigs/tree/main/out
It looks possible to do the integration with the project instead to tracking distro configs in this project.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-03-29 10:44](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/119#issuecomment-2027058765):

@evdenis, thank you!

We can use these kconfig files in CI to check `kernel-hardening-checker` and reorganize the [kernel_hardening_checker/config_files](https://github.com/a13xp0p0v/kernel-hardening-checker/tree/master/kernel_hardening_checker/config_files) directory.

#### <img src="https://avatars.githubusercontent.com/u/150761?u=f98bb82be5009ecefd6ee9bc3d60fcf082f8cf49&v=4" width="50">[evdenis](https://github.com/evdenis) commented at [2024-05-02 10:16](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/119#issuecomment-2090098802):

https://blogs.oracle.com/linux/post/explore-linux-kernel-kconfigs

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-11-23 20:20](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/119#issuecomment-2495643779):

Closing as done!


-------------------------------------------------------------------------------

# [\#118 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/118) `closed`: The separation between desktop and server.
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/163189276?v=4" width="50">[migrgh](https://github.com/migrgh) opened issue at [2024-03-16 00:51](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/118):

Hello,

i would like to discuss the idea of implementing a separation between server and desktop.
There is separation between arch and show output.

- -m {verbose,json,show_ok,show_fail}, --mode {verbose,json,show_ok,show_fail}
- -p {X86_64,X86_32,ARM64,ARM}, --print {X86_64,X86_32,ARM64,ARM}

I have found the following obvious config that prevent booting a desktop.

- CONFIG_FB
- CONFIG_VT 
- CONFIG_KCMP # Selected by [y]: DRM [=y]

There are of course a few more, but they are not necessary for booting.
CONFIG_USE_NS # firefox / unprivileged container like systemd-nspawn

#### <img src="https://avatars.githubusercontent.com/u/158655396?v=4" width="50">[wryMitts](https://github.com/wryMitts) commented at [2024-03-16 23:55](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/118#issuecomment-2002192365):

Another distinction is virtual machine desktop and virtual machine server.

A server still needs CONFIG_FB to show boot display if something goes wrong in initrd, etc. Virtual machine server with serial does not. Certain cloud servers available for sale online have both serial and video options available, some none at all (SSH only). So this is a very usecase specific item.  

This may be harder to add because many hypervisors such as Xen, KVM, Virtualbox, might require different kernel options enabled to function as expected.

#### <img src="https://avatars.githubusercontent.com/u/163189276?v=4" width="50">[migrgh](https://github.com/migrgh) commented at [2024-03-18 01:02](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/118#issuecomment-2002700145):

current situation of automatic merging the Kconfig fragment you have to manual go over options like CONFIG_FB if in need.

or have a profile which work using automatic merging of the Kconfig fragment.

but yes it's very use case specific how a profile should look like.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-03-24 13:22](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/118#issuecomment-2016808731):

Hello @migrgh and @wryMitts,

Thanks for creating this issue. It is connected to the issue #50.

CC @petervanvugt, @egberts.

Please have a look and give your ideas.

What do you think about a mechanism allowing the `kernel-hardening-checker` users to create new custom checks and redefine the existing rules?

For example, `kernel-hardening-checker` may have a new `-r` argument for specifying a file with rule changes from the user.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-09-04 12:50](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/118#issuecomment-2328933111):

Closing this issue for now.
The feature will be implemented in #50.


-------------------------------------------------------------------------------

# [\#117 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/117) `closed`: Linux 6.9 Renames Many CPU Mitigation CONFIGs to CONFIG_MITIGATION_...
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/158655396?v=4" width="50">[wryMitts](https://github.com/wryMitts) opened issue at [2024-03-14 12:56](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/117):

Hello,

Looks like big change for naming schemes

Merged by Torvalds for 6.9

Many options will be renamed, for example:
```
x86/bugs: Rename CONFIG_RETHUNK              => CONFIG_MITIGATION_RETHUNK
  x86/bugs: Rename CONFIG_CPU_SRSO             => CONFIG_MITIGATION_SRSO
  x86/bugs: Rename CONFIG_CPU_IBRS_ENTRY       => CONFIG_MITIGATION_IBRS_ENTRY
  x86/bugs: Rename CONFIG_CPU_UNRET_ENTRY      => CONFIG_MITIGATION_UNRET_ENTRY
  x86/bugs: Rename CONFIG_SLS                  => CONFIG_MITIGATION_SLS
```
And several more in this commit below

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=685d98211273f60e38a6d361b62d7016c545297e

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-06-02 13:14](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/117#issuecomment-2143849819):

Implemented in:
https://github.com/a13xp0p0v/kernel-hardening-checker/commit/9d1c4cf0068065842f838125245ead146bf247b6
https://github.com/a13xp0p0v/kernel-hardening-checker/commit/86b67f39d3846fddb4419689c0e2d3ff35876cc5
https://github.com/a13xp0p0v/kernel-hardening-checker/commit/78f559541028faaa02884f0fd9cc955fbbf4ca47

Closing.
Thanks!


-------------------------------------------------------------------------------

# [\#116 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/116) `closed`: Add check for CONFIG_MITIGATION_RFDS
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/158655396?v=4" width="50">[wryMitts](https://github.com/wryMitts) opened issue at [2024-03-14 12:38](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/116):

Hello, please consider these new options


Intel's hardware vulnurability for Atom cores; Register File Data Sampling. 

https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00898.html

Merged by Torvalds

Kconfig
```
+config MITIGATION_RFDS
+	bool "RFDS Mitigation"
+	depends on CPU_SUP_INTEL
+	default y
+	help
+	  Enable mitigation for Register File Data Sampling (RFDS) by default.
+	  RFDS is a hardware vulnerability which affects Intel Atom CPUs. It
+	  allows unprivileged speculative access to stale data previously
+	  stored in floating point, vector and integer registers.
+	  See also <file:Documentation/admin-guide/hw-vuln/reg-file-data-sampling.rst>
+
```
Boot flags:

```
+	reg_file_data_sampling=
+			[X86] Controls mitigation for Register File Data
+			Sampling (RFDS) vulnerability. RFDS is a CPU
+			vulnerability which may allow userspace to infer
+			kernel data values previously stored in floating point
+			registers, vector registers, or integer registers.
+			RFDS only affects Intel Atom processors.
+
+			on:	Turns ON the mitigation.
+			off:	Turns OFF the mitigation.
+
+			This parameter overrides the compile time default set
+			by CONFIG_MITIGATION_RFDS. Mitigation cannot be
+			disabled when other VERW based mitigations (like MDS)
+			are enabled. In order to disable RFDS mitigation all
+			VERW based mitigations need to be disabled.
+
+			For details see:
+			Documentation/admin-guide/hw-vuln/reg-file-data-sampling.rst
+
```
Selected automatically by boot command `mitigations=auto` per this line: https://github.com/torvalds/linux/blob/master/arch/x86/kernel/cpu/bugs.c#L504

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=0e33cf955f07e3991e45109cb3e29fbc9ca51d06

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-06-02 15:02](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/116#issuecomment-2143890934):

Implemented in https://github.com/a13xp0p0v/kernel-hardening-checker/commit/da9b9115004ada8fa1f10860a973d2147c968b7c

Done, closing.

Thanks!


-------------------------------------------------------------------------------

# [\#115 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/115) `merged`: Improve JSON output format for enhanced processing

#### <img src="https://avatars.githubusercontent.com/u/75043245?u=158cd63a4ea78542e040508eaecc580f03cd2b98&v=4" width="50">[krishjainx](https://github.com/krishjainx) opened issue at [2024-03-14 09:23](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/115):

This pull request enhances the JSON output format, introducing a more structured and informative JSON schema. The changes include:

- Addition of a boolean `check_result` field to clearly indicate the success or failure of each check.
- Refinement of the output to an array of objects, where each object represents a check with detailed attributes such as:
  - `option_name`: The name of the option being checked.
  - `type`: The type of check performed (kconfig or cmdline).
  - `desired_val`: The expected or desired value for the check.
  - `decision`: The source for the decision (eg. grsec, clipos, defconfig).
  - `reason`: A brief explanation for the decision.
  - `check_result_text`: A human-readable description of the check result.
  - `check_result`: A boolean indicating the success or failure of the check.

- Ensures compatibility with JSON processing tools like `jq`, facilitating easier integration with automated scripts and tools.

The updated format provides a clearer, more actionable output for users and developers, streamlining the process of analyzing and acting upon the check results.

Resolves: #108 

#### <img src="https://avatars.githubusercontent.com/u/75043245?u=158cd63a4ea78542e040508eaecc580f03cd2b98&v=4" width="50">[krishjainx](https://github.com/krishjainx) commented at [2024-03-14 09:35](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/115#issuecomment-1997024947):

The tests need to be modified in https://github.com/a13xp0p0v/kernel-hardening-checker/blob/master/kernel_hardening_checker/test_engine.py to work with this improved JSON schema. But am I on the right track?  @a13xp0p0v

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-03-16 22:03](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/115#issuecomment-2002152834):

Hello @krishjainx, thanks a lot for your pull request!
Please see my comments.

#### <img src="https://avatars.githubusercontent.com/u/75043245?u=158cd63a4ea78542e040508eaecc580f03cd2b98&v=4" width="50">[krishjainx](https://github.com/krishjainx) commented at [2024-03-17 07:25](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/115#issuecomment-2002344196):

Good now? @a13xp0p0v

#### <img src="https://avatars.githubusercontent.com/u/75043245?u=158cd63a4ea78542e040508eaecc580f03cd2b98&v=4" width="50">[krishjainx](https://github.com/krishjainx) commented at [2024-03-17 21:43](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/115#issuecomment-2002627298):

Done @a13xp0p0v


-------------------------------------------------------------------------------

# [\#114 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/114) `closed`: Add kconfig option for Intel CET shadow stack
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/107318481?u=7423ac118deca5f7f745e28ac2e3f6a487465973&v=4" width="50">[winterknife](https://github.com/winterknife) opened issue at [2024-03-12 21:48](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/114):

Consider adding `CONFIG_X86_USER_SHADOW_STACK` kconfig option to enable support for userspace shadow stack on capable hardware. This is in addition to the kconfig option for enabling kernel IBT that's already implemented. This feature should be present on all 64-bit x86 CPUs since Intel TGL.

More information: https://docs.kernel.org/arch/x86/shstk.html




-------------------------------------------------------------------------------

# [\#113 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/113) `closed`: Suggestions for kernel-hardening-checker
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/4741819?v=4" width="50">[asarubbo](https://github.com/asarubbo) opened issue at [2024-03-07 09:08](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/113):

Hello @a13xp0p0v 

I have two suggestions for [kernel-hardening-checker](https://github.com/a13xp0p0v/kernel-hardening-checker)

1) It's a matter of fact that enable all suggested security features impact on perfomance and I have verified this by myself, e.g. a 64 threads modern server takes 10 more minutes to compile chromium.
Would be great have a column that gives a rank (from 1-10) maybe about how much a CONFIG_* impacts on performance.
To give an idea about what I'm talking, with a general example with C and stack protection:
`FORTIFY_SOURCE` has impact of 1;
`-fstack-protector-strong` has an impact of 5;
`-fstack-protector-all` has an impact of 8;

Rank number can be on your judge with will give the idea to the user.

2) I noticed that the option do not follow the order from menuconfig. For example for enable the first suggestion from [kernel-hardening-checker](https://github.com/a13xp0p0v/kernel-hardening-checker) I need to go in a section of the kernel, then for the second suggestion I need to go to another section, and for the third I maybe come back to the section of the first suggestion. That takes a lot of time for navigating into the menuconfig sections, while group CONFIG_* based on the menuconfig order will save a lot of time.

Thanks

#### <img src="https://avatars.githubusercontent.com/u/163189276?v=4" width="50">[migrgh](https://github.com/migrgh) commented at [2024-03-16 00:34](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/113#issuecomment-2000799564):

I had similar thoughts, the performance rating sounds sensible
but is probably difficult to implement because you always have
to ask yourself in which scenario you achieve a plus or not.
I would say that someone who uses the suggestions does not 
use them from a performance point of view but from a security 
point of view.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-03-17 14:16](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/113#issuecomment-2002487325):

Hello @asarubbo and @migrgh!

> Would be great have a column that gives a rank (from 1-10) maybe about how much a CONFIG_* impacts on performance.

@asarubbo, that's an interesting idea. Could you please describe it in the issue #66 as well?

However, creating such a rating would not be easy because some kernel security features have different performance penalty depending on the type of system workload (a number and type of system calls, for example).

Do you have an idea which particular kernel option makes your system run slow on compiling chromium?

First of all, I would recommend comparing performance of the default configuration and hardened configuration without `mitigations=auto,nosmt` and `nosmt` boot options (they may have the biggest performance penalty). I guess, in that comparison, you will not see a big difference in the chromium compilation time.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-03-17 14:18](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/113#issuecomment-2002487872):

> I noticed that the option do not follow the order from menuconfig.

@asarubbo, yes, that's true. Currently, the options are sorted by the complexity of the checking rule. It's easier for maintenance.

You have multiple options to avoid exhausting navigation in menuconfig.

- Try using search in menuconfig: press '/', enter the option name, hit enter, and then choose the number (`1`, `2`, `3`, ...) of the option that you want to see. I like it.
- Try automatic merging of the Kconfig fragment with options that you want to change. See the [example in the README](https://github.com/a13xp0p0v/kernel-hardening-checker?tab=readme-ov-file#generating-a-kconfig-fragment-with-the-security-hardening-options).

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-09-04 12:46](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/113#issuecomment-2328914367):

Closing for now.
Feel free to reopen this issue, if you have new info.
Thanks!


-------------------------------------------------------------------------------

# [\#112 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/112) `closed`: Add ia32_emulation kernel cmdline parameter to disable 32-bit emulation support on 64-bit x86 CPUs

#### <img src="https://avatars.githubusercontent.com/u/107318481?u=7423ac118deca5f7f745e28ac2e3f6a487465973&v=4" width="50">[winterknife](https://github.com/winterknife) opened issue at [2024-02-27 19:49](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/112):

Consider adding the kernel command-line parameter `ia32_emulation=0` to disable 32-bit programs support at boot-time. This is in addition to the `CONFIG_IA32_EMULATION` kconfig option that's already implemented.

More information here: https://www.phoronix.com/news/Linux-6.7-IA32-Emulation-Boot

#### <img src="https://avatars.githubusercontent.com/u/107318481?u=7423ac118deca5f7f745e28ac2e3f6a487465973&v=4" width="50">[winterknife](https://github.com/winterknife) commented at [2024-02-27 19:52](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/112#issuecomment-1967485006):

Duplicate of #87


-------------------------------------------------------------------------------

# [\#111 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/111) `closed`: Kernel Debug Metadata Access with CONFIG_DYNAMIC_DEBUG
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/158655396?v=4" width="50">[wryMitts](https://github.com/wryMitts) opened issue at [2024-02-26 21:35](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/111):

Despite restricting access to kernel logs, it seems like this kernel debug log file is accessible with permissions `644` at `/proc/dynamic_debug/control`

It is listed to be located on DebugFS, although, it can also live in ProcFS, as it is on my system without DebugFS, per docs.

I also have `kernel.dmesg_restrict = 1` too. 

Maybe this is an oversight from kernel developers? I don't know. I don't see any memory addresses in mine, they seem to be removed, but this file still should probably not be readable by all users?

https://www.kernel.org/doc/html/v4.12/admin-guide/dynamic-debug-howto.html
https://cateee.net/lkddb/web-lkddb/DYNAMIC_DEBUG.html

**EDIT: I've realized this isn't necessarily a log file but still seems to be a little revealing. Feel free to close if this is out of scope, since this is more a job for distro to secure the file rather than Kernel.**

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-03-16 22:31](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/111#issuecomment-2002162578):

Hello @wryMitts,
Thanks for creating the issue.
Unprivileged user can only read this file.
Do you see security-sensitive data in it?

#### <img src="https://avatars.githubusercontent.com/u/158655396?v=4" width="50">[wryMitts](https://github.com/wryMitts) commented at [2024-03-16 23:50](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/111#issuecomment-2002190569):

Hello @a13xp0p0v ,

After additional review, the file simply identifies some hardware information. I have updated the title to reflect. The original was in error. The user-readable sensitive security data is only on OS like Whonix, and is likely out of scope for this project. 

The file also interacts with the kernel when written to.  

It appears that if kernel debug logging is already disabled ( pr_debug()/dev_dbg(), print_hex_dump_debug()/print_hex_dump_bytes() calls not present or removed by other configs) , this file does not produce additional logs in dmesg. 

I tested with  commands such as `echo -n 'file svcsock.c line 1603 +p' > /proc/dynamic_debug/control`.

dmesg indicates that it received the query but takes no additional logging action (test by writing bad data to `/proc/dynamic_debug/control`).  My hardened config has debug data removed in this test with other config options.

Perhaps it is safe to remove as an attack surface reduction if the file has no use or purpose otherwise outside of debugging, since it still interacts with kernel code.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-03-17 06:18](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/111#issuecomment-2002327103):

Thanks for the info, @wryMitts !
For now, closing the issue.


-------------------------------------------------------------------------------

# [\#110 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/110) `closed`: Reducing Kernel Symbols on File System by Disabling CONFIG_VMLINUX_MAP and CONFIG_DEBUG_KERNEL
**Labels**: `good_first_issue`, `new_check`


#### <img src="https://avatars.githubusercontent.com/u/158655396?v=4" width="50">[wryMitts](https://github.com/wryMitts) opened issue at [2024-02-19 05:20](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/110):

CONFIG_VMLINUX_MAP generates a system.map file, which contains debugging symbols, and other information that may leak information about the kernel. It is automatically generated with the kernel, and it is delivered in Debian packages for the kernel when built with the dpkg-deb mode of the kernel build system. 

Kicksecure OS has an automatic script to delete this file when a kernel is installed.

https://forums.whonix.org/t/kernel-hardening-security-misc/7296/84
https://gitlab.tails.boum.org/tails/tails/-/issues/10951
https://en.wikipedia.org/wiki/System.map

The CONFIG_DEBUG_KERNEL option generates a similar, large debug file that can be installed along the kernel. It is not installed by default, although it is automatically created on the build system. It will cause similar damage to the a system.map file. Disabling this optional also speeds up kernel build time extensively, and reduces disk usage on the build system.
https://wiki.ubuntu.com/Debug%20Symbol%20Packages 


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-02-19 12:56](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/110#issuecomment-1952397715):

Hi @wryMitts,

Thanks for the idea.

I think shipping the debug info separately is a good compromise.
If system administrators need the kernel debug info, they can install the additional package.
Otherwise the system doesn't contain the debug info that might be useful for attackers.

So disabling CONFIG_VMLINUX_MAP and leaving CONFIG_DEBUG_KERNEL enabled provide this compromise.
Do you agree?

#### <img src="https://avatars.githubusercontent.com/u/158655396?v=4" width="50">[wryMitts](https://github.com/wryMitts) commented at [2024-02-19 19:40](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/110#issuecomment-1953069373):

Hi @a13xp0p0v 

That is a fair compromise. It may also be a good idea to also mention somewhere that the build files should not be on the same machine where kernel security is required, as build files can reveal sensitive information too. Surely some users might build their kernels on the same machine they run the kernels, which negates security.

#### <img src="https://avatars.githubusercontent.com/u/67371653?u=f5d8536b55c751c2bdb6358897d72523a01006a2&v=4" width="50">[Willenst](https://github.com/Willenst) commented at [2025-02-24 09:38](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/110#issuecomment-2677870594):

Hi colleagues @a13xp0p0v @wryMitts , I was looking for some simple kconfig for pull request and came across your talk. I think there are some misconceptions in it, and neither config needs to be implemented at all! Let me explain:

`CONFIG_VMLINUX_MAP` is not responsible for creating `system.map`, this file is always created and we can't do anything with it. It is pulled into the `/boot` folder as a readable file, which is bad, but we can't influence it with kernel configs. This behavior is hardwired into the `Makefiles`:
https://elixir.bootlin.com/linux/v6.13.3/source/arch/loongarch/Makefile#L182
https://elixir.bootlin.com/linux/v6.13.3/source/Makefile#L1144

`CONFIG_VMLINUX_MAP` is responsible for another file: `vmlinux.map`. This is described in the configure docs itself https://cateee.net/lkddb/web-lkddb/VMLINUX_MAP.html
The file itself contains potentially dangerous information, but it does not leave the kernel sources folder. I've checked by building kernels both on the machine and externally, unless you pull it out yourself, it's safe.

CONFIG_DEBUG_KERNEL affects the ability to enable other options, it does nothing by itself. Moreover, the following configs in the kernel-hardening-checker itself depend on it:
SCHED_STACK_END_CHECK
DEBUG_VIRTUAL
DEBUG_LIST
DEBUG_SG
DEBUG_NOTIFIERS
DEBUG_RODATA
So, if we don't want to break anything down, we must leave this kconfig.

By the way, aren't you confusing this kconfig with the CONFIG_DEBUG_INFO_ group? Couple of them really create sensitive information in the form of debug symbols in the kernel binary itself. Maybe we should consider creating a check for CONFIG_DEBUG_INFO_NONE=y?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-03-09 15:06](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/110#issuecomment-2708904438):

Excellent, thanks @Willenst!

As for `CONFIG_DEBUG_INFO_NONE`, I think we don't need it.

Closing this issue.


-------------------------------------------------------------------------------

# [\#109 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/109) `closed`: Add io_uring_disabled sysctl to disable/limit io_uring creation
**Labels**: `good_first_issue`, `new_check`


#### <img src="https://avatars.githubusercontent.com/u/107318481?u=7423ac118deca5f7f745e28ac2e3f6a487465973&v=4" width="50">[winterknife](https://github.com/winterknife) opened issue at [2024-02-13 04:29](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/109):

Consider disabling IO_uring access using sysctl tunable apart from the `CONFIG_IO_URING` kconfig option that's already implemented.

More information here: [https://www.phoronix.com/news/Google-Restricting-IO_uring](https://www.phoronix.com/news/Google-Restricting-IO_uring)

[https://www.phoronix.com/news/Linux-6.6-sysctl-IO_uring](https://www.phoronix.com/news/Linux-6.6-sysctl-IO_uring)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-09-04 12:41](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/109#issuecomment-2328889704):

Closing as finished.
Thanks @Willenst.


-------------------------------------------------------------------------------

# [\#108 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/108) `closed`: Better json output
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/153538?v=4" width="50">[avnik](https://github.com/avnik) opened issue at [2024-02-12 11:40](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/108):

Would be nice to improve JSON output format, like

```json
  [{
    "check": "CONFIG_DRM_LEGACY",
    "kind": "kconfig",
    "value": "is not set",
    "vendor": "maintainer",
    "group": "cut_attack_surface",
    "result_text": "OK: is not found",
    "result": true
  },
  {
    "check": "CONFIG_FB",
    "kind": "kconfig",
    "value": "is not set",
    "vendor": "maintainer",
    "group": "cut_attack_surface",
    "result_text": "FAIL: \"y\"",
    "result": false
  }],
```

This change would allow flexible process resulting json with tools like `jq` as well as with own scripts.
(one of reasons -- to have boolean field, which clearly show if check fails)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-02-19 12:39](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/108#issuecomment-1952366902):

Hello @avnik,

Nice idea!

For the field names, I would recommend using something similar to the terms from the table header:
```
=========================================================================================================================
              option name               | type  |desired val | decision |      reason      | check result
=========================================================================================================================
CONFIG_BUG                              |kconfig|     y      |defconfig | self_protection  | OK
-------------------------------------------------------------------------------------------------------------------------
``` 

Do you have some time and motivation to work on the pull request?

#### <img src="https://avatars.githubusercontent.com/u/153538?v=4" width="50">[avnik](https://github.com/avnik) commented at [2024-02-20 10:58](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/108#issuecomment-1953963510):

Sure, I have both time and motiovation (although I travelling at the moment).

My main motivation is writing tool on top of it, to assert our configs based on kernel-hardening-checker report (ignoring checks which we consider safe to ignore). Maybe later would be nice to integrate it as well, but is too early to discuss not yet written tool.

#### <img src="https://avatars.githubusercontent.com/u/75043245?u=158cd63a4ea78542e040508eaecc580f03cd2b98&v=4" width="50">[krishjainx](https://github.com/krishjainx) commented at [2024-03-14 10:24](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/108#issuecomment-1997115530):

@avnik @a13xp0p0v My pull request #115  should implement this. Please take a look

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-03-17 22:47](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/108#issuecomment-2002644297):

In addition to @krishjainx 's  work, I changed the table column names and JSON field names a bit (https://github.com/a13xp0p0v/kernel-hardening-checker/commit/9015662bb264a2aaff9913d31c8d4974ad6b945c).

Now they fit each other.

In JSON mode:
```
[
  {
    "option_name": "CONFIG_BUG",
    "type": "kconfig",
    "desired_val": "y",
    "decision": "defconfig",
    "reason": "self_protection",
    "check_result": "OK",
    "check_result_bool": true
  },
  {
    "option_name": "CONFIG_SLUB_DEBUG",
    "type": "kconfig",
    "desired_val": "y",
    "decision": "defconfig",
    "reason": "self_protection",
    "check_result": "OK",
    "check_result_bool": true
  },
...
```

In normal mode:
```
[+] Kconfig file to check: /boot/config-6.6.13-200.fc39.x86_64
[+] Detected microarchitecture: X86_64
[+] Detected kernel version: (6, 6, 13)
[+] Detected compiler: GCC 130201
=========================================================================================================================
              option_name               | type  |desired_val | decision |      reason      | check_result
=========================================================================================================================
CONFIG_BUG                              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_SLUB_DEBUG                       |kconfig|     y      |defconfig | self_protection  | OK
...
```


-------------------------------------------------------------------------------

# [\#107 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/107) `closed`: New CONFIG_MODULE_SIG_SHA3_512 option in kernel 6.7
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/3797768?v=4" width="50">[morfikov](https://github.com/morfikov) opened issue at [2024-02-07 11:28](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/107):

It looks like a [new option was introduced for module signing](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f2b88bab69c86d4dab2bfd25a0e741d7df411f7a) with the kernel 6.7 release. 

So basically we have now:

`CONFIG_MODULE_SIG_SHA512 `

and

`CONFIG_MODULE_SIG_SHA3_512`


When `CONFIG_MODULE_SIG_SHA3_512` is enabled, the `CONFIG_MODULE_SIG_SHA512` is automatically disabled because you can have only one at a time, and hence kernel-hardening-checker reports:

```
=========================================================================================================================
              option name               | type  |desired val | decision |      reason      | check result
=========================================================================================================================
..
CONFIG_MODULE_SIG_SHA512                |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
```



#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-02-19 12:27](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/107#issuecomment-1952347689):

Thanks for the idea, @morfikov,

Now it looks like that:
```
-------------------------------------------------------------------------------------------------------------------------
    <<< OR >>>                                                                             | OK: CONFIG_MODULE_SIG_SHA3_512 is "y"
CONFIG_MODULE_SIG_SHA512                |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
CONFIG_MODULE_SIG_SHA3_512              |kconfig|     y      |    my    | self_protection  | OK
CONFIG_MODULES                          |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
-------------------------------------------------------------------------------------------------------------------------

```


-------------------------------------------------------------------------------

# [\#106 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/106) `closed`: Minimal kernel version ?
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/1485263?v=4" width="50">[ffontaine](https://github.com/ffontaine) opened issue at [2024-02-06 11:53](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/106):

Hi, thanks for your great tool.
I'm wondering if there is a minimal kernel requirement for kernel-hardening-check?
Can I run it on any kernel configuration (e.g. on a kernel 4.1.x)?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-02-18 18:37](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/106#issuecomment-1951409705):

Hello @ffontaine,
Thanks for your kind words.
For sure, you can use `kernel-hardening-checker` for checking configuration of the old kernels.
Of course, some of the failing checks can't be resolved for old kernels because the recent security features haven't been backported to them.


-------------------------------------------------------------------------------

# [\#105 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/105) `closed`: add check for UNWIND_PATCH_PAC_INTO_SCS, which reduces security compared to using both PAC + SCS
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) opened issue at [2024-02-04 04:36](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/105):

The `UNWIND_PATCH_PAC_INTO_SCS` configuration option disables ShadowCallStack when PAC is supported by the hardware. it does this by removing the SCS instructions and dynamically patches PAC instructions into SCS instructions when PAC is unavailable.

PAC is a purely probabilistic security feature which can be bypassed through brute force attacks. PAC normally has 16 bits in the default configuration with 39-bit address space and 4k pages, but it drops to 7 bits with a 48-bit address space. It's even lower in some of the other configurations. SCS is a deterministic security feature, but it lacks a way to protect the shadow stack from arbitrary writes. It's difficult to say which is better, but having both enabled is clearly better for security than only PAC.

SCS has higher overhead than PAC, but it was deemed acceptable enough to deploy it on Pixels in production long before PAC was available. Going from SCS to SCS + PAC isn't a big deal. When PAC is enabled, it adds entry/exit instructions to each function and the entry function replaces the BTI instruction in non-leaf functions since it counts as the BTI instruction too. BTI is enabled by default, but Google is currently disabling it for Android in the kernel because they use the overlapping Clang CFI feature (which will be replaced by Clang's kCFI implementation).

We're choosing to enable SCS in addition to PAC for GrapheneOS because we're concerned about going from a deterministic mitigation to a probabilistic one, and SCS was deemed cheap enough before so it should still be fine on significantly better hardware. GrapheneOS is choosing to enable BTI in addition to Clang CFI because there are indirect calls excluded from Clang CFI for architectural compatibility reasons. Google also excluded certain hooks for performance reasons. We're prefer to have kCFI already deployed along with architecture support to get full coverage, but we have to use what's available. We currently enable 48-bit address space which reduces PAC from 16 bit to 7 bit, so we're having to reconsider doing that. We don't like the design of the PAC feature and would greatly prefer having 8 bit or higher MTE (instead of only 4 bits) along with a hardware shadow stack like Intel CET for deterministic return protection instead of probabilistic PAC. PAC can be used for more than protecting returns, but currently it's only used for protecting returns. There are better ways to do things than PAC and we find it unfortunate ARM went with this for performance reasons which Google is going along with too.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-02-19 13:16](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/105#issuecomment-1952431105):

Hello @thestinger,

Thanks a lot for the explanation.

As I understand you, GrapheneOS uses:
 1) CONFIG_SHADOW_CALL_STACK + CONFIG_ARM64_PTR_AUTH_KERNEL for backward-edge CFI,
 2) CONFIG_ARM64_BTI_KERNEL + CONFIG_CFI_CLANG for forward-edge CFI.
Is it correct?

So you recommend to check that CONFIG_UNWIND_PATCH_PAC_INTO_SCS is disabled to avoid security degradation. Am I right?

By the way, could you please have a look at this part of the [Linux Kernel Defence Map](https://github.com/a13xp0p0v/linux-kernel-defence-map):
![Снимок экрана от 2024-02-19 16-13-45](https://github.com/a13xp0p0v/kernel-hardening-checker/assets/1419667/61eb10ab-1686-4fb3-9b29-4888bd4ae870)
I hope it describes all concepts correctly.

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2024-02-19 13:56](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/105#issuecomment-1952505694):

> CONFIG_SHADOW_CALL_STACK + CONFIG_ARM64_PTR_AUTH_KERNEL for backward-edge CFI,
> CONFIG_ARM64_BTI_KERNEL + CONFIG_CFI_CLANG for forward-edge CFI.
> Is it correct?

Yes, that's correct.

AOSP or the stock OS on the Pixel 8 uses PAC without SCS via CONFIG_UNWIND_PATCH_PAC_INTO_SCS and Clang CFI without BTI enabled. GrapheneOS uses PAC + SCS and Clang CFI + BTI. BTI would be useless if CFI had full coverage but it doesn't since they had to exclude a fair bit of stuff for compatibility with the architecture such as things like exception tables. They also excluded certain hooks for Android from Clang CFI for performance reasons, but that part of the exclusions will hopefully go away when the traditional Clang CFI is replaced by kCFI. kCFI should get closer to full coverage but as long as there's anything excluded it's still at least minimally useful.

> So you recommend to check that CONFIG_UNWIND_PATCH_PAC_INTO_SCS is disabled to avoid security degradation. Am I right?

Yes, since PAC is a sidegrade from SCS by itself. SCS is a deterministic mitigation itself and currently depends on ASLR to protect the deterministic metadata (shadow stack). PAC is purely probabilistic and the strength depends on the memory configuration which is quite annoying since a larger address space with better ASLR and more importantly lots of room for address space based mitigations reduces PAC security.

> By the way, could you please have a look at this part of the [Linux Kernel Defence Map](https://github.com/a13xp0p0v/linux-kernel-defence-map):

That looks correct.

The PAC instructions at the start of functions are interpreted as BTI instructions for performance reasons to avoid needing BTI instructions in those functions, which means non-leaf functions which get protected by PAC don't need their own BTI instruction but also means that all non-leaf functions are considered indirectly callable even if the compiler can figure out they aren't such as functions marked static without their address taken. It doesn't really matter much since it's incredibly coarse either way, but PAC + BTI makes BTI a bit more coarse.

It might also be worth distinguishing probabilistic vs. deterministic.

Clang CFI (traditional or kCFI) and most of RAP is deterministic based on type signatures. RAP also has a probabilistic return defense via a form of XOR canary (Samsung also had something similar to the latter but I'm unsure if they still do).

PAC is purely probabilistic. If you can predict/leak the values, you can bypass it.

SCS is deterministic itself but lacks write protection for the shadow stack like Intel CET so it depends on ASLR for protecting that against arbitrary writes, but writes to the stack are protected against deterministically. I'd still call it deterministic for the main value but it does depend on ASLR for the broader threat model it doesn't do well against (and ASLR is much weaker in the kernel).

I personally dislike the approach used for PAC and think they made a major mistake not providing a shadow stack and a different approach for protecting data. PAC is at odds with using bits more other purposes such as memory tagging and a larger address space. It's purely probabilistic. It also requires a lot of work to integrate, unlike memory tagging which only needs support in heap memory allocators such as malloc and allocations made by the compiler. MTE is also primarily aimed at detecting the initial memory corruption, not protecting specific targets but rather stopping the memory corruption occurring at all. It would be possible to use MTE to protect specific things but the main use is tagging every allocation which could have an overflow or use-after-free including stack allocations when using stack MTE.

PAC is still worth using since it's there... but especially when using it only for protecting return values as is the case on Linux currently, it's such a disappointment. It would be so much better having deterministic hardware shadow stack support, more tagging bits for MTE and other mitigations focused on deterministic protections.

We don't quite know what to do about PAC right now. If SCS didn't rely on ASLR to protect the shadow stack, we could just disable PAC in the kernel itself. SCS is trickier to fully deploy in userspace than the kernel so using PAC there is easier. It only demonstrates how much nicer the hardware shadow stack approach would be. It's not too late for ARM to add that.

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2024-02-19 13:59](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/105#issuecomment-1952511295):

> They also excluded certain hooks for Android from Clang CFI for performance reasons

We're considering undoing this. The issue is that as part of GKI, they moved scheduler customizations to using hooks in the core kernel code which call into dynamically loaded kernel modules. This adds the overhead of calls into dynamic kernel modules which is increased with certain configuration options such as the full arm64 KASLR implementation for modules (not very valuable, since it only randomizes modules separately from the base kernel, which wouldn't happen without using modules anyway). Clang CFI before kCFI is particularly expensive for this case. I'm not sure how much kCFI will help with it. Pixel 8 is using the 5.15 LTS branch so there's no kCFI yet unless they backport it. They might move Pixels to the 6.1 LTS branch since they even have a test branch for the Pixel 6 based on 6.1 but it's not clear. New kernels have lots of regressions and previous Pixels didn't have the 5 and now 7 year support lifetimes they do now where moving to at least 1 new kernel branch starts to seem mandatory.

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2024-02-19 14:02](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/105#issuecomment-1952516428):

We've also determined that enabling BTI is broken with CONFIG_UNWIND_PATCH_PAC_INTO_SCS enabled for the Pixel 8 kernel but his issue is **likely** fixed in mainline already or may not have ever been a problem there. They implemented Clang CFI, CONFIG_UNWIND_PATCH_PAC_INTO_SCS, etc. downstream first and then ported them to mainline later to be upstreamed so sometimes there are actually regressions in the mainline implementation compared to the initial GKI branch implementation. It's quite a mess. CFI is really only just becoming usable in mainline, particularly for x86. They were missing lots of required fixes for undefined behavior caught by CFI and other issues especially on x86 until recently. kCFI should result in broader adoption due to better performance so maybe it will get much better soon if traditional distributions actually start using it which they haven't so far.

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2024-08-29 17:16](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/105#issuecomment-2318420244):

It would be nice if the recommendation to use this was at least removed since it's encouraging downgrading security if you have both SCS and PAC enabled. It considers it a failure for checking the GrapheneOS kernel even though we're doing something more secure by having both enabled.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-09-04 12:34](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/105#issuecomment-2328869309):

@thestinger, thanks.
[Removed](https://github.com/a13xp0p0v/kernel-hardening-checker/commit/d9953fca88da324b5387cb73b018be0b7b8cf92f) it for now because there is no consensus about this feature:
https://github.com/KSPP/kspp.github.io/issues/2


-------------------------------------------------------------------------------

# [\#104 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/104) `closed`: add check for CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE=0x0 too
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) opened issue at [2024-01-19 07:30](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/104):

Disabling SYSRQ support entirely is nice, but not always possible. For example, Android uses `/proc/sysrq-trigger` from userspace processes for multiple purposes from privileged core system processes and controls access via SELinux. Android still sets the `kernel.sysrq` sysctl to 0 in early boot via init to disable using it via a keyboard, but it makes a lot more sense for that to happen via the kernel to close any opportunity  to use it before init disables it. It would make sense to check for CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE=0x0 when SYSRQ isn't disabled to at least disable doing it via the keyboard by default.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-02-18 18:27](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/104#issuecomment-1951407421):

Hello @thestinger ,

Thanks for the idea.

Collecting all pieces together, we can have the following rules:
```
l += [OR(KconfigCheck('cut_attack_surface', 'clipos', 'MAGIC_SYSRQ', 'is not set'),
         KconfigCheck('cut_attack_surface', 'my', 'MAGIC_SYSRQ_DEFAULT_ENABLE', '0x0'))]
...
l += [CmdlineCheck('cut_attack_surface', 'my', 'sysrq_always_enabled', 'is not set')]
...
l += [SysctlCheck('cut_attack_surface', 'my', 'kernel.sysrq', '0')]
```
Do you agree?

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2024-02-19 14:13](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/104#issuecomment-1952537486):

MAGIC_SYSRQ_DEFAULT_ENABLE being set to 0x0 without being enabled via sysrq_always_enabled or kernel.sysrq should provide similar benefits. It's probably still best to fully disable the functionality.

Disabling it via the sysctl alone leaves a gap in early boot where it's enabled if MAGIC_SYSRQ_DEFAULT_ENABLE is 0x1 which seemed like a problem.

There's also MAGIC_SYSRQ_SERIAL for controlling whether sysrq can be enabled via the serial port. Having that enabled is a potential hole although it depends on having something implementing it.

I think either having MAGIC_SYSRQ disabled or having MAGIC_SYSRQ_DEFAULT_ENABLE set to 0x0 + MAGIC_SYSRQ_SERIAL disabled + not overriding it via kernel command line or kernel.sysrq is fine.

Android sets kernel.sysrq in early boot but yet lots of devices enable it via sysrq_always_enabled on the kernel command line and disabling in early boot also doesn't really seem right since there's a gap between the kernel being ready and init disabling it.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-06-16 04:40](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/104#issuecomment-2171043282):

Hello @thestinger,

Thanks again for your explanation.

I added:
  - the `MAGIC_SYSRQ_DEFAULT_ENABLE` check: https://github.com/a13xp0p0v/kernel-hardening-checker/commit/48ff85596d7c1ed707a74844cfac72d736d0c71c 
  - the `kernel.sysrq` check: https://github.com/a13xp0p0v/kernel-hardening-checker/commit/538af12944c3a16f5707db51f49b1f4d053300d0
  - the `MAGIC_SYSRQ_SERIAL` check: https://github.com/a13xp0p0v/kernel-hardening-checker/commit/d995dd6eab4d14d8400abe16bbf14c3364f99fb6

Do you like it?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-06-16 04:43](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/104#issuecomment-2171043838):

By the way, the KSPP added this [recommendation](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings): 
```
CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE=176
``` 
It allows sync, remount read-only and reboot/poweroff.

@thestinger, what do you think about it?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-07 13:32](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/104#issuecomment-2212452556):

Hi @thestinger!

Currently, these sysrq checks in `kernel-hardening-checker` are marked as my recommendations.
But it would be nice to mark them as  `GrapheneOS` recommendations.
Could you give a link to the GrapheneOS documentation or code enforcing this configuration?
I would put it to the [references](https://github.com/a13xp0p0v/kernel-hardening-checker?tab=readme-ov-file#features). 

And what do you think about `CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE=176` recommended by [KSPP](https://kspp.github.io/Recommended_Settings)?

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2024-07-07 15:32](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/104#issuecomment-2212486700):

We don't really need credit for it particularly since many of the KSPP recommendations came from us anyway.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-07 17:59](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/104#issuecomment-2212523903):

I mean the sysrq checks that I developed according to this issue #104:
```
l += [OR(KconfigCheck('cut_attack_surface', 'clipos', 'MAGIC_SYSRQ', 'is not set'),
         KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'MAGIC_SYSRQ_DEFAULT_ENABLE', '0x0'))]
l += [OR(KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'MAGIC_SYSRQ_SERIAL', 'is not set'),
         KconfigCheck('cut_attack_surface', 'a13xp0p0v', 'MAGIC_SYSRQ_DEFAULT_ENABLE', '0x0'))]

l += [CmdlineCheck('cut_attack_surface', 'a13xp0p0v', 'sysrq_always_enabled', 'is not set')]

l += [OR(SysctlCheck('cut_attack_surface', 'a13xp0p0v', 'kernel.sysrq', '0'),
         AND(KconfigCheck('cut_attack_surface', 'clipos', 'MAGIC_SYSRQ', 'is not set'),
             have_kconfig))]
```

They are currently marked as `clipos` or `a13xp0p0v`.
They are more restrictive than the KSPP recommendation.

Is it possible to refer to the GrapheneOS documentation or code for these checks?

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2024-07-07 18:01](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/104#issuecomment-2212524501):

There's just https://github.com/GrapheneOS/kernel_common-6.6/commit/af734ccc119eb324e99f55da9883617ab0bc6304.

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2024-07-07 18:15](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/104#issuecomment-2212528621):

You can see our overall core kernel changes here:

https://github.com/GrapheneOS/kernel_common-6.6/commits/15/

Bear in mind we're starting from the Android Generic Kernel Image configuration with Clang CFI, etc. already enabled and some downstream hardening features. Android uses strict full system SELinux policies and that is what gets used to restrict eBPF, io_uring, userfaultfd, ioctl commands, dmesg, perf events, etc. rather than very coarse kernel features that are close to all or nothing. This means most things related to restricting userspace access aren't relevant since SELinux policy is used. We also introduce our own extensions to SELinux.

Some our hardening is hardware-specific so it's outside of this GKI repository.

As an example of how a feature can be spread out across a bunch of areas, we have this USB-C / pogo pins port control feature for reducing attack surface while locked at both a software (kernel) and hardware (USB-C / pogo pins controller) level:

https://grapheneos.org/features#usb-c-port-and-pogo-pins-control

Due to this feature, disabling SYSRQ support isn't very relevant since we disable USB at a hardware and software level anyway.

Here's our software-level USB protection infrastructure in the kernel:

https://github.com/GrapheneOS/kernel_common-6.6/commit/777f92add12737c27bdf21a4314f88096055525d
https://github.com/GrapheneOS/kernel_common-6.6/commit/7da1fe795c7d4770b2e6cc48e231db0ebaa96950
https://github.com/GrapheneOS/kernel_common-6.6/commit/57b0d1cd602249e442142482a15e8de61c9dbb0d
https://github.com/GrapheneOS/kernel_common-6.6/commit/1b31f2c37ee57134f49f48a6bf9cbc86a79e8999

Hardware-level USB-C and pogo pins protection infrastructure:

https://github.com/GrapheneOS/kernel_google-modules_soc_gs/commits/14/ and 
https://github.com/GrapheneOS/kernel_gs/commits/14/  (USB-C driver)
https://github.com/GrapheneOS/kernel_devices_google_tangorpro/commits/14/ (pogo pins driver)

The userspace part is spread across several repositories, at least these:

https://github.com/GrapheneOS/platform_frameworks_base/commits/14/ (tiny portion of our changes there are relevant)
https://github.com/GrapheneOS/platform_system_sepolicy/commits/14/ (small portion of our changes there are relevant)
https://github.com/GrapheneOS/platform_packages_apps_Settings/commits/14/ (tiny portion of our changes there are relevant)
https://github.com/GrapheneOS/device_google_gs101/commits/14/ (small portion of our changes there are relevant)
https://github.com/GrapheneOS/device_google_gs201/commits/14/ (small portion of our changes there are relevant)
https://github.com/GrapheneOS/device_google_zuma/commits/14/ (small portion of our changes there are relevant)

Just as an example of one of our major features which involves kernel changes. There are others, and we try to put as much as possible in SELinux, etc. as possible rather than changing the kernel so there's not really that much there especially since we try to upstream stuff.

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2024-07-07 18:18](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/104#issuecomment-2212529599):

There are GKI repositories for 5.10, 5.15, 6.1 and 6.6 but soon only the 6.1 and 6.6 ones will be relevant once Pixels all move to 6.1 which hopefully happens sooner rather than later. 6th/7th gen Pixels have out-of-tree drivers built from kernel/gs (kernel_gs) but 8th gen onwards have moved to having small repositories used with the GKI common kernel repository instead rather than both the common kernel repository for the kernel image / generic modules and another device kernel repository. Will go away for 6th/7th gen Pixels when they move to a newer kernel. Anyway, it's spread out more than you'd probably think. We've also been trying to do as much as we can via SELinux, seccomp-bpf and userspace code rather than patching the kernel when not necessary. When things get a bit cleaner when Pixels move to newer GKI branches and the last device kernel repository is gone (kernel_gs), we'll probably start making more kernel changes again such as making our hardened allocator with a best in class MTE implementation as we did in userspace.


-------------------------------------------------------------------------------

# [\#103 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/103) `closed`: add disabling CONFIG_AIO (legacy POSIX AIO) as a recommendation
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) opened issue at [2024-01-08 05:31](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/103):

POSIX AIO is a legacy feature and adds significant attack surface, albeit not nearly as much as IO_URING. POSIX AIO was poorly designed and hardly got any usage. The glibc and musl implementation doesn't use the kernel implementation and it requires a dedicated library, but is essentially obsolete now beyond it being used before io_uring was an option and still not being replaced in rare applications using it. Essentially everything using it can fall back to not using it via thread pools though, with little impact to most people. High performance software would be using io_uring anyway, not this legacy approach.

As an example, Android used AIO for implementing the fastboot, adb and mtp USB gadget protocols with fallback to synchronous IO but then moved to using io_uring for fastboot and also adopted it for snapuserd too. io_uring is limited to fastbootd/snapuserd via SELinux, but AIO was allowed for everything. It would be best if they moved adb and mtp to io_uring too and removed the AIO system calls from the seccomp-bpf whitelist. Apps can't use io_uring and none use AIO in practice, particularly since they provide no bindings for it for apps to use, only the base OS.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-01-16 23:16](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/103#issuecomment-1894672881):

Hi @thestinger,

Yes, the code currently performs checking AIO: [checks.py#L372](https://github.com/a13xp0p0v/kernel-hardening-checker/blob/master/kernel_hardening_checker/checks.py#L372):
```
    l += [KconfigCheck('cut_attack_surface', 'clipos', 'AIO', 'is not set')]
```

The new `kernel-hardening-checker` [release](https://github.com/a13xp0p0v/kernel-hardening-checker/releases/tag/v0.6.6) includes this.


-------------------------------------------------------------------------------

# [\#102 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/102) `closed`: drop check for dependency-only CONFIG_GCC_PLUGINS due to Clang
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) opened issue at [2024-01-08 05:10](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/102):

It makes sense to check for the functionality provided by the plugins if there's no Clang alternative, but it doesn't make sense to fail from an irrelevant dependency for those features being unavailable. For example, using CONFIG_INIT_STACK_ALL_ZERO is more secure than the STRUCTLEAK plugin anyway, and has insignificant performance overhead. There are already checks for the latent entropy, RANDSTRUCT and STACKLEAK plugins, but there could be alternatives to those for Clang, and not having GCC_PLUGINS enabled is irrelevant.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-01-16 21:52](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/102#issuecomment-1894574347):

@thestinger, I agree. I'll think and return with the solution.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-03-25 19:12](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/102#issuecomment-2018724266):

Hello @thestinger,

I've found the solution.

1) Dropped the `CONFIG_GCC_PLUGINS` check. This check is not security-relevant and it's not needed in case of building the kernel with `clang`.

2) Added the `CONFIG_CC_IS_GCC` dependency for `gcc` plugins, that don't have analogues in `clang`.

Let's see the output of `kernel-hardening-checker` for a kernel config created with `clang`.

```
[+] Special report mode: verbose
[+] Kconfig file to check: my/arm64_full_hardened_6.6_clang.config
[+] Detected microarchitecture: ARM64
[+] Detected kernel version: (6, 6, 7)
[+] Detected compiler: CLANG 150006
```
`clang` and `gcc` support `CONFIG_INIT_STACK_ALL_ZERO` as alternative to `CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL`:
```
-------------------------------------------------------------------------------------------------------------------------
    <<< OR >>>                                                                             | OK
CONFIG_INIT_STACK_ALL_ZERO              |kconfig|     y      |defconfig | self_protection  | OK
CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL  |kconfig|     y      |   kspp   | self_protection  | None
-------------------------------------------------------------------------------------------------------------------------
```
Clang will support `CONFIG_RANDSTRUCT_FULL` starting from version 16:
```
-------------------------------------------------------------------------------------------------------------------------
    <<< OR >>>                                                                             | FAIL: is not found
CONFIG_RANDSTRUCT_FULL                  |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_GCC_PLUGIN_RANDSTRUCT            |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
-------------------------------------------------------------------------------------------------------------------------
    <<< AND >>>                                                                            | FAIL: CONFIG_RANDSTRUCT_FULL is not "y"
CONFIG_RANDSTRUCT_PERFORMANCE           |kconfig| is not set |   kspp   | self_protection  | None
CONFIG_GCC_PLUGIN_RANDSTRUCT_PERFORMANCE|kconfig| is not set |   kspp   | self_protection  | None
    <<< OR >>>                                                                             | FAIL: is not found
CONFIG_RANDSTRUCT_FULL                  |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
CONFIG_GCC_PLUGIN_RANDSTRUCT            |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
-------------------------------------------------------------------------------------------------------------------------
```
The `CONFIG_GCC_PLUGIN_LATENT_ENTROPY ` check gives `FAIL: CONFIG_CC_IS_GCC is not "y"`:
```
-------------------------------------------------------------------------------------------------------------------------
    <<< AND >>>                                                                            | FAIL: CONFIG_CC_IS_GCC is not "y"
CONFIG_GCC_PLUGIN_LATENT_ENTROPY        |kconfig|     y      |   kspp   | self_protection  | None
CONFIG_CC_IS_GCC                        |kconfig|     y      |    -     |        -         | FAIL: is not found
-------------------------------------------------------------------------------------------------------------------------
```
The `CONFIG_GCC_PLUGIN_STACKLEAK` check gives the same:
```
-------------------------------------------------------------------------------------------------------------------------
    <<< AND >>>                                                                            | FAIL: CONFIG_CC_IS_GCC is not "y"
CONFIG_GCC_PLUGIN_STACKLEAK             |kconfig|     y      |   kspp   | self_protection  | None
CONFIG_CC_IS_GCC                        |kconfig|     y      |    -     |        -         | FAIL: is not found
-------------------------------------------------------------------------------------------------------------------------
```

I decided not to remove the `gcc`-specific checks for `clang` builds and vice-versa.
I think users should see the options they miss when they choose a compiler for the kernel.
The example with the `CONFIG_CFI_CLANG` check for the `gcc` kernel build:
```
-------------------------------------------------------------------------------------------------------------------------
    <<< AND >>>                                                                            | FAIL: CONFIG_CC_IS_CLANG is not "y"
CONFIG_CFI_CLANG                        |kconfig|     y      |   kspp   | self_protection  | None
CONFIG_CC_IS_CLANG                      |kconfig|     y      |    -     |        -         | FAIL: is not found
-------------------------------------------------------------------------------------------------------------------------
    <<< AND >>>                                                                            | FAIL: CONFIG_CC_IS_CLANG is not "y"
CONFIG_CFI_PERMISSIVE                   |kconfig| is not set |   kspp   | self_protection  | None
CONFIG_CFI_CLANG                        |kconfig|     y      |   kspp   | self_protection  | None
CONFIG_CC_IS_CLANG                      |kconfig|     y      |    -     |        -         | FAIL: is not found
-------------------------------------------------------------------------------------------------------------------------
```

What do you think?

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2024-03-25 21:44](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/102#issuecomment-2018972196):

@a13xp0p0v Yes, that makes perfect sense. Some features are GCC exclusive and some are Clang exclusive. PaX and grsecurity still exist where features going beyond what Clang provides for CFI exist for GCC but that's not available upstream where Clang has a big advantage until GCC provides kCFI.

https://gcc.gnu.org/bugzilla/show_bug.cgi?id=107048

The main thing missing upstream for Clang is STACKLEAK. Latent entropy really doesn't matter on any decent hardware but would still be quite useful in problematic environments.


-------------------------------------------------------------------------------

# [\#101 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/101) `closed`: CONFIG_ARCH_MMAP_RND_BITS check is wrong for arm64
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) opened issue at [2024-01-08 04:37](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/101):

The expected value on arm64 for a 48-bit address space (4 level page tables with 4k pages) is 33, not 32, which makes the check fail even though it's higher. arm64 has configurable page size and page table levels. Typical Linux devices have 4k pages and 3 level page tables resulting in a 39-bit address space, providing much less ASLR entropy as the maximum. A hardened kernel should use 4 level page tables resulting in a 48-bit address space and an expected value of 33 here. 4k pages also provide more granularity for guard pages, although it's much less important on ARMv9 devices supporting MTE such as the Pixel 8 where a reserved tag can be used for 16 byte granularity guards rather than using pages.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-01-16 21:37](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/101#issuecomment-1894555189):

Hi @thestinger,

I agree with you, currently the code already does this.

Quoting [__init__.py#L328](https://github.com/a13xp0p0v/kernel-hardening-checker/blob/master/kernel_hardening_checker/__init__.py#L328):
```
        # hackish refinement of the CONFIG_ARCH_MMAP_RND_BITS check
        mmap_rnd_bits_max = parsed_kconfig_options.get('CONFIG_ARCH_MMAP_RND_BITS_MAX', None)
        if mmap_rnd_bits_max:
            override_expected_value(config_checklist, 'CONFIG_ARCH_MMAP_RND_BITS', mmap_rnd_bits_max)
        else:
            # remove the CONFIG_ARCH_MMAP_RND_BITS check to avoid false results
            print('[-] Can\'t check CONFIG_ARCH_MMAP_RND_BITS without CONFIG_ARCH_MMAP_RND_BITS_MAX')
            config_checklist[:] = [o for o in config_checklist if o.name != 'CONFIG_ARCH_MMAP_RND_BITS']
```
So `kernel-hardening-checker` creates this recommendation dynamically.

The example output for `arm64_defconfig_6.6.config`:
```
[+] Kconfig file to check: kernel_hardening_checker/config_files/defconfigs/arm64_defconfig_6.6.config
[+] Detected microarchitecture: ARM64
[+] Detected kernel version: 6.6
[+] Detected compiler: GCC 130001
...
CONFIG_ARCH_MMAP_RND_BITS               |kconfig|     33     |    my    | harden_userspace | FAIL: "18"
```
I'll create a new tag very soon, and this will get into the new release of the tool.

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2024-01-16 21:40](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/101#issuecomment-1894558946):

I can also start testing with the git revision now before making recommendations, it just didn't occur to me that it had been a long time since the last stable release and I didn't see recent commits for those things.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-01-16 21:48](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/101#issuecomment-1894569310):

@thestinger, thank you for testing!

Preparing a release of the tool corresponding to the new kernel version takes a lot of effort.

I hope to find resources to do that more often.


-------------------------------------------------------------------------------

# [\#100 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/100) `closed`: CONFIG_COMPAT_VDSO has a completely different meaning for arm64 and recommending disabling it doesn't make sense there
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) opened issue at [2024-01-08 04:34](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/100):

On arm64, CONFIG_COMPAT_VDSO determines whether the vdso is mapped in 32-bit processes at all. It's not a compatibility hack with security implications like it is on x86 but rather has a completely different meaning.

It makes sense to recommend disabling 32-bit ARM support as a whole (CONFIG_COMPAT), but there's no reason to recommend disabling this particular option.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-01-16 21:26](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/100#issuecomment-1894537837):

Hello @thestinger,

Yes, the code already describes the same thing.
Quoting [checks.py#L298](https://github.com/a13xp0p0v/kernel-hardening-checker/blob/master/kernel_hardening_checker/checks.py#L298):
```
    if arch in ('X86_64', 'X86_32'):
        l += [KconfigCheck('cut_attack_surface', 'kspp', 'COMPAT_VDSO', 'is not set')]
              # CONFIG_COMPAT_VDSO disabled ASLR of vDSO only on X86_64 and X86_32;
              # on ARM64 this option has different meaning
```

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2024-01-16 21:30](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/100#issuecomment-1894543152):

Ah, it's because https://github.com/a13xp0p0v/kernel-hardening-checker/commit/22728555223c98630180c2f642cc7e369424bd8a isn't in a stable tag yet and I was using the Arch Linux package instead of the latest revision.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-01-16 21:31](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/100#issuecomment-1894544028):

Right! 
I'll create a new tag very soon, and this will get into the new release of the tool.


-------------------------------------------------------------------------------

# [\#99 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/99) `closed`: skip CONFIG_DEBUG_NOTIFIERS requirement when CONFIG_CFI_CLANG is set with CONFIG_CFI_PERMISSIVE disabled
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) opened issue at [2024-01-08 04:30](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/99):

CONFIG_DEBUG_NOTIFIERS only checks that the notifier function pointer is in kernel text. CFI already does that for everything that's not excluded from it. CONFIG_DEBUG_NOTIFIERS is obsolete when using CFI, and there should be no clear reason to enable it.

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2024-01-16 20:27](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/99#issuecomment-1894462962):

This is partly motivated by CONFIG_DEBUG_NOTIFIERS being buggy on some architectures. It works properly on x86 but we had issues with it on arm64 previously. It's the only user of `func_ptr_is_kernel_text` so there's little motivation for that function to work universally for such a niche feature that's no longer even useful if you use CFI. The whole feature is this:

```c
#ifdef CONFIG_DEBUG_NOTIFIERS
		if (unlikely(!func_ptr_is_kernel_text(nb->notifier_call))) {
			WARN(1, "Invalid notifier called!");
			nb = next_nb;
			continue;
		}
#endif
```

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-01-16 20:40](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/99#issuecomment-1894479180):

@thestinger, thanks for the idea!

Added the commit  https://github.com/a13xp0p0v/kernel-hardening-checker/commit/cd5bb8a0364e6a28b2d03a8ac0d7520194a9f07a.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-01-16 20:42](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/99#issuecomment-1894481143):

One moment, you are right, CFI_PERMISSIVE should be disabled as well.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-01-16 21:20](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/99#issuecomment-1894530696):

Added the commit https://github.com/a13xp0p0v/kernel-hardening-checker/commit/65ff79dbe2c36347283d71d3fa1959030bf6838f.

Now the verbose result for checking this config ...
```
# CONFIG_DEBUG_NOTIFIERS is not set
CONFIG_CFI_CLANG=y
CONFIG_CFI_PERMISSIVE=y
```
... looks like that:
```
-------------------------------------------------------------------------------------------------------------------------
    <<< OR >>>                                                                             | FAIL: "is not set"
CONFIG_DEBUG_NOTIFIERS                  |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
    <<< AND >>>                                                                            | FAIL: CONFIG_CFI_PERMISSIVE is not "is not set"
CONFIG_CFI_CLANG                        |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_CFI_PERMISSIVE                   |kconfig| is not set |   kspp   | self_protection  | FAIL: "y"
-------------------------------------------------------------------------------------------------------------------------
```
And the verbose result of checking this config...
```
# CONFIG_DEBUG_NOTIFIERS is not set
CONFIG_CFI_CLANG=y
# CONFIG_CFI_PERMISSIVE is not set
```
... looks like that:
```
-------------------------------------------------------------------------------------------------------------------------
    <<< OR >>>                                                                             | OK: CONFIG_CFI_CLANG is "y"
CONFIG_DEBUG_NOTIFIERS                  |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
    <<< AND >>>                                                                            | OK
CONFIG_CFI_CLANG                        |kconfig|     y      |   kspp   | self_protection  | OK
CONFIG_CFI_PERMISSIVE                   |kconfig| is not set |   kspp   | self_protection  | OK
-------------------------------------------------------------------------------------------------------------------------
```


-------------------------------------------------------------------------------

# [\#98 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/98) `closed`: skip CONFIG_SCHED_STACK_END_CHECK requirement when CONFIG_VMAP_STACK is set
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) opened issue at [2024-01-08 04:20](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/98):

CONFIG_SCHED_STACK_END_CHECK only provides stack exhaustion detection after it's already too late and it can be bypassed. CONFIG_VMAP_STACK provides reliable detection of stack exhaustion and there shouldn't be any need for CONFIG_SCHED_STACK_END_CHECK with it.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-01-16 20:08](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/98#issuecomment-1894435929):

Hello @thestinger,

As I remember, SCHED_STACK_END_CHECK checks the magic value at the end of the kernel thread stack, and VMAP_STACK adds guard pages near it. So they do a bit different things, but VMAP_STACK is more reliable.

I agree with your point.

Added the commit https://github.com/a13xp0p0v/kernel-hardening-checker/commit/c0fc9e89d7a21dfd734bc6c3b946f835493502ca.

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2024-01-16 20:24](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/98#issuecomment-1894458928):

> As I remember, SCHED_STACK_END_CHECK checks the magic value at the end of the kernel thread stack, and VMAP_STACK adds guard pages near it. So they do a bit different things, but VMAP_STACK is more reliable.

Yes, SCHED_STACK_END_CHECK checks a magic value at certain times such as exiting the kernel back to userspace, at which point the exploit can already have succeeded. The attacker may also have been able to clobber the value so that it's not detected. VMAP_STACK directly detects it with memory protection, which combined with making sure no large stack frames or VLAs exist prevents an overflow past the guard.


-------------------------------------------------------------------------------

# [\#97 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/97) `closed`: Get rid of CONFIG_DEBUG_CREDENTIALS
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/23581360?v=4" width="50">[Sporif](https://github.com/Sporif) opened issue at [2023-12-22 15:37](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/97):

This config has been removed recently.

[master](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ae1914174a63a558113e80d24ccac2773f9f7b2b) 

[stable](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?h=linux-6.6.y&id=207f135d819344c03333246f784f6666e652e081)

#### <img src="https://avatars.githubusercontent.com/u/1505226?u=0edff17ad0c4acebbd8660dc1854229d526a6dc4&v=4" width="50">[thestinger](https://github.com/thestinger) commented at [2024-01-08 04:14](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/97#issuecomment-1880362163):

The checking tool isn't only for the most recent kernel versions, and this was a mildly useful hardening feature despite not being designed as one. It would be possible to do a much better job, but people use what's available upstream.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-01-16 19:27](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/97#issuecomment-1894377361):

Thanks for the info!

Later, I'll add the dependency on the kernel version for the CONFIG_DEBUG_CREDENTIALS check.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-03-11 11:30](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/97#issuecomment-1988229377):

Hello @Sporif and @thestinger,

I've implemented parsing all three numbers of the kernel version and added the version check for `DEBUG_CREDENTIALS` https://github.com/a13xp0p0v/kernel-hardening-checker/commit/1a595757bc0aaef86550440f2a449569b6450ba5.

```
$ diff config667 config668
3c3
< # Linux/x86 6.6.7 Kernel Configuration
---
> # Linux/x86 6.6.8 Kernel Configuration
5065,5066d5064
< 
< # CONFIG_DEBUG_CREDENTIALS is not set
```

Output for v6.6.7:
```
[+] Special report mode: verbose
[+] Kconfig file to check: /home/a13x/develop_local/linux-stable/linux-stable/config667
[+] Detected microarchitecture: X86_64
[+] Detected kernel version: (6, 6, 7)
...
-------------------------------------------------------------------------------------------------------------------------
    <<< OR >>>                                                                             | FAIL: "is not set"
CONFIG_DEBUG_CREDENTIALS                |kconfig|     y      |   kspp   | self_protection  | FAIL: "is not set"
kernel version >= (6, 6, 8)                                                                | FAIL: version < (6, 6, 8)
-------------------------------------------------------------------------------------------------------------------------
```

Output for v6.6.8:
```
[+] Special report mode: verbose
[+] Kconfig file to check: /home/a13x/develop_local/linux-stable/linux-stable/config668
[+] Detected microarchitecture: X86_64
[+] Detected kernel version: (6, 6, 8)
...
-------------------------------------------------------------------------------------------------------------------------
    <<< OR >>>                                                                             | OK: version >= (6, 6, 8)
CONFIG_DEBUG_CREDENTIALS                |kconfig|     y      |   kspp   | self_protection  | FAIL: is not found
kernel version >= (6, 6, 8)                                                                | OK: version >= (6, 6, 8)
-------------------------------------------------------------------------------------------------------------------------
```


-------------------------------------------------------------------------------

# [\#96 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/96) `closed`: new tag?
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/4741819?v=4" width="50">[asarubbo](https://github.com/asarubbo) opened issue at [2023-12-07 12:04](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/96):

Hello @a13xp0p0v

[kernel-hardening-checker](https://github.com/a13xp0p0v/kernel-hardening-checker) it's really a great work!

I have recently added it into the [Gentoo tree](https://github.com/gentoo/gentoo/commit/151491904fa748c04cdff48a3884d52e18da9c0a) and I noticed that a lot of commits have been done after the last tag. Would you mind to issue a new minor release?
Thanks a lot

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-12-09 05:54](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/96#issuecomment-1848252596):

Hello @asarubbo, thanks for kind words!

I'm currently preparing a new release of the tool.  A new tag will appear soon.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-01-16 23:19](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/96#issuecomment-1894675464):

Done!

The release [v0.6.6](https://github.com/a13xp0p0v/kernel-hardening-checker/releases/tag/v0.6.6) is published!
It corresponds to the Linux kernel 6.6.


-------------------------------------------------------------------------------

# [\#95 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/95) `closed`: Check for module force loading?
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/89150207?v=4" width="50">[vobst](https://github.com/vobst) opened issue at [2023-12-07 08:30](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/95):

Would it make sense to check for `CONFIG_MODULE_FORCE_LOAD`? It could prevent attackers from loading slightly mismatching kernel modules. However, but it seems kind of redundant given that you already recommend disabling modules or enforcing signatures. Maybe it could be checked as a fall back if both stronger measures are disabled.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-12-09 05:51](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/95#issuecomment-1848251810):

Hello @vobst, thanks for the idea.

Added [e5f804e](https://github.com/a13xp0p0v/kernel-hardening-checker/commit/e5f804ede6ea7f66f674c2825396c15c216c718d).


-------------------------------------------------------------------------------

# [\#94 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/94) `merged`: add --kernel-version option

#### <img src="https://avatars.githubusercontent.com/u/1485263?v=4" width="50">[ffontaine](https://github.com/ffontaine) opened issue at [2023-11-29 16:46](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/94):

`--kernel-version` option will extract the version in `/proc/version`. This is especially useful on embedded systems where `config.gz` doesn't always contain the kernel version

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-12-01 13:38](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/94#issuecomment-1836135013):

Hello @ffontaine,

Nice idea, thanks!

I would ask for some small changes.


-------------------------------------------------------------------------------

# [\#93 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/93) `closed`: added wsl config
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/8870284?u=ec42118bfcab2ddd30e7fb094422d250164c3150&v=4" width="50">[mrkoykang](https://github.com/mrkoykang) opened issue at [2023-11-15 01:58](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/93):

added wsl config files

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-11-22 09:33](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/93#issuecomment-1822409439):

Hello @mrkoykang,

Thanks for the pull request.

1) These two kconfig files are mostly identical. How about adding only the more recent one?

2) Could you please add a link to this kconfig in [this file](https://github.com/a13xp0p0v/kernel-hardening-checker/blob/master/kernel_hardening_checker/config_files/links.txt)?

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-05-14 15:07](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/93#issuecomment-2110489221):

Closing for now.
@mrkoykang, feel free to reopen.


-------------------------------------------------------------------------------

# [\#92 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/92) `closed`: new make hardening.config available
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/77795961?v=4" width="50">[osevan](https://github.com/osevan) opened issue at [2023-11-06 00:09](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/92):

https://github.com/torvalds/linux/blob/master/kernel/configs/hardening.config

https://www.phoronix.com/news/Linux-6.7-Hardening

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-11-22 10:07](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/92#issuecomment-1822464512):

Hello @osevan,

Thanks for the links.

Need your opinion: how should `kernel-hardening-checker` use this new `make` target?

#### <img src="https://avatars.githubusercontent.com/u/4741819?v=4" width="50">[asarubbo](https://github.com/asarubbo) commented at [2023-12-19 07:51](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/92#issuecomment-1862276038):

> Need your opinion: how should `kernel-hardening-checker` use this new `make` target?

Not sure I have understood at all the question, but just port these option into `kernel-hardening-checker` and update them from time to time is an option?

I mean to just monitor changes like this https://github.com/torvalds/linux/commits/master/kernel/configs/hardening.config

#### <img src="https://avatars.githubusercontent.com/u/77795961?v=4" width="50">[osevan](https://github.com/osevan) commented at [2024-07-15 06:56](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/92#issuecomment-2227812946):

Ok great thx for link

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-08-11 15:33](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/92#issuecomment-2282798403):

Hello!
I've compared `kernel-hardening-checker` and `kernel/configs/hardening.config`.

Added some lines to `hardening.config` to perform checking:
```
+CONFIG_X86_64=y
+CONFIG_CC_IS_CLANG=y
```

Run the tool and looked at FAILures :
```
$ ./bin/kernel-hardening-checker -c ~/develop_local/linux-stable/linux-stable/kernel/configs/hardening.config -v /proc/version |grep FAIL | grep -v "is not found"
CONFIG_GCC_PLUGIN_LATENT_ENTROPY        |kconfig|     y      |   kspp   | self_protection  | FAIL: CONFIG_CC_IS_GCC is not "y"
CONFIG_GCC_PLUGIN_STACKLEAK             |kconfig|     y      |   kspp   | self_protection  | FAIL: CONFIG_CC_IS_GCC is not "y"
CONFIG_STACKLEAK_METRICS                |kconfig| is not set |   kspp   | self_protection  | FAIL: CONFIG_CC_IS_GCC is not "y"
CONFIG_STACKLEAK_RUNTIME_DISABLE        |kconfig| is not set |   kspp   | self_protection  | FAIL: CONFIG_CC_IS_GCC is not "y"
[+] Config check is finished: 'OK' - 161 / 'FAIL' - 43
```
Looks good.

Then looked at the options in `hardening.config` that don't have the corresponding check in `kernel-hardening-checker`:
```
$ ./bin/kernel-hardening-checker -c ~/develop_local/linux-stable/linux-stable/kernel/configs/hardening.config -v /proc/version -m verbose| grep "No check"
[?] No check for kconfig option CONFIG_X86_64 (y)
[?] No check for kconfig option CONFIG_UBSAN (y)
```
Looks good as well.

Finally got OK-checks, that are not `kspp` or `defconfig`:
```
./bin/kernel-hardening-checker -c ~/develop_local/linux-stable/linux-stable/kernel/configs/hardening.config -v /proc/version -m show_ok | grep -v "OK:" |grep -v defconfig | grep -v kspp
[+] Special report mode: show_ok
[+] Kconfig file to check: /home/a13x/develop_local/linux-stable/linux-stable/kernel/configs/hardening.config
[+] Detected microarchitecture: X86_64
[+] Detected kernel version: (6, 9, 12)
[-] Can't detect the compiler: no CONFIG_GCC_VERSION or CONFIG_CLANG_VERSION
[-] Can't check CONFIG_ARCH_MMAP_RND_BITS without CONFIG_ARCH_MMAP_RND_BITS_MAX
=========================================================================================================================
              option_name               | type  |desired_val | decision |      reason      | check_result
=========================================================================================================================

[+] Config check is finished: 'OK' - 161 / 'FAIL' - 43 (suppressed in output)
```
Looks good.

I also manually looked at
```
./arch/arm/configs/hardening.config
./arch/arm64/configs/hardening.config
./arch/x86/configs/hardening.config
```
`kernel-hardening-checker` contains all the corresponding checks.

Well done, closing the issue.


-------------------------------------------------------------------------------

# [\#91 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/91) `closed`: Modify requirements for Android configs

#### <img src="https://avatars.githubusercontent.com/u/65050545?u=3d095cc7726e6bbf544ea4857c4223033ea90921&v=4" width="50">[petervanvugt](https://github.com/petervanvugt) opened issue at [2023-10-30 19:27](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/91):

Android configs require various things that are currently disallowed in this tool. We can use CONFIG_ANDROID to detect Android configs and generate reports with fewer positives that cannot/should not be changed.


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-11-22 09:35](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/91#issuecomment-1822411251):

Hello @petervanvugt,

Nice idea, thanks.

Let's discuss some details.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-03 16:51](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/91#issuecomment-2206788042):

For now, closing this pull request.

See the details in #142.


-------------------------------------------------------------------------------

# [\#90 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/90) `merged`: Use /usr/bin/env in shebangs

#### <img src="https://avatars.githubusercontent.com/u/7258858?u=a54fac3b63cbbe0467081806f40a605a76191180&v=4" width="50">[SuperSandro2000](https://github.com/SuperSandro2000) opened issue at [2023-10-05 22:41](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/90):

This is guaranteed to work everything including NixOS

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-10-16 04:34](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/90#issuecomment-1763710410):

Merged. Thanks, @SuperSandro2000!


-------------------------------------------------------------------------------

# [\#89 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/89) `closed`: Fix a false positive in REFCOUNT_FULL in recent 5.4.x

#### <img src="https://avatars.githubusercontent.com/u/4372440?u=15d14bb4fbd7edc5b6fe55f5aa7d39d2933c6ad8&v=4" width="50">[hlein](https://github.com/hlein) opened issue at [2023-09-22 03:41](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/89):

Extend VersionCheck to be able to take a three-tuple, x.y.z kernel version in order to properly recognise 5.4.208 as when this became the default behavior and thus CONFIG_REFCOUNT_FULL disappeared.


Closes: https://github.com/a13xp0p0v/kernel-hardening-checker/issues/88

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-10-04 18:13](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/89#issuecomment-1747405606):

@hlein, thanks for your pull request.

I think you need to adapt  `detect_kernel_version()` to get the third number of the kernel version from the kconfig file.

One more aspect: you need to compare this number in the `check()` method of the `VersionCheck` class. Otherwise it will return wrong results.

#### <img src="https://avatars.githubusercontent.com/u/4372440?u=15d14bb4fbd7edc5b6fe55f5aa7d39d2933c6ad8&v=4" width="50">[hlein](https://github.com/hlein) commented at [2023-10-04 18:29](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/89#issuecomment-1747427507):

> @hlein, thanks for your pull request.
> 
> I think you need to adapt `detect_kernel_version()` to get the third number of the kernel version from the kconfig file.

Oh, you are probably right. I didn't have access to the box or config in question any more, so fabricated some data I was testing against; my tests must have been incomplete / accidentally-successful.

> One more aspect: you need to compare this number in the `check()` method of the `VersionCheck` class. Otherwise it will return wrong results.

Oof, you're right. I think I had done things a different way before refactoring the `self.ver_expected_print` out, but then lost the check against `self.ver_expected[2]` when cleaning up. Ugh!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-03-10 00:17](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/89#issuecomment-1987020924):

Closing. The feature is implemented.
Please see https://github.com/a13xp0p0v/kernel-hardening-checker/issues/88#issuecomment-1987020054.


-------------------------------------------------------------------------------

# [\#88 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/88) `closed`: False positive on CONFIG_REFCOUNT_FULL in recent 5.4.x kernels

#### <img src="https://avatars.githubusercontent.com/u/4372440?u=15d14bb4fbd7edc5b6fe55f5aa7d39d2933c6ad8&v=4" width="50">[hlein](https://github.com/hlein) opened issue at [2023-09-22 03:07](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/88):

Similar to https://github.com/a13xp0p0v/kernel-hardening-checker/issues/30, `CONFIG_REFCOUNT_FULL` was removed from 5.4.x kernels starting with v5.4.208, because full refcount became always-on, in this commit:

https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?h=linux-5.4.y&id=d0d583484d2ed9f5903edbbfa7e2a68f78b950b0

Currently we complain when it is not found, like:
`CONFIG_REFCOUNT_FULL      |kconfig|     y      |defconfig | self_protection  | FAIL: is not found`

I don't know an easier way to find which kernel first included that commit other than:

```
$ egrep url .git/config 
        url = https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
$ git tag --contains d0d583484d2ed9f5903edbbfa7e2a68f78b950b0 | head -n2
v5.4.208
v5.4.209
```
I think the fix is to return OK for 5.4.x where x >= 208.

Except... that's done via `VersionCheck` in `engine.py` which, if I'm reading it right, takes only major and minor versions, no third parameter:

```
class VersionCheck:
    def __init__(self, ver_expected):
        assert(ver_expected and isinstance(ver_expected, tuple) and len(ver_expected) == 2), \
               f'invalid version "{ver_expected}" for VersionCheck'
```
So that function would have to be made a bit more flexible.

I don't know if other `CONFIG_*` knobs disappeared / became defaults in the middle of a given major.minor kernel version, but it would not surprise me.


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-10-04 17:58](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/88#issuecomment-1747385253):

Hello @hlein,

Thanks for your comment!

The REFCOUNT_FULL config option was removed from the mainline in the commit [fb041bb7c0a918b95c6889fc965cdc4a75b4c0ca](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?h=v6.6-rc4&id=fb041bb7c0a918b95c6889fc965cdc4a75b4c0ca)

This commit appeared in the mainline kernel v5.5-rc1:
```
$ cd linux/
$ git describe --match 'v*' --contains fb041bb7c0a918b95c6889fc965cdc4a75b4c0ca
v5.5-rc1~149^2~2
```

The commit [d0d583484d2ed9f5903edbbfa7e2a68f78b950b0](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?h=linux-5.4.y&id=d0d583484d2ed9f5903edbbfa7e2a68f78b950b0) is the backport of the upstream commit to the stable branch:
```
$ cd linux-stable/
$ git describe --match 'v*' --contains d0d583484d2ed9f5903edbbfa7e2a68f78b950b0
v5.4.208~21
```

I didn't find backports of this commit to other stable branches.

So, technically, it's not wrong to say that REFCOUNT_FULL was removed in v5.4.208 :) 

I'll take a look at your pull request. Thanks a lot!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-03-10 00:14](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/88#issuecomment-1987020054):

Hello @hlein,

I've implemented parsing all three numbers of the kernel version.

Let's see how it works for `CONFIG_REFCOUNT_FULL` now:
```
$ diff config207 config208
3c3
< # Linux/x86 5.4.207 Kernel Configuration
---
> # Linux/x86 5.4.208 Kernel Configuration
709,710d708
< CONFIG_ARCH_HAS_REFCOUNT=y
< # CONFIG_REFCOUNT_FULL is not set
```

The tool gives the correct output for Linux v5.4.207:
```
[+] Special report mode: verbose
[+] Kconfig file to check: /home/a13x/develop_local/linux-stable/linux-stable/config207
[+] Detected microarchitecture: X86_64
[+] Detected kernel version: (5, 4, 207)
...
-------------------------------------------------------------------------------------------------------------------------
    <<< OR >>>                                                                             | FAIL: "is not set"
CONFIG_REFCOUNT_FULL                    |kconfig|     y      |defconfig | self_protection  | FAIL: "is not set"
kernel version >= (5, 4, 208)                                                              | FAIL: version < (5, 4, 208)
-------------------------------------------------------------------------------------------------------------------------
```

And for Linux v5.4.208:
```
[+] Special report mode: verbose
[+] Kconfig file to check: /home/a13x/develop_local/linux-stable/linux-stable/config208
[+] Detected microarchitecture: X86_64
[+] Detected kernel version: (5, 4, 208)
...
-------------------------------------------------------------------------------------------------------------------------
    <<< OR >>>                                                                             | OK: version >= (5, 4, 208)
CONFIG_REFCOUNT_FULL                    |kconfig|     y      |defconfig | self_protection  | FAIL: is not found
kernel version >= (5, 4, 208)                                                              | OK: version >= (5, 4, 208)
-------------------------------------------------------------------------------------------------------------------------
```

CC #89

#### <img src="https://avatars.githubusercontent.com/u/4372440?u=15d14bb4fbd7edc5b6fe55f5aa7d39d2933c6ad8&v=4" width="50">[hlein](https://github.com/hlein) commented at [2024-03-10 20:39](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/88#issuecomment-1987355466):

Great, thank you!


-------------------------------------------------------------------------------

# [\#87 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/87) `closed`: Add a check for IA32_EMULATION
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2023-09-14 12:36](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/87):

As [reported by phoronix](https://www.phoronix.com/news/Linux-6.7-ia32_emulation-Boot), it's now possible to disable 32b support on amd64, to reduce attack surface.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-11-22 10:09](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/87#issuecomment-1822468556):

Thanks @jvoisin,

This will be added in the next release of `kernel-hardening-checker`.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-12-17 10:23](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/87#issuecomment-1859129322):

Hello @jvoisin,

The `ia32_emulation` boot param was introduced in Linux v6.7.

I'm currently preparing the `kernel-hardening-checker` release corresponding to the kernel v6.6.

So this boot option and `IA32_EMULATION_DEFAULT_DISABLED` will be added in the next release.

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-03-04 20:38](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/87#issuecomment-1977414071):

Hello @jvoisin and @winterknife,

The `ia32_emulation` check is added: https://github.com/a13xp0p0v/kernel-hardening-checker/commit/98ccb216ebc61a231207830f0b6b37c8133d0d48

It's not simple:
```
if arch == 'X86_64':
    l += [OR(CmdlineCheck('cut_attack_surface', 'my', 'ia32_emulation', '0'),
             KconfigCheck('cut_attack_surface', 'kspp', 'IA32_EMULATION', 'is not set'),
             AND(KconfigCheck('cut_attack_surface', 'my', 'IA32_EMULATION_DEFAULT_DISABLED', 'y'),
                 CmdlineCheck('cut_attack_surface', 'my', 'ia32_emulation', 'is not set')))]
```

Let's see how it works in the verbose mode:

1) If `IA32_EMULATION` is disabled, the check gives `OK: CONFIG_IA32_EMULATION is "is not set"`:
```
-------------------------------------------------------------------------------------------------------------------------
    <<< OR >>>                                                                             | OK: CONFIG_IA32_EMULATION is "is not set"
ia32_emulation                          |cmdline|     0      |    my    |cut_attack_surface| FAIL: is not found
CONFIG_IA32_EMULATION                   |kconfig| is not set |   kspp   |cut_attack_surface| OK
    <<< AND >>>                                                                            | None
CONFIG_IA32_EMULATION_DEFAULT_DISABLED  |kconfig|     y      |    my    |cut_attack_surface| None
ia32_emulation                          |cmdline| is not set |    my    |cut_attack_surface| None
-------------------------------------------------------------------------------------------------------------------------
```

2) If we enable `IA32_EMULATION` and don't set `IA32_EMULATION_DEFAULT_DISABLED` and `ia32_emulation`, the check gives `FAIL`:
```
-------------------------------------------------------------------------------------------------------------------------
    <<< OR >>>                                                                             | FAIL: is not found
ia32_emulation                          |cmdline|     0      |    my    |cut_attack_surface| FAIL: is not found
CONFIG_IA32_EMULATION                   |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
    <<< AND >>>                                                                            | FAIL: "is not set"
CONFIG_IA32_EMULATION_DEFAULT_DISABLED  |kconfig|     y      |    my    |cut_attack_surface| FAIL: "is not set"
ia32_emulation                          |cmdline| is not set |    my    |cut_attack_surface| OK: is not found
-------------------------------------------------------------------------------------------------------------------------
```

3) If we then enable `IA32_EMULATION_DEFAULT_DISABLED`, the check gives `OK: CONFIG_IA32_EMULATION_DEFAULT_DISABLED is "y"`:
```
-------------------------------------------------------------------------------------------------------------------------
    <<< OR >>>                                                                             | OK: CONFIG_IA32_EMULATION_DEFAULT_DISABLED is "y"
ia32_emulation                          |cmdline|     0      |    my    |cut_attack_surface| FAIL: is not found
CONFIG_IA32_EMULATION                   |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
    <<< AND >>>                                                                            | OK
CONFIG_IA32_EMULATION_DEFAULT_DISABLED  |kconfig|     y      |    my    |cut_attack_surface| OK
ia32_emulation                          |cmdline| is not set |    my    |cut_attack_surface| OK: is not found
-------------------------------------------------------------------------------------------------------------------------
```

4) But if we then enable `ia32_emulation`, it overrides the `IA32_EMULATION_DEFAULT_DISABLED` option and the check gives `FAIL: "1"`:
```
-------------------------------------------------------------------------------------------------------------------------
    <<< OR >>>                                                                             | FAIL: "1"
ia32_emulation                          |cmdline|     0      |    my    |cut_attack_surface| FAIL: "1"
CONFIG_IA32_EMULATION                   |kconfig| is not set |   kspp   |cut_attack_surface| FAIL: "y"
    <<< AND >>>                                                                            | FAIL: ia32_emulation is not "is not set"
CONFIG_IA32_EMULATION_DEFAULT_DISABLED  |kconfig|     y      |    my    |cut_attack_surface| None
ia32_emulation                          |cmdline| is not set |    my    |cut_attack_surface| FAIL: "1"
-------------------------------------------------------------------------------------------------------------------------
```

5) Finally, setting `ia32_emulation=0` gives `OK`:
```
-------------------------------------------------------------------------------------------------------------------------
    <<< OR >>>                                                                             | OK
ia32_emulation                          |cmdline|     0      |    my    |cut_attack_surface| OK
CONFIG_IA32_EMULATION                   |kconfig| is not set |   kspp   |cut_attack_surface| None
    <<< AND >>>                                                                            | None
CONFIG_IA32_EMULATION_DEFAULT_DISABLED  |kconfig|     y      |    my    |cut_attack_surface| None
ia32_emulation                          |cmdline| is not set |    my    |cut_attack_surface| None
-------------------------------------------------------------------------------------------------------------------------
```

Please comment if you see anything wrong.

#### <img src="https://avatars.githubusercontent.com/u/107318481?u=7423ac118deca5f7f745e28ac2e3f6a487465973&v=4" width="50">[winterknife](https://github.com/winterknife) commented at [2024-03-05 13:09](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/87#issuecomment-1978745383):

Ah, I wasn't aware of `CONFIG_IA32_EMULATION_DEFAULT_DISABLED` but yes, that logic seems sound to me.

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-03-05 22:41](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/87#issuecomment-1979760140):

Why can't we have nice and straightforward things, sigh.

But yes, it does look good to me.


-------------------------------------------------------------------------------

# [\#86 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/86) `merged`: Add colors to output

#### <img src="https://avatars.githubusercontent.com/u/5826484?u=2cc3ddef5824379423495733759ef362d0600078&v=4" width="50">[frakman1](https://github.com/frakman1) opened issue at [2023-09-10 17:49](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/86):

Shows OK in green and FAIL in red

<img width="1047" alt="image" src="https://github.com/a13xp0p0v/kconfig-hardened-check/assets/5826484/d098d14f-2e1a-4569-af22-54ef2bc0eecb">

fixes #81

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-09-10 19:25](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/86#issuecomment-1712916729):

@frakman1, thanks for the pull request!

There are some small mistakes that break the tests.

Looking forward to your fixes.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-09-11 18:25](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/86#issuecomment-1714376333):

Hello @frakman1, the CI tests are broken again.

Please see, the argument of `colorize_result()` may be None in the verbose mode of the tool.
So we need to add something like that at the beginning of the function:
```
    if input is None:
        return input
```

Also please fix two pylint warnings added by this PR:

1) W0311: Bad indentation. Found 17 spaces, expected 16 (bad-indentation)

2) W0622: Redefining built-in 'input' (redefined-builtin).
To fix this, you need to rename the argument of the function.

Thanks again!
Looking forward to the fixes.

#### <img src="https://avatars.githubusercontent.com/u/65553080?u=b7ee84d82e25b493051d810390e97b15f716d7ef&v=4" width="50">[codecov-commenter](https://github.com/codecov-commenter) commented at [2023-09-11 23:05](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/86#issuecomment-1714703072):

## [Codecov](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/86?src=pr&el=h1&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) Report
> Merging [#86](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/86?src=pr&el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (374aee3) into [master](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/commit/108eb7374967b0f66e70b68cca60a0548f12844c?el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (108eb73) will **decrease** coverage by `1.32%`.
> The diff coverage is `87.50%`.

:exclamation: Your organization needs to install the [Codecov GitHub app](https://github.com/apps/codecov/installations/select_target) to enable full functionality.

```diff
@@             Coverage Diff             @@
##            master      #86      +/-   ##
===========================================
- Coverage   100.00%   98.68%   -1.32%     
===========================================
  Files            6        5       -1     
  Lines         1049      839     -210     
  Branches       184      187       +3     
===========================================
- Hits          1049      828     -221     
- Misses           0        5       +5     
- Partials         0        6       +6     
```

| [Flag](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/86/flags?src=pr&el=flags&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) | Coverage Δ | |
|---|---|---|
| [engine_unit-test](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/86/flags?src=pr&el=flag&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) | `?` | |
| [functional_test](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/86/flags?src=pr&el=flag&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) | `98.68% <87.50%> (-0.23%)` | :arrow_down: |

Flags with carried forward coverage won't be shown. [Click here](https://docs.codecov.io/docs/carryforward-flags?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#carryforward-flags-in-the-pull-request-comment) to find out more.

| [Files Changed](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/86?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) | Coverage Δ | |
|---|---|---|
| [kconfig\_hardened\_check/engine.py](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/86?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#diff-a2NvbmZpZ19oYXJkZW5lZF9jaGVjay9lbmdpbmUucHk=) | `94.58% <87.50%> (-5.42%)` | :arrow_down: |

... and [1 file with indirect coverage changes](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/86/indirect-changes?src=pr&el=tree-more&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)

:mega: We’re building smart automated test selection to slash your CI/CD build times. [Learn more](https://about.codecov.io/iterative-testing/?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-09-12 17:40](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/86#issuecomment-1716159903):

@frakman1, thanks for the fixes!

I think we should better add colors to the `stdout_result` in the unit tests instead of filtering them out before `assertEqual()`.

That would allow to test that `colorize_result()` works as expected.

#### <img src="https://avatars.githubusercontent.com/u/5826484?u=2cc3ddef5824379423495733759ef362d0600078&v=4" width="50">[frakman1](https://github.com/frakman1) commented at [2023-09-12 22:12](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/86#issuecomment-1716580970):

I'm sorry, this is outside the scope of my knowledge or effort. Not intersted in re-writing test cases.

#### <img src="https://avatars.githubusercontent.com/u/5826484?u=2cc3ddef5824379423495733759ef362d0600078&v=4" width="50">[frakman1](https://github.com/frakman1) commented at [2023-09-13 22:14](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/86#issuecomment-1718385583):

Thank you!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-09-13 22:50](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/86#issuecomment-1718412639):

Added f8f7033.

Thanks for you contribution, @frakman1!


-------------------------------------------------------------------------------

# [\#85 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/85) `merged`: Rename kconfig-hardened-check into kernel-hardening-checker

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2023-09-10 12:18](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/85):

**kconfig-hardened-check** is a tool for checking the security hardening options of the Linux kernel.

In addition to Kconfig options, it now can check kernel cmdline arguments and sysctl parameters.

It's time to give this project a new name that describes it better: **kernel-hardening-checker**.

#### <img src="https://avatars.githubusercontent.com/u/65553080?u=b7ee84d82e25b493051d810390e97b15f716d7ef&v=4" width="50">[codecov-commenter](https://github.com/codecov-commenter) commented at [2023-09-10 12:19](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/85#issuecomment-1712799348):

## [Codecov](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/85?src=pr&el=h1&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) Report
> Merging [#85](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/85?src=pr&el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (032f67f) into [master](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/commit/f8e47e12ddf6b5c7b7562af6b85b8f65481e4b07?el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (f8e47e1) will **decrease** coverage by `0.04%`.
> The diff coverage is `n/a`.

:exclamation: Your organization needs to install the [Codecov GitHub app](https://github.com/apps/codecov/installations/select_target) to enable full functionality.

```diff
@@            Coverage Diff             @@
##           master      #85      +/-   ##
==========================================
- Coverage   99.81%   99.77%   -0.04%     
==========================================
  Files           6        2       -4     
  Lines        1087      451     -636     
  Branches      174        0     -174     
==========================================
- Hits         1085      450     -635     
  Misses          1        1              
+ Partials        1        0       -1     
```

| [Flag](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/85/flags?src=pr&el=flags&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) | Coverage Δ | |
|---|---|---|
| [engine_unit-test](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/85/flags?src=pr&el=flag&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) | `99.77% <ø> (ø)` | |
| [functional_test](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/85/flags?src=pr&el=flag&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) | `?` | |

Flags with carried forward coverage won't be shown. [Click here](https://docs.codecov.io/docs/carryforward-flags?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#carryforward-flags-in-the-pull-request-comment) to find out more.

| [Files Changed](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/85?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) | Coverage Δ | |
|---|---|---|
| [kernel\_hardening\_checker/engine.py](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/85?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#diff-a2VybmVsX2hhcmRlbmluZ19jaGVja2VyL2VuZ2luZS5weQ==) | `99.50% <ø> (ø)` | |
| [kernel\_hardening\_checker/test\_engine.py](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/85?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#diff-a2VybmVsX2hhcmRlbmluZ19jaGVja2VyL3Rlc3RfZW5naW5lLnB5) | `100.00% <ø> (ø)` | |

... and [4 files with indirect coverage changes](https://app.codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/85/indirect-changes?src=pr&el=tree-more&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)

:mega: We’re building smart automated test selection to slash your CI/CD build times. [Learn more](https://about.codecov.io/iterative-testing/?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)


-------------------------------------------------------------------------------

# [\#84 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/84) `closed`: Add RDK Linux Hardening specification flags
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/5826484?u=2cc3ddef5824379423495733759ef362d0600078&v=4" width="50">[frakman1](https://github.com/frakman1) opened issue at [2023-09-01 12:48](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/84):

The [RDK Linux Hardening specification](https://developer.rdkcentral.com/documentation/documentation/licensee_specific_subsystems/rdk_security_concepts/rdk_software_security_specifications/rdk_linux_hardening_specification/) lists many flags that are not checked in this tool. The first five I looked for were not there: `CONFIG_DEBUG_KERNEL` `CONFIG_MARKERS` `CONFIG_DEBUG_MEMLEAK` and `CONFIG_ELF_CORE`

Perhaps these can be added as part of a new 'RDK security policy' check for the 'decision' column

#### <img src="https://avatars.githubusercontent.com/u/5826484?u=2cc3ddef5824379423495733759ef362d0600078&v=4" width="50">[frakman1](https://github.com/frakman1) commented at [2023-09-05 14:23](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/84#issuecomment-1706723756):

Link no longer appears to be up. I saved a cache for reference:

----

RDK Linux Hardening specification 
Created on June 21, 2022 
1.	Ensure no hard-coded credentials are present in the clear
2.	Ensure compliance with Comcast specifications for crypto and TLS 
o	All STB connections to servers must be secured using TLS 1.2 or above, and verified to be correctly performing server certificate chain validation
3.	Build with stack-smashing (at least for modules implementing security) 
o	Enable CONFIG_CC_STACKPROTECTOR, -fstack-protector-all, -Wstack-protector
o	Libc function buffer overrun checks: _FORTIFY_SOURCE=2
o	Initial requirement would be to enable this for all security sensitive modules with follow up to enable for the entire build.
4.	Scan all non-OSS sources with static analyzer
5.	Network port blocking 
o	All ports not specifically used must be blocked by ipTables rules 
6.	Disable all unused devices (USB, Bluetooth, etc)
7.	Implement multiuser/sandbox strategy (Restrict Linux process privileges) 
o	No applications/utilities within a sandbox should run as root or have any means to achieve root privileges.  Sandbox shall not contains hard links to outside files.  Every sandbox connected to external network shall contain its own firewall and shall be configured using a whitelist.
o	Configure processes to the minimum capabilities and resources required for their operation.  Have unique user and group own service components/applications that need to be isolated.  Users have permissions to access the required device files only.  Shared files are access controlled using group permissions. Default permissions for newly created files include read/write/exec permissions for the owner only.  Always use setresuid() and setresgid() functions to change the current user and group. Always confirm the change with getresuid() and getresgid() function.  Users and groups must have unique ID’s
o	In progress, containerization via LXC is being implemented for subset of RDK processes.  OEM may choose to use a technology other than LXC to sandbox their processes.
8.	Vet all open source 
o	Currently being done using Whitesource tool
9.	Disable kernel module load 
o	Making modules statically linked to the kernel would be a significant effort.
o	Disable module load after boot using /proc/sys/kernel/module_disabled 
10.	Disable kernel module unload 
o	Set CONFIG_MODULE_UNLOAD
11.	Kernel module parameters must be R/O or trusted 
o	Audit boot scripts to ensure loadable kernel module parameters are hard coded and don’t rely on data from persistent storage or other writable source
12.	Remove kernel debugging and profiling options 
o	CONFIG_DEBUG_KERNEL CONFIG_MARKERS CONFIG_DEBUG_MEMLEAK CONFIG_KPROBES
o	CONFIG_SLUB_DEBUG CONFIG_PROFILING CONFIG_DEBUG_FS CONFIG_KPTRACE
o	CONFIG_KALLSYMS CONFIG_LTT CONFIG_UNUSED_SYMBOLS CONFIG_TRACE_IRQFLAGS_SUPPORT
o	CONFIG_RELAY CONFIG_MAGIC_SYSRQ CONFIG_VM_EVENT_COUNTERS CONFIGU_UNWIND_INFO
o	CONFIG_BPA2_ALLOC_TRACE CONFIG_PRINTK
o	CONFIG_CRASH_DUMP CONFIG_BUG CONFIG_SCSI_LOGGING CONFIG_ELF_CORE CONFIG_FULL_PANIC
o	CONFIG_TASKSTATUS CONFIG_AUDIT CONFIG_BSD_PROCESS_ACCT CONFIG_KEXEC
o	CONFIG_EARLY_PRINTK CONFIG_IKCONFIG CONFIG_NETFILTER_DEBUG
o	CONFIG_MTD_UBI_DEBUG CONFIG_B43_DEBUG CONFIG_SSB_DEBUG CONFIG_FB_INTEL_DEBUG
o	CONFIG_TRACING CONFIG_PERF_EVENTS 
13.	Disable unused file system and block device support
14.	Enable heap protection and pointer obfuscation features. 
o	Enabled by default in glibc.  Protects heap from buffer overflows.  Available in glibc 2.3.4 or above, Enabled using environment variable malloc_check_
15.	Restrict /dev/mem to minimal regions of memory required
16.	Remove support for /dev/kmem
17.	Remove support for /dev/kcore 
o	Kernel core dumping should be disabled in production
18.	Enable format, buffer, and object size checks
19.	Restrict /proc to process owners (except for IDS)
20.	Disable kernel configfs 
o	Allows modification of kernel objects
21.	Remove ldconfig from target filesystem and [ld.so](http://ld.so/).conf and [ld.so](http://ld.so/).cache should be empty 
o	Removes caching of symbolic links.  Will cause a performance hit.
o	Impact: glibc changes. Would allow loading libraries from a non-standard library path even if we don’t use LD_LIBRARY_PATH.
22.	Security critical software are compiled as PIE (Position Independent Executable), if supported
23.	Kernel boots with “ro” in command line  
o	Mount filesystem as readonly. 
24.	Mount filesystems with minimal privileges. For example, filesystem containing no executable code shall have “noexec” option specified. 
25.	Mount temporary storage (/tmp) shall in dedicated filesystem (eg. tmpfs) and its contents does not survive reboots
26.	Flush cache after accessing sensitive data
27.	No overlay of writable mounts on read-only data 
28.	system directories such as /proc or /dev shall not be writable within a sandbox
29.	Applications and utilities shall not have the setgid or setuid bit set
30.	Configure default shell to /dev/null
31.	Remove all unused executables and libraries
32.	Disable PTRACE, General restriction on PTRACE should be applied at kernel level with Yama LSM  
o	http://linux-audit.com/protect-ptrace-processes-kernel-yama-ptrace_scope/ 
o	PTRACE is used by GDB.  Disable only for production builds.  Both compile time and runtime changes required (can restrict PTRACE to root if required)
33.	Don’t use LD_LIBRARY_PATH (loads libraries from default locations only)
34.	Full runtime path for non-standard libraries included in code image 
o	Use -rpath and -rpath-link
35.	Mount filesystems with ro option and change permission temporarily when needed
36.	Kernel init parameters / command line must be R/O and trusted
37.	Restrict kernel syslog (dmesg) to root user only
38.	Disable kernel debugfs 
o	Part of sysfs used to enable kernel debug messaging.  If printk is disabled this becomes irrelevant
39.	Use ELF format only 
o	May break scripts like Python
40.	Dynamic linker configuration changes 
o	Remove LD_DEBUG support from dynamic linker 
o	Remove LD_PRELOAD support from dynamic linker 
o	Remove LD_PROFILE support from the dynamic linker 
o	Remove LD_AUDIT support from the dynamic linker 
o	Remove LD_SHOW_AUXV support from the dynamic linker
o	Remove LD_TRACE_LOADED_OBJECTS support from the dynamic linker 
o	Link dynamic programs with -z now and -z relro options 
41.	Hide restricted kernel pointers 
o	Restricted pointers replaced with 0’s.
o	Relates to printk handling of printing pointer values.  This is a runtime setting, enable/disable via /proc/sys/kernel/kptr_restrict
42.	Review use of SYSFS, disable it if possible
43.	Mark unchanging files in writable partition with “immutable”
44.	Use all compiler security features 
o	Compile -wall, -Werror and fail on warnings (and possibly -Wextra)
45.	Replace strcpy with strncpy 
o	All code should use safer, bounds checking versions of string library functions (such as strncpy instead of strcpy) to avoid potential buffer overruns.
46.	Prevent file races, open temp files with O_CREAT | O_EXCL 
o	Makes check for file existence and creation atomic.  Prevents multiple threads creating same file. 
47.	Set sticky bit for temporary directories to prevent acc
idental deletion
o	Only owner and root can delete directory
48.	Restrict kernel network settings to be the most restrictive possible
49.	Limit temporary storage (tmpfs) memory size 
50.	Enable kernel ABI Version Check
51.	Disable kernel symbol resolution 
o	Disable CONFIG_KALLSYMS
o	Limits our ability to debug kernel crash dumps
52.	Disable kernel crashdump 
o	Disable CONFIG_CRASH_DUMP 
53.	Minimum MMAPable address set to 4K min. 
o	This prevents mapping NULL address

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-11-22 10:16](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/84#issuecomment-1822479661):

Need to compare these recommendations with the current `kernel-hardening-checker` rules.

Gonna do that after preparing the next release of the tool.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-07 13:00](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/84#issuecomment-2212442244):

I looked through these ideas.
Not all of them are about the kernel.

I've added the `CONFIG_CRASH_DUMP` check also recommended by ClipOS.

Thanks! Closing the issue.


-------------------------------------------------------------------------------

# [\#83 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/83) `closed`: Enhancement add kmalloc hardening
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/77795961?v=4" width="50">[osevan](https://github.com/osevan) opened issue at [2023-08-29 23:53](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/83):

https://www.phoronix.com/news/Linux-Randomize-Kmalloc-Cache

Thanks and
Best regards

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-09-03 15:45](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/83#issuecomment-1704338755):

@osevan, thanks!
I'll consider it during preparing the next release of the tool.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-12-16 23:42](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/83#issuecomment-1858987573):

Done! Thanks @osevan.


-------------------------------------------------------------------------------

# [\#82 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/82) `closed`: Consider removing/not recommending CONFIG_ZERO_CALL_USED_REGS
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) opened issue at [2023-05-08 12:38](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/82):

CONFIG_ZERO_CALL_USED_REGS is [useless at best](https://dustri.org/b/paper-notes-clean-the-scratch-registers-a-way-to-mitigate-return-oriented-programming-attacks.html), with a **significant** performance impact.

This is a security theatre knob, and the performance budget would be better spent elsewhere.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-09-03 15:52](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/82#issuecomment-1704340181):

@jvoisin, thanks for the article!
It looks reasonable, we'll discuss it.


-------------------------------------------------------------------------------

# [\#81 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/81) `closed`: Color indicators for "check result" column
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/4941656?v=4" width="50">[harisphnx](https://github.com/harisphnx) opened issue at [2023-04-27 13:16](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/81):

Would the maintainers be open to adding colors to the output of the "check result" column? For example, the output would be red for FAIL, and green for OK?

#### <img src="https://avatars.githubusercontent.com/u/4941656?v=4" width="50">[harisphnx](https://github.com/harisphnx) commented at [2023-04-27 13:17](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/81#issuecomment-1525681451):

If so, I can make the change and create a PR

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-05-07 16:41](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/81#issuecomment-1537488610):

Yes, it would be nice.
Looking forward to your PR.

#### <img src="https://avatars.githubusercontent.com/u/5826484?u=2cc3ddef5824379423495733759ef362d0600078&v=4" width="50">[frakman1](https://github.com/frakman1) commented at [2023-09-01 17:04](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/81#issuecomment-1703069739):

Has anyone done this yet?
I made a hacky attempt of this last year before the `sysctl` support was added. I added different colors for the two sections too:

<img width="1282" alt="image" src="https://github.com/a13xp0p0v/kconfig-hardened-check/assets/5826484/e880006a-5f1d-4580-b3e2-dcc0b104b089">

I just tried to overlay it onto the latest code but it's too different now. My changes were in `kconfig_hardened_check/__init__.py` but everything has moved since then. Unfortunately, not an easy merge.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-09-03 15:40](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/81#issuecomment-1704337689):

@frakman1 thanks, it looks nice.
Could you give a link to your commit? I'll help to rebase it.

#### <img src="https://avatars.githubusercontent.com/u/5826484?u=2cc3ddef5824379423495733759ef362d0600078&v=4" width="50">[frakman1](https://github.com/frakman1) commented at [2023-09-03 16:16](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/81#issuecomment-1704345063):

Thank you @a13xp0p0v. 
I just checked and my changes were based on [this](https://github.com/a13xp0p0v/kconfig-hardened-check/blob/899752c13f4d1260d1a33985672b72b3a9cb60ec/kconfig_hardened_check/__init__.py) commit:
```
* 899752c - (Sun Oct 2 21:45:13 2022 +0300) Also check 'nospectre_v2' with 'spectre_v2' - <Alexander Popov> (HEAD -> master, origin/master, origin/HEAD)
```
Unfortunately, I never commited it and just stashed it before doing a `git pull`

Original File (rename to .py):
[__init__.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/12506520/__init__.txt)


Colored File (rename to .py):
[__init__.color.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/12506521/__init__.color.txt)

I created a patch file using:
```
git diff --no-index --patch --output=color.diff __init__.py __init__.color.py
```

patch file (optionally rename to .diff):
[color.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/12506530/color.txt)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-09-03 19:51](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/81#issuecomment-1704387355):

Thanks, I see the approach.

Let's print OK results in green and FAIL results in red.

We need to modify the `table_print()` method of classes in [engine.py](https://github.com/a13xp0p0v/kconfig-hardened-check/blob/master/kconfig_hardened_check/engine.py).

I would recommend something like that:

1) defining ANSI escape sequences at the beginning of the file:
```
GREEN_COLOR = '\x1b[32m'
RED_COLOR = '\x1b[31m'
COLOR_END = '\x1b[0m'
```

2) modify printing methods this way:
```
if with_results:
    if self.result.startswith('OK'):
        color = GREEN_COLOR
    elif self.result.startswith('FAIL:'):
        color = RED_COLOR
    else:
        assert(False), f'unexpected result "{self.result}"'
    colored_result = f'{color}{self.result}{COLOR_END}'
    print(f'| {colored_result}', end='')
```

What do you think?
Would you like to prepare a pull request?

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/141440559?u=a2256f43745996b332a33cc986eb796c084caed2&v=4" width="50">[trclst](https://github.com/trclst) commented at [2023-09-03 23:34](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/81#issuecomment-1704435599):

I would only going to color `OK `and `FAIL` not full line.
Besides, I don't know if there aren't more important things a `| grep FAIL` can do.
Maybe it is better to keep the code small, the information is still there whether in color or not.
Anyway hope it looks fancy.

#### <img src="https://avatars.githubusercontent.com/u/5826484?u=2cc3ddef5824379423495733759ef362d0600078&v=4" width="50">[frakman1](https://github.com/frakman1) commented at [2023-09-04 05:16](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/81#issuecomment-1704624719):

If you only want to see the failures, you can use the `-m show_fail` option

#### <img src="https://avatars.githubusercontent.com/u/5826484?u=2cc3ddef5824379423495733759ef362d0600078&v=4" width="50">[frakman1](https://github.com/frakman1) commented at [2023-09-04 18:33](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/81#issuecomment-1705607069):

> What do you think? Would you like to prepare a pull request?

I like it. Thank you for the guidance. I just attempted it and it seems I have to repeat that logic in three places before I could get all the prints.

sample output:

<img width="1047" alt="image" src="https://github.com/a13xp0p0v/kconfig-hardened-check/assets/5826484/d098d14f-2e1a-4569-af22-54ef2bc0eecb">

Diffs located in my fork ~~[here](https://github.com/frakman1/kconfig-hardened-check/compare/108eb7374967b0f66e70b68cca60a0548f12844c...71c8e35842b805e8e6b819bf599b07fdd0d48479)~~

@a13xp0p0v Let me know if that looks good. If so, I will issue a pull request.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-09-09 16:56](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/81#issuecomment-1712554168):

Thanks @frakman1 !

I would propose creating a function `colorize_result()` and call several times to avoid copying the code.

#### <img src="https://avatars.githubusercontent.com/u/5826484?u=2cc3ddef5824379423495733759ef362d0600078&v=4" width="50">[frakman1](https://github.com/frakman1) commented at [2023-09-09 18:20](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/81#issuecomment-1712570988):

I've updated the code with your recommendations. See changes [here](https://github.com/frakman1/kconfig-hardened-check/commit/fb9aeb5392762c6ea3aa67096a18e163e63ec6ea)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-09-09 19:17](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/81#issuecomment-1712582213):

I've left some comments. The main point: it's better to leave printing inside of the `table_print()` method. The `colorize_result()` function should only return the colored string.

#### <img src="https://avatars.githubusercontent.com/u/5826484?u=2cc3ddef5824379423495733759ef362d0600078&v=4" width="50">[frakman1](https://github.com/frakman1) commented at [2023-09-09 21:12](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/81#issuecomment-1712623127):

Changes applied [here](https://github.com/frakman1/kconfig-hardened-check/compare/108eb7374967b0f66e70b68cca60a0548f12844c..b317b9f)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-09-10 11:04](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/81#issuecomment-1712783879):

Good!

Please remove the unneeded whitespaces and send the pull request.

Looking forward to it.

#### <img src="https://avatars.githubusercontent.com/u/5826484?u=2cc3ddef5824379423495733759ef362d0600078&v=4" width="50">[frakman1](https://github.com/frakman1) commented at [2023-09-10 17:49](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/81#issuecomment-1712896232):

Done.
https://github.com/a13xp0p0v/kconfig-hardened-check/pull/86


-------------------------------------------------------------------------------

# [\#80 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/80) `merged`: Added support for gzipped config (eg. /proc/config.gz)

#### <img src="https://avatars.githubusercontent.com/u/3389586?u=71aa9a963297407bb515b073245e398e8049d582&v=4" width="50">[nE0sIghT](https://github.com/nE0sIghT) opened issue at [2023-03-25 09:41](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/80):



#### <img src="https://avatars.githubusercontent.com/u/65553080?u=b7ee84d82e25b493051d810390e97b15f716d7ef&v=4" width="50">[codecov-commenter](https://github.com/codecov-commenter) commented at [2023-03-26 15:02](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/80#issuecomment-1484123415):

## [Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/80?src=pr&el=h1&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) Report
> Merging [#80](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/80?src=pr&el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (8def541) into [master](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/commit/b65af76d6e84b4cd80f4fb4c72799bdd49237024?el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (b65af76) will **decrease** coverage by `0.24%`.
> The diff coverage is `80.00%`.

:mega: This organization is not using Codecov’s [GitHub App Integration](https://github.com/apps/codecov). We recommend you install it so Codecov can continue to function properly for your repositories. [Learn more](https://about.codecov.io/blog/codecov-is-updating-its-github-integration/?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)

```diff
@@            Coverage Diff             @@
##           master      #80      +/-   ##
==========================================
- Coverage   98.39%   98.16%   -0.24%     
==========================================
  Files           6        6              
  Lines         812      818       +6     
  Branches      160      161       +1     
==========================================
+ Hits          799      803       +4     
- Misses          7        8       +1     
- Partials        6        7       +1     
```

| Flag | Coverage Δ | |
|---|---|---|
| engine_unit-test | `76.80% <ø> (ø)` | |
| functional_test | `97.97% <80.00%> (-0.26%)` | :arrow_down: |

Flags with carried forward coverage won't be shown. [Click here](https://docs.codecov.io/docs/carryforward-flags?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#carryforward-flags-in-the-pull-request-comment) to find out more.

| [Impacted Files](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/80?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) | Coverage Δ | |
|---|---|---|
| [kconfig\_hardened\_check/\_\_init\_\_.py](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/80?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#diff-a2NvbmZpZ19oYXJkZW5lZF9jaGVjay9fX2luaXRfXy5weQ==) | `99.10% <80.00%> (-0.90%)` | :arrow_down: |

:mega: We’re building smart automated test selection to slash your CI/CD build times. [Learn more](https://about.codecov.io/iterative-testing/?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-03-26 16:01](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/80#issuecomment-1484141857):

Hello @nE0sIghT,

I've merged your pull request and added:
 - informing about supporting *.gz kconfig files,
 - functional testing of this feature.

Thanks!
Alexander


-------------------------------------------------------------------------------

# [\#79 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/79) `closed`: Create unit-tests for the engine checking the correctness
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2023-03-06 08:03](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/79):

That would prevent the bug in cb779a71bf57d95b. See the fix d006bfa48e87.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-04-02 12:51](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/79#issuecomment-1493323795):

Good. This task is completed.

Unit-tests for the `kconfig-hardened-check` engine are created:
[kconfig_hardened_check/test_engine.py](https://github.com/a13xp0p0v/kconfig-hardened-check/blob/master/kconfig_hardened_check/test_engine.py)

CI performs unit-testing on each repository push:
https://github.com/a13xp0p0v/kconfig-hardened-check/actions/workflows/engine_unit-test.yml

These unit-tests check the correctness of the engine results and cover 100% of the engine code.

Reverting the aforementioned fix https://github.com/a13xp0p0v/kconfig-hardened-check/commit/d006bfa48e87600e70aae1a696ede3182f6c1cbd is detected by these unit-tests:
```
======================================================================
FAIL: test_simple_kconfig (kconfig_hardened_check.test_engine.TestEngine)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "/home/a13x/land/Develop/Linux_Kernel/kconfig-hardened-check/kconfig_hardened_check/test_engine.py", line 130, in test_simple_kconfig
    self.assertEqual(
AssertionError: Lists differ: [['CO[701 chars]8', 'OK: is not off, "off"'], ['CONFIG_NAME_9'[169 chars]nd']] != [['CO[701 chars]8', 'FAIL: is off'], ['CONFIG_NAME_9', 'kconfi[160 chars]nd']]

First differing element 7:
['CON[25 chars]is not off', 'decision_8', 'reason_8', 'OK: is not off, "off"']
['CON[25 chars]is not off', 'decision_8', 'reason_8', 'FAIL: is off']
```


-------------------------------------------------------------------------------

# [\#78 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/78) `closed`: Fix nixos integration

#### <img src="https://avatars.githubusercontent.com/u/96200?u=9ed15c85825694d00e996d605d728179b830c4fa&v=4" width="50">[Mic92](https://github.com/Mic92) opened issue at [2022-12-29 10:00](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/78):



#### <img src="https://avatars.githubusercontent.com/u/65553080?u=b7ee84d82e25b493051d810390e97b15f716d7ef&v=4" width="50">[codecov-commenter](https://github.com/codecov-commenter) commented at [2022-12-29 10:02](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/78#issuecomment-1367203889):

# [Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/78?src=pr&el=h1&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) Report
> Merging [#78](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/78?src=pr&el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (6fde9d6) into [master](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/commit/6211b6852b6b35f6f5d18ec2f0e713d2afea5a87?el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (6211b68) will **increase** coverage by `0.40%`.
> The diff coverage is `n/a`.

```diff
@@            Coverage Diff             @@
##           master      #78      +/-   ##
==========================================
+ Coverage   92.79%   93.20%   +0.40%     
==========================================
  Files           3        3              
  Lines         736      736              
  Branches      171      171              
==========================================
+ Hits          683      686       +3     
+ Misses         26       24       -2     
+ Partials       27       26       -1     
```

| Flag | Coverage Δ | |
|---|---|---|
| functional_test | `93.20% <ø> (+0.40%)` | :arrow_up: |

Flags with carried forward coverage won't be shown. [Click here](https://docs.codecov.io/docs/carryforward-flags?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#carryforward-flags-in-the-pull-request-comment) to find out more.

| [Impacted Files](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/78?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) | Coverage Δ | |
|---|---|---|
| [kconfig\_hardened\_check/\_\_init\_\_.py](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/78/diff?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#diff-a2NvbmZpZ19oYXJkZW5lZF9jaGVjay9fX2luaXRfXy5weQ==) | `93.25% <0.00%> (+0.41%)` | :arrow_up: |

:mega: We’re building smart automated test selection to slash your CI/CD build times. [Learn more](https://about.codecov.io/iterative-testing/?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-01-19 19:58](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/78#issuecomment-1397525515):

Hello @Mic92,

Closing, this issue has been fixed in https://github.com/a13xp0p0v/kconfig-hardened-check/pull/77.

Thanks!


-------------------------------------------------------------------------------

# [\#77 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/77) `merged`: add get-nixos-kconfig nix script

#### <img src="https://avatars.githubusercontent.com/u/106462796?v=4" width="50">[o8opi](https://github.com/o8opi) opened issue at [2022-12-29 09:15](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/77):

Hello,

This nix script, when run with `nix-build get-nixos-kconfig.nix` will output 3 kernel configuration files (linux_latest, linux_hardened, and the linux_lts)  for NixOS

Has been tested on Ubuntu 20.04

#63  relevant

#### <img src="https://avatars.githubusercontent.com/u/65553080?u=b7ee84d82e25b493051d810390e97b15f716d7ef&v=4" width="50">[codecov-commenter](https://github.com/codecov-commenter) commented at [2023-01-19 15:00](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/77#issuecomment-1397110519):

# [Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/77?src=pr&el=h1&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) Report
> Merging [#77](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/77?src=pr&el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (6149a3e) into [master](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/commit/6211b6852b6b35f6f5d18ec2f0e713d2afea5a87?el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (6211b68) will **not change** coverage.
> The diff coverage is `n/a`.

```diff
@@           Coverage Diff           @@
##           master      #77   +/-   ##
=======================================
  Coverage   92.79%   92.79%           
=======================================
  Files           3        3           
  Lines         736      736           
  Branches      171      171           
=======================================
  Hits          683      683           
  Misses         26       26           
  Partials       27       27           
```

| Flag | Coverage Δ | |
|---|---|---|
| functional_test | `92.79% <ø> (ø)` | |

Flags with carried forward coverage won't be shown. [Click here](https://docs.codecov.io/docs/carryforward-flags?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#carryforward-flags-in-the-pull-request-comment) to find out more.


:mega: We’re building smart automated test selection to slash your CI/CD build times. [Learn more](https://about.codecov.io/iterative-testing/?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-01-19 16:06](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/77#issuecomment-1397219216):

Thanks a lot, @o8opi!

It's merged.

I also generated the NixOS kernel configs using `nix-build get-nixos-kconfig.nix`: https://github.com/a13xp0p0v/kconfig-hardened-check/commit/0267c39d10364e2afb0779f2ce271539eff6f4e1


-------------------------------------------------------------------------------

# [\#76 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/76) `closed`: iommu=force

#### <img src="https://avatars.githubusercontent.com/u/74207682?u=fc82f6c725c4a6a1e0e8786b3ecee80b18118c92&v=4" width="50">[d4rklynk](https://github.com/d4rklynk) opened issue at [2022-12-13 17:58](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/76):

It seems it helps indirectly from DMA attacks (from what I understand). It is recommended by ANSSI.

From this [PDF](https://www.ssi.gouv.fr/uploads/2019/02/fr_np_linux_configuration-v2.0.pdf) (in french) at the chapter "**5.2.1 Configuration de la mémoire**"

Or from this [older version](https://www.ssi.gouv.fr/uploads/2019/03/linux_configuration-en-v1.2.pdf) of the same PDF but in english : chapter "**4.3 IOMMU Service (input/output virtualization)**"

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-01-21 22:03](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/76#issuecomment-1399341218):

Added this check in https://github.com/a13xp0p0v/kconfig-hardened-check/commit/4e0065c8baf8d40c733f7f4c5c920c07b93c55b6

Thanks, @d4rklynk!


-------------------------------------------------------------------------------

# [\#75 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/75) `closed`: Integrity Measurement Architecture 
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/97197406?u=3fc2e7c1b9d9f1b9b1c8e7268aaa11204944694e&v=4" width="50">[JohnVengert](https://github.com/JohnVengert) opened issue at [2022-11-14 04:40](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/75):

The Integrity Measurement Architecture is a subsystem that is responsible
 for calculating file hashes. this allows greater security . This option would be ideal
 to be integrated, 

Kernel Config -

```
CONFIG_IMA=y
CONFIG_IMA_MEASURE_PCR_IDX=10
CONFIG_IMA_LSM_RULES=y
CONFIG_IMA_NG_TEMPLATE=y
# CONFIG_IMA_SIG_TEMPLATE is not set
CONFIG_IMA_DEFAULT_TEMPLATE="ima-ng"
# CONFIG_IMA_DEFAULT_HASH_SHA1 is not set
# CONFIG_IMA_DEFAULT_HASH_SHA256 is not set
CONFIG_IMA_DEFAULT_HASH_SHA512=y
CONFIG_IMA_DEFAULT_HASH="sha512"
CONFIG_IMA_WRITE_POLICY=y
CONFIG_IMA_READ_POLICY=y
CONFIG_IMA_APPRAISE=y
CONFIG_IMA_ARCH_POLICY=y
CONFIG_IMA_APPRAISE_BUILD_POLICY=y
CONFIG_IMA_APPRAISE_REQUIRE_FIRMWARE_SIGS=y
CONFIG_IMA_APPRAISE_REQUIRE_KEXEC_SIGS=y
CONFIG_IMA_APPRAISE_REQUIRE_MODULE_SIGS=y
CONFIG_IMA_APPRAISE_REQUIRE_POLICY_SIGS=y
CONFIG_IMA_APPRAISE_BOOTPARAM=y
CONFIG_IMA_APPRAISE_MODSIG=y
CONFIG_IMA_TRUSTED_KEYRING=y
CONFIG_IMA_KEYRINGS_PERMIT_SIGNED_BY_BUILTIN_OR_SECONDARY=y
CONFIG_IMA_BLACKLIST_KEYRING=y
CONFIG_IMA_LOAD_X509=y
CONFIG_IMA_X509_PATH="/etc/keys/x509_ima.der"
CONFIG_IMA_APPRAISE_SIGNED_INIT is not set (This option breaks memory, do not select)
CONFIG_IMA_MEASURE_ASYMMETRIC_KEYS=y
CONFIG_IMA_QUEUE_EARLY_BOOT_KEYS=y
CONFIG_IMA_SECURE_AND_OR_TRUSTED_BOOT=y
CONFIG_IMA_DISABLE_HTABLE=y
CONFIG_EVM=y
CONFIG_EVM_ATTR_FSUUID=y
CONFIG_EVM_EXTRA_SMACK_XATTRS=y
CONFIG_EVM_ADD_XATTRS=y
CONFIG_EVM_LOAD_X509=y
CONFIG_EVM_X509_PATH="/etc/keys/x509_evm.der"

```
My system integrates this security 
https://sourceforge.net/projects/anti-ransomware/

Thank you very much



#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-12-08 13:29](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/75#issuecomment-1342739444):

Hello @JohnVengert,

1. As I understand, IMA doesn't have direct influence on Linux **kernel** security.
It's important for the userspace security, isn't it?

2. Does this functionality require any userspace support or actions to work?

3. You've provided a large list of options. Could you create a shortlist with the most important of them?

Thanks!


-------------------------------------------------------------------------------

# [\#74 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/74) `closed`: Add disabling compatibility mode.

#### <img src="https://avatars.githubusercontent.com/u/7232674?u=dba600128b18073a4e3c33b76f5c601591d8f613&v=4" width="50">[Manouchehri](https://github.com/Manouchehri) opened issue at [2022-10-20 22:00](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/74):

I'm not a kernel maintainer, so I added myself a new category. I don't think I'm wrong about this one though, here's a few public examples I found within a minute of searching:

https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
https://bugs.chromium.org/p/project-zero/issues/detail?id=1574
https://outflux.net/blog/archives/2010/10/19/cve-2010-2963-v4l-compat-exploit/
http://inertiawar.com/compat1/
http://inertiawar.com/compat2/

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-10-22 18:57](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/74#issuecomment-1287883856):

Hello @Manouchehri,

Thanks for your pull request and the idea.

I looked up. That's how `CONFIG_COMPAT` is currently implemented:
```
config COMPAT
	def_bool y
	depends on IA32_EMULATION || X86_X32_ABI
```
So we can't enable/disable it in the menuconfig directly.

The KSPP project already recommends disabling `IA32_EMULATION` and `X86_X32`:
```
CONFIG_IA32_EMULATION    |kconfig| is not set |   kspp   |cut_attack_surface
CONFIG_X86_X32           |kconfig| is not set |   kspp   |cut_attack_surface
```

So maybe adding a separate check for `COMPAT` is not needed.

But wait, `COMPAT` depends on `X86_X32_ABI` and not `X86_X32`.

There is a Linux kernel commit `83a44a4f47ad20997aebb311fc678a13cde391d7` (Mar 14 2022)
that renamed this config option. I will ask to update it at the KSPP wiki.
Then I will add a new check for `X86_X32_ABI`.

Thank you very much!

This case shows that from time to time we need to look up all config options that should be disabled.
Maybe some of them have been renamed in the Linux kernel.

#### <img src="https://avatars.githubusercontent.com/u/7232674?u=dba600128b18073a4e3c33b76f5c601591d8f613&v=4" width="50">[Manouchehri](https://github.com/Manouchehri) commented at [2022-10-22 19:02](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/74#issuecomment-1287884800):

CONFIG_COMPAT depends on the arch too. For example, neither `X86_X32_ABI` or `X86_X32` will cover arm64 systems.

```
menuconfig COMPAT
	bool "Kernel support for 32-bit EL0"
	depends on ARM64_4K_PAGES || EXPERT
```

https://github.com/torvalds/linux/blob/master/arch/arm64/Kconfig#L1526-L1542

I don't see the harm in a separate check for `COMPAT`. That flag has been around for years and not changed across architectures IIRC.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-10-22 19:06](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/74#issuecomment-1287885578):

That's a good point!
I'll return with the results.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-01-14 18:01](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/74#issuecomment-1382873066):

Hello @Manouchehri,

I contacted KSPP. Now their recommendations [contain](https://kernsec.org/wiki/index.php?title=Kernel_Self_Protection_Project%2FRecommended_Settings&action=historysubmit&type=revision&diff=4064&oldid=4060) disabling `CONFIG_COMPAT` and `CONFIG_X86_X32_ABI`.

Please see the commit https://github.com/a13xp0p0v/kconfig-hardened-check/commit/f3ba594b3acbc154eeade43d87a76b90352ab1d1, where I added these KSPP recommendations.

Thank you for the idea!
Closing the PR.


-------------------------------------------------------------------------------

# [\#73 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/73) `closed`: ERORR?

#### <img src="https://avatars.githubusercontent.com/u/77776927?v=4" width="50">[alpahca](https://github.com/alpahca) opened issue at [2022-09-24 15:03](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/73):

i was try to some book(Billimoria, Kaiwan N. Linux Kernel Debugging: Leverage proven tools and advanced techniques to effectively debug Linux kernels and kernel modules (p. 61). Packt Publishing. Kindle Edition. ).

but.

$ bin/kconfig-hardened-check -p X86_64 -c ~/lkd_kernels/kconfig.prod01/.config
[!] ERROR: --config and --print can't be used together

what should i do?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-09-24 21:18](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/73#issuecomment-1257066908):

Hi @alpahca,

Quoting `kconfig-hardened-check --help`:
```
  -p {X86_64,X86_32,ARM64,ARM}, --print {X86_64,X86_32,ARM64,ARM}
                        print security hardening preferences for the selected architecture
  -c CONFIG, --config CONFIG
                        check the kernel kconfig file against these preferences
```

So for checking your kernel config simply do this:
```
$ bin/kconfig-hardened-check -c ~/lkd_kernels/kconfig.prod01/.config
```

#### <img src="https://avatars.githubusercontent.com/u/77776927?v=4" width="50">[alpahca](https://github.com/alpahca) commented at [2022-10-11 07:42](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/73#issuecomment-1274233073):

Oh thx.
But... 
VirtualBox:~/lkd_kernels/kconfig_prod01$ '/home/ked/kconfig-hardened-check/bin/kconfig-hardened-check' -c '/home/ked/lkd_kernels/kconfig_prod01'
[+] Kconfig file to check: /home/ked/lkd_kernels/kconfig_prod01
Traceback (most recent call last):
File "/home/ked/kconfig-hardened-check/bin/kconfig-hardened-check", line 16, in
kconfig_hardened_check.main()
File "/home/ked/kconfig-hardened-check/kconfig_hardened_check/init.py", line 976, in main
arch, msg = detect_arch(args.config, supported_archs)
File "/home/ked/kconfig-hardened-check/kconfig_hardened_check/init.py", line 275, in detect_arch
with open(fname, 'r') as f:
IsADirectoryError: [Errno 21] Is a directory: '/home/ked/lkd_kernels/kconfig_prod01'
​
Uhm... that should be my problem?
​
-----Original Message-----
From: "Alexander ***@***.***>
To: ***@***.***>;
Cc: ***@***.***>; ***@***.***>;
Sent: 2022-09-25 (일) 06:18:44 (GMT+09:00)
Subject: Re: [a13xp0p0v/kconfig-hardened-check] ERORR? (Issue #73)

Hi @alpahca,
Quoting kconfig-hardened-check --help:
-p {X86_64,X86_32,ARM64,ARM}, --print {X86_64,X86_32,ARM64,ARM} print security hardening preferences for the selected architecture -c CONFIG, --config CONFIG check the kernel kconfig file against these preferences
So for checking your kernel config simply do this:
$ bin/kconfig-hardened-check -c ~/lkd_kernels/kconfig.prod01/.config
—
Reply to this email directly, view it on GitHub, or unsubscribe.
You are receiving this because you were mentioned.Message ID: ***@***.***>
​

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-10-22 19:27](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/73#issuecomment-1287890539):

Hi @alpahca,

Please try to use `-c` with the path to the kconfig file, not a directory.

Best regards,
Alexander


-------------------------------------------------------------------------------

# [\#71 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/71) `closed`: Config change in 5.19.X

#### <img src="https://avatars.githubusercontent.com/u/11868071?u=d7a5841263276e1f323827fc21b04345df594a60&v=4" width="50">[Churam](https://github.com/Churam) opened issue at [2022-08-31 08:18](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/71):

Hello,

The X86_SMAP option is no longer present in 5.19.X kernels. It is now enforced.
( [commit](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?h=v5.19.5&id=c5a3d3c01e90e74166f95eec9db6fcc3ba72a9d6) )

Since it has been removed, the script mark the entry as failed.
```
[+] Special report mode: show_fail
[+] Kconfig file to check: /opt/KERNEL/linux-5.19.5/.config
[+] Detected architecture: X86_64
[+] Detected kernel version: 5.19
=========================================================================================================================
              option name               | type  |desired val | decision |      reason      | check result
=========================================================================================================================
CONFIG_X86_SMAP                         |kconfig|     y      |defconfig | self_protection  | FAIL: not found
```



The GCC_PLUGIN_RANDSTRUCT and GCC_PLUGIN_RANDSTRUCT_PERFORMANCE have changed now that CLANG has the feature. ( [commit](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?h=linux-5.19.y&id=595b893e2087de306d0781795fb8ec47873596a6) ). They are now nammed RANDSTRUCT_FULL and RANDSTRUCT_PERFORMANCE respectively. 

At the moment they don't fail but the new entries should be added in the script I think. 
```
 grep RANDSTRUCT ./.config
# CONFIG_RANDSTRUCT_NONE is not set
CONFIG_RANDSTRUCT_FULL=y
# CONFIG_RANDSTRUCT_PERFORMANCE is not set
CONFIG_RANDSTRUCT=y
CONFIG_GCC_PLUGIN_RANDSTRUCT=y
```



#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-09-02 11:42](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/71#issuecomment-1235396338):

Hi @Churam,

Thanks for your report!

I've improved the checks, please have a look.

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2022-09-06 19:29](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/71#issuecomment-1238566204):

maybe it would make sense to tag a new release after :cat:

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-09-09 08:23](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/71#issuecomment-1241663085):

Hi @anthraxx,

I have a complex and time-consuming procedure for preparing the kconfig-hardened-check releases.

I’m planning to do this work for the next Linux kernel release.


-------------------------------------------------------------------------------

# [\#70 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/70) `closed`: COPR repo with built kernel with suggested recommendations

#### <img src="https://avatars.githubusercontent.com/u/75043245?u=158cd63a4ea78542e040508eaecc580f03cd2b98&v=4" width="50">[krishjainx](https://github.com/krishjainx) opened issue at [2022-07-21 15:19](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/70):

Hi. This repository has been incredibly useful to me as of late. I’m trying to do the following: create a COPR repository for example such that it takes the kernel configuration from Fedora’s latest kernel build for say 36 and then applies the recommended options here, handles setting everything on/off etc for everything that depends on that option and everything setting that option depends on while blacklisting certain recommendations such that it doesn’t break certain apps etc. Post doing this it would grab the source code for that kernel versions and build it with those configs and then one would just install the kernel normally.

How would one go about implementing this? Thank you!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-07-21 19:48](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/70#issuecomment-1191870587):

Hi Krish,

This approach can be called "creating a kernel flavour". Some distros do that.

For example, see:
 - Ubuntu kernel flavours: https://wiki.ubuntu.com/Kernel/Dev/Flavours
 - Suse kernel flavours: https://www.suse.com/support/kb/doc/?id=000017133
 - The discussion about NixOS hardened kernel: https://github.com/NixOS/nixpkgs/issues/76850

#### <img src="https://avatars.githubusercontent.com/u/75043245?u=158cd63a4ea78542e040508eaecc580f03cd2b98&v=4" width="50">[krishjainx](https://github.com/krishjainx) commented at [2022-07-21 22:18](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/70#issuecomment-1191988714):

Yes, thank you I understand that but how would I have your script/tool change the .config to be more hardened and then have that grab new kernel sources and automatically build like if I was to hold a COPR?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-07-22 21:00](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/70#issuecomment-1192931275):

Thanks Krish, now I see what you mean.

There is an enhancement #67. Maybe it would help to solve your task.
```
Create a tool that changes kconfig options according the recommendations
```
It should use the JSON output of `kconfig-hardened-check` and work with kconfig with [kconfiglib](https://pypi.org/project/kconfiglib/).

What do you think?

#### <img src="https://avatars.githubusercontent.com/u/75043245?u=158cd63a4ea78542e040508eaecc580f03cd2b98&v=4" width="50">[krishjainx](https://github.com/krishjainx) commented at [2022-07-23 03:10](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/70#issuecomment-1193047106):

For sure, this project is perhaps one of the best and most usable for kernel hardening and I would definitely be able to help if you can get started or others with implementing this. Thank you!

#### <img src="https://avatars.githubusercontent.com/u/75043245?u=158cd63a4ea78542e040508eaecc580f03cd2b98&v=4" width="50">[krishjainx](https://github.com/krishjainx) commented at [2022-07-23 03:12](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/70#issuecomment-1193047378):

It would be incredibly useful to instead of being developing sideways independent projects like linux-hardened or grsecurity to be working more close with upstream like you are - getting all the performance improvements, bug fixes and applying all available "vanilla" security fixes and pushing this to distributions using that tool. Then people can work off it. Even if it's not "revolutionary" I definitely believe in the long term it would help make Linux even better!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-07-24 15:44](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/70#issuecomment-1193343924):

I can't comment about `grsecurity`. This topic is complex... Anyway, they are pioneers in kernel security hardening.

The goal of `KSPP` is to develop kernel self-protection features for the mainline kernel. I hope my `kconfig-hardened-check` project also promotes these security features among Linux distros.


-------------------------------------------------------------------------------

# [\#69 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/69) `open`: Create documentation describing Linux kernel security options
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2022-07-04 10:43](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/69):



#### <img src="https://avatars.githubusercontent.com/u/106462796?v=4" width="50">[o8opi](https://github.com/o8opi) commented at [2023-04-09 20:27](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/69#issuecomment-1501206810):

Would love to see this, even if it's just a list of links and pointers to other resources :)

#### <img src="https://avatars.githubusercontent.com/u/75043245?u=158cd63a4ea78542e040508eaecc580f03cd2b98&v=4" width="50">[krishjainx](https://github.com/krishjainx) commented at [2024-03-14 13:41](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/69#issuecomment-1997489225):

@a13xp0p0v @o8opi Are you looking for something like this? https://www.kernelconfig.io/CONFIG_BUG

The general form is https://www.kernelconfig.io/**CONFIG_NAME**

#### <img src="https://avatars.githubusercontent.com/u/2813729?u=bac11ecbbd914d8254373bd39962b41c2c5ab2e3&v=4" width="50">[jbmaillet](https://github.com/jbmaillet) commented at [2024-03-15 09:31](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/69#issuecomment-1999263790):

https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings

Especially this page, but actually the whole site, an initiative from Kernel security maintainer Kees Cook:
https://lore.kernel.org/kernel-hardening/CAGXu5jJ3FgxXK9WuOLRwnEq=y4dS+CTm+WQBxWe3sYZ7e9p6Gg@mail.gmail.com/

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-03-16 21:32](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/69#issuecomment-2002141196):

@krishjainx, @jbmaillet, yes, I mean creating the documentation describing how the checked parameters influence Linux kernel security.

Another good example is CLIP OS documentation: https://docs.clip-os.org/clipos/kernel.html#configuration

I think of creating `doc` directory with markdown files describing Kconfig options, kernel cmdline arguments, and sysctl parameters.

#### <img src="https://avatars.githubusercontent.com/u/75043245?u=158cd63a4ea78542e040508eaecc580f03cd2b98&v=4" width="50">[krishjainx](https://github.com/krishjainx) commented at [2024-03-18 02:52](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/69#issuecomment-2002781626):

@a13xp0p0v That sounds like a great idea! That's a lot of checked parameters, however, we should try to automate it so we can do it at scale. What do you think? There's reliable kernel documentation out there we could parse?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-03-24 13:48](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/69#issuecomment-2016815988):

@krishjainx , yes, some part of this work can be automated.

For `self_protection`, `security_policy`, and `harden_userspace` parameters, the Kconfig descriptions and [kernel documentation](https://docs.kernel.org/admin-guide) contain some security-relevant info.
Example: https://cateee.net/lkddb/web-lkddb/CFI_CLANG.html

But for `cut_attack_surface` parameters, the kernel documentation doesn't say much about the security implications.

#### <img src="https://avatars.githubusercontent.com/u/325724?u=4446b76c0f4ebcbecb2678759f8d13817a67f85d&v=4" width="50">[jvoisin](https://github.com/jvoisin) commented at [2024-04-15 12:21](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/69#issuecomment-2056723547):

> But for cut_attack_surface parameters, the kernel documentation doesn't say much about the security implications.

I think it would make sense to add some info upstream in the Kconfig description. Ideally we should be able to run a glorified `grep` on the Kconfig and generate proper documentation.

#### <img src="https://avatars.githubusercontent.com/u/23032146?u=b7f1c1c76eb3090e07f73ed855b136435d577db6&v=4" width="50">[jo-so](https://github.com/jo-so) commented at [2025-01-11 17:10](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/69#issuecomment-2585344565):

There is also [Linux Hardening Guide | Madaidan's Insecurities](https://madaidans-insecurities.github.io/guides/linux-hardening.html) which describes options like [hidepid](https://madaidans-insecurities.github.io/guides/linux-hardening.html#hidepid).


-------------------------------------------------------------------------------

# [\#68 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/68) `closed`: Create a tool reporting mainline kernel versions that support a recommended option
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2022-07-04 00:34](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/68):



#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-07-17 15:25](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/68#issuecomment-1186547339):

The LKDDb project solves this task. Added info to the README.

Good. Closing the issue.


-------------------------------------------------------------------------------

# [\#67 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/67) `closed`: Create a tool that changes kconfig options according to the recommendations
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2022-07-04 00:25](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/67):

It should use the JSON output of kconfig-hardened-check.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-07-17 13:43](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/67#issuecomment-1186522515):

See https://pypi.org/project/kconfiglib/

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-02-17 16:06](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/67#issuecomment-1434854140):

That tool would also help to filter out the kconfig options that can't be enabled for the given kernel version.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-06-12 15:32](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/67#issuecomment-1587577476):

This feature is implemented as a part of the `kconfig-hardened-check` tool.

With the `-g` argument, the tool generates a Kconfig fragment with the security hardening options for the selected microarchitecture.

This Kconfig fragment can be merged with the existing Linux kernel config:

```
$ ./bin/kconfig-hardened-check -g X86_64 > /tmp/fragment
$ cd ~/linux-src/
$ ./scripts/kconfig/merge_config.sh .config /tmp/fragment
Using .config as base
Merging /tmp/fragment
Value of CONFIG_BUG_ON_DATA_CORRUPTION is redefined by fragment /tmp/fragment:
Previous value: # CONFIG_BUG_ON_DATA_CORRUPTION is not set
New value: CONFIG_BUG_ON_DATA_CORRUPTION=y
 ...
```


-------------------------------------------------------------------------------

# [\#66 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/66) `open`: Evaluate performance penalty of the recommended kernel options
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2022-07-03 09:57](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/66):

As the first step, @BlackIkeEagle made some performance tests and described the results in [this article](https://blog.herecura.eu/blog/2020-05-30-kconfig-hardening-tests/).

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-12-08 14:46](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/66#issuecomment-1342846087):

Create a solution for automating this process:
 1. Take defconfig as a basic kernel configuration.
 2. Build the Linux kernel.
 3. Start test system with this kernel (a hardware machine may give more consistent results than a virtual machine). If the system doesn't boot, go to step 6.
 4. Run the chosen performance tests (hackbench, kernel compilation, network throughput evaluation, etc).
 5. Save the test results.
 6. Set another kernel option from the kconfig-hardened-check json output and go to step 2 (see #67). If all recommendations are already tested, then proceed to step 7.
 7. Analyze the results of the performance testing.

That approach would save us from plenty of boring manual routine.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-12-08 18:58](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/66#issuecomment-1343190811):

Similar performance testing of a group of  security hardening options may give interesting results as well.


-------------------------------------------------------------------------------

# [\#65 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/65) `closed`: Support checking sysctl security options
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2022-07-03 09:50](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/65):

The `OptCheck` class inheritance now allows to implement this feature.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-08-14 12:36](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/65#issuecomment-1677237521):

Checking sysctl parameters is supported now:
```
$ ./bin/kconfig-hardened-check 
usage: kconfig-hardened-check [-h] [--version] [-m {verbose,json,show_ok,show_fail}]
                              [-c CONFIG] [-l CMDLINE] [-s SYSCTL]
                              [-p {X86_64,X86_32,ARM64,ARM}]
                              [-g {X86_64,X86_32,ARM64,ARM}]

A tool for checking the security hardening options of the Linux kernel

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -m {verbose,json,show_ok,show_fail}, --mode {verbose,json,show_ok,show_fail}
                        choose the report mode
  -c CONFIG, --config CONFIG
                        check the security hardening options in the kernel Kconfig file
                        (also supports *.gz files)
  -l CMDLINE, --cmdline CMDLINE
                        check the security hardening options in the kernel cmdline file
                        (contents of /proc/cmdline)
  -s SYSCTL, --sysctl SYSCTL
                        check the security hardening options in the sysctl output file
                        (`sudo sysctl -a > file`)
  -p {X86_64,X86_32,ARM64,ARM}, --print {X86_64,X86_32,ARM64,ARM}
                        print the security hardening recommendations for the selected
                        microarchitecture
  -g {X86_64,X86_32,ARM64,ARM}, --generate {X86_64,X86_32,ARM64,ARM}
                        generate a Kconfig fragment with the security hardening options
                        for the selected microarchitecture
```


-------------------------------------------------------------------------------

# [\#64 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/64) `closed`: script fetch configs from different kernel images for current architecture

#### <img src="https://avatars.githubusercontent.com/u/106462796?v=4" width="50">[o8opi](https://github.com/o8opi) opened issue at [2022-06-01 06:34](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/64):

This script now tries to fetch and/or build the different kernel images for current architecture and derive the kernel configs from them

#### <img src="https://avatars.githubusercontent.com/u/106462796?v=4" width="50">[o8opi](https://github.com/o8opi) commented at [2022-06-01 06:36](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/64#issuecomment-1143174866):

This might resolve #63

#### <img src="https://avatars.githubusercontent.com/u/65553080?u=b7ee84d82e25b493051d810390e97b15f716d7ef&v=4" width="50">[codecov-commenter](https://github.com/codecov-commenter) commented at [2022-06-08 15:30](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/64#issuecomment-1150072367):

# [Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/64?src=pr&el=h1&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) Report
> Merging [#64](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/64?src=pr&el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (86b6b08) into [master](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/commit/0d5c56f297fca50a48dfc602a5b4118b8ebdbceb?el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (0d5c56f) will **not change** coverage.
> The diff coverage is `n/a`.

```diff
@@           Coverage Diff           @@
##           master      #64   +/-   ##
=======================================
  Coverage   98.08%   98.08%           
=======================================
  Files           3        3           
  Lines         625      625           
  Branches      139      139           
=======================================
  Hits          613      613           
  Misses          5        5           
  Partials        7        7           
```

| Flag | Coverage Δ | |
|---|---|---|
| functional_test | `98.08% <ø> (ø)` | |

Flags with carried forward coverage won't be shown. [Click here](https://docs.codecov.io/docs/carryforward-flags?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#carryforward-flags-in-the-pull-request-comment) to find out more.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-06-10 16:49](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/64#issuecomment-1152552051):

Hello @o8opi,

I tried your version of this script in a Docker container with Ubuntu 20.04.2.

It failed with the error:
```
...
copying path '/nix/store/l920bx9bw37jd681pk98dfra0j3lanva-libarchive-3.6.1-lib' from 'https://cache.nixos.org'...
copying path '/nix/store/km0c80plib16fp76prmhcdwbag9iqnvf-nix-2.9.1' from 'https://cache.nixos.org'...
copying path '/nix/store/0szyscpg632p7vlj9if5gadwlvwcb91d-nix-2.9.1-dev' from 'https://cache.nixos.org'...
building '/nix/store/yz1y19d71lp53jymd51h4qw9c2663x6a-builder.pl.drv'...
building '/nix/store/c539pzdghlrfcik2qymswm30ycbdj3yz-python3-3.9.13-env.drv'...
created 226 symlinks in user environment
Traceback (most recent call last):
  File "/home/a13x/src/kconfig-hardened-check/contrib/./get-nix-kconfig.py", line 61, in <module>
    main()
  File "/home/a13x/src/kconfig-hardened-check/contrib/./get-nix-kconfig.py", line 16, in main
    data = json.loads(proc.stdout)
  File "/nix/store/553d7c4xcwp9j1a1gb9cb1s9ry3x1pi9-python3-3.9.13/lib/python3.9/json/__init__.py", line 346, in loads
    return _default_decoder.decode(s)
  File "/nix/store/553d7c4xcwp9j1a1gb9cb1s9ry3x1pi9-python3-3.9.13/lib/python3.9/json/decoder.py", line 337, in decode
    obj, end = self.raw_decode(s, idx=_w(s, 0).end())
  File "/nix/store/553d7c4xcwp9j1a1gb9cb1s9ry3x1pi9-python3-3.9.13/lib/python3.9/json/decoder.py", line 355, in raw_decode
    raise JSONDecodeError("Expecting value", s, err.value) from None
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
```

It looks like ` json.loads()` didn't manage to handle the output of `nix search`.

#### <img src="https://avatars.githubusercontent.com/u/106462796?v=4" width="50">[o8opi](https://github.com/o8opi) commented at [2022-07-16 11:53](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/64#issuecomment-1186164603):

this should work better now

#### <img src="https://avatars.githubusercontent.com/u/106462796?v=4" width="50">[o8opi](https://github.com/o8opi) commented at [2022-07-17 21:53](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/64#issuecomment-1186613685):

I have tested in an Ubuntu-20.04 container and it worked for me, can share Dockerfile if needed :)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-07-21 19:38](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/64#issuecomment-1191862516):

Hello @o8opi,

Now it works better, but gives a bunch of other errors:
```
created 223 symlinks in user environment
extract-vmlinux: Cannot find vmlinux.
Usage: extract-ikconfig <kernel-image>
failed to extract config from legacyPackages.x86_64-linux.linuxPackages_5_10_hardened.kernel
extract-vmlinux: Cannot find vmlinux.
Usage: extract-ikconfig <kernel-image>
failed to extract config from legacyPackages.x86_64-linux.linuxPackages_5_15_hardened.kernel
extract-vmlinux: Cannot find vmlinux.
Usage: extract-ikconfig <kernel-image>
failed to extract config from legacyPackages.x86_64-linux.linuxPackages_5_18_hardened.kernel
extract-vmlinux: Cannot find vmlinux.
Usage: extract-ikconfig <kernel-image>
failed to extract config from legacyPackages.x86_64-linux.linuxPackages_hardened.kernel
error: Package ‘linux-4.14.180-176’ in /nix/store/xcba8ikxvdzw7ycg5ncnfq37w9491cn9-source/pkgs/os-specific/linux/kernel/linux-hardkernel-4.14.nix:4 is not supported on ‘x86_64-linux’, refusing to evaluate.

       a) To temporarily allow packages that are unsupported for this system, you can use an environment variable
          for a single invocation of the nix tools.

            $ export NIXPKGS_ALLOW_UNSUPPORTED_SYSTEM=1

        Note: For `nix shell`, `nix build`, `nix develop` or any other Nix 2.4+
        (Flake) command, `--impure` must be passed in order to read this
        environment variable.

       b) For `nixos-rebuild` you can set
         { nixpkgs.config.allowUnsupportedSystem = true; }
       in configuration.nix to override this.

       c) For `nix-env`, `nix-build`, `nix-shell` or any other Nix command you can add
         { allowUnsupportedSystem = true; }
       to ~/.config/nixpkgs/config.nix.
(use '--show-trace' to show detailed location information)
failed to build legacyPackages.x86_64-linux.linuxPackages_hardkernel_latest.kernel
extract-vmlinux: Cannot find vmlinux.
Usage: extract-ikconfig <kernel-image>
failed to extract config from legacyPackages.x86_64-linux.linuxPackages_latest.kernel
extract-vmlinux: Cannot find vmlinux.
Usage: extract-ikconfig <kernel-image>
failed to extract config from legacyPackages.x86_64-linux.linuxPackages_latest-libre.kernel
extract-vmlinux: Cannot find vmlinux.
Usage: extract-ikconfig <kernel-image>
failed to extract config from legacyPackages.x86_64-linux.linuxPackages_lqx.kernel
error: Package ‘linux-5.18.12-bcachefs-unstable-2022-04-25’ in /nix/store/xcba8ikxvdzw7ycg5ncnfq37w9491cn9-source/pkgs/os-specific/linux/kernel/linux-testing-bcachefs.nix:15 is marked as broken, refusing to evaluate.

       a) To temporarily allow broken packages, you can use an environment variable
          for a single invocation of the nix tools.

            $ export NIXPKGS_ALLOW_BROKEN=1

        Note: For `nix shell`, `nix build`, `nix develop` or any other Nix 2.4+
        (Flake) command, `--impure` must be passed in order to read this
        environment variable.

       b) For `nixos-rebuild` you can set
         { nixpkgs.config.allowBroken = true; }
       in configuration.nix to override this.

       c) For `nix-env`, `nix-build`, `nix-shell` or any other Nix command you can add
         { allowBroken = true; }
       to ~/.config/nixpkgs/config.nix.
(use '--show-trace' to show detailed location information)
failed to build legacyPackages.x86_64-linux.linuxPackages_testing_bcachefs.kernel
extract-vmlinux: Cannot find vmlinux.
Usage: extract-ikconfig <kernel-image>
failed to extract config from legacyPackages.x86_64-linux.linuxPackages_xanmod.kernel
extract-vmlinux: Cannot find vmlinux.
Usage: extract-ikconfig <kernel-image>
failed to extract config from legacyPackages.x86_64-linux.linuxPackages_xanmod_latest.kernel
extract-vmlinux: Cannot find vmlinux.
Usage: extract-ikconfig <kernel-image>
failed to extract config from legacyPackages.x86_64-linux.linuxPackages_zen.kernel
```

I see at least three different kinds of errors here.
Could you have a look?

I would also ask you to rebase your branch over `origin/master`.

Thanks!


-------------------------------------------------------------------------------

# [\#63 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/63) `closed`: Fix getting Nix kconfig (contrib)
**Labels**: `bug/fix`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2022-04-27 23:30](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/63):

Hello @Mic92, could you help with this Nix problem?

I tested the installation of `kconfig-hardened-check` in a Docker container with Ubuntu 20.04.4 LTS.

It failed with the following error:

```
a13x@dc92d9d74557:~/src/1/kconfig-hardened-check/contrib$ ./get-nix-kconfig.py 
these 50 paths will be fetched (94.58 MiB download, 374.80 MiB unpacked):
  /nix/store/058drky7qcyd04rzqcmxh86xmifw96dx-glibc-2.34-115-bin
  /nix/store/1442kn5q9ah0bhhqm99f8nr76diczqgm-gnused-4.8
  /nix/store/19xbyxc31snlk60cil7cx6l4xw126ids-gcc-11.2.0
  /nix/store/4r26nvzfa1qfjaqgr2bpw2fz8c6qnk3s-gnutar-1.34
  /nix/store/58pwclg9yr437h0pfgrnbd0jis8fqasd-gcc-wrapper-11.2.0
  /nix/store/5h6q8cmqjd8iqpd99566hrg2a56pwdkc-acl-2.3.1
  /nix/store/6rbwy3mf0w8z119bwqs7dcrc2vyql9sf-expand-response-params
  /nix/store/7b2vmi7cq7lzw8g6kaihzg2kyilj4slm-bash-interactive-5.1-p16-dev
  /nix/store/87xq1difvspida4391y23vylkjdcgllf-linux-headers-5.16
  /nix/store/9l06npv9sp8avdraahzi4kqhcp607d8p-tzdata-2022a
  /nix/store/9pxskbhf92x9cxvg87nbzw2q1kmkrym6-bash-interactive-5.1-p16-info
  /nix/store/9wq21cbqsxpdx4dk0q6gab00fcir04d1-gzip-1.12
  /nix/store/a0k6rfn47h9f69p15pg415x6pfpxhsl5-gdbm-1.23
  /nix/store/a5xpjds3mlln26469h72v1jmd00jq6lv-xz-5.2.5
  /nix/store/ayrsyv7npr0lcbann4k9lxr19x813f0z-glibc-2.34-115
  /nix/store/b36ilvc5hhfpcp7kv1kvrkgcxxpmxfsd-zlib-1.2.12
  /nix/store/bavmqg7c4366hbiccpsdawbilh68dajy-xz-5.2.5-bin
  /nix/store/bndvc0y3v4djij152wiqbyn13zs2xivy-pcre-8.45
  /nix/store/bqkx3pi50phcglv0l551jhp96bq8njl0-gnugrep-3.7
  /nix/store/c7062r0rh84w3v77pqwdcggrsdlvy1df-findutils-4.9.0
  /nix/store/clkdigybx5w29rjxnwnsk76q49gb12k7-ncurses-6.3
  /nix/store/d60gkg5dkw4y5kc055n4m0xyvcjz65im-bash-interactive-5.1-p16
  /nix/store/dgic5ks4yixhh0havidjwd02rskmqlgp-binutils-wrapper-2.38
  /nix/store/dxj6b99zh4fh5z65rqirmcfvffxx5ig0-readline-8.1p2
  /nix/store/f2fnhhjanmxganm3xa5inwgvi6wj2ran-bash-interactive-5.1-p16-doc
  /nix/store/fcd0m68c331j7nkdxvnnpb8ggwsaiqac-bash-5.1-p16
  /nix/store/gm6q7jmajjmnwd29wgbq2jm3x37vsw3h-libffi-3.4.2
  /nix/store/hgl0ydlkgs6y6hx9h7k209shw3v7z77j-coreutils-9.0
  /nix/store/hym1n0ygqp9wcm7pxn4sfrql3fg7xa09-python3-3.9.12
  /nix/store/ik4qlj53grwmg7avzrfrn34bjf6a30ch-libunistring-1.0
  /nix/store/jm3nxvmxcm5nvalbv28acvygismcykvj-gnumake-4.3
  /nix/store/k3wp5kdxwa4ysb6nh5y9yll5n30cja5m-patch-2.7.6
  /nix/store/m2vh2ny7bqpwij1gpmvl5gxj7y4dgr4f-binutils-2.38
  /nix/store/n239ln3v669s5fkir2fd8niqawyg6qrv-attr-2.5.1
  /nix/store/pmyiksh5sgqzakbr84qsfxqy8fgirmic-stdenv-linux
  /nix/store/psijdi9190zgbp053y6dj3ax4y2l70gk-gcc-11.2.0-lib
  /nix/store/pvn23vycg674bj6nypjcfyhqbr85rqxa-glibc-2.34-115-dev
  /nix/store/qd3g8rk5hx5zkb70idjh6fa12sh6bipg-mailcap-2.1.53
  /nix/store/qvs678k05yrv566dmqdnxfbzi4s6ir1n-sqlite-3.38.2
  /nix/store/rf3j3p8cvn0dr5wdl65ns9f8wnlca8h6-readline-6.3p08
  /nix/store/sj2plsn7wz94dkwvg1wlb11pjch6r70v-diffutils-3.8
  /nix/store/v8vpzh3slc5hm4d9id5bim4dsb4d2ndh-openssl-1.1.1n
  /nix/store/v990x4cib4dssspn4778rlz46jmm3a9k-expat-2.4.7
  /nix/store/vz05jxs509mgp5i5jbrgvgvg4a2p3a3m-ed-1.18
  /nix/store/w3zngkrag7vnm7v1q8vnqb71q6a1w8gn-libidn2-2.3.2
  /nix/store/wcj03nlvxsjrc1cmpl2nhpn80l5wvf8j-gawk-5.1.1
  /nix/store/x6jr3j9hxs8ld8cy69gy9aykrm3iz8rv-patchelf-0.14.5
  /nix/store/yjndwl7872iqhw7m97gv7kwgwd5d66s5-bzip2-1.0.6.0.2-bin
  /nix/store/zf03nlnk9h724gz7qzzbrzyqif8gbwhq-bzip2-1.0.6.0.2
  /nix/store/zghsxxqb2gyz460q4r7jfdc2lpg3rgjw-bash-interactive-5.1-p16-man
copying path '/nix/store/f2fnhhjanmxganm3xa5inwgvi6wj2ran-bash-interactive-5.1-p16-doc' from 'https://cache.nixos.org'...
copying path '/nix/store/9pxskbhf92x9cxvg87nbzw2q1kmkrym6-bash-interactive-5.1-p16-info' from 'https://cache.nixos.org'...
copying path '/nix/store/zghsxxqb2gyz460q4r7jfdc2lpg3rgjw-bash-interactive-5.1-p16-man' from 'https://cache.nixos.org'...
copying path '/nix/store/ik4qlj53grwmg7avzrfrn34bjf6a30ch-libunistring-1.0' from 'https://cache.nixos.org'...
copying path '/nix/store/87xq1difvspida4391y23vylkjdcgllf-linux-headers-5.16' from 'https://cache.nixos.org'...
copying path '/nix/store/w3zngkrag7vnm7v1q8vnqb71q6a1w8gn-libidn2-2.3.2' from 'https://cache.nixos.org'...
copying path '/nix/store/qd3g8rk5hx5zkb70idjh6fa12sh6bipg-mailcap-2.1.53' from 'https://cache.nixos.org'...
copying path '/nix/store/ayrsyv7npr0lcbann4k9lxr19x813f0z-glibc-2.34-115' from 'https://cache.nixos.org'...
copying path '/nix/store/9l06npv9sp8avdraahzi4kqhcp607d8p-tzdata-2022a' from 'https://cache.nixos.org'...
copying path '/nix/store/n239ln3v669s5fkir2fd8niqawyg6qrv-attr-2.5.1' from 'https://cache.nixos.org'...
copying path '/nix/store/fcd0m68c331j7nkdxvnnpb8ggwsaiqac-bash-5.1-p16' from 'https://cache.nixos.org'...
copying path '/nix/store/5h6q8cmqjd8iqpd99566hrg2a56pwdkc-acl-2.3.1' from 'https://cache.nixos.org'...
copying path '/nix/store/zf03nlnk9h724gz7qzzbrzyqif8gbwhq-bzip2-1.0.6.0.2' from 'https://cache.nixos.org'...
copying path '/nix/store/hgl0ydlkgs6y6hx9h7k209shw3v7z77j-coreutils-9.0' from 'https://cache.nixos.org'...
copying path '/nix/store/yjndwl7872iqhw7m97gv7kwgwd5d66s5-bzip2-1.0.6.0.2-bin' from 'https://cache.nixos.org'...
copying path '/nix/store/sj2plsn7wz94dkwvg1wlb11pjch6r70v-diffutils-3.8' from 'https://cache.nixos.org'...
copying path '/nix/store/vz05jxs509mgp5i5jbrgvgvg4a2p3a3m-ed-1.18' from 'https://cache.nixos.org'...
copying path '/nix/store/6rbwy3mf0w8z119bwqs7dcrc2vyql9sf-expand-response-params' from 'https://cache.nixos.org'...
copying path '/nix/store/v990x4cib4dssspn4778rlz46jmm3a9k-expat-2.4.7' from 'https://cache.nixos.org'...
copying path '/nix/store/c7062r0rh84w3v77pqwdcggrsdlvy1df-findutils-4.9.0' from 'https://cache.nixos.org'...
copying path '/nix/store/wcj03nlvxsjrc1cmpl2nhpn80l5wvf8j-gawk-5.1.1' from 'https://cache.nixos.org'...
copying path '/nix/store/psijdi9190zgbp053y6dj3ax4y2l70gk-gcc-11.2.0-lib' from 'https://cache.nixos.org'...
copying path '/nix/store/a0k6rfn47h9f69p15pg415x6pfpxhsl5-gdbm-1.23' from 'https://cache.nixos.org'...
copying path '/nix/store/058drky7qcyd04rzqcmxh86xmifw96dx-glibc-2.34-115-bin' from 'https://cache.nixos.org'...
copying path '/nix/store/jm3nxvmxcm5nvalbv28acvygismcykvj-gnumake-4.3' from 'https://cache.nixos.org'...
copying path '/nix/store/pvn23vycg674bj6nypjcfyhqbr85rqxa-glibc-2.34-115-dev' from 'https://cache.nixos.org'...
copying path '/nix/store/1442kn5q9ah0bhhqm99f8nr76diczqgm-gnused-4.8' from 'https://cache.nixos.org'...
copying path '/nix/store/4r26nvzfa1qfjaqgr2bpw2fz8c6qnk3s-gnutar-1.34' from 'https://cache.nixos.org'...
copying path '/nix/store/9wq21cbqsxpdx4dk0q6gab00fcir04d1-gzip-1.12' from 'https://cache.nixos.org'...
copying path '/nix/store/gm6q7jmajjmnwd29wgbq2jm3x37vsw3h-libffi-3.4.2' from 'https://cache.nixos.org'...
copying path '/nix/store/clkdigybx5w29rjxnwnsk76q49gb12k7-ncurses-6.3' from 'https://cache.nixos.org'...
copying path '/nix/store/v8vpzh3slc5hm4d9id5bim4dsb4d2ndh-openssl-1.1.1n' from 'https://cache.nixos.org'...
copying path '/nix/store/k3wp5kdxwa4ysb6nh5y9yll5n30cja5m-patch-2.7.6' from 'https://cache.nixos.org'...
copying path '/nix/store/x6jr3j9hxs8ld8cy69gy9aykrm3iz8rv-patchelf-0.14.5' from 'https://cache.nixos.org'...
copying path '/nix/store/bndvc0y3v4djij152wiqbyn13zs2xivy-pcre-8.45' from 'https://cache.nixos.org'...
copying path '/nix/store/rf3j3p8cvn0dr5wdl65ns9f8wnlca8h6-readline-6.3p08' from 'https://cache.nixos.org'...
copying path '/nix/store/bqkx3pi50phcglv0l551jhp96bq8njl0-gnugrep-3.7' from 'https://cache.nixos.org'...
copying path '/nix/store/dxj6b99zh4fh5z65rqirmcfvffxx5ig0-readline-8.1p2' from 'https://cache.nixos.org'...
copying path '/nix/store/a5xpjds3mlln26469h72v1jmd00jq6lv-xz-5.2.5' from 'https://cache.nixos.org'...
copying path '/nix/store/d60gkg5dkw4y5kc055n4m0xyvcjz65im-bash-interactive-5.1-p16' from 'https://cache.nixos.org'...
copying path '/nix/store/bavmqg7c4366hbiccpsdawbilh68dajy-xz-5.2.5-bin' from 'https://cache.nixos.org'...
copying path '/nix/store/7b2vmi7cq7lzw8g6kaihzg2kyilj4slm-bash-interactive-5.1-p16-dev' from 'https://cache.nixos.org'...
copying path '/nix/store/b36ilvc5hhfpcp7kv1kvrkgcxxpmxfsd-zlib-1.2.12' from 'https://cache.nixos.org'...
copying path '/nix/store/m2vh2ny7bqpwij1gpmvl5gxj7y4dgr4f-binutils-2.38' from 'https://cache.nixos.org'...
copying path '/nix/store/19xbyxc31snlk60cil7cx6l4xw126ids-gcc-11.2.0' from 'https://cache.nixos.org'...
copying path '/nix/store/dgic5ks4yixhh0havidjwd02rskmqlgp-binutils-wrapper-2.38' from 'https://cache.nixos.org'...
copying path '/nix/store/qvs678k05yrv566dmqdnxfbzi4s6ir1n-sqlite-3.38.2' from 'https://cache.nixos.org'...
copying path '/nix/store/58pwclg9yr437h0pfgrnbd0jis8fqasd-gcc-wrapper-11.2.0' from 'https://cache.nixos.org'...
copying path '/nix/store/hym1n0ygqp9wcm7pxn4sfrql3fg7xa09-python3-3.9.12' from 'https://cache.nixos.org'...

copying path '/nix/store/pmyiksh5sgqzakbr84qsfxqy8fgirmic-stdenv-linux' from 'https://cache.nixos.org'...
Traceback (most recent call last):
  File "/home/a13x/src/1/kconfig-hardened-check/contrib/./get-nix-kconfig.py", line 30, in <module>
    main()
  File "/home/a13x/src/1/kconfig-hardened-check/contrib/./get-nix-kconfig.py", line 16, in main
    data = json.loads(proc.stdout)
  File "/nix/store/hym1n0ygqp9wcm7pxn4sfrql3fg7xa09-python3-3.9.12/lib/python3.9/json/__init__.py", line 346, in loads
    return _default_decoder.decode(s)
  File "/nix/store/hym1n0ygqp9wcm7pxn4sfrql3fg7xa09-python3-3.9.12/lib/python3.9/json/decoder.py", line 337, in decode
    obj, end = self.raw_decode(s, idx=_w(s, 0).end())
  File "/nix/store/hym1n0ygqp9wcm7pxn4sfrql3fg7xa09-python3-3.9.12/lib/python3.9/json/decoder.py", line 355, in raw_decode
    raise JSONDecodeError("Expecting value", s, err.value) from None
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
```

Hoping for your help with Nix, @Mic92!

#### <img src="https://avatars.githubusercontent.com/u/106462796?v=4" width="50">[o8opi](https://github.com/o8opi) commented at [2022-12-28 21:16](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/63#issuecomment-1366920764):

Hello, is this still relevant ?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-12-28 22:11](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/63#issuecomment-1366954405):

Hello @o8opi,

It would be nice to fix this script or remove it.

Is it possible to get a Nix kernel config somewhere without building the Linux kernel for NixOS?

Thank you!

#### <img src="https://avatars.githubusercontent.com/u/96200?u=9ed15c85825694d00e996d605d728179b830c4fa&v=4" width="50">[Mic92](https://github.com/Mic92) commented at [2022-12-29 10:00](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/63#issuecomment-1367202486):

The script was fixed in https://github.com/a13xp0p0v/kconfig-hardened-check/pull/78

#### <img src="https://avatars.githubusercontent.com/u/96200?u=9ed15c85825694d00e996d605d728179b830c4fa&v=4" width="50">[Mic92](https://github.com/Mic92) commented at [2022-12-29 10:01](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/63#issuecomment-1367203173):

I don't think the kernel config can be easily get otherwise. It is generated by nix code depending on enabled features and kernel versions.

#### <img src="https://avatars.githubusercontent.com/u/96200?u=9ed15c85825694d00e996d605d728179b830c4fa&v=4" width="50">[Mic92](https://github.com/Mic92) commented at [2022-12-29 10:02](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/63#issuecomment-1367204327):

However there is https://github.com/cachix/install-nix-action combined https://github.com/marketplace/actions/create-pull-request could automatically keep this up-to-date.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-01-19 16:15](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/63#issuecomment-1397233625):

Hello @Mic92,

Closing, this issue has been fixed in https://github.com/a13xp0p0v/kconfig-hardened-check/pull/77.

Thanks!


-------------------------------------------------------------------------------

# [\#62 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/62) `merged`: Add BLK_DEV_FD_RAWCMD

#### <img src="https://avatars.githubusercontent.com/u/150761?u=f98bb82be5009ecefd6ee9bc3d60fcf082f8cf49&v=4" width="50">[evdenis](https://github.com/evdenis) opened issue at [2022-04-27 18:15](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/62):

See commit torvalds/linux@233087ca0636 ("floppy: disable FDRAWCMD by default")

Signed-off-by: Denis Efremov <efremov@linux.com>

#### <img src="https://avatars.githubusercontent.com/u/65553080?u=b7ee84d82e25b493051d810390e97b15f716d7ef&v=4" width="50">[codecov-commenter](https://github.com/codecov-commenter) commented at [2022-04-27 18:16](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/62#issuecomment-1111331853):

# [Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/62?src=pr&el=h1&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) Report
> Merging [#62](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/62?src=pr&el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (bbe60e7) into [master](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/commit/61bfef8931bcefc1abb6d3d46e169c8372ce729b?el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (61bfef8) will **increase** coverage by `0.01%`.
> The diff coverage is `100.00%`.

```diff
@@            Coverage Diff             @@
##           master      #62      +/-   ##
==========================================
+ Coverage   90.32%   90.33%   +0.01%     
==========================================
  Files           3        3              
  Lines         589      590       +1     
  Branches      137      137              
==========================================
+ Hits          532      533       +1     
  Misses         29       29              
  Partials       28       28              
```

| Flag | Coverage Δ | |
|---|---|---|
| functional_test | `90.33% <100.00%> (+0.01%)` | :arrow_up: |

Flags with carried forward coverage won't be shown. [Click here](https://docs.codecov.io/docs/carryforward-flags?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#carryforward-flags-in-the-pull-request-comment) to find out more.

| [Impacted Files](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/62?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) | Coverage Δ | |
|---|---|---|
| [kconfig\_hardened\_check/\_\_init\_\_.py](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/62/diff?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#diff-a2NvbmZpZ19oYXJkZW5lZF9jaGVjay9fX2luaXRfXy5weQ==) | `90.34% <100.00%> (+0.01%)` | :arrow_up: |

------

[Continue to review full report at Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/62?src=pr&el=continue&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov).
> **Legend** - [Click here to learn more](https://docs.codecov.io/docs/codecov-delta?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)
> `Δ = absolute <relative> (impact)`, `ø = not affected`, `? = missing data`
> Powered by [Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/62?src=pr&el=footer&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov). Last update [61bfef8...bbe60e7](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/62?src=pr&el=lastupdated&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov). Read the [comment docs](https://docs.codecov.io/docs/pull-request-comments?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov).

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-04-28 11:41](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/62#issuecomment-1112102364):

Thanks @evdenis!
👍


-------------------------------------------------------------------------------

# [\#61 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/61) `closed`: Let user select configs without absolute path

#### <img src="https://avatars.githubusercontent.com/u/29118926?v=4" width="50">[dmknght](https://github.com/dmknght) opened issue at [2022-03-26 15:15](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/61):

## System info:
Parrot OS 5.0, python 3
kconfig-hardened-check version 5.14
I've tried all options in help menu and I didn't find anything similar to my idea

## Idea
1. Create an option to list all config. Maybe it supports search as well.
2. Let user select module without absolute path. For example, when I do Debian packaging for this tool, the configs are at `/usr/lib/python3/dist-packages/kconfig_hardened_check/config_files/` and users don't know where to search configs / modules.
Solution:
1. Add a `__init__.py` file into `config_files`. By this, folder `configs` is a module of the whole project.
2. You can do `from kconfig-hardnerned-check.<any path> import config_files`. Absolute path of the module will be `config_files.__path__[0]`
3. All modules are listed by `walk_dir(config_files.__path__[0])`. By this, you can have an option in argv to list all configs
4. When user provide `-c` flag, like `-c distros/debian.config`, absolute path is merged with `config_files.__path__[0]` so there's no need to know absolute path.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-04-08 18:06](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/61#issuecomment-1093149751):

Hello @dmknght,

Thanks for writing!

Actually, the config files in `kconfig_hardened_check/config_files/` are provided as examples that are used for developing and testing of this tool. These configs are updated not that often, they don't cover all major distros.

The main use case for users is to check their own kernel config. The example from Fedora:
```
./bin/kconfig-hardened-check -c /boot/config-5.16.11-100.fc34.x86_64
```
So I don't think users care about the location of these example config files. How do you think?

#### <img src="https://avatars.githubusercontent.com/u/29118926?v=4" width="50">[dmknght](https://github.com/dmknght) commented at [2022-05-06 05:37](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/61#issuecomment-1119275930):

> Hello @dmknght,
> 
> Thanks for writing!
> 
> Actually, the config files in `kconfig_hardened_check/config_files/` are provided as examples that are used for developing and testing of this tool. These configs are updated not that often, they don't cover all major distros.
> 
> The main use case for users is to check their own kernel config. The example from Fedora:
> 
> ```
> ./bin/kconfig-hardened-check -c /boot/config-5.16.11-100.fc34.x86_64
> ```
> 
> So I don't think users care about the location of these example config files. How do you think?

Hello! Sorry for very late reply. I had issue with my mail notification LuL. Anyway, I think that's a very interesting point that i didn't know. In this case, I think `kconfig-hardened-check` can have a flag like `auto check` to do the command automatically. The workflow is like:
1. Check if there is `config file` that matches `kernel version` at `/boot/`
2. If exists, run the system check automatically
3. If doesn't exists, tells user to try some examples. In this case, i think absolute path of examples is needed.

What do you think about this? To me I think it's easier to user to just do `run and read` the result without thinking about wrong profiles.

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2022-05-07 12:00](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/61#issuecomment-1120197457):

Some distros don't expose kernel config at /boot and I don't see why average user would be interested in checking example config which is probably totally unrelated to their system.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-05-08 13:33](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/61#issuecomment-1120420075):

I agree with @Bernhard40.

@dmknght, I would avoid adding the code for searching the kernel config on a local machine.

Moreover, Linux kernel developers often use the `kconfig-hardened-check` tool for the configs of the kernels that they develop (not the config of the local machine).

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/29118926?v=4" width="50">[dmknght](https://github.com/dmknght) commented at [2022-05-09 08:49](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/61#issuecomment-1120822656):

> @dmknght, I would avoid adding the code for searching the kernel config on a local machine.

Well it's not that hard. From what i checked, you just need to get kernel version, and map the path `/boot/config-<kernel version>`

> Moreover, Linux kernel developers often use the kconfig-hardened-check tool for the configs of the kernels that they develop (not the config of the local machine).
Well i see. So i guess I can close the issue now because the scope is different.


-------------------------------------------------------------------------------

# [\#60 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/60) `merged`: UBSAN_SANITIZE_ALL not available on ARM

#### <img src="https://avatars.githubusercontent.com/u/7194705?u=be917f131efce086bc9785f2b606107afe2d2fc3&v=4" width="50">[cyanidium](https://github.com/cyanidium) opened issue at [2022-03-26 14:29](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/60):

ARCH_HAS_UBSAN_SANITIZE_ALL is not selected for arm arch, which prevents selection of CONFIG_UBSAN_SANITIZE_ALL

https://github.com/torvalds/linux/blob/master/arch/arm/Kconfig
https://github.com/torvalds/linux/blob/master/lib/Kconfig.ubsan

#### <img src="https://avatars.githubusercontent.com/u/65553080?u=b7ee84d82e25b493051d810390e97b15f716d7ef&v=4" width="50">[codecov-commenter](https://github.com/codecov-commenter) commented at [2022-03-26 14:30](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/60#issuecomment-1079705754):

# [Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/60?src=pr&el=h1&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) Report
> Merging [#60](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/60?src=pr&el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (b9c72b3) into [master](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/commit/b0b91b58adc962da01c7fc45cef662ae1b462828?el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (b0b91b5) will **increase** coverage by `0.01%`.
> The diff coverage is `100.00%`.

```diff
@@            Coverage Diff             @@
##           master      #60      +/-   ##
==========================================
+ Coverage   91.46%   91.48%   +0.01%     
==========================================
  Files           3        3              
  Lines         586      587       +1     
  Branches      133      134       +1     
==========================================
+ Hits          536      537       +1     
  Misses         25       25              
  Partials       25       25              
```

| Flag | Coverage Δ | |
|---|---|---|
| functional_test | `91.48% <100.00%> (+0.01%)` | :arrow_up: |

Flags with carried forward coverage won't be shown. [Click here](https://docs.codecov.io/docs/carryforward-flags?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#carryforward-flags-in-the-pull-request-comment) to find out more.

| [Impacted Files](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/60?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) | Coverage Δ | |
|---|---|---|
| [kconfig\_hardened\_check/\_\_init\_\_.py](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/60/diff?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#diff-a2NvbmZpZ19oYXJkZW5lZF9jaGVjay9fX2luaXRfXy5weQ==) | `91.50% <100.00%> (+0.01%)` | :arrow_up: |

------

[Continue to review full report at Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/60?src=pr&el=continue&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov).
> **Legend** - [Click here to learn more](https://docs.codecov.io/docs/codecov-delta?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)
> `Δ = absolute <relative> (impact)`, `ø = not affected`, `? = missing data`
> Powered by [Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/60?src=pr&el=footer&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov). Last update [b0b91b5...b9c72b3](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/60?src=pr&el=lastupdated&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov). Read the [comment docs](https://docs.codecov.io/docs/pull-request-comments?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov).

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-04-08 16:43](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/60#issuecomment-1093077908):

Hello @cyanidium, 

Thanks for your PR.

You are right, UBSAN_SANITIZE_ALL is not available for arm for now.
See the discussion for more info https://github.com/KSPP/linux/issues/25#issuecomment-928154612

I'm going to merge your branch.
Thanks!


-------------------------------------------------------------------------------

# [\#59 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/59) `merged`: EFI mitigations can't be enabled if EFI is not set

#### <img src="https://avatars.githubusercontent.com/u/7194705?u=be917f131efce086bc9785f2b606107afe2d2fc3&v=4" width="50">[cyanidium](https://github.com/cyanidium) opened issue at [2022-03-15 12:38](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/59):

Both EFI_DISABLE_PCI_DMA and RESET_ATTACK_MITIGATION depend on EFI, but if EFI is not set, neither config is required.

Useful on embedded devices that use u-boot or similar instead of EFI.




-------------------------------------------------------------------------------

# [\#58 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/58) `closed`: CONFIG_TRIM_UNUSED_KSYMS and CONFIG_MODULES not in sync

#### <img src="https://avatars.githubusercontent.com/u/11868071?u=d7a5841263276e1f323827fc21b04345df594a60&v=4" width="50">[Churam](https://github.com/Churam) opened issue at [2022-01-17 17:17](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/58):

It seems there is a problem with the current stable kernel (5.15.14 at the date of this issue). 

The kernel option TRIM_UNUSED_KSYMS is defined in my config as: 
```
Symbol: TRIM_UNUSED_KSYMS [=n]
Type  : bool
Defined at init/Kconfig:2301
Prompt: Trim unused exported kernel symbols
Depends on: MODULES [=n] && !COMPILE_TEST [=n]
Visible if: MODULES [=n] && !COMPILE_TEST [=n] && EXPERT [=y]
Location: 
(1) -> Enable loadable module support (MODULES [=n])

```
Or the script (with the setup above) outputs me: 
CONFIG_TRIM_UNUSED_KSYMS                     |      y      |    my    | cut_attack_surface |   FAIL: not found

But as the hardening requires to have MODULES = n (is not set) it is impossible to set TRIM_UNUSED_KSYMS through menuconfig.



#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-01-21 15:53](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/58#issuecomment-1018632628):

@Churam thanks for your report!

Fixed.

The output for your case now:
```
CONFIG_TRIM_UNUSED_KSYMS   |   y   |   my   | cut_attack_surface |  OK: CONFIG_MODULES "is not set"
```

#### <img src="https://avatars.githubusercontent.com/u/11868071?u=d7a5841263276e1f323827fc21b04345df594a60&v=4" width="50">[Churam](https://github.com/Churam) commented at [2022-01-24 11:04](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/58#issuecomment-1019976819):

Fix OK
Output is now as expected, closing issue


-------------------------------------------------------------------------------

# [\#57 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/57) `closed`: CONFIG_AMD_IOMMU_V2 = m appears also to be correct
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/15869?u=31910a5ba7214eaf12efd39cbdf71b69af1b7db0&v=4" width="50">[brandonweeks](https://github.com/brandonweeks) opened issue at [2022-01-10 09:40](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/57):

```
CONFIG_AMD_IOMMU = y
CONFIG_AMD_IOMMU_V2 = m
```
appears to correctly setup the AMD v2 IOMMU on supported hardware (tested on NixOS) and is the config option used by [Fedora/RHEL](https://gitlab.com/cki-project/kernel-ark/-/blob/os-build/redhat/configs/common/generic/x86/x86_64/CONFIG_AMD_IOMMU_V2).

If you agree with this assessment, any pointers on how to add an OR to the existing AND conditional for `CONFIG_AMD_IOMMU`?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-01-21 15:29](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/57#issuecomment-1018612527):

Hello @brandonweeks 

Could you give any details on tests you mentioned?

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2024-07-07 13:06](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/57#issuecomment-2212444115):

Closing for now.
Please reopen if needed.
Thanks!


-------------------------------------------------------------------------------

# [\#56 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/56) `closed`: Add RISC-V support
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) opened issue at [2021-11-21 12:07](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/56):

It would be nice to have `kconfig-hardened-check` adapted for `RISC-V` kernel configs.  

#### <img src="https://avatars.githubusercontent.com/u/125879?v=4" width="50">[cybernet](https://github.com/cybernet) commented at [2021-12-24 13:35](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/56#issuecomment-1000842582):

👍

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-05-04 23:19](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/56#issuecomment-2849492267):

@bcoles has started and I've finished this big work.

Now `RISC-V` is officially supported in `kernel-hardening-checker`.
The tool properly checks:
 - Security hardening options enabled in the `RISC-V` defconfig,
 - KSPP recommendations applicable for `RISC-V`.

During this work I also:
 - Fixed some mistakes in the checks,
 - Cleaned up the kconfig collection,
 - Improved the kernel-hardening-checker engine a bit.

Cool!


-------------------------------------------------------------------------------

# [\#55 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/55) `closed`: Should slub_debug be considered a hardening cmd line parameter?
**Labels**: `question`


#### <img src="https://avatars.githubusercontent.com/u/3797768?v=4" width="50">[morfikov](https://github.com/morfikov) opened issue at [2021-10-28 21:16](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/55):

[According to this](https://github.com/a13xp0p0v/kconfig-hardened-check/blob/2b5bf3548b6a7edbf7cd74278d570b658f9ab34a/kconfig_hardened_check/__init__.py#L13-L21), the `slub_debug` is a hardening cmd line parameter. But when you use this option, you will see the following in the syslog on newer kernels:

```
kernel: **********************************************************
kernel: **   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **
kernel: **                                                      **
kernel: ** This system shows unhashed kernel memory addresses   **
kernel: ** via the console, logs, and other interfaces. This    **
kernel: ** might reduce the security of your system.            **
kernel: **                                                      **
kernel: ** If you see this message and you are not debugging    **
kernel: ** the kernel, report this immediately to your system   **
kernel: ** administrator!                                       **
kernel: **                                                      **
kernel: **   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **
kernel: **********************************************************
```
More [here](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=792702911f581f7793962fbeb99d5c3a1b28f4c3) and [here](https://patchwork.kernel.org/project/linux-mm/patch/20210214161348.369023-4-timur@kernel.org/).

So, should users use slub_debug=FZP or slub_debug=ZP?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2021-11-09 19:26](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/55#issuecomment-964465176):

Hello @morfikov!

My code comment in `__init__.py` is a note for future development within https://github.com/a13xp0p0v/kconfig-hardened-check/issues/46. It's not a final decision.

Currently I consider `slub_debug=F` and `slub_debug=Z` as debugging features, as you can see at the [Linux Kernel Defence Map](https://github.com/a13xp0p0v/linux-kernel-defence-map).

And I will have to learn more about `init_on_free` and `slub_debug=P` to choose between them.

Thanks!


-------------------------------------------------------------------------------

# [\#54 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/54) `merged`: Add BLK_DEV_FD

#### <img src="https://avatars.githubusercontent.com/u/150761?u=f98bb82be5009ecefd6ee9bc3d60fcf082f8cf49&v=4" width="50">[evdenis](https://github.com/evdenis) opened issue at [2021-09-10 15:41](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/54):

Floppy driver was written many years ago. It was designed to
work in a single-threaded environment (many global variables)
and to work on real hardware which has significant delays
(floppy drives are slow). Nowadays, when we use virtual
devices (which are fast) and multi-core cpus, floppy driver
shows its problems including deadlocking/livelocking and
other security-related issues. However, we can't just
rewrite it because lack of real hardware and compatibility
with existing userspace tools, many of which rely on
undocumented driver behavior.

Here are some CVEs related to floppy driver:
 - CVE-2014-1737 privileges escalation in FDRAWCMD ioctl
 - CVE-2014-1738 info leak from kernel heap in FDRAWCMD ioctl
 - CVE-2018-7755 kernel pointer lead in FDGETPRM ioctl
 - CVE-2019-14283 integer overflow and out-of-bounds read in set_geometry
 - CVE-2019-14284 denial of service in setup_format_params
 - CVE-2020-9383 out-of-bounds read in set_fdc
 - CVE-2021-20261 race condition in floppy_revalidate,
   floppy_check_events

As pointed by Linus [1]:
> The only users are virtualization, and even they are going away
> because floppies are so small, and other things have become more
> standard anyway (ie USB disk) or easier to emulate (NVMe or whatever).
> So I suspect the only reason floppy is used even in that area is just
> legacy "we haven't bothered updating to anything better and we have
> old scripts and images that work".

CONFIG_BLK_DEV_FD is not enabled in defconfig on x86_64.
Many distros already require root access for /dev/fd0.
However, qemu (5.2.0) still enables floppy device by default.

[1] https://lore.kernel.org/all/CAHk-=whFAAV_TOLFNnj=wu4mD2L9OvgB6n2sKDdmd8buMKFv8A@mail.gmail.com/

#### <img src="https://avatars.githubusercontent.com/u/65553080?u=b7ee84d82e25b493051d810390e97b15f716d7ef&v=4" width="50">[codecov-commenter](https://github.com/codecov-commenter) commented at [2021-09-10 21:23](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/54#issuecomment-917220941):

# [Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/54?src=pr&el=h1&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) Report
> Merging [#54](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/54?src=pr&el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (17d70c5) into [master](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/commit/b54dca6a96b7a07d3d1aec56b5a1df6386bb7d61?el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (b54dca6) will **increase** coverage by `0.01%`.
> The diff coverage is `100.00%`.

[![Impacted file tree graph](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/54/graphs/tree.svg?width=650&height=150&src=pr&token=GOOVXMV5Kb&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/54?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)

```diff
@@            Coverage Diff             @@
##           master      #54      +/-   ##
==========================================
+ Coverage   92.95%   92.96%   +0.01%     
==========================================
  Files           3        3              
  Lines         511      512       +1     
  Branches      116      116              
==========================================
+ Hits          475      476       +1     
  Misses         18       18              
  Partials       18       18              
```

| Flag | Coverage Δ | |
|---|---|---|
| functional_test | `92.96% <100.00%> (+0.01%)` | :arrow_up: |

Flags with carried forward coverage won't be shown. [Click here](https://docs.codecov.io/docs/carryforward-flags?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#carryforward-flags-in-the-pull-request-comment) to find out more.

| [Impacted Files](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/54?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) | Coverage Δ | |
|---|---|---|
| [kconfig\_hardened\_check/\_\_init\_\_.py](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/54/diff?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#diff-a2NvbmZpZ19oYXJkZW5lZF9jaGVjay9fX2luaXRfXy5weQ==) | `93.02% <100.00%> (+0.01%)` | :arrow_up: |

------

[Continue to review full report at Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/54?src=pr&el=continue&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov).
> **Legend** - [Click here to learn more](https://docs.codecov.io/docs/codecov-delta?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)
> `Δ = absolute <relative> (impact)`, `ø = not affected`, `? = missing data`
> Powered by [Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/54?src=pr&el=footer&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov). Last update [b54dca6...17d70c5](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/54?src=pr&el=lastupdated&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov). Read the [comment docs](https://docs.codecov.io/docs/pull-request-comments?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov).

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2021-09-10 21:28](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/54#issuecomment-917223378):

Thanks a lot @evdenis :)
The pull request is merged.


-------------------------------------------------------------------------------

# [\#53 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/53) `closed`: Justification of UBSAN-related choices?

#### <img src="https://avatars.githubusercontent.com/u/601177?v=4" width="50">[equaeghe](https://github.com/equaeghe) opened issue at [2021-09-04 21:22](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/53):

Currently, `UBSAN`-related choices are as follows:

https://github.com/a13xp0p0v/kconfig-hardened-check/blob/4dc94be8a5e0c3a0889679f7079aa93c7f44464d/kconfig_hardened_check/__init__.py#L421-L423

It is unclear to me why the last two are chosen. `UBSAN_MISC=y` seems like a good thing, as it enables more checks. `UBSAN_TRAP=y` seems like a bad thing, as it enables denial of service attacks. Furthermore, if I understand things correctly, `UBSAN_SANITIZE_ALL=y` would be needed to practically activate `UBSAN`.

Is my understanding correct, or a misunderstanding (which is perfectly possible). In the latter case, I would be grateful for a pointer to an appropriate resource.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2021-09-10 13:40](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/53#issuecomment-916912883):

Hello @equaeghe 

Thanks for your question.

Please have a look, @kees wrote about that in his article about security-related things in the Linux kernel 5.7:
https://outflux.net/blog/archives/2020/09/21/security-things-in-linux-v5-7/

Quote:
```
For runtime checking, the Undefined Behavior Sanitizer has an option for adding runtime array bounds checking
for catching things like this where the compiler cannot perform a static analysis of the index values.

...

It was, however, not separate (via kernel Kconfig) until Elena Petrova and I split it out into
CONFIG_UBSAN_BOUNDS, which is fast enough for production kernel use. 

...

Since UBSAN (and the other Sanitizers) only WARN() by default, system owners need to
set panic_on_warn=1 too if they want to defend against attacks targeting these kinds of flaws.
Because of this, and to avoid bloating the kernel image with all the warning messages, I introduced
CONFIG_UBSAN_TRAP which effectively turns these conditions into a BUG() without needing
additional sysctl settings.
```

Does that provide answers to your questions?

#### <img src="https://avatars.githubusercontent.com/u/601177?v=4" width="50">[equaeghe](https://github.com/equaeghe) commented at [2021-09-10 14:04](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/53#issuecomment-916929875):

Thanks, that explains why `UBSAN_TRAP=y`. I am still unclear why `UBSAN_MISC is not set` and why nothing is said about `UBSAN_SANITIZE_ALL`.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2021-09-10 14:56](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/53#issuecomment-916967782):

It looks like other UBSAN modes are for kernel debugging, not for hardening:
```
[*]   Perform checking for bit-shift overflows
[*]   Perform checking for integer divide-by-zero
[*]   Perform checking for non-boolean values used as boolean
[*]   Perform checking for out of bounds enum values
[*]   Perform checking for misaligned pointer usage
```
Previously they were collected under UBSAN_MISC, but now I see that they are separate since the kernel commit  c637693b20da8706b7f48d96882c9c80ae935151. I will have a closer look at them.

I will also test UBSAN_SANITIZE_ALL behavior.

Thanks @equaeghe !

#### <img src="https://avatars.githubusercontent.com/u/1110841?u=e5e99e1ac8260e791433baa2423f7d173eea4c1c&v=4" width="50">[kees](https://github.com/kees) commented at [2021-09-10 18:50](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/53#issuecomment-917133371):

`UBSAN_SANITIZE_ALL` is needed to gain coverage over the kernel as a whole. Otherwise, only opted-in things will have the UBSAN features applied.

I.e. for production workloads, I recommend:

```
CONFIG_UBSAN=y
CONFIG_UBSAN_BOUNDS=y
CONFIG_UBSAN_SANITIZE_ALL=y
```

and depending on one's crash tolerances, either use `panic_on_warn=1` or `CONFIG_UBSAN_TRAP=y`.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2021-09-10 21:20](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/53#issuecomment-917219349):

Thank you very much @kees !


-------------------------------------------------------------------------------

# [\#52 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/52) `closed`: Add RANDOMIZE_KSTACK_OFFSET_DEFAULT

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) opened issue at [2021-08-25 19:44](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/52):

Randomize kernel stack offset on syscall entry

The kernel stack offset can be randomized (after pt_regs) by
roughly 5 bits of entropy, frustrating memory corruption
attacks that depend on stack address determinism or
cross-syscall address exposures. This feature is controlled
by kernel boot param "randomize_kstack_offset=on/off", and this
config chooses the default boot state.

#### <img src="https://avatars.githubusercontent.com/u/65553080?u=b7ee84d82e25b493051d810390e97b15f716d7ef&v=4" width="50">[codecov-commenter](https://github.com/codecov-commenter) commented at [2021-08-25 19:46](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/52#issuecomment-905823752):

# [Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/52?src=pr&el=h1&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) Report
> Merging [#52](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/52?src=pr&el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (5d12e64) into [master](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/commit/57379d8c851656116e2b149e3f1d4003c17d22d9?el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (57379d8) will **increase** coverage by `0.01%`.
> The diff coverage is `100.00%`.

[![Impacted file tree graph](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/52/graphs/tree.svg?width=650&height=150&src=pr&token=GOOVXMV5Kb&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/52?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)

```diff
@@            Coverage Diff             @@
##           master      #52      +/-   ##
==========================================
+ Coverage   92.87%   92.88%   +0.01%     
==========================================
  Files           3        3              
  Lines         505      506       +1     
  Branches      115      115              
==========================================
+ Hits          469      470       +1     
  Misses         18       18              
  Partials       18       18              
```

| Flag | Coverage Δ | |
|---|---|---|
| functional_test | `92.88% <100.00%> (+0.01%)` | :arrow_up: |

Flags with carried forward coverage won't be shown. [Click here](https://docs.codecov.io/docs/carryforward-flags?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#carryforward-flags-in-the-pull-request-comment) to find out more.

| [Impacted Files](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/52?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) | Coverage Δ | |
|---|---|---|
| [kconfig\_hardened\_check/\_\_init\_\_.py](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/52/diff?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#diff-a2NvbmZpZ19oYXJkZW5lZF9jaGVjay9fX2luaXRfXy5weQ==) | `92.94% <100.00%> (+0.01%)` | :arrow_up: |

------

[Continue to review full report at Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/52?src=pr&el=continue&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov).
> **Legend** - [Click here to learn more](https://docs.codecov.io/docs/codecov-delta?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)
> `Δ = absolute <relative> (impact)`, `ø = not affected`, `? = missing data`
> Powered by [Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/52?src=pr&el=footer&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov). Last update [57379d8...5d12e64](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/52?src=pr&el=lastupdated&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov). Read the [comment docs](https://docs.codecov.io/docs/pull-request-comments?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov).

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2021-09-10 12:14](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/52#issuecomment-916859414):

Hi @anthraxx 

You might be busy, so I've made the fixes myself in the commit b54dca6a96b7a07d3d1aec56b5a1df6386bb7d61.
Hope you wouldn't mind.

Thanks!
Alexander

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2021-09-10 12:15](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/52#issuecomment-916860190):

@a13xp0p0v nah, i was just about to make it KSPP official hence the delay. should have communicated it. Will create a followup PR marking it as kspp soon :cat:

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2021-09-10 13:45](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/52#issuecomment-916916530):

@anthraxx , ah, OK!

Sure, looking forward to your new pull request!


-------------------------------------------------------------------------------

# [\#51 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/51) `merged`: Added cbl-mariner kernel configuration file.

#### <img src="https://avatars.githubusercontent.com/u/25109036?u=507c0397c0e27f6fc1a1b3115f293c66b8056199&v=4" width="50">[Hacks4Snacks](https://github.com/Hacks4Snacks) opened issue at [2021-08-19 20:49](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/51):

Hello,

I have added the CBL-Mariner 1.0 distribution kernel configuration file.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2021-08-20 17:22](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/51#issuecomment-902842367):

Hello @Hacks4Snacks,
Could you please add the corresponding info to `kconfig_hardened_check/config_files/links.txt` and update your pull request?
Thank you!

#### <img src="https://avatars.githubusercontent.com/u/25109036?u=507c0397c0e27f6fc1a1b3115f293c66b8056199&v=4" width="50">[Hacks4Snacks](https://github.com/Hacks4Snacks) commented at [2021-08-20 17:42](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/51#issuecomment-902853201):

Sure thing! A link to the publicly available configuration has been added. @a13xp0p0v

#### <img src="https://avatars.githubusercontent.com/u/65553080?u=b7ee84d82e25b493051d810390e97b15f716d7ef&v=4" width="50">[codecov-commenter](https://github.com/codecov-commenter) commented at [2021-08-20 18:11](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/51#issuecomment-902869062):

# [Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/51?src=pr&el=h1&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) Report
> Merging [#51](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/51?src=pr&el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (a5686b1) into [master](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/commit/38bde65d9df70a6b1ec772b93b07e98778cb7e34?el=desc&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov) (38bde65) will **not change** coverage.
> The diff coverage is `n/a`.

[![Impacted file tree graph](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/51/graphs/tree.svg?width=650&height=150&src=pr&token=GOOVXMV5Kb&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/51?src=pr&el=tree&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)

```diff
@@           Coverage Diff           @@
##           master      #51   +/-   ##
=======================================
  Coverage   92.87%   92.87%           
=======================================
  Files           3        3           
  Lines         505      505           
  Branches      115      115           
=======================================
  Hits          469      469           
  Misses         18       18           
  Partials       18       18           
```

| Flag | Coverage Δ | |
|---|---|---|
| functional_test | `92.87% <ø> (ø)` | |

Flags with carried forward coverage won't be shown. [Click here](https://docs.codecov.io/docs/carryforward-flags?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov#carryforward-flags-in-the-pull-request-comment) to find out more.


------

[Continue to review full report at Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/51?src=pr&el=continue&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov).
> **Legend** - [Click here to learn more](https://docs.codecov.io/docs/codecov-delta?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov)
> `Δ = absolute <relative> (impact)`, `ø = not affected`, `? = missing data`
> Powered by [Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/51?src=pr&el=footer&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov). Last update [38bde65...a5686b1](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/51?src=pr&el=lastupdated&utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov). Read the [comment docs](https://docs.codecov.io/docs/pull-request-comments?utm_medium=referral&utm_source=github&utm_content=comment&utm_campaign=pr+comments&utm_term=Alexander+Popov).

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2021-08-20 18:22](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/51#issuecomment-902874845):

Merged. Thanks @Hacks4Snacks!


-------------------------------------------------------------------------------

# [\#50 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/50) `open`: Allow redefining rules and expanding rule sets
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/65050545?u=3d095cc7726e6bbf544ea4857c4223033ea90921&v=4" width="50">[petervanvugt](https://github.com/petervanvugt) opened issue at [2021-02-20 01:10](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/50):

I have found this tool quite helpful for quickly auditing embedded kernel configs. However, I've been finding that on embedded systems, I often have unique, application-specific security requirements:

- Embedded SoC vendors often have drivers that haven't made it into mainline that need to be checked (e.g. special HW RNG drivers, TZ drivers, PMIC drivers)
- The application may want to even further prioritize the correct operation of the system over performance or reliability (i.e. be willing to sacrifice battery life, CPU bandwidth, or resistance to DoS attacks to increase hardness)
- Since the required kernel functionality is fully defined (e.g. we know we'll _never_ need FAT filesystem support, don't want UART or kernel console driver, don't want USB gadget drivers, etc.), specify that unused drivers must be removed, lest they be leveraged by an attacker

I propose moving the config tests currently hard-coded in `__init__` into a set of yaml configs that can be included by a top-level config, like this:
```
# Includes are optional. Recursively walk through them, each test/error will be tagged with the source yaml
# Last included definition for a CONFIG_ is used
includes:
  - kspp.yaml
  - clipos.yaml
  - my.yaml
  - soc_a.yaml
# Tests
tests: !!seq [
  # Description of test
  RANDOMIZE_BASE: {
    # Test passes if CONFIG=value
    require: value,
    # Test passes if config not found, or "is not set"
    # require: is not set,
    # Optional: only test if other config is set to something
    if_config: MODULES,
    # Optional: only test specific kernel versions
    if_kernel_ver_gt_eq: 5.9,
    if_kernel_ver_lt: 5.8,
    # Optional: only test specific architectures
    if_arch: [X86_64, ARM64, X86_32],
  },
  # Example: require CONFIG_BUG=y
  BUG: {
    require: y,
  },
]
```
This would enable the config requirements to be layered, similar to the way kernel `defconfigs` can be layered (i.e. arch | Android | SoC vendor | device). I have some free time next week to implement this if you're open to it.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2021-02-21 22:15](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/50#issuecomment-782937216):

Hello @petervanvugt,

Thanks for your initiative!

May I ask you to describe your use-case in details?
Which new requirements to `kconfig-hardened-check` behavior does it have?

Maybe a layered yaml that you propose is not a single solution for your use-case.

Moreover, I see that your use-case relates to this discussion: https://github.com/a13xp0p0v/kconfig-hardened-check/pull/9#issuecomment-453810119
I think we can define some common solution.

Now about the syntax of check definitions.
- Currently all checks are grouped together in `kconfig_hardened_check/__init__.py`.
- The check definitions are very short.

So I can observe them altogether. That helps me to understand and maintain these checks, which is not an easy task.
That is my main rationale.

Here you propose a completely different syntax.
I think we should discuss it before we start coding.
My thoughts:
1. Can we separate changing check definition syntax from changing `kconfig-hardened-check` behavior?
2. The given syntax example doesn't cover all check types that we have. Could you please write *all* current checks in your new syntax? I think we need that for making the decision.

(I'm travelling till the beginning of March, excuse me for delayed replies)

Best regards,
Alexander

#### <img src="https://avatars.githubusercontent.com/u/65050545?u=3d095cc7726e6bbf544ea4857c4223033ea90921&v=4" width="50">[petervanvugt](https://github.com/petervanvugt) commented at [2021-02-23 02:26](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/50#issuecomment-783833502):

Hi @a13xp0p0v ,

My use essentially falls into three cases:

1. My system has kconfigs **not in mainline that must always be set**.
 
_For example_, I might want to verify `PANIC_ON_DATA_CORRUPTION` [from Android](https://android.googlesource.com/kernel/msm/+/7b49b86d3aa3d0c6400454a346bad1bbdf0cc78f%5E%21/) is enabled, as a defensive measure, because I'd rather the system immediately reboot at the first sign things are going off the rails, rather than risk being exploited by an attacker.

2. My system has kconfigs that **are in mainline, which are only in play for my hardware**.

_For example_, I may want to verify that my chip's `CONFIG_<HWVENDOR>_HWRANDOM` is enabled, because I'm using it as a cryptographically secure source of enropy.

3. My system has kconfigs that **are in mainline, which many/most users want enabled, but I want disabled**, because they add no benefit, and some nonzero risk.

_For example_, if I'm building an embedded system that uses NXP's i.MX line, I may want to verify `CONFIG_SERIAL_IMX` and `CONFIG_SERIAL_IMX_CONSOLE` are not enabled, because I want to be absolutely certain that the serial drivers and associated kernel console drivers haven't been included. Or, in a similar vein to **(1)**, I may want to enable `CONFIG_PANIC_ON_OOPS` because I prioritize the correctness of my system over its availability.

[EDIT] Another, potentially stronger example I have run into recently is `PROC_PAGE_MONITOR`. The grsecurity patch set removes it for good reason, because access to `/proc/<pid>/smaps` can leak memory mapping information defeating ASLR. While there are mitigations all recent versions of the kernel to prevent insufficiently privileged processes from reading the map of a more privileged process, there have been a few race conditions and side channels that have been shown to circumvent this. So, it is reasonable that many users will want to disable this altogether. However, Android's *libmeminfo* needs to read this entry to compute process memory utilization, which is pretty hard to live without in some applications.

Can we serve all these use cases?

Clearly, there a few paths that could be taken here. We could add these requirements to the very compact representation in `kconfig_hardened_check/__init__.py`. And for **(1)** and **(2)**, we could likely produce some combination of AND/OR kconfig checks (albeit sometimes non-trivial) that keeps the check from generating unnecessarily noisy output/false positives when run on configs for non-applicable hardware, or for kernels that don't fully track mainline. But this wouldn't solve for **(3)**, unless we require the tool be specially patched for such cases, or we add runtime args that turn on each of these checks.

If we want to be able to specify additional requirements at runtime and/or override requirements at runtime, we need a way to specify alternate requirements. This is why I am proposing representing the requirements as runtime configuration, rather than code. As to how we would represent some of the more complex requirements, I am proposing we break them down into requirements that each only check one config each, optionally only checked for some combination of specific architectures/kernel versions/`CONFIG_`s.

We could take configs whose names changed, such as this:
```
282     l += [OR(OptCheck('self_protection', 'defconfig', 'STACKPROTECTOR_STRONG', 'y'),
283              OptCheck('self_protection', 'defconfig', 'CC_STACKPROTECTOR_STRONG', 'y'))]
```
and split them into two separate requirements, the first one for kernels >= 4.18, and the second one for kernels >= 3.14 and < 4.18.

The most complex requirement I see is this one:
```
307     if arch == 'ARM64':
...
310         l += [OR(OptCheck('self_protection', 'defconfig', 'HARDEN_EL2_VECTORS', 'y'),
311                  AND(OptCheck('self_protection', 'defconfig', 'RANDOMIZE_BASE', 'y'),
312                      VerCheck((5, 9))))] # HARDEN_EL2_VECTORS was included in RANDOMIZE_BASE in v5.9
```
which could be split into two requirements: one for `RANDOMIZE_BASE` on kernels >= 5.9 for ARM64, and a second check for `HARDEN_EL2_VECTORS` on older kernels >= 4.17 and < 5.9, also for ARM64. This would keep the requirements more readable in the long run.

What do you think?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2021-03-05 19:16](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/50#issuecomment-791625966):

@petervanvugt thanks a lot for describing your use-cases.
I think they match with [this one](https://github.com/a13xp0p0v/kconfig-hardened-check/pull/9#issuecomment-453810119).
I want to make them possible.

I think `kconfig-hardened-check` should allow to override the default checks and append custom checks.
As a first step, we need some simple solution without changing the check description syntax.
Then we can ponder over the check description syntax.

I will experiment with that.
If you create any prototype, please share!

#### <img src="https://avatars.githubusercontent.com/u/10352354?u=97ab0d446ea4204b959ae74734f8436c78de18e7&v=4" width="50">[egberts](https://github.com/egberts) commented at [2021-08-31 13:08](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/50#issuecomment-909221366):

other use case is prevent leakage of kernel pointers to log file, /proc directory files, or terminal output.  

Which is just a bunch of debugs and dmesg turned off. 


another one is the one provided by Whonix.org (a KSPP variant) which is more rigorous form of kernel security. 

Another one is for Spectre, et. al., mitigation and that has a bunch of config s as well.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2023-04-23 07:33](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/50#issuecomment-1518980838):

I implemented a part of this feature in `override_expected_value()`.

1. Implementation: https://github.com/a13xp0p0v/kconfig-hardened-check/commit/c1090722157b531261a7cf0257f2dccb744bd93d

2. Unit-test: https://github.com/a13xp0p0v/kconfig-hardened-check/commit/7194de8dfe8b6232166eded1516eb7fdd21c14ed

3.  Refinement of the CONFIG_ARCH_MMAP_RND_BITS check using this feature: https://github.com/a13xp0p0v/kconfig-hardened-check/commit/9bbea5b5bad45aac84aadf83536e31f9bd5e395e

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-19 21:39](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/50#issuecomment-3092585705):

This feature could be used for customizing the kernel security checks for Android.


-------------------------------------------------------------------------------

# [\#49 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/49) `closed`: Some checks seem to be at odds with what the recommended settings are

#### <img src="https://avatars.githubusercontent.com/u/14325582?v=4" width="50">[wdormann](https://github.com/wdormann) opened issue at [2021-02-11 14:34](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/49):

I did not go through them all, but these in particular stuck out to me:

```
CONFIG_GCC_PLUGIN_RANDSTRUCT_PERFORMANCE     | is not set  |  clipos  |  self_protection   |   FAIL: CONFIG_GCC_PLUGIN_RANDSTRUCT not "y"
CONFIG_STACKLEAK_METRICS                     | is not set  |  clipos  |  self_protection   |   FAIL: CONFIG_GCC_PLUGIN_STACKLEAK not "y"
CONFIG_STACKLEAK_RUNTIME_DISABLE             | is not set  |  clipos  |  self_protection   |   FAIL: CONFIG_GCC_PLUGIN_STACKLEAK not "y"
```

If I'm reading this properly, the recommended setting for these is ```not set```
However, the specific tests show as ```FAIL``` because they are ```not "y"```

Perhaps I'm just interpreting the report incorrectly, but at first glance it would appear that the check for the desired result is wrong.


#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2021-02-11 15:06](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/49#issuecomment-777552022):

Hi @wdormann,

Thanks for your question.
The output is correct, let me explain.

```
CONFIG_GCC_PLUGIN_RANDSTRUCT                 |      y      |   kspp   |  self_protection   |   FAIL: not found
...
CONFIG_GCC_PLUGIN_RANDSTRUCT_PERFORMANCE     | is not set  |  clipos  |  self_protection   |   FAIL: CONFIG_GCC_PLUGIN_RANDSTRUCT not "y"
```
`RANDSTRUCT` is disabled and the first check fails.
The `RANDSTRUCT_PERFORMANCE` feature is dependent on `RANDSTRUCT`.
That's why the second check fails too with the explanation: `CONFIG_GCC_PLUGIN_RANDSTRUCT not "y"`.

The situation with `STACKLEAK_METRICS` and `STACKLEAK_RUNTIME_DISABLE` is similar.
These checks fail because they depend on `STACKLEAK` which is not `"y"`.

#### <img src="https://avatars.githubusercontent.com/u/14325582?v=4" width="50">[wdormann](https://github.com/wdormann) commented at [2021-02-11 15:19](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/49#issuecomment-777570144):

Reading comprehension is apparently important!
Thanks for the clarification.


-------------------------------------------------------------------------------

# [\#48 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/48) `merged`: Do not check CONFIG_HARDEN_EL2_VECTORS for v5.9+

#### <img src="https://avatars.githubusercontent.com/u/20878259?v=4" width="50">[pgils](https://github.com/pgils) opened issue at [2020-10-19 13:45](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/48):

The CONFIG_HARDEN_EL2_VECTORS Kconfig was removed in Linux 5.9: torvalds/linux@a59a2ed.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-10-21 15:06](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/48#issuecomment-713644849):

Hi @pgils, thanks for your pull request!

In fact HARDEN_EL2_VECTORS is now included in RANDOMIZE_BASE.
So simple check of the kernel version is not enough.

I think of making nested ComplexOptCheck possible to write such a rule.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-10-22 16:12](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/48#issuecomment-714601175):

Hi @pgils,
I added nested `ComplexOptChecks` support, merged and improved your rule.
Thanks!

#### <img src="https://avatars.githubusercontent.com/u/20878259?v=4" width="50">[pgils](https://github.com/pgils) commented at [2020-10-24 14:14](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/48#issuecomment-715921069):

thanks @a13xp0p0v, that's a nice feature!

Do you think it would be worthwhile using this for complex dependencies such as this one for `ARM64_PTR_AUTH` which currently `'FAIL'`s for my ARMv8-A config but is not selectable in `menuconfig`?:
```
(CC_HAS_SIGN_RETURN_ADDRESS [=n] || CC_HAS_BRANCH_PROT_PAC_RET [=n]) \
    && AS_HAS_PAC [=n] \
    && (LD_IS_LLD [=n] \
        || LD_VERSION [=235000000]>=233010000 
        || CC_IS_GCC [=y] && GCC_VERSION [=100200]<90100) \
    && (!CC_IS_CLANG [=n] || AS_HAS_CFI_NEGATE_RA_STATE [=y]) \
    && (!FUNCTION_GRAPH_TRACER [=n] || DYNAMIC_FTRACE_WITH_REGS [=n])
```

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-10-30 18:16](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/48#issuecomment-719717934):

@pgils, I guess you can't enable `ARM64_PTR_AUTH` because your current toolchain doesn't fit the requirements.
I would recommend improving the toolchain to get this nice feature.

See the output about my toolchain (in Fedora 32):
```
Depends on: (CC_HAS_SIGN_RETURN_ADDRESS [=y] || CC_HAS_BRANCH_PROT_PAC_RET [=y]) && AS_HAS_PAC [=y] && (LD_IS_LLD [=n] || LD_VERSION [=234000000]>=233010000 || CC_IS_GCC [=y] && GCC_VERSION [=90201]<90100) && (!CC_IS_CLANG [=n] || AS_HAS_CFI_NEGATE_RA_STATE [=y]) && (!FUNCTION_GRAPH_TRACER [=n] || DYNAMIC_FTRACE_WITH_REGS [=n])
```


-------------------------------------------------------------------------------

# [\#47 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/47) `closed`: Please support /proc/config.gz

#### <img src="https://avatars.githubusercontent.com/u/3797768?v=4" width="50">[morfikov](https://github.com/morfikov) opened issue at [2020-10-13 14:58](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/47):

Currently only uncompressed `config-*` files in /boot/ are supported, but the current kernel config can also be accessed via `/proc/config.gz` . There's no way to use this file. Please support this path as well. 

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-10-14 12:25](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/47#issuecomment-708366463):

No problem, I would recommend this:
```
  # zcat /proc/config.gz > my.config
  # ./bin/kconfig-hardened-check -c my.config
```

#### <img src="https://avatars.githubusercontent.com/u/3797768?v=4" width="50">[morfikov](https://github.com/morfikov) commented at [2020-10-14 13:43](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/47#issuecomment-708410948):

Yes, I know, but this is the same as just using `-c /boot/config-*` . I thought of using `/proc/config.gz` because in such case a user would just use one file no matter what kernel version he's using. When you decompress the file first, it's an extra step which could be eliminated to simplify the whole process and make it easier.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-10-21 14:44](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/47#issuecomment-713629103):

Not all kernels provide the kernel config via `/proc/config.gz`.
For example, RHEL, Fedora, Ubuntu, Debian don't do that.

I think we can use `zcat` separately, if we need.


-------------------------------------------------------------------------------

# [\#46 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/46) `closed`: CPU specific options and the kernel cmd line 
**Labels**: `new_feature`


#### <img src="https://avatars.githubusercontent.com/u/3797768?v=4" width="50">[morfikov](https://github.com/morfikov) opened issue at [2020-10-04 15:39](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/46):

I have an Intel CPU, and when I run `kconfig-hardened-check` I get the following FAILs:

```
CONFIG_AMD_IOMMU                             |      y      |defconfig |  self_protection   |   FAIL: "is not set"
CONFIG_AMD_IOMMU_V2                          |      y      |    my    |  self_protection   |   FAIL: not found
```

It would be nice to have such CPU specific options hidden in the results. 

The behavior of some options can be controlled via the kernel cmd line, for instance:

```
CONFIG_SLUB_DEBUG_ON                         |      y      |    my    |  self_protection   |   FAIL: "is not set"
CONFIG_X86_VSYSCALL_EMULATION                | is not set  |  clipos  | cut_attack_surface |   FAIL: "y"
```

If a user set `slub_debug=FZP` and `vsyscall=none` in the kernel cmd line, I think he would achieve the same behavior. So, `kconfig-hardened-check` could check such kernel cmd line options before giving a FAIL. 

What do you think about such improvements? 

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-10-05 10:09](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/46#issuecomment-703535817):

Hi @morfikov, thanks for your ideas.

1. I think we can group AMD_IOMMU recommendations with the corresponding ones for Intel using `OR`.
That would allow to avoid incorrect FAIL reports.

2. Parsing the kernel command line is a nice feature, it's on my TODO list. Moreover, we can get it from `/proc/cmdline` without additional privileges, which is nice.

I'm going to work on `kconfig-hardened-check` in the coming days.
If you want to participate, come on, your pull requests will be welcome!

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2020-10-05 11:03](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/46#issuecomment-703560552):

I always seen this project scope as simple kernel config checker not running system audit tool and I believe in old  unix mantra _Do One Thing and Do It Well_ so I'm skeptical about this additions. Taking  `/proc/cmdline` into account would mean same config would yield different result across systems. Having OR between amd and intel features make it less useful for distros which would want them all.

I think end users are capable of ignoring amd warnings when they have intel cpu and the opposite and also be aware o what they added to their cmdline.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-10-05 11:55](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/46#issuecomment-703583549):

Hi @Bernhard40 

> Having OR between amd and intel features make it less useful for distros which would want them all.

Hm, you are right. I would agree on that point.

> Taking /proc/cmdline into account would mean same config would yield different result across systems

I would propose a compromise: add a separate flag for checking `/proc/cmdline` (disabled by default).
Is it OK for you?

In fact, I see checking cmdline parameters as a very big improvement.
There are several important cases when checking kernel config is not enough for a correct conclusion about the kernel security.
Examples: `mitigations`, `page_poison`, `init_on_alloc/init_on_free` and some others.

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2020-10-05 20:35](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/46#issuecomment-703873764):

> I would propose a compromise: add a separate flag for checking /proc/cmdline (disabled by default).
> Is it OK for you?

I don't mind if you are ready to maintain it.

> In fact, I see checking cmdline parameters as a very big improvement.
> There are several important cases when checking kernel config is not enough for a correct conclusion about the kernel security.

Yes but for now checking kernel config is the only thing this project ever promised (see readme). Conclusions about kernel security needs expanding the project scope which may be a rabbit hole as if you add cmdlne support then sysctl support should be next etc.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-10-05 21:01](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/46#issuecomment-703886769):

@Bernhard40, I'll do my best.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2022-05-28 19:19](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/46#issuecomment-1140317020):

Now kconfig-hardened-check supports checking kernel cmdline parameters.

Cool!

```
usage: kconfig-hardened-check [-h] [--version] [-p {X86_64,X86_32,ARM64,ARM}]
                              [-c CONFIG]
                              [-l CMDLINE]
                              [-m {verbose,json,show_ok,show_fail}]

A tool for checking the security hardening options of the Linux kernel

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -p {X86_64,X86_32,ARM64,ARM}, --print {X86_64,X86_32,ARM64,ARM}
                        print security hardening preferences for the selected architecture
  -c CONFIG, --config CONFIG
                        check the kernel kconfig file against these preferences
  -l CMDLINE, --cmdline CMDLINE
                        check the kernel cmdline file against these preferences
  -m {verbose,json,show_ok,show_fail}, --mode {verbose,json,show_ok,show_fail}
                        choose the report mode
```


-------------------------------------------------------------------------------

# [\#45 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/45) `closed`: Request for command line options to display only OK/FAIL items

#### <img src="https://avatars.githubusercontent.com/u/14027079?u=379b0b0fcecea8820dea0f220dc09e3342cc4519&v=4" width="50">[fonic](https://github.com/fonic) opened issue at [2020-07-13 10:07](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/45):

I'd like to request command line options to reduce output to OK/FAIL items only, e.g.
```
-o, --ok      only list items checked as OK
-f, --fail    only list items checked as FAIL
```

This would make it much easier to work through the list of settings when hardening kernel configurations, especially if one only applies few at a time to test their impact.

This tool is great, many thanks!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-07-15 11:55](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/45#issuecomment-658724615):

Hello @fonic,

Please see `show_ok` and `show_fail` modes:
```
usage: kconfig-hardened-check [-h] [--version] [-p {X86_64,X86_32,ARM64,ARM}]
                              [-c CONFIG]
                              [-m {verbose,json,show_ok,show_fail}]

Checks the hardening options in the Linux kernel config

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -p {X86_64,X86_32,ARM64,ARM}, --print {X86_64,X86_32,ARM64,ARM}
                        print hardening preferences for selected architecture
  -c CONFIG, --config CONFIG
                        check the kernel config file against these preferences
  -m {verbose,json,show_ok,show_fail}, --mode {verbose,json,show_ok,show_fail}
                        choose the report mode
```

Output example:
```
$ ./bin/kconfig-hardened-check -c kconfig_hardened_check/config_files/distros/ubuntu-focal.config -m show_ok
[+] Special report mode: show_ok
[+] Config file to check: kconfig_hardened_check/config_files/distros/ubuntu-focal.config
[+] Detected architecture: X86_64
[+] Detected kernel version: 5.4
=========================================================================================================================
                 option name                 | desired val | decision |       reason       |   check result
=========================================================================================================================
CONFIG_BUG                                   |      y      |defconfig |  self_protection   |   OK
CONFIG_SLUB_DEBUG                            |      y      |defconfig |  self_protection   |   OK
CONFIG_STACKPROTECTOR_STRONG                 |      y      |defconfig |  self_protection   |   OK
CONFIG_STRICT_KERNEL_RWX                     |      y      |defconfig |  self_protection   |   OK
CONFIG_STRICT_MODULE_RWX                     |      y      |defconfig |  self_protection   |   OK
CONFIG_IOMMU_SUPPORT                         |      y      |defconfig |  self_protection   |   OK
CONFIG_MICROCODE                             |      y      |defconfig |  self_protection   |   OK
CONFIG_RETPOLINE                             |      y      |defconfig |  self_protection   |   OK
CONFIG_X86_SMAP                              |      y      |defconfig |  self_protection   |   OK
CONFIG_SYN_COOKIES                           |      y      |defconfig |  self_protection   |   OK
CONFIG_X86_UMIP                              |      y      |defconfig |  self_protection   |   OK: CONFIG_X86_INTEL_UMIP "y"
CONFIG_PAGE_TABLE_ISOLATION                  |      y      |defconfig |  self_protection   |   OK
CONFIG_RANDOMIZE_MEMORY                      |      y      |defconfig |  self_protection   |   OK
CONFIG_INTEL_IOMMU                           |      y      |defconfig |  self_protection   |   OK
CONFIG_AMD_IOMMU                             |      y      |defconfig |  self_protection   |   OK
CONFIG_VMAP_STACK                            |      y      |defconfig |  self_protection   |   OK
CONFIG_RANDOMIZE_BASE                        |      y      |defconfig |  self_protection   |   OK
CONFIG_THREAD_INFO_IN_TASK                   |      y      |defconfig |  self_protection   |   OK
CONFIG_DEBUG_WX                              |      y      |   kspp   |  self_protection   |   OK
CONFIG_SCHED_STACK_END_CHECK                 |      y      |   kspp   |  self_protection   |   OK
CONFIG_SLAB_FREELIST_HARDENED                |      y      |   kspp   |  self_protection   |   OK
CONFIG_SLAB_FREELIST_RANDOM                  |      y      |   kspp   |  self_protection   |   OK
CONFIG_SHUFFLE_PAGE_ALLOCATOR                |      y      |   kspp   |  self_protection   |   OK
CONFIG_FORTIFY_SOURCE                        |      y      |   kspp   |  self_protection   |   OK
CONFIG_INIT_ON_ALLOC_DEFAULT_ON              |      y      |   kspp   |  self_protection   |   OK
CONFIG_HARDENED_USERCOPY                     |      y      |   kspp   |  self_protection   |   OK
CONFIG_MODULE_SIG                            |      y      |   kspp   |  self_protection   |   OK
CONFIG_MODULE_SIG_ALL                        |      y      |   kspp   |  self_protection   |   OK
CONFIG_MODULE_SIG_SHA512                     |      y      |   kspp   |  self_protection   |   OK
CONFIG_INIT_ON_FREE_DEFAULT_ON               |      y      |   kspp   |  self_protection   |   OK: CONFIG_PAGE_POISONING "y"
CONFIG_DEFAULT_MMAP_MIN_ADDR                 |    65536    |   kspp   |  self_protection   |   OK
CONFIG_INTEL_IOMMU_SVM                       |      y      |  clipos  |  self_protection   |   OK
CONFIG_RESET_ATTACK_MITIGATION               |      y      |    my    |  self_protection   |   OK
CONFIG_SECURITY                              |      y      |defconfig |  security_policy   |   OK
CONFIG_SECURITY_YAMA                         |      y      |   kspp   |  security_policy   |   OK
CONFIG_SECURITY_WRITABLE_HOOKS               | is not set  |    my    |  security_policy   |   OK: not found
CONFIG_SECURITY_LOCKDOWN_LSM                 |      y      |  clipos  |  security_policy   |   OK
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY           |      y      |  clipos  |  security_policy   |   OK
CONFIG_SECURITY_SAFESETID                    |      y      |    my    |  security_policy   |   OK
CONFIG_SECCOMP                               |      y      |defconfig | cut_attack_surface |   OK
CONFIG_SECCOMP_FILTER                        |      y      |defconfig | cut_attack_surface |   OK
CONFIG_STRICT_DEVMEM                         |      y      |defconfig | cut_attack_surface |   OK
CONFIG_ACPI_CUSTOM_METHOD                    | is not set  |   kspp   | cut_attack_surface |   OK
CONFIG_COMPAT_BRK                            | is not set  |   kspp   | cut_attack_surface |   OK
CONFIG_DEVKMEM                               | is not set  |   kspp   | cut_attack_surface |   OK
CONFIG_COMPAT_VDSO                           | is not set  |   kspp   | cut_attack_surface |   OK
CONFIG_OABI_COMPAT                           | is not set  |   kspp   | cut_attack_surface |   OK: not found
CONFIG_X86_PTDUMP                            | is not set  |grsecurity| cut_attack_surface |   OK
CONFIG_ZSMALLOC_STAT                         | is not set  |grsecurity| cut_attack_surface |   OK
CONFIG_PAGE_OWNER                            | is not set  |grsecurity| cut_attack_surface |   OK
CONFIG_DEBUG_KMEMLEAK                        | is not set  |grsecurity| cut_attack_surface |   OK
CONFIG_BINFMT_AOUT                           | is not set  |grsecurity| cut_attack_surface |   OK: not found
CONFIG_DRM_LEGACY                            | is not set  |maintainer| cut_attack_surface |   OK
CONFIG_X86_IOPL_IOPERM                       | is not set  | lockdown | cut_attack_surface |   OK: not found
CONFIG_MMIOTRACE_TEST                        | is not set  | lockdown | cut_attack_surface |   OK
CONFIG_X86_INTEL_TSX_MODE_OFF                |      y      |  clipos  | cut_attack_surface |   OK
CONFIG_INTEGRITY                             |      y      |defconfig |userspace_hardening |   OK

[+] Config check is finished: 'OK' - 57 / 'FAIL' - 79 (suppressed in output)
```

#### <img src="https://avatars.githubusercontent.com/u/14027079?u=379b0b0fcecea8820dea0f220dc09e3342cc4519&v=4" width="50">[fonic](https://github.com/fonic) commented at [2020-07-15 15:14](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/45#issuecomment-658827875):

Awesome, just tested it. That makes an already great tool even better. Many thanks!


-------------------------------------------------------------------------------

# [\#44 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/44) `closed`: KSPP future in defconf linux distribution.

#### <img src="https://avatars.githubusercontent.com/u/3471772?u=8db711eeb856b86264fa6d1e6887577d76af09ad&v=4" width="50">[bryn1u](https://github.com/bryn1u) opened issue at [2020-05-10 18:01](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/44):

Hello,

Im just curious what is the status of implementing KSPP to default kernel of linux GNU distribution ? Why linux distributions dont impelment for example most of kspp solutions for example steackleak or gcc hardeneing ? I use most of kspp feature based on your script Alexander and kernel works like a charm. Someone can explain to me ?

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2020-05-11 11:40](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/44#issuecomment-626650276):

Some settings may affect performance, debugability, support for older userspace software, etc.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-05-18 09:58](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/44#issuecomment-630078520):

> Some settings may affect performance, debugability, support for older userspace software, etc.

I agree. 
Moreover, kernel self-protection features often give different performance penalty for different kinds of workload. It's difficult to find one kernel configuration that makes everyone happy.

I think Linux distributions could provide several kernel flavours for different purposes (e.g. generic, hardened, low-latency), to improve the situation.

I'm sure @kees has more insights about this.

#### <img src="https://avatars.githubusercontent.com/u/1110841?u=e5e99e1ac8260e791433baa2423f7d173eea4c1c&v=4" width="50">[kees](https://github.com/kees) commented at [2020-05-18 15:16](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/44#issuecomment-630251690):

Yup! There is an open bug with KSPP to provide a defconfig fragment selection interface to the upstream kernel. You can see more details here:
https://github.com/KSPP/linux/issues/14

#### <img src="https://avatars.githubusercontent.com/u/3471772?u=8db711eeb856b86264fa6d1e6887577d76af09ad&v=4" width="50">[bryn1u](https://github.com/bryn1u) commented at [2020-05-20 21:06](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/44#issuecomment-631726899):

Okey. Thanks guys for your work and explanation.


-------------------------------------------------------------------------------

# [\#43 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/43) `merged`: Upgrading to Ubuntu 20.04 kernel config

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) opened issue at [2020-05-05 09:12](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/43):

Hi @a13xp0p0v, 

Here is the Ubuntu kernel configuration update.

Best regards.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-05-06 21:41](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/43#issuecomment-624906056):

Thanks @HacKurx!


-------------------------------------------------------------------------------

# [\#42 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/42) `closed`: add tests

#### <img src="https://avatars.githubusercontent.com/u/3125993?v=4" width="50">[shamilbi](https://github.com/shamilbi) opened issue at [2020-04-14 12:10](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/42):



#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-04-24 23:29](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/42#issuecomment-619279461):

Hello @shamilbi !
Could you please describe the purpose of this PR?
By the way, tests for `kconfig-hardened-check` already exist as GitHub Actions (kind of continuous integration).

#### <img src="https://avatars.githubusercontent.com/u/3125993?v=4" width="50">[shamilbi](https://github.com/shamilbi) commented at [2020-04-25 07:33](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/42#issuecomment-619335943):

> Hello @shamilbi !
> Could you please describe the purpose of this PR?
> By the way, tests for `kconfig-hardened-check` already exist as GitHub Actions (kind of continuous integration).

If files `tests/results/**/*.check` are proper results of kconfig-hardened-check applied to `kconfig_hardened_check/config_files/**/*.config` then this PR just compares output of a current kconfig_hardened_check (a current commit) with those proper results.
This gives you an exact diff in output from a last commit

#### <img src="https://avatars.githubusercontent.com/u/3125993?v=4" width="50">[shamilbi](https://github.com/shamilbi) commented at [2020-04-25 07:43](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/42#issuecomment-619337059):

[My workflows file](https://github.com/shamilbi/kconfig-hardened-check/blob/master/.github/workflows/test-master.yml)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-05-06 21:19](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/42#issuecomment-624897025):

Yes, sometimes I use ouput diff during the `kconfig-hardened-check` development.
However I don't think we need to commit the output results to the repository.
Thank you anyway.


-------------------------------------------------------------------------------

# [\#41 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/41) `merged`: Add CONFIG_INPUT_EVBUG

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) opened issue at [2020-04-09 11:38](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/41):

Hi @a13xp0p0v,

The "evbug" module records key events and mouse movements in the system log.
Useful for debugging, this is a security threat, its use can be hijacked as a keylogger.

An attacker will be able to retrieve your passwords using this module.

Thank you.

Best regards,

#### <img src="https://avatars.githubusercontent.com/u/8655789?u=4694f03b321aa2287d9fe05155adcddb23272e81&v=4" width="50">[codecov-io](https://github.com/codecov-io) commented at [2020-04-09 11:39](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/41#issuecomment-611482374):

# [Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/41?src=pr&el=h1) Report
> Merging [#41](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/41?src=pr&el=desc) into [master](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/commit/100a39e2b01dadd2d27ed805cbe2b4ead7fc8b05&el=desc) will **increase** coverage by `0.01%`.
> The diff coverage is `100.00%`.

[![Impacted file tree graph](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/41/graphs/tree.svg?width=650&height=150&src=pr&token=GOOVXMV5Kb)](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/41?src=pr&el=tree)

```diff
@@            Coverage Diff             @@
##           master      #41      +/-   ##
==========================================
+ Coverage   93.19%   93.20%   +0.01%     
==========================================
  Files           3        3              
  Lines         470      471       +1     
  Branches      100      100              
==========================================
+ Hits          438      439       +1     
  Misses         17       17              
  Partials       15       15              
```

| Flag | Coverage Δ | |
|---|---|---|
| #functional_test | `93.20% <100.00%> (+0.01%)` | :arrow_up: |

| [Impacted Files](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/41?src=pr&el=tree) | Coverage Δ | |
|---|---|---|
| [kconfig\_hardened\_check/\_\_init\_\_.py](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/41/diff?src=pr&el=tree#diff-a2NvbmZpZ19oYXJkZW5lZF9jaGVjay9fX2luaXRfXy5weQ==) | `93.27% <100.00%> (+0.01%)` | :arrow_up: |

------

[Continue to review full report at Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/41?src=pr&el=continue).
> **Legend** - [Click here to learn more](https://docs.codecov.io/docs/codecov-delta)
> `Δ = absolute <relative> (impact)`, `ø = not affected`, `? = missing data`
> Powered by [Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/41?src=pr&el=footer). Last update [100a39e...a7e1677](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/41?src=pr&el=lastupdated). Read the [comment docs](https://docs.codecov.io/docs/pull-request-comments).


-------------------------------------------------------------------------------

# [\#40 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/40) `merged`: pylint some code

#### <img src="https://avatars.githubusercontent.com/u/3125993?v=4" width="50">[shamilbi](https://github.com/shamilbi) opened issue at [2020-04-08 07:01](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/40):



#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-04-09 15:35](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/40#issuecomment-611595095):

Thanks @shamilbi.
Merged.


-------------------------------------------------------------------------------

# [\#39 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/39) `closed`: VerCheck: work with 3-digit kernel versions

#### <img src="https://avatars.githubusercontent.com/u/3125993?v=4" width="50">[shamilbi](https://github.com/shamilbi) opened issue at [2020-04-03 15:54](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/39):



#### <img src="https://avatars.githubusercontent.com/u/8655789?u=4694f03b321aa2287d9fe05155adcddb23272e81&v=4" width="50">[codecov-io](https://github.com/codecov-io) commented at [2020-04-03 16:25](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/39#issuecomment-608535796):

# [Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/39?src=pr&el=h1) Report
> Merging [#39](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/39?src=pr&el=desc) into [master](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/commit/bdac2c22b96b3a682801674efed92fddc8a347b0&el=desc) will **increase** coverage by `0.60%`.
> The diff coverage is `76.92%`.

[![Impacted file tree graph](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/39/graphs/tree.svg?width=650&height=150&src=pr&token=GOOVXMV5Kb)](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/39?src=pr&el=tree)

```diff
@@            Coverage Diff             @@
##           master      #39      +/-   ##
==========================================
+ Coverage   93.10%   93.70%   +0.60%     
==========================================
  Files           2        2              
  Lines         464      461       -3     
  Branches      100      101       +1     
==========================================
  Hits          432      432              
+ Misses         17       15       -2     
+ Partials       15       14       -1     
```

| Flag | Coverage Δ | |
|---|---|---|
| #functional_test | `93.70% <76.92%> (+0.60%)` | :arrow_up: |

| [Impacted Files](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/39?src=pr&el=tree) | Coverage Δ | |
|---|---|---|
| [kconfig\_hardened\_check/\_\_init\_\_.py](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/39/diff?src=pr&el=tree#diff-a2NvbmZpZ19oYXJkZW5lZF9jaGVjay9fX2luaXRfXy5weQ==) | `93.80% <76.92%> (+0.61%)` | :arrow_up: |

------

[Continue to review full report at Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/39?src=pr&el=continue).
> **Legend** - [Click here to learn more](https://docs.codecov.io/docs/codecov-delta)
> `Δ = absolute <relative> (impact)`, `ø = not affected`, `? = missing data`
> Powered by [Codecov](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/39?src=pr&el=footer). Last update [bdac2c2...97b9f90](https://codecov.io/gh/a13xp0p0v/kconfig-hardened-check/pull/39?src=pr&el=lastupdated). Read the [comment docs](https://docs.codecov.io/docs/pull-request-comments).

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-04-06 13:32](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/39#issuecomment-609796546):

Hello @shamilbi,
Thanks for your work!

Yes, the kernel version consists of 3 numbers (not digits). 
Example from the main kernel Makefile:
```
VERSION = 5
PATCHLEVEL = 6
SUBLEVEL = 0
```

New features come during the merge window of a new release of the mainline kernel.
It is defined by 2 numbers - `version` and `patchlevel`.
More info: https://www.kernel.org/doc/html/latest/process/2.Process.html
That's why currently only two numbers are checked and IMO that's enough.

Thanks!
Alexander

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-04-07 15:47](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/39#issuecomment-610465555):

@shamilbi, could you please move pylint fixes to a separate pull request?
I would like to merge it. Thanks!

#### <img src="https://avatars.githubusercontent.com/u/3125993?v=4" width="50">[shamilbi](https://github.com/shamilbi) commented at [2020-04-08 08:35](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/39#issuecomment-610828778):

> @shamilbi, could you please move pylint fixes to a separate pull request?
> I would like to merge it. Thanks!
OK, done


-------------------------------------------------------------------------------

# [\#38 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/38) `closed`: graphics related options

#### <img src="https://avatars.githubusercontent.com/u/5088003?v=4" width="50">[danvet](https://github.com/danvet) opened issue at [2020-04-03 08:52](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/38):

Discussion with dmitry yukov on twitter:

CONFIG_DRM_LEGACY: Really old drivers from the 90s, with unfixable by design security holes. Unfortunately userspace for one modern driver (drm/nouveau) has used until just a few years ago by accident (we didn't delete all the old legacy driver setup code), so can't remove it all completely yet from kernel sources.

CONFIG_FB: Old display subsystem from the 90s, essentially unmaintained for over 10 years, would need serious effort to get up to speed with modern security best practices. This even includes the minimal fbdev emulation support built on top of drm gpu drivers, since the issues are in core fbdev code.

CONFIG_VT: Maybe the most disputed of all, but a lot of the console drivers this exposes to userspace are also from the 90s, and without CONFIG_FB this isn't really useful even for a desktop. A hardened distro definitely wants to make sure this is not set at all.



#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2020-04-03 12:03](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/38#issuecomment-608395946):

> You need at least one virtual terminal device in order to make use of your keyboard and monitor. Therefore, only people configuring an embedded system would want to say N here in order to save some memory; the only way to log into such a system is then via a serial or network connection.

Is this comment from [CONFIG_VT](https://cateee.net/lkddb/web-lkddb/VT.html) wrong then?

#### <img src="https://avatars.githubusercontent.com/u/5088003?v=4" width="50">[danvet](https://github.com/danvet) commented at [2020-04-03 12:32](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/38#issuecomment-608407778):

This comment hasn't been updated since decades (I checked historical trees ...). Nowadays Xorg and wayland compositors should be able to run without a VT. And kmscon (although abandoned due to lack of interest) can provide you a userspace implementation of VTs if you don't want to run X11 or wayland, using pseudo TTYs (like a terminal emulator).

A paranoid desktop distro imo should really not have VT enabled, and ofc whatever compositor they opt for (wayland, X11, or something like kmscon) needs to be walled in with a container.

But the comment is also correct in that without a userspace compositor you indeed will only be able to log in through the network or serial lines.

#### <img src="https://avatars.githubusercontent.com/u/5088003?v=4" width="50">[danvet](https://github.com/danvet) commented at [2020-04-03 12:42](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/38#issuecomment-608412082):

Maybe an addition: If you want multi-user switching without CONFIG_VT then you need something like systemd's logind, so that the (forced) handover of input and output devices works correctly. But the VT subsystem's only role there is as an rpc between compositors, it has 0 functionality to actually force compositors to hand over devices to the next compositor (which is what logind does, using some of the new ioctl calls added specifically for this for both input and drm subsystems).

So if you want actual secure multi-user switching then you should be running with all that new stuff already anyway (and then CONFIG_VT really shouldn't be enabled, to prevent creating a mess).

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-04-03 17:03](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/38#issuecomment-608553993):

Thanks @danvet !
Done: https://github.com/a13xp0p0v/kconfig-hardened-check/commit/75bed5d6178375a64f93ced4795ee0cf47442df1

#### <img src="https://avatars.githubusercontent.com/u/5088003?v=4" width="50">[danvet](https://github.com/danvet) commented at [2020-04-03 17:24](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/38#issuecomment-608563651):

Thanks, looks neat. Hopefully this pushes a few more people to make this happen finally.

#### <img src="https://avatars.githubusercontent.com/u/1095328?u=91175c42d0de0ad8ba9f70cc6b9a41bbfbe70de8&v=4" width="50">[dvyukov](https://github.com/dvyukov) commented at [2020-04-03 17:28](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/38#issuecomment-608565745):

@a13xp0p0v Are these enabled in any distros for which you have canned configs?

@danvet I just noticed on the current upstream HEAD:
```
$ rm .config
$ make defconfig
$ egrep "CONFIG_VT=|CONFIG_FB=" .config
CONFIG_VT=y
CONFIG_FB=y
```
So that may be the first step :)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-04-03 20:18](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/38#issuecomment-608639217):

@dvyukov, yes, these are enabled in many distributions:
```
AOSP_Pixel3A:
  CONFIG_DRM_LEGACY    | is not set  |maintainer| cut_attack_surface |   OK
  CONFIG_FB            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"
  CONFIG_VT            | is not set  |maintainer| cut_attack_surface |   OK

AmazonLinux2:
  CONFIG_DRM_LEGACY    | is not set  |maintainer| cut_attack_surface |   OK
  CONFIG_FB            | is not set  |maintainer| cut_attack_surface |   FAIL: "m"
  CONFIG_VT            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"

ubuntu-bionic-generic:
  CONFIG_DRM_LEGACY    | is not set  |maintainer| cut_attack_surface |   OK
  CONFIG_FB            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"
  CONFIG_VT            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"

oracle-uek6:
  CONFIG_DRM_LEGACY    | is not set  |maintainer| cut_attack_surface |   FAIL: "y"
  CONFIG_FB            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"
  CONFIG_VT            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"

Archlinux-hardened:
  CONFIG_DRM_LEGACY    | is not set  |maintainer| cut_attack_surface |   OK
  CONFIG_FB            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"
  CONFIG_VT            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"

clearlinux-master:
  CONFIG_DRM_LEGACY    | is not set  |maintainer| cut_attack_surface |   FAIL: "y"
  CONFIG_FB            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"
  CONFIG_VT            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"

SLE15:
  CONFIG_DRM_LEGACY    | is not set  |maintainer| cut_attack_surface |   OK
  CONFIG_FB            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"
  CONFIG_VT            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"

openSUSE-15.1:
  CONFIG_DRM_LEGACY    | is not set  |maintainer| cut_attack_surface |   OK
  CONFIG_FB            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"
  CONFIG_VT            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"

pentoo-livecd:
  CONFIG_DRM_LEGACY    | is not set  |maintainer| cut_attack_surface |   OK
  CONFIG_FB            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"
  CONFIG_VT            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"

rhel-8.0:
  CONFIG_DRM_LEGACY    | is not set  |maintainer| cut_attack_surface |   OK
  CONFIG_FB            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"
  CONFIG_VT            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"

nixpkgs-linux_hardened:
  CONFIG_DRM_LEGACY    | is not set  |maintainer| cut_attack_surface |   FAIL: "y"
  CONFIG_FB            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"
  CONFIG_VT            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"

debian-buster:
  CONFIG_DRM_LEGACY    | is not set  |maintainer| cut_attack_surface |   FAIL: "y"
  CONFIG_FB            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"
  CONFIG_VT            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"

Alpinelinux-edge:
  CONFIG_DRM_LEGACY    | is not set  |maintainer| cut_attack_surface |   FAIL: "y"
  CONFIG_FB            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"
  CONFIG_VT            | is not set  |maintainer| cut_attack_surface |   FAIL: "y"
```

#### <img src="https://avatars.githubusercontent.com/u/1080275?v=4" width="50">[arndb](https://github.com/arndb) commented at [2020-04-04 09:48](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/38#issuecomment-609004574):

The hyperv framebuffer driver came up on the mailing list recently when I noticed a patch to add support for arm64 and suggested having it converted to DRM. Other hardware-independent drivers that don't seem to have a DRM counterpart at the moment are the UEFI framebuffer that is often used in the absence of a hardware specific driver and the goldfish driver for Android device emulation.

It might help to also look at each distro to see which device drivers are enabled for DRM_LEGACY and FBDEV, as there may be others that are important and need to be converted.

#### <img src="https://avatars.githubusercontent.com/u/5088003?v=4" width="50">[danvet](https://github.com/danvet) commented at [2020-04-04 11:12](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/38#issuecomment-609012871):

@dvyukov the trouble is you'll break pretty much any general purpose distro with this stuff disabled. Iirc most compositors keel over if they can't open a vt (but they should all have options to survive without one). Plus since neither kmscon nor system-consoled ever happened for real no kernel console without these, so all the whitebeards will be screaming with their pitchforks. Really not something you can do in a defconfig unfortunately.

@arndb yeah there was simpledrm also back around kmscon to make this happen, but it didn't. For everything else we seem to have a small community of people now pushing out drm drivers for all these things, but more is always welcome. A drm driver in less that 1kloc is fairly standard nowadays, trouble only happens if you have a strange new constraint.

Wrt DRM_LEGACY and FBDEV drivers in general, I get the impression that distros which enable them just enable everything, because. E.g. debian still enables DRM_LEGACY, but they long ago stopped shipping the corresponding userspace drivers. So just plain nonsense in their defconfig (and a CVE when you load drm/nouveau.ko because backwards compat)


-------------------------------------------------------------------------------

# [\#37 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/37) `closed`: conflict with the latest grsecurity

#### <img src="https://avatars.githubusercontent.com/u/50359848?v=4" width="50">[pythonmandev](https://github.com/pythonmandev) opened issue at [2020-03-30 14:20](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/37):

CONFIG_REFCOUNT_FULL conflict with PAX_REFCOUNT
PAGE_TABLE_ISOLATION conflict with PAX_MEMORY_UDEREF
VMAP_STACK conflict with GRKERNSEC_KSTACKOVERFLOW
SECURITY_YAMA conflict with GRKERNSEC
RANDOMIZE_BASE also can not enable.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-03-31 11:29](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/37#issuecomment-606569944):

Hello @pythonmandev!
What do you mean saying "latest grsecurity"?

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2020-03-31 11:38](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/37#issuecomment-606574067):

its not an openly available patchset anymore hence i suggest to not take it into account. I would think differently if it would be open source, but sadly its not.


-------------------------------------------------------------------------------

# [\#36 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/36) `closed`: null

#### <img src="(unknown)" width="50">[(unknown)]((unknown)) opened issue at [2020-03-30 14:13](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/36):

null




-------------------------------------------------------------------------------

# [\#35 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/35) `closed`: can't add version check for constraints in a logical product

#### <img src="https://avatars.githubusercontent.com/u/785111?u=8feaa758657096dbcadcd190fbea88e371aab7be&v=4" width="50">[tych0](https://github.com/tych0) opened issue at [2020-03-26 17:44](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/35):

If I try to do:

```
diff --git a/kconfig_hardened_check/__init__.py b/kconfig_hardened_check/__init__.py
index 3fcb5e0..1c31c40 100755
--- a/kconfig_hardened_check/__init__.py
+++ b/kconfig_hardened_check/__init__.py
@@ -251,8 +251,8 @@ def construct_checklist(checklist, arch):
         checklist.append(OptCheck('MICROCODE',                   'y', 'defconfig', 'self_protection')) # is needed for mitigating CPU bugs
         checklist.append(OptCheck('RETPOLINE',                   'y', 'defconfig', 'self_protection'))
         checklist.append(OptCheck('X86_SMAP',                    'y', 'defconfig', 'self_protection'))
-        checklist.append(OR(OptCheck('X86_UMIP',                 'y', 'defconfig', 'self_protection'), \
-                            OptCheck('X86_INTEL_UMIP',           'y', 'defconfig', 'self_protection')))
+        checklist.append(OR(AND(OptCheck('X86_UMIP',                 'y', 'defconfig', 'self_protection'), VerCheck((5, 5))), \
+                            AND(OptCheck('X86_INTEL_UMIP',           'y', 'defconfig', 'self_protection'), VerCheck((4, 14)))))
         checklist.append(OptCheck('SYN_COOKIES',                 'y', 'defconfig', 'self_protection')) # another reason?
     if arch == 'X86_64':
         checklist.append(OptCheck('PAGE_TABLE_ISOLATION',        'y', 'defconfig', 'self_protection'))
```

I get:

```
Traceback (most recent call last):
  File "/home/tycho/.local/bin/kconfig-hardened-check", line 10, in <module>
    sys.exit(main())
  File "/home/tycho/.local/lib/python3.7/site-packages/kconfig_hardened_check/__init__.py", line 611, in main
    check_config_file(config_checklist, args.config, arch)
  File "/home/tycho/.local/lib/python3.7/site-packages/kconfig_hardened_check/__init__.py", line 554, in check_config_file
    perform_checks(checklist, parsed_options)
  File "/home/tycho/.local/lib/python3.7/site-packages/kconfig_hardened_check/__init__.py", line 519, in perform_checks
    o.state = parsed_options.get(o.name, None)
AttributeError: can't set attribute
```

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-03-28 20:54](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/35#issuecomment-605518372):

Hello @tych0!
I'm glad that you had a look at this project!
How are you doing? :)

Yes, currently the combination of `ComplexOptCheck` objects is not supported (there have been no cases that needed it).

The original logic behind `X86_UMIP` check:
 - if `X86_UMIP` or `X86_INTEL_UMIP` is set to `y`, then `OK`;
 - otherwise `FAIL`.

What is the purpose of combining `UMIP` check with version check?

I designed `VerCheck` for cases like that:
 - if `REFCOUNT_FULL` is set to `y`, then `OK`;
 - if kernel version >= `5.5`, then `OK` (since `REFCOUNT_FULL` is enabled by default and dropped since v5.5);
 - otherwise `FAIL`.

N.B. There is an implicit drawback with checking kernel versions.
Some kernel features are backported to previous stable kernels.
That's why checking the version can give false positive or false negative result.
Detailed example: https://github.com/a13xp0p0v/kconfig-hardened-check/pull/32

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/785111?u=8feaa758657096dbcadcd190fbea88e371aab7be&v=4" width="50">[tych0](https://github.com/tych0) commented at [2020-03-29 14:51](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/35#issuecomment-605648635):

On Sat, Mar 28, 2020 at 01:55:08PM -0700, Alexander Popov wrote:
> Hello @tych0!
> I'm glad that you had a look at this project!
> How are you doing? :)

Good, just hacking away :)

> Yes, currently the combination of `ComplexOptCheck` objects is not supported (there have been no cases that needed it).
> 
> The original logic behind `X86_UMIP` check:
>  - if `X86_UMIP` or `X86_INTEL_UMIP` is set to `y`, then `OK`;
>  - otherwise `FAIL`.
> 
> What is the purpose of combining `UMIP` check with version check?

It's only present in 4.15 or greater; I'm running a 4.14 kernel and
kconfig-hardened-check is complaining at me :)

> I designed `VerCheck` for cases like that:
>  - if `REFCOUNT_FULL` is set to `y`, then `OK`;
>  - if kernel version >= `5.5`, then `OK` (since `REFCOUNT_FULL` is enabled by default and dropped since v5.5);
>  - otherwise `FAIL`.
> 
> N.B. There is an implicit drawback with checking kernel versions.
> Some kernel features are backported to previous stable kernels.
> That's why checking the version can give false positive or false negative result.
> Detailed example: https://github.com/a13xp0p0v/kconfig-hardened-check/pull/32

"Not present" is also risky though, if people don't have some of the
dependencies of a feature enabled. A version whitelist seems the best.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-03-30 21:12](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/35#issuecomment-606252748):

>> What is the purpose of combining `UMIP` check with version check?

> It's only present in 4.15 or greater; I'm running a 4.14 kernel and kconfig-hardened-check is complaining at me :)

Yes, that's good. The tool inspires you to switch onto a newer kernel :)

> "Not present" is also risky though, if people don't have some of the
dependencies of a feature enabled. 

You know, I haven't seen any example of such unmet dependencies. I suppose that kernel feature dependencies are resolved by Kconfig.

> A version whitelist seems the best.

I would like to avoid version checking as much as possible.
Relying on kernel version brings so many troubles!
For example:
 - sometimes new features are backported to previous stable kernels,
 - sometimes Linux distributions cherry-pick features into their kernels,
 - some Linux distributions have custom kernel versioning scheme -- look at Ubuntu or Red Hat.

Finally, the most important aspect.
I like that kernels of different versions are checked against the same list of recommendations.
Hence they can be compared using `OK/FAIL` numbers that are printed by the tool in the end:
```
[+] config check is finished: 'OK' - 55 / 'FAIL' - 77
```

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-04-10 16:49](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/35#issuecomment-612117051):

@tych0 your issue reminded me the idea to create some formatted annotations, that can be used for muting checks for a particular kernel. That was discussed in #9.
Thank you.

#### <img src="https://avatars.githubusercontent.com/u/785111?u=8feaa758657096dbcadcd190fbea88e371aab7be&v=4" width="50">[tych0](https://github.com/tych0) commented at [2020-04-10 16:55](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/35#issuecomment-612119721):

Sorry, I read this and forgot to respond :)

> Yes, that's good. The tool inspires you to switch onto a newer kernel :)

Yes, but switching is not so easy sometimes, because of institutional challenges. If we want to add this to our CI to check our kernel configs or something, it would be nice to exclude stuff that doesn't exist in our kernel. I can do this manually, but it would be nicer to have this knowledge baked into the script.

> You know, I haven't seen any example of such unmet dependencies. I suppose that kernel feature dependencies are resolved by Kconfig.

Consider GCC_PLUGIN_STACKLEAK; we'll report "Not present" if the user hasn't set CONFIG_GCC_PLUGINS=n, but it really should be an error.

#### <img src="https://avatars.githubusercontent.com/u/785111?u=8feaa758657096dbcadcd190fbea88e371aab7be&v=4" width="50">[tych0](https://github.com/tych0) commented at [2020-04-10 16:56](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/35#issuecomment-612119803):

Anwyay, I'll check out the updates, thanks :)


-------------------------------------------------------------------------------

# [\#34 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/34) `merged`: GrapheneOS is the continuation of CopperheadOS

#### <img src="https://avatars.githubusercontent.com/u/50278627?v=4" width="50">[madaidan](https://github.com/madaidan) opened issue at [2020-03-22 19:44](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/34):

"CopperheadOS" is the project's legacy name which is now being used for a scam focused on attacking GrapheneOS, the true continuation.

https://twitter.com/DanielMicay/status/1171170734380654597

https://twitter.com/DanielMicay/status/1160831422908829696

https://old.reddit.com/r/CopperheadOS/comments/8qdnn3/goodbye/

https://github.com/yegortimoshenko/copperhead-takeover




-------------------------------------------------------------------------------

# [\#33 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/33) `closed`: CONFIG_STATIC_USERMODEHELPER

#### <img src="https://avatars.githubusercontent.com/u/543852?v=4" width="50">[anthonyryan1](https://github.com/anthonyryan1) opened issue at [2020-03-20 22:25](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/33):

I read over the CLIP OS notes regarding this option, and they also mention that they are not currently using it in the second paragraph.

It seems to be that this option isn't actually helpful unless you've already got a usermode helper program?

Just questioning the wisdom of this option as I imagine some people will just enable everything they see here, and may wind up with this pointing at a non-existent binary.

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2020-03-21 10:52](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/33#issuecomment-602026415):

Yes, this option needs userspace support and yes, blindly enabling everything may cause harm.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-03-23 15:22](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/33#issuecomment-602670488):

@Bernhard40, absolutely agree.
N.B. There is a comment about `STATIC_USERMODEHELPER` in the source code:
```
checklist.append(OptCheck('STATIC_USERMODEHELPER', 'y', 'clipos', 'self_protection')) # needs userspace support (systemd)
```


-------------------------------------------------------------------------------

# [\#32 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/32) `closed`: Fix LDISC_AUTOLOAD check

#### <img src="https://avatars.githubusercontent.com/u/50278627?v=4" width="50">[madaidan](https://github.com/madaidan) opened issue at [2020-03-09 18:01](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/32):

CONFIG_LDISC_AUTOLOAD has existed since v4.14, not v5.1: https://lkml.org/lkml/2019/4/15/890

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-03-14 09:52](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/32#issuecomment-599034709):

Hello @madaidan,

Thanks for noticing that!

CONFIG_LDISC_AUTOLOAD was introduced in 5.1:
changelog https://kernelnewbies.org/Linux_5.1
upstream commit https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=7c0cca7c847e6e019d67b7d793efbbe3b947d004

I checked, it was later backported to stable kernels 4.14, 4.9 and 4.4.
So we can't have a correct check based on a kernel version.
For example this option exists in kernel 4.4.216, but doesn't exist in 4.5.

I think the correct approach here is to add another type of check that can distinguish "is not set" and "not found".

What do you think?

#### <img src="https://avatars.githubusercontent.com/u/50278627?v=4" width="50">[madaidan](https://github.com/madaidan) commented at [2020-03-14 20:29](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/32#issuecomment-599131303):

How about a whitelist of allowed versions? So it checks for 4.4, 4.9, 4.14 or ≥5.1 but not 4.5.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-03-31 11:46](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/32#issuecomment-606577240):

Hm, I got an idea.
I'll try to create a new check that the option __exists__ in the config.
So for `LDISC_AUTOLOAD` we can create a rule `(exists) AND (is not set)`.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-03-31 14:13](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/32#issuecomment-606654029):

Done!
Thanks!


-------------------------------------------------------------------------------

# [\#31 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/31) `merged`: Update config files

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) opened issue at [2020-02-24 20:27](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/31):

Hi @a13xp0p0v, 

Here are the updates of the distributions configuration files. I also had to update some links.
Please note that we now have the majority of configurations with versions >= to linux 5.3 🧙‍♂️

See you soon.

Best regards,

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-02-27 17:36](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/31#issuecomment-592084682):

Thanks, @HacKurx!

N.B. I'm going to work on support of new kernel releases in the near future.

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2020-03-04 19:09](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/31#issuecomment-594761475):

@a13xp0p0v, 
> N.B. I'm going to work on support of new kernel releases in the near future.

https://kernsec.org/wiki/index.php?title=Kernel_Self_Protection_Project/Recommended_Settings&diff=4001&oldid=prev

:wink:

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-03-04 19:55](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/31#issuecomment-594797254):

Yes, thanks, I'm already working on that!


-------------------------------------------------------------------------------

# [\#30 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/30) `closed`: Has CONFIG_REFCOUNT_FULL and VMAP_STACK been removed from Kernel-5.5 ?

#### <img src="https://avatars.githubusercontent.com/u/3471772?u=8db711eeb856b86264fa6d1e6887577d76af09ad&v=4" width="50">[bryn1u](https://github.com/bryn1u) opened issue at [2020-02-01 12:24](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/30):

Hey everyone,

Im trying to configure Kernel-5.5 config and i don't see CONFIG_REFCOUNT_FULL option and the same with VMAP_STACK.
I use Kernel-5.3 for now and there is an option available. Soo should i think that this option is no longer available ?

Thanks !

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2020-02-02 13:05](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/30#issuecomment-581133592):

`CONFIG_REFCOUNT_FULL` was removed but `CONFIG_VMAP_STACK` is still available.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-02-05 16:54](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/30#issuecomment-582504214):

Yes, `REFCOUNT_FULL` was removed...
Have to find a way how to check it without false positive.

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2020-02-06 12:30](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/30#issuecomment-582884278):

@a13xp0p0v there is kernel version printed in config header, like:

```
#
# Automatically generated file; DO NOT EDIT.
# Linux/x86 5.5.2 Kernel Configuration
#
```

maybe you can parse those?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-02-06 15:25](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/30#issuecomment-582957059):

Yes, it looks like we have to add some limited kernel version checking...

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-02-06 15:29](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/30#issuecomment-582959470):

I may have time to work on that only after OffensiveCon.
Does anybody want to prepare a pull request?

#### <img src="https://avatars.githubusercontent.com/u/3471772?u=8db711eeb856b86264fa6d1e6887577d76af09ad&v=4" width="50">[bryn1u](https://github.com/bryn1u) commented at [2020-02-09 13:03](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/30#issuecomment-583842999):

Hey,

Is a CONFIG_HAVE_ARCH_VMAP_STACK in Kernel-5.5.2 equivalent to
CONFIG_VMAPSTACK ?

Thanks !

czw., 6 lut 2020 o 16:29 Alexander Popov <notifications@github.com>
napisał(a):

> I may have time to work on that only after OffensiveCon.
> Does anybody want to prepare a pull request?
>
> —
> You are receiving this because you authored the thread.
> Reply to this email directly, view it on GitHub
> <https://github.com/a13xp0p0v/kconfig-hardened-check/issues/30?email_source=notifications&email_token=AA2PTHCFMA26NITNFRMNTU3RBQUHBA5CNFSM4KOS3L22YY3PNVWWK3TUL52HS4DFVREXG43VMVBW63LNMVXHJKTDN5WW2ZLOORPWSZGOEK7UC3Q#issuecomment-582959470>,
> or unsubscribe
> <https://github.com/notifications/unsubscribe-auth/AA2PTHBA772R35Y6MYOQS6DRBQUHBANCNFSM4KOS3L2Q>
> .
>

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2020-02-10 14:32](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/30#issuecomment-584150411):

> Is a CONFIG_HAVE_ARCH_VMAP_STACK in Kernel-5.5.2 equivalent to
> CONFIG_VMAPSTACK ?

No `CONFIG_HAVE_ARCH_VMAP_STACK` tells only if `VMAP_STACK` is available for specific cpu architecture. `CONFIG_VMAP_STACK` tells if `VMAP_STACK` is enabled.

You can check that [VMAP_STACK definitely still exist up to 5.6-rc](https://cateee.net/lkddb/web-lkddb/VMAP_STACK.html).

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-03-05 11:03](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/30#issuecomment-595170199):

Hello!

Worked with that issue in 0ace19012b626203d14332090cdcd40ed2237100, 918b12cf6f652ad148c885d1a802459e73d20c48 and 17c22224ac5b20c3d0ed49e7859642756e178bd9.

Also have a look at 61b5ca3c8f95212141284be8eb4036c8c1bda9e7: that fixes the false positive report about LDISC_AUTOLOAD for old kernels.


-------------------------------------------------------------------------------

# [\#29 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/29) `closed`: Recommend PANIC_ON_OOPS

#### <img src="https://avatars.githubusercontent.com/u/50278627?v=4" width="50">[madaidan](https://github.com/madaidan) opened issue at [2020-01-13 21:28](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/29):

This causes the kernel to panic on an oops.

Recommended by the KSPP and CLIP OS.

https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings

> \# Reboot devices immediately if kernel experiences an Oops.
> CONFIG_PANIC_ON_OOPS=y
> CONFIG_PANIC_TIMEOUT=-1

https://docs.clip-os.org/clipos/kernel.html

> CONFIG_PANIC_ON_OOPS=y
> CONFIG_PANIC_TIMEOUT=-1
>
>    Prevent potential further exploitation of a bug by immediately panicking the kernel.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-01-14 09:23](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/29#issuecomment-574081092):

Hello @madaidan,

Yes, I saw this KSPP recommendation.
I personally don't support it because it provides easy denial-of-service attack for the whole system (there are a lot of BUG()'s in the kernel).

In my opinion having CONFIG_BUG is enough. If we have kernel oops in the process context, the offending/attacking process is killed.

#### <img src="https://avatars.githubusercontent.com/u/50278627?v=4" width="50">[madaidan](https://github.com/madaidan) commented at [2020-01-14 16:52](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/29#issuecomment-574269683):

I think the kernel exploits this can prevent are more important than DoS.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-01-16 10:06](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/29#issuecomment-575078024):

> I think the kernel exploits this can prevent are more important than DoS.

Could you please give a real example of the exploit that:
  1. is NOT blocked by having `CONFIG_BUG=y`,
and
  2. is blocked by having `CONFIG_PANIC_ON_OOPS=y`.

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/50278627?v=4" width="50">[madaidan](https://github.com/madaidan) commented at [2020-01-16 17:30](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/29#issuecomment-575259978):

This is a good example since it explicitly mentions panic_on_oops: https://googleprojectzero.blogspot.com/2018/09/a-cache-invalidation-bug-in-linux.html

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-01-17 15:10](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/29#issuecomment-575664888):

> This is a good example since it explicitly mentions panic_on_oops: https://googleprojectzero.blogspot.com/2018/09/a-cache-invalidation-bug-in-linux.html

No, sorry, that's a wrong example.

In that exploit Jann Horn used the output of `WARN_ON_ONCE()`.
Having `CONFIG_PANIC_ON_OOPS=y` doesn't prevent his method, since kernel continues to run after `WARN_ON_ONCE()` anyway.

Moreover, let me quote Jann about CONFIG_PANIC_ON_OOPS:
```
It is off by default in the upstream kernel - and enabling it by default in distributions
would probably be a bad idea -, but it is e.g. enabled by Android.
```

If some users want to enable it anyway, they can always use `kernel.panic_on_oops` sysctl or the corresponding kernel command line parameter.

#### <img src="https://avatars.githubusercontent.com/u/50278627?v=4" width="50">[madaidan](https://github.com/madaidan) commented at [2020-01-20 17:34](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/29#issuecomment-576372137):

Alright. Fair enough.


-------------------------------------------------------------------------------

# [\#28 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/28) `closed`: Don't give errors about CONFIG_PAGE_POISONING when using an alternative

#### <img src="https://avatars.githubusercontent.com/u/50278627?v=4" width="50">[madaidan](https://github.com/madaidan) opened issue at [2020-01-09 19:36](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/28):

Some people use `CONFIG_INIT_ON_ALLOC_DEFAULT_ON`/`CONFIG_INIT_ON_FREE_DEFAULT_ON` or linux-hardened's `CONFIG_PAGE_SANITIZE` (for LTS kernels) instead of `CONFIG_PAGE_POISONING`. People using these alternatives will get pointless errors that may confuse them.

It would be better if the errors were only shown when not using these.

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2020-01-09 19:38](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/28#issuecomment-572720806):

I would love this :P

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-01-10 15:26](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/28#issuecomment-573079631):

As I remember, all these features are different in some sense.
Are you sure that they are alternative to each other?

#### <img src="https://avatars.githubusercontent.com/u/50278627?v=4" width="50">[madaidan](https://github.com/madaidan) commented at [2020-01-10 16:40](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/28#issuecomment-573110783):

As far as I know, they all have the same goal which is to overwrite memory to prevent use-after-free but they have some slight differences as `PAGE_POISONING` forces debugging bloat (as it is actually a debugging feature) which makes `init_on_{,free,alloc}` or `PAGE_SANITIZE` (which was dropped in newer linux-hardened versions for `init_on_{,free,alloc}`) better.

`init_on_{,free,alloc}` actually disables itself when `PAGE_POISONING` is being used to prevent conflict.

https://github.com/torvalds/linux/commit/6471384af2a6530696fc0203bafe4de41a23c9ef

> If either SLUB poisoning or page poisoning is enabled, those options take
precedence over init_on_alloc and init_on_free: initialization is only
applied to unpoisoned allocations.

Also notice that linux-hardened and ClipOS do not enable `PAGE_POISONING` but use the others instead.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-01-14 10:28](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/28#issuecomment-574108331):

@madaidan, thanks for the details.
So yes, `PAGE_POISONING` is a debugging feature.
It provides less erasing than `INIT_ON_FREE_DEFAULT_ON`.

I joined these checks with OR giving preference to `INIT_ON_FREE_DEFAULT_ON`.
Please see the linked commit.

#### <img src="https://avatars.githubusercontent.com/u/50278627?v=4" width="50">[madaidan](https://github.com/madaidan) commented at [2020-01-14 16:55](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/28#issuecomment-574271418):

Great, thanks.


-------------------------------------------------------------------------------

# [\#27 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27) `closed`: add nix build files

#### <img src="https://avatars.githubusercontent.com/u/96200?u=9ed15c85825694d00e996d605d728179b830c4fa&v=4" width="50">[Mic92](https://github.com/Mic92) opened issue at [2020-01-02 09:02](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27):



#### <img src="https://avatars.githubusercontent.com/u/96200?u=9ed15c85825694d00e996d605d728179b830c4fa&v=4" width="50">[Mic92](https://github.com/Mic92) commented at [2020-01-02 10:44](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27#issuecomment-570172617):

These are all possible kernel configurations:
There might be duplicate since linux-latest is basically linux-5.4.
I am not sure which configuration you want to include in this repository.
Maybe _hardened, _latest and the default kernel.

[nixpkgs-linux_latest-libre-config.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/4015570/nixpkgs-linux_latest-libre-config.txt)
[nixpkgs-linux_latest_hardened-config.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/4015571/nixpkgs-linux_latest_hardened-config.txt)
[nixpkgs-linux_testing_hardened-config.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/4015572/nixpkgs-linux_testing_hardened-config.txt)
[nixpkgs-linux_hardened-config.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/4015573/nixpkgs-linux_hardened-config.txt)
[nixpkgs-linux_latest-config.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/4015574/nixpkgs-linux_latest-config.txt)
[nixpkgs-linux_testing_bcachefs-config.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/4015575/nixpkgs-linux_testing_bcachefs-config.txt)
[nixpkgs-linux_testing-config.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/4015576/nixpkgs-linux_testing-config.txt)
[nixpkgs-linux_5_4-config.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/4015577/nixpkgs-linux_5_4-config.txt)
[nixpkgs-linux_5_3-config.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/4015578/nixpkgs-linux_5_3-config.txt)
[nixpkgs-linux_4_9-config.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/4015579/nixpkgs-linux_4_9-config.txt)
[nixpkgs-linux_4_14-config.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/4015580/nixpkgs-linux_4_14-config.txt)
[nixpkgs-linux_4_4-config.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/4015581/nixpkgs-linux_4_4-config.txt)
[nixpkgs-linux_4_19-config.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/4015582/nixpkgs-linux_4_19-config.txt)
[nixpkgs-linux_mptcp_94-config.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/4015583/nixpkgs-linux_mptcp_94-config.txt)
[nixpkgs-linux_mptcp_95-config.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/4015584/nixpkgs-linux_mptcp_95-config.txt)
[nixpkgs-linux_mptcp-config.txt](https://github.com/a13xp0p0v/kconfig-hardened-check/files/4015585/nixpkgs-linux_mptcp-config.txt)

#### <img src="https://avatars.githubusercontent.com/u/96200?u=9ed15c85825694d00e996d605d728179b830c4fa&v=4" width="50">[Mic92](https://github.com/Mic92) commented at [2020-01-02 10:47](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27#issuecomment-570173237):

This is the output for our hardened kernel:
cc @joachifm (hardened maintainer)

```
[+] Trying to detect architecture in "kconfig/nixpkgs-linux_hardened-config.txt"...
[+] Detected architecture: X86_64
[+] Checking "kconfig/nixpkgs-linux_hardened-config.txt" against hardening preferences...
                 option name                 | desired val | decision |       reason       |   check result
=========================================================================================================================
CONFIG_BUG                                   |      y      |defconfig |  self_protection   |   OK
CONFIG_STRICT_KERNEL_RWX                     |      y      |defconfig |  self_protection   |   OK
CONFIG_STACKPROTECTOR_STRONG                 |      y      |defconfig |  self_protection   |   OK
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
CONFIG_BUG_ON_DATA_CORRUPTION                |      y      |   kspp   |  self_protection   |   OK
CONFIG_DEBUG_WX                              |      y      |   kspp   |  self_protection   |   OK
CONFIG_SCHED_STACK_END_CHECK                 |      y      |   kspp   |  self_protection   |   OK
CONFIG_SLAB_FREELIST_HARDENED                |      y      |   kspp   |  self_protection   |   OK
CONFIG_SLAB_FREELIST_RANDOM                  |      y      |   kspp   |  self_protection   |   OK
CONFIG_SHUFFLE_PAGE_ALLOCATOR                |      y      |   kspp   |  self_protection   |   FAIL: not found
CONFIG_FORTIFY_SOURCE                        |      y      |   kspp   |  self_protection   |   OK
CONFIG_GCC_PLUGINS                           |      y      |   kspp   |  self_protection   |   OK
CONFIG_GCC_PLUGIN_RANDSTRUCT                 |      y      |   kspp   |  self_protection   |   OK
CONFIG_GCC_PLUGIN_LATENT_ENTROPY             |      y      |   kspp   |  self_protection   |   OK
CONFIG_DEBUG_LIST                            |      y      |   kspp   |  self_protection   |   OK
CONFIG_DEBUG_SG                              |      y      |   kspp   |  self_protection   |   OK
CONFIG_DEBUG_CREDENTIALS                     |      y      |   kspp   |  self_protection   |   OK
CONFIG_DEBUG_NOTIFIERS                       |      y      |   kspp   |  self_protection   |   OK
CONFIG_PAGE_POISONING                        |      y      |   kspp   |  self_protection   |   OK
CONFIG_HARDENED_USERCOPY                     |      y      |   kspp   |  self_protection   |   OK
CONFIG_HARDENED_USERCOPY_FALLBACK            | is not set  |   kspp   |  self_protection   |   OK
CONFIG_MODULE_SIG                            |      y      |   kspp   |  self_protection   |   FAIL: "is not set"
CONFIG_MODULE_SIG_ALL                        |      y      |   kspp   |  self_protection   |   FAIL: not found
CONFIG_MODULE_SIG_SHA512                     |      y      |   kspp   |  self_protection   |   FAIL: not found
CONFIG_MODULE_SIG_FORCE                      |      y      |   kspp   |  self_protection   |   FAIL: not found
CONFIG_DEFAULT_MMAP_MIN_ADDR                 |    65536    |   kspp   |  self_protection   |   OK
CONFIG_REFCOUNT_FULL                         |      y      |   kspp   |  self_protection   |   OK
CONFIG_INIT_STACK_ALL                        |      y      |  clipos  |  self_protection   |   OK: CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL "y"
CONFIG_INIT_ON_ALLOC_DEFAULT_ON              |      y      |  clipos  |  self_protection   |   FAIL: not found
CONFIG_INIT_ON_FREE_DEFAULT_ON               |      y      |  clipos  |  self_protection   |   FAIL: not found
CONFIG_SECURITY_DMESG_RESTRICT               |      y      |  clipos  |  self_protection   |   FAIL: "is not set"
CONFIG_DEBUG_VIRTUAL                         |      y      |  clipos  |  self_protection   |   FAIL: "is not set"
CONFIG_STATIC_USERMODEHELPER                 |      y      |  clipos  |  self_protection   |   FAIL: "is not set"
CONFIG_SLAB_MERGE_DEFAULT                    | is not set  |  clipos  |  self_protection   |   FAIL: "y"
CONFIG_GCC_PLUGIN_RANDSTRUCT_PERFORMANCE     | is not set  |  clipos  |  self_protection   |   FAIL: "y"
CONFIG_GCC_PLUGIN_STACKLEAK                  |      y      |  clipos  |  self_protection   |   FAIL: not found
CONFIG_STACKLEAK_METRICS                     | is not set  |  clipos  |  self_protection   |   FAIL: CONFIG_GCC_PLUGIN_STACKLEAK is needed
CONFIG_STACKLEAK_RUNTIME_DISABLE             | is not set  |  clipos  |  self_protection   |   FAIL: CONFIG_GCC_PLUGIN_STACKLEAK is needed
CONFIG_RANDOM_TRUST_CPU                      | is not set  |  clipos  |  self_protection   |   OK
CONFIG_INTEL_IOMMU_SVM                       |      y      |  clipos  |  self_protection   |   FAIL: "is not set"
CONFIG_INTEL_IOMMU_DEFAULT_ON                |      y      |  clipos  |  self_protection   |   FAIL: "is not set"
CONFIG_SLUB_DEBUG_ON                         |      y      |    my    |  self_protection   |   FAIL: "is not set"
CONFIG_RESET_ATTACK_MITIGATION               |      y      |    my    |  self_protection   |   FAIL: "is not set"
CONFIG_PAGE_POISONING_NO_SANITY              | is not set  |    my    |  self_protection   |   FAIL: "y"
CONFIG_PAGE_POISONING_ZERO                   | is not set  |    my    |  self_protection   |   FAIL: "y"
CONFIG_AMD_IOMMU_V2                          |      y      |    my    |  self_protection   |   FAIL: "m"
CONFIG_SECURITY                              |      y      |defconfig |  security_policy   |   OK
CONFIG_SECURITY_YAMA                         |      y      |   kspp   |  security_policy   |   OK
CONFIG_SECURITY_LOADPIN                      |      y      |    my    |  security_policy   |   FAIL: "is not set"
CONFIG_SECURITY_LOCKDOWN_LSM                 |      y      |    my    |  security_policy   |   FAIL: not found
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY           |      y      |    my    |  security_policy   |   FAIL: not found
CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY|      y      |    my    |  security_policy   |   FAIL: not found
CONFIG_SECCOMP                               |      y      |defconfig | cut_attack_surface |   OK
CONFIG_SECCOMP_FILTER                        |      y      |defconfig | cut_attack_surface |   OK
CONFIG_STRICT_DEVMEM                         |      y      |defconfig | cut_attack_surface |   OK
CONFIG_MODULES                               | is not set  |   kspp   | cut_attack_surface |   FAIL: "y"
CONFIG_DEVMEM                                | is not set  |   kspp   | cut_attack_surface |   FAIL: "y"
CONFIG_IO_STRICT_DEVMEM                      |      y      |   kspp   | cut_attack_surface |   OK
CONFIG_ACPI_CUSTOM_METHOD                    | is not set  |   kspp   | cut_attack_surface |   OK
CONFIG_COMPAT_BRK                            | is not set  |   kspp   | cut_attack_surface |   OK
CONFIG_DEVKMEM                               | is not set  |   kspp   | cut_attack_surface |   OK
CONFIG_COMPAT_VDSO                           | is not set  |   kspp   | cut_attack_surface |   OK: not found
CONFIG_BINFMT_MISC                           | is not set  |   kspp   | cut_attack_surface |   FAIL: "y"
CONFIG_INET_DIAG                             | is not set  |   kspp   | cut_attack_surface |   FAIL: "y"
CONFIG_KEXEC                                 | is not set  |   kspp   | cut_attack_surface |   FAIL: "y"
CONFIG_PROC_KCORE                            | is not set  |   kspp   | cut_attack_surface |   OK
CONFIG_LEGACY_PTYS                           | is not set  |   kspp   | cut_attack_surface |   OK
CONFIG_HIBERNATION                           | is not set  |   kspp   | cut_attack_surface |   FAIL: "y"
CONFIG_LEGACY_VSYSCALL_NONE                  |      y      |   kspp   | cut_attack_surface |   OK
CONFIG_IA32_EMULATION                        | is not set  |   kspp   | cut_attack_surface |   OK
CONFIG_X86_X32                               | is not set  |   kspp   | cut_attack_surface |   OK
CONFIG_MODIFY_LDT_SYSCALL                    | is not set  |   kspp   | cut_attack_surface |   FAIL: "y"
CONFIG_X86_PTDUMP                            | is not set  |grsecurity| cut_attack_surface |   FAIL: "m"
CONFIG_ZSMALLOC_STAT                         | is not set  |grsecurity| cut_attack_surface |   OK
CONFIG_PAGE_OWNER                            | is not set  |grsecurity| cut_attack_surface |   OK
CONFIG_DEBUG_KMEMLEAK                        | is not set  |grsecurity| cut_attack_surface |   OK
CONFIG_BINFMT_AOUT                           | is not set  |grsecurity| cut_attack_surface |   OK: not found
CONFIG_KPROBES                               | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_UPROBES                               | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_GENERIC_TRACER                        | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_PROC_VMCORE                           | is not set  |grsecurity| cut_attack_surface |   OK: not found
CONFIG_PROC_PAGE_MONITOR                     | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_USELIB                                | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_CHECKPOINT_RESTORE                    | is not set  |grsecurity| cut_attack_surface |   OK
CONFIG_USERFAULTFD                           | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_HWPOISON_INJECT                       | is not set  |grsecurity| cut_attack_surface |   OK: not found
CONFIG_MEM_SOFT_DIRTY                        | is not set  |grsecurity| cut_attack_surface |   OK: not found
CONFIG_DEVPORT                               | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_DEBUG_FS                              | is not set  |grsecurity| cut_attack_surface |   FAIL: "y"
CONFIG_NOTIFIER_ERROR_INJECTION              | is not set  |grsecurity| cut_attack_surface |   OK
CONFIG_ACPI_TABLE_UPGRADE                    | is not set  | lockdown | cut_attack_surface |   FAIL: "y"
CONFIG_ACPI_APEI_EINJ                        | is not set  | lockdown | cut_attack_surface |   OK: not found
CONFIG_PROFILING                             | is not set  | lockdown | cut_attack_surface |   FAIL: "y"
CONFIG_BPF_SYSCALL                           | is not set  | lockdown | cut_attack_surface |   FAIL: "y"
CONFIG_MMIOTRACE_TEST                        | is not set  | lockdown | cut_attack_surface |   OK: not found
CONFIG_KSM                                   | is not set  |  clipos  | cut_attack_surface |   FAIL: "y"
CONFIG_KALLSYMS                              | is not set  |  clipos  | cut_attack_surface |   FAIL: "y"
CONFIG_X86_VSYSCALL_EMULATION                | is not set  |  clipos  | cut_attack_surface |   FAIL: "y"
CONFIG_MAGIC_SYSRQ                           | is not set  |  clipos  | cut_attack_surface |   FAIL: "y"
CONFIG_KEXEC_FILE                            | is not set  |  clipos  | cut_attack_surface |   FAIL: "y"
CONFIG_USER_NS                               | is not set  |  clipos  | cut_attack_surface |   FAIL: "y"
CONFIG_LDISC_AUTOLOAD                        | is not set  |  clipos  | cut_attack_surface |   FAIL: "y"
CONFIG_MMIOTRACE                             | is not set  |    my    | cut_attack_surface |   OK
CONFIG_LIVEPATCH                             | is not set  |    my    | cut_attack_surface |   OK: not found
CONFIG_IP_DCCP                               | is not set  |    my    | cut_attack_surface |   FAIL: "m"
CONFIG_IP_SCTP                               | is not set  |    my    | cut_attack_surface |   FAIL: "m"
CONFIG_FTRACE                                | is not set  |    my    | cut_attack_surface |   FAIL: "y"
CONFIG_BPF_JIT                               | is not set  |    my    | cut_attack_surface |   FAIL: "y"
CONFIG_ARCH_MMAP_RND_BITS                    |     32      |  clipos  |userspace_hardening |   FAIL: "28"

[+] config check is finished: 'OK' - 66 / 'FAIL' - 57
```

#### <img src="https://avatars.githubusercontent.com/u/96200?u=9ed15c85825694d00e996d605d728179b830c4fa&v=4" width="50">[Mic92](https://github.com/Mic92) commented at [2020-01-02 10:51](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27#issuecomment-570174082):

cc @fpletz @andir @flokli @nequissimus regarding security/kernel maintenance.

#### <img src="https://avatars.githubusercontent.com/u/628342?u=948c2401c073b8097e8ec160019140fb6043f266&v=4" width="50">[NeQuissimus](https://github.com/NeQuissimus) commented at [2020-01-02 16:07](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27#issuecomment-570253840):

There is no (official) open source grsecurity for recent kernels. But for the other options, I'd be interested in a discussion in the nixpkgs repo.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-01-02 23:11](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27#issuecomment-570392431):

Hello @Mic92,

> I am not sure which configuration you want to include in this repository.
> Maybe _hardened, _latest and the default kernel.

I would like to have only the default and hardened config for NixOS.
That's useful for a brief comparison of kernel hardening adoption by various Linux distributions.
By the way, we don't have a goal to collect all the latest configs from all the distributions.
@HacKurx updates them from time to time.

Hello @NeQuissimus,

> There is no (official) open source grsecurity for recent kernels. 

Yes.
And do you mean that there is an unofficial grsecurity patch for recent kernels available in public?

> But for the other options, I'd be interested in a discussion in the nixpkgs repo.

I would be glad to join that discussion.
I've accumulated some knowledge about the vanilla kernel hardening.
Please see my Linux Kernel Defence Map https://github.com/a13xp0p0v/linux-kernel-defence-map.
It shows the the relationships between:
 - Vulnerability classes,
 - Exploitation techniques,
 - Bug detection mechanisms,
 - Defense technologies.

It could be useful for making a decision about enabling kernel hardening config options.

@Mic92 @fpletz @andir @flokli @NeQuissimus,
Does NixOS have a documentation describing the difference between its hardened and default kernels?

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/628342?u=948c2401c073b8097e8ec160019140fb6043f266&v=4" width="50">[NeQuissimus](https://github.com/NeQuissimus) commented at [2020-01-03 00:29](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27#issuecomment-570414239):

I was thinking of minipli but I guess those are only for 4.9.

I opened NixOS/nixpkgs#76850, which links to the kernel flags we set for the standard kernel builds and for the hardened one.
Unfortunately I do not think there is good documentation.

#### <img src="https://avatars.githubusercontent.com/u/96200?u=9ed15c85825694d00e996d605d728179b830c4fa&v=4" width="50">[Mic92](https://github.com/Mic92) commented at [2020-01-03 08:37](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27#issuecomment-570503332):

> Hello @Mic92,
> 
> > I am not sure which configuration you want to include in this repository.
> > Maybe _hardened, _latest and the default kernel.
> 
> I would like to have only the default and hardened config for NixOS.
> That's useful for a brief comparison of kernel hardening adoption by various Linux distributions.
> By the way, we don't have a goal to collect all the latest configs from all the distributions.
> @HacKurx updates them from time to time.

Fair enough I think the other changes that are actually part of this pull request should be still useful though.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-01-10 14:12](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27#issuecomment-573050822):

> Fair enough I think the other changes that are actually part of this pull request should be still useful though.

Hi @Mic92,
Could you have a look at my comments for your PR https://github.com/a13xp0p0v/kconfig-hardened-check/pull/26 ?
I need some clarifications to be able to integrate your work.
Thanks!

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2020-02-24 20:57](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27#issuecomment-590544879):

Hi,

I haven't tested NixOS yet, is there a quick and easy way to retrieve the kernel configuration or it's only dynamically generated?
I only find this but without config files:
https://hydra.nixos.org/job/nixos/release-19.09/nixpkgs.linuxPackages_latest_hardened.kernel.x86_64-linux

Beside the point, I'm not a fan of that :
https://github.com/NixOS/nixpkgs/commit/1b9bf8fa7559d1bbf030f3fe3513d25eada65a41

#### <img src="https://avatars.githubusercontent.com/u/96200?u=9ed15c85825694d00e996d605d728179b830c4fa&v=4" width="50">[Mic92](https://github.com/Mic92) commented at [2020-02-25 09:26](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27#issuecomment-590768293):

@HacKurx It's generated by nix code. Can you explain why a RANDSTRUCT read from /dev/random is better than a checksum over the linux kernel tarball? From my understanding, once that a package is build, one could extract the seed from the build. In that way reproducible builds would give us other properties i.e. verifying a correct build.

#### <img src="https://avatars.githubusercontent.com/u/41977?u=ba54c9de3752a1aa05a462e38bd6e84bdc26a2bb&v=4" width="50">[joachifm](https://github.com/joachifm) commented at [2020-02-25 17:26](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27#issuecomment-590976475):

@Mic92 I agree with you. I think it's fair to say that any compile-time randomization is rendered (nearly) pointless by publishing the image.  In our case, the value is likely to change whenever source/config changes, so might be considered "better" than a static seed value (whether it makes any real difference is another matter).  I think users who really care about this type of mitigation should build their own kernel with a custom seed (support for this was added in a later patch, iirc).

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2020-02-25 21:10](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27#issuecomment-591070826):

@Mic92, @joachifm,
The person who recompile a kernel from your source should have another seed (not your) for more security.
It seems preferable to me of change the SEED variable every time you update the nix kernel. Use a compilation based of a date or the kernel number for example.

#### <img src="https://avatars.githubusercontent.com/u/41977?u=ba54c9de3752a1aa05a462e38bd6e84bdc26a2bb&v=4" width="50">[joachifm](https://github.com/joachifm) commented at [2020-02-25 22:20](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27#issuecomment-591100811):

@HacKurx note that `${src}` in the snippet you linked above expands to a string that contains both the checksum of the linux source tarball and the version number: it is certain to change in case of version bumps.  

I wouldn't mind including more information in the seed construction to further increase the likelihood that it will differ between builds, but whatever is added needs to preserve determinism (in the sense that same inputs give same output).  

Reproducibility is a key goal for Nix/NixPkgs and usually overrides other concerns.  In this case, I think giving users of the prebuilt image a weak(ened) variant of the mitigation while making it easy to supply a custom seed is a more than fair tradeoff, especially given that the full benefit of this type of mitigation can only be realized with a self-built package anyway.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-03-27 19:45](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27#issuecomment-605284899):

Hello @Mic92!
I installed Nix on a Debian machine to test your scripts.
Unfortunately I have to revert the commit that adds `contrib/get-nix-kconfig.py`.
This script is corrupted (has unexpected symbols).
It also has numerous troubles with Python 3.5.3.

#### <img src="https://avatars.githubusercontent.com/u/96200?u=9ed15c85825694d00e996d605d728179b830c4fa&v=4" width="50">[Mic92](https://github.com/Mic92) commented at [2020-03-27 19:52](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27#issuecomment-605287211):

@a13xp0p0v just add:

```
#! /usr/bin/env nix-shell
#! nix-shell -i python3
```

as a shebang. Nixpkgs has python3.6 and the script depends nix anyway.
It is not corrupted but depends on python3.6 or newer.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-03-27 20:27](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27#issuecomment-605300321):

Thanks for prompt reply!
1. I perform:
```
$ nix-shell
```
2. Then I change the shebang as you described and run the script:
```
[nix-shell:~/kconfig-hardened-check/contrib]$ ./get-nix-kconfig.py 
error: getting status of '/home/x/kconfig-hardened-check/contrib/default.nix': No such file or directory
```
3. Finally this makes it work:
```
[nix-shell:~/kconfig-hardened-check/contrib]$ python3 get-nix-kconfig.py 
```
I got kernel configs and added hardened one to the collection: 4768e21b33fa9663114eb30c2b2c2cf9e6cf4721

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/96200?u=9ed15c85825694d00e996d605d728179b830c4fa&v=4" width="50">[Mic92](https://github.com/Mic92) commented at [2020-03-28 03:18](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/27#issuecomment-605387095):

My mistake it should have been:

```
#! /usr/bin/env nix-shell
#! nix-shell -i python3 -p python3
```


-------------------------------------------------------------------------------

# [\#26 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/26) `closed`: enable distribution via pip/setuptools

#### <img src="https://avatars.githubusercontent.com/u/96200?u=9ed15c85825694d00e996d605d728179b830c4fa&v=4" width="50">[Mic92](https://github.com/Mic92) opened issue at [2020-01-02 09:01](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/26):



#### <img src="https://avatars.githubusercontent.com/u/96200?u=9ed15c85825694d00e996d605d728179b830c4fa&v=4" width="50">[Mic92](https://github.com/Mic92) commented at [2020-02-25 09:34](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/26#issuecomment-590771724):

> Hi Jörg,
> Thanks a lot for your work.
> I'm not familiar with setuptools, but it looks to me that integrating that is a good idea.
> There are a few aspects that I would like to fix before merging.
> 
>     1. Can we avoid creating the `kconfig_hardened_check` directory? I would rather have `bin` and `config_files`.
> 

No one needs a distinct module to put the python code in to avoid conflicts with other installed python packages.

>     2. What is the purpose of splitting the code onto `bin/kconfig_hardened_check` and `kconfig_hardened_check/__init__.py`? Is it some special python feng-shui? (I'm asking because I'm just a kernel developer)
> 

`bin/kconfig_hardened_check` is for people just checking out the repository and running the script without installing it. If you install it with `setuptools`,
it will generate its own wrapper that will eventually load `kconfig_hardened_check/__init__.py`.

>     3. I would like to split setuptools integration and the code refactoring onto separate commits. Moreover, I don't understand the `List[Any]` changes.

`List[Any]` is a type annotation. When you use a typechecker like mypy you can typecheck your code that way.

> 
>     4. Are you sure that the classifiers in `setup.cfg` are correct? It looks like some of them don't fit this project.


> 
>     5. The `package_data` in `setup.cfg` misses some files in the repository. Is it ok?

It should only contain files that are supposed to be installed. I am not even sure having those config files provides any benefit for a user of the tool.
Let me know and I would not include them at all.

> 
> 
> Thanks!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-03-26 13:20](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/26#issuecomment-604427052):

Hello @Mic92,
I carefully reimplemented your proof-of-concept in a set of separate commits.
Fixed mistakes in setup.cfg, added MANIFEST.in, fixed issues with global variables.
Thank you very much, I learned a lot!


-------------------------------------------------------------------------------

# [\#25 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/25) `closed`: Hardened Kernel Config File for Virtual Machines (VMs) ("cloud kernel")

#### <img src="https://avatars.githubusercontent.com/u/1985040?u=b84e7065f9f8d62fbff9ac468a0cf0757718ed77&v=4" width="50">[adrelanos](https://github.com/adrelanos) opened issue at [2019-12-28 20:35](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/25):

A kernel config specialized for better security inside virtual machines is in development.

The development preview version can be found here:
https://github.com/Whonix/hardened-kernel/blob/master/usr/share/hardened-kernel/hardened-vm-kernel

This work is being done by @madaidan who also contributed pull requests to [linux-hardened](https://github.com/anthraxx/linux-hardened).

https://github.com/anthraxx/linux-hardened/pulls?utf8=%E2%9C%93&q=author%3Amadaidan

Discussions about the kernel config happen mostly in Whonix forums.

https://forums.whonix.org/t/kernel-recompilation-for-better-hardening/7598/214

The hardened kernel config was contributed by @madaidan to the @Whonix project but as the maintainer of Whonix I think that it is not the most suitable project to maintain a kernel config. It would be more impactful and would get more eyes on it if it was hosted here.

Therefore I am wondering if there is any chance you would accept a pull request for a hardened (VM) config file? Which folder would be suitable for such a config file?

@madaidan is also working on a hardened bare metal (i.e. non-VM) kernel config:
https://github.com/Whonix/hardened-kernel/blob/master/usr/share/hardened-kernel/hardened-host-kernel

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-01-02 23:27](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/25#issuecomment-570397241):

Hello @adrelanos,
I guess Whonix has a default and hardened config, am I right?
Is the difference between them documented anywhere?
We can take Whonix official configs to the `config_files/distros/`.
That's useful for a brief comparison of kernel hardening adoption by various Linux distributions.
There is also the `config_files/links.txt` file that describes how to get official configs from various distros.
Thanks!

#### <img src="https://avatars.githubusercontent.com/u/50278627?v=4" width="50">[madaidan](https://github.com/madaidan) commented at [2020-01-05 17:22](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/25#issuecomment-570930694):

The current Whonix default is the Debian default. It will be changed to the config mentioned in the post once it's finished.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2020-01-10 15:20](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/25#issuecomment-573077384):

Ok.
So when it is finished, you are welcome to send me the pull request that
 - adds the official Whonix hardened config to `config_files/distros/`;
 - adds the corresponding info to `config_files/links.txt`.

#### <img src="https://avatars.githubusercontent.com/u/42802201?v=4" width="50">[tsautereau-anssi](https://github.com/tsautereau-anssi) commented at [2020-01-13 15:59](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/25#issuecomment-573735007):

@madaidan After reading your [post](https://github.com/anthraxx/linux-hardened/issues/21) on the linux-hardened repository, it seems you might be interested in contributing some of your changes to the [CLIP OS kernel](https://github.com/clipos/src_external_linux/) (see our current configuration [here](https://github.com/clipos/src_platform_config-linux-hardware/tree/master/kernel_config)). If so, don't hesitate to [open an issue](https://github.com/clipos/bugs), it would be much appreciated!

Thanks @msalaun-anssi for the heads-up ;)

#### <img src="https://avatars.githubusercontent.com/u/1985040?u=b84e7065f9f8d62fbff9ac468a0cf0757718ed77&v=4" width="50">[adrelanos](https://github.com/adrelanos) commented at [2020-01-13 16:25](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/25#issuecomment-573747860):

Created https://github.com/clipos/bugs/issues/38 for it.

#### <img src="https://avatars.githubusercontent.com/u/50278627?v=4" width="50">[madaidan](https://github.com/madaidan) commented at [2020-01-13 18:15](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/25#issuecomment-573797636):

> @madaidan After reading your post on the linux-hardened repository, it seems you might be interested in contributing some of your changes to the CLIP OS kernel (see our current configuration here). If so, don't hesitate to open an issue, it would be much appreciated!

Sounds great. I'll see what I can do.


-------------------------------------------------------------------------------

# [\#24 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/24) `closed`: Create debian-buster.config

#### <img src="https://avatars.githubusercontent.com/u/89727?u=8ae8d032737536db91e96a6a3dcd9bc80a833eae&v=4" width="50">[alexandernst](https://github.com/alexandernst) opened issue at [2019-08-27 23:19](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/24):

```
[+] Trying to detect architecture in "../linux-source-4.19/.config"...
[+] Detected architecture: X86_64
[+] Checking "../linux-source-4.19/.config" against hardening preferences...
              option name               | desired val | decision |       reason       ||        check result
====================================================================================================================
CONFIG_BUG                              |      y      |defconfig |  self_protection   ||             OK
CONFIG_STRICT_KERNEL_RWX                |      y      |defconfig |  self_protection   ||             OK
CONFIG_STACKPROTECTOR_STRONG            |      y      |defconfig |  self_protection   ||             OK
CONFIG_SLUB_DEBUG                       |      y      |defconfig |  self_protection   ||             OK
CONFIG_STRICT_MODULE_RWX                |      y      |defconfig |  self_protection   ||             OK
CONFIG_PAGE_TABLE_ISOLATION             |      y      |defconfig |  self_protection   ||             OK
CONFIG_RANDOMIZE_MEMORY                 |      y      |defconfig |  self_protection   ||             OK
CONFIG_RANDOMIZE_BASE                   |      y      |defconfig |  self_protection   ||             OK
CONFIG_RETPOLINE                        |      y      |defconfig |  self_protection   ||             OK
CONFIG_X86_SMAP                         |      y      |defconfig |  self_protection   ||             OK
CONFIG_X86_INTEL_UMIP                   |      y      |defconfig |  self_protection   ||             OK
CONFIG_SYN_COOKIES                      |      y      |defconfig |  self_protection   ||             OK
CONFIG_VMAP_STACK                       |      y      |defconfig |  self_protection   ||             OK
CONFIG_THREAD_INFO_IN_TASK              |      y      |defconfig |  self_protection   ||             OK
CONFIG_BUG_ON_DATA_CORRUPTION           |      y      |   kspp   |  self_protection   ||             OK
CONFIG_DEBUG_WX                         |      y      |   kspp   |  self_protection   ||             OK
CONFIG_SCHED_STACK_END_CHECK            |      y      |   kspp   |  self_protection   ||             OK
CONFIG_SLAB_FREELIST_HARDENED           |      y      |   kspp   |  self_protection   ||             OK
CONFIG_SLAB_FREELIST_RANDOM             |      y      |   kspp   |  self_protection   ||             OK
CONFIG_SHUFFLE_PAGE_ALLOCATOR           |      y      |   kspp   |  self_protection   ||      FAIL: not found
CONFIG_FORTIFY_SOURCE                   |      y      |   kspp   |  self_protection   ||             OK
CONFIG_GCC_PLUGINS                      |      y      |   kspp   |  self_protection   ||      FAIL: not found
CONFIG_GCC_PLUGIN_RANDSTRUCT            |      y      |   kspp   |  self_protection   ||      FAIL: not found
CONFIG_GCC_PLUGIN_LATENT_ENTROPY        |      y      |   kspp   |  self_protection   ||      FAIL: not found
CONFIG_DEBUG_LIST                       |      y      |   kspp   |  self_protection   ||             OK
CONFIG_DEBUG_SG                         |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"
CONFIG_DEBUG_CREDENTIALS                |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"
CONFIG_DEBUG_NOTIFIERS                  |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"
CONFIG_PAGE_POISONING                   |      y      |   kspp   |  self_protection   ||             OK
CONFIG_HARDENED_USERCOPY                |      y      |   kspp   |  self_protection   ||             OK
CONFIG_HARDENED_USERCOPY_FALLBACK       | is not set  |   kspp   |  self_protection   ||             OK
CONFIG_MODULE_SIG                       |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"
CONFIG_MODULE_SIG_ALL                   |      y      |   kspp   |  self_protection   ||      FAIL: not found
CONFIG_MODULE_SIG_SHA512                |      y      |   kspp   |  self_protection   ||      FAIL: not found
CONFIG_MODULE_SIG_FORCE                 |      y      |   kspp   |  self_protection   ||      FAIL: not found
CONFIG_DEFAULT_MMAP_MIN_ADDR            |    65536    |   kspp   |  self_protection   ||             OK
CONFIG_REFCOUNT_FULL                    |      y      |   kspp   |  self_protection   ||             OK
CONFIG_LOCK_DOWN_KERNEL                 |      y      |  clipos  |  self_protection   ||             OK
CONFIG_SECURITY_DMESG_RESTRICT          |      y      |  clipos  |  self_protection   ||             OK
CONFIG_DEBUG_VIRTUAL                    |      y      |  clipos  |  self_protection   ||     FAIL: "is not set"
CONFIG_STATIC_USERMODEHELPER            |      y      |  clipos  |  self_protection   ||     FAIL: "is not set"
CONFIG_SLAB_MERGE_DEFAULT               | is not set  |  clipos  |  self_protection   ||         FAIL: "y"
CONFIG_GCC_PLUGIN_RANDSTRUCT_PERFORMANCE| is not set  |  clipos  |  self_protection   ||FAIL: CONFIG_GCC_PLUGIN_RANDSTRUCT is needed
CONFIG_GCC_PLUGIN_STACKLEAK             |      y      |  clipos  |  self_protection   ||      FAIL: not found
CONFIG_STACKLEAK_METRICS                | is not set  |  clipos  |  self_protection   ||FAIL: CONFIG_GCC_PLUGIN_STACKLEAK is needed
CONFIG_STACKLEAK_RUNTIME_DISABLE        | is not set  |  clipos  |  self_protection   ||FAIL: CONFIG_GCC_PLUGIN_STACKLEAK is needed
CONFIG_RANDOM_TRUST_CPU                 | is not set  |  clipos  |  self_protection   ||         FAIL: "y"
CONFIG_MICROCODE                        |      y      |  clipos  |  self_protection   ||             OK
CONFIG_IOMMU_SUPPORT                    |      y      |  clipos  |  self_protection   ||             OK
CONFIG_INTEL_IOMMU                      |      y      |  clipos  |  self_protection   ||             OK
CONFIG_INTEL_IOMMU_SVM                  |      y      |  clipos  |  self_protection   ||             OK
CONFIG_INTEL_IOMMU_DEFAULT_ON           |      y      |  clipos  |  self_protection   ||     FAIL: "is not set"
CONFIG_INIT_STACK_ALL                   |      y      |    my    |  self_protection   ||      FAIL: not found
CONFIG_SLUB_DEBUG_ON                    |      y      |    my    |  self_protection   ||     FAIL: "is not set"
CONFIG_SECURITY_LOADPIN                 |      y      |    my    |  self_protection   ||     FAIL: "is not set"
CONFIG_RESET_ATTACK_MITIGATION          |      y      |    my    |  self_protection   ||     FAIL: "is not set"
CONFIG_PAGE_POISONING_NO_SANITY         | is not set  |    my    |  self_protection   ||         FAIL: "y"
CONFIG_PAGE_POISONING_ZERO              | is not set  |    my    |  self_protection   ||             OK
CONFIG_AMD_IOMMU                        |      y      |    my    |  self_protection   ||             OK
CONFIG_AMD_IOMMU_V2                     |      y      |    my    |  self_protection   ||             OK
CONFIG_SECURITY                         |      y      |defconfig |  security_policy   ||             OK
CONFIG_SECURITY_YAMA                    |      y      |   kspp   |  security_policy   ||             OK
CONFIG_SECCOMP                          |      y      |defconfig | cut_attack_surface ||             OK
CONFIG_SECCOMP_FILTER                   |      y      |defconfig | cut_attack_surface ||             OK
CONFIG_STRICT_DEVMEM                    |      y      |defconfig | cut_attack_surface ||             OK
CONFIG_MODULES                          | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"
CONFIG_DEVMEM                           | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"
CONFIG_IO_STRICT_DEVMEM                 |      y      |   kspp   | cut_attack_surface ||             OK
CONFIG_ACPI_CUSTOM_METHOD               | is not set  |   kspp   | cut_attack_surface ||             OK
CONFIG_COMPAT_BRK                       | is not set  |   kspp   | cut_attack_surface ||             OK
CONFIG_DEVKMEM                          | is not set  |   kspp   | cut_attack_surface ||             OK
CONFIG_COMPAT_VDSO                      | is not set  |   kspp   | cut_attack_surface ||             OK
CONFIG_BINFMT_MISC                      | is not set  |   kspp   | cut_attack_surface ||             OK
CONFIG_INET_DIAG                        | is not set  |   kspp   | cut_attack_surface ||             OK
CONFIG_KEXEC                            | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"
CONFIG_PROC_KCORE                       | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"
CONFIG_LEGACY_PTYS                      | is not set  |   kspp   | cut_attack_surface ||             OK
CONFIG_HIBERNATION                      | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"
CONFIG_LEGACY_VSYSCALL_NONE             |      y      |   kspp   | cut_attack_surface ||             OK
CONFIG_IA32_EMULATION                   | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"
CONFIG_X86_X32                          | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"
CONFIG_MODIFY_LDT_SYSCALL               | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"
CONFIG_X86_PTDUMP                       | is not set  |grsecurity| cut_attack_surface ||             OK
CONFIG_ZSMALLOC_STAT                    | is not set  |grsecurity| cut_attack_surface ||       OK: not found
CONFIG_PAGE_OWNER                       | is not set  |grsecurity| cut_attack_surface ||             OK
CONFIG_DEBUG_KMEMLEAK                   | is not set  |grsecurity| cut_attack_surface ||             OK
CONFIG_BINFMT_AOUT                      | is not set  |grsecurity| cut_attack_surface ||       OK: not found
CONFIG_KPROBES                          | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"
CONFIG_UPROBES                          | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"
CONFIG_GENERIC_TRACER                   | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"
CONFIG_PROC_VMCORE                      | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"
CONFIG_PROC_PAGE_MONITOR                | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"
CONFIG_USELIB                           | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"
CONFIG_CHECKPOINT_RESTORE               | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"
CONFIG_USERFAULTFD                      | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"
CONFIG_HWPOISON_INJECT                  | is not set  |grsecurity| cut_attack_surface ||             OK
CONFIG_MEM_SOFT_DIRTY                   | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"
CONFIG_DEVPORT                          | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"
CONFIG_DEBUG_FS                         | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"
CONFIG_NOTIFIER_ERROR_INJECTION         | is not set  |grsecurity| cut_attack_surface ||             OK
CONFIG_ACPI_TABLE_UPGRADE               | is not set  | lockdown | cut_attack_surface ||         FAIL: "y"
CONFIG_ACPI_APEI_EINJ                   | is not set  | lockdown | cut_attack_surface ||             OK
CONFIG_PROFILING                        | is not set  | lockdown | cut_attack_surface ||         FAIL: "y"
CONFIG_BPF_SYSCALL                      | is not set  | lockdown | cut_attack_surface ||         FAIL: "y"
CONFIG_MMIOTRACE_TEST                   | is not set  | lockdown | cut_attack_surface ||             OK
CONFIG_KSM                              | is not set  |  clipos  | cut_attack_surface ||         FAIL: "y"
CONFIG_IKCONFIG                         | is not set  |  clipos  | cut_attack_surface ||         FAIL: "m"
CONFIG_KALLSYMS                         | is not set  |  clipos  | cut_attack_surface ||         FAIL: "y"
CONFIG_X86_VSYSCALL_EMULATION           | is not set  |  clipos  | cut_attack_surface ||         FAIL: "y"
CONFIG_MAGIC_SYSRQ                      | is not set  |  clipos  | cut_attack_surface ||         FAIL: "y"
CONFIG_KEXEC_FILE                       | is not set  |  clipos  | cut_attack_surface ||         FAIL: "y"
CONFIG_USER_NS                          | is not set  |  clipos  | cut_attack_surface ||         FAIL: "y"
CONFIG_LDISC_AUTOLOAD                   | is not set  |  clipos  | cut_attack_surface ||         FAIL: "y"
CONFIG_MMIOTRACE                        | is not set  |    my    | cut_attack_surface ||         FAIL: "y"
CONFIG_LIVEPATCH                        | is not set  |    my    | cut_attack_surface ||         FAIL: "y"
CONFIG_IP_DCCP                          | is not set  |    my    | cut_attack_surface ||             OK
CONFIG_IP_SCTP                          | is not set  |    my    | cut_attack_surface ||             OK
CONFIG_FTRACE                           | is not set  |    my    | cut_attack_surface ||         FAIL: "y"
CONFIG_BPF_JIT                          | is not set  |    my    | cut_attack_surface ||         FAIL: "y"
CONFIG_ARCH_MMAP_RND_BITS               |     32      |  clipos  |userspace_protection||         FAIL: "28"

[+] config check is finished: 'OK' - 60 / 'FAIL' - 60
```

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-08-30 12:40](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/24#issuecomment-526586258):

Hello @alexandernst,

Thanks for your PR.

I decided to compare the your config with one available here:
https://packages.debian.org/buster/linux-image-4.19.0-5-amd64

They differ a lot.
Where did you get your config?

Best regards,
Alexander

#### <img src="https://avatars.githubusercontent.com/u/89727?u=8ae8d032737536db91e96a6a3dcd9bc80a833eae&v=4" width="50">[alexandernst](https://github.com/alexandernst) commented at [2019-08-30 12:56](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/24#issuecomment-526591340):

The config file was generated using the instructions in https://kernel-team.pages.debian.net/kernel-handbook/ch-common-tasks.html#s-common-building

```
apt install -y linux-source fakeroot libelf-dev libssl-dev
tar xaf /usr/src/linux-source-4.19.tar.xz
cd linux-source-4.19/
yes "" | make localmodconfig
scripts/config --disable MODULE_SIG
```

#### <img src="https://avatars.githubusercontent.com/u/89727?u=8ae8d032737536db91e96a6a3dcd9bc80a833eae&v=4" width="50">[alexandernst](https://github.com/alexandernst) commented at [2019-08-30 12:58](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/24#issuecomment-526591989):

Oh, this was built using an AWS EC2 instance, so that might be causing the differences between a vainilla debian config and my config.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-08-30 13:07](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/24#issuecomment-526595179):

Right, let me quote the kernel documentation:
```
"make localmodconfig" Create a config based on current config and loaded modules (lsmod).
```
https://www.kernel.org/doc/html/latest/admin-guide/README.html?highlight=localmodconfig

Would you like to fix your PR?
If so I would also ask to add info to `config_files/links.txt`.

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/89727?u=8ae8d032737536db91e96a6a3dcd9bc80a833eae&v=4" width="50">[alexandernst](https://github.com/alexandernst) commented at [2019-08-30 13:38](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/24#issuecomment-526605210):

I'm not really sure if by "fix" you mean rename the file to something like `debian-buster-aws.config` or by replace the config with the one from https://packages.debian.org/buster/linux-image-4.19.0-5-amd64 ?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-08-30 13:44](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/24#issuecomment-526607017):

I think adding an original Debian config would be more useful for everyone.
Also it would be nice if you find a direct link to this config and add it to `links.txt`.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-11-28 07:36](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/24#issuecomment-559376496):

Closing the PR (I've finally did it myself: ad80700, 4f9c653).
Thanks.


-------------------------------------------------------------------------------

# [\#23 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/23) `closed`: LOCK_DOWN_KERNEL 

#### <img src="https://avatars.githubusercontent.com/u/11277437?v=4" width="50">[rubeecube](https://github.com/rubeecube) opened issue at [2019-07-22 12:05](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/23):

Hello,

Thank you for this awesome project!

It seems that "LOCK_DOWN_KERNEL" / "LOCK_DOWN MANDATORY" enable other flags.

- No unsigned modules and no modules for which can't validate the signature.
- No use of ioperm(), iopl() and no writing to /dev/port.
- No writing to /dev/mem or /dev/kmem.
- No hibernation.
- Restrict PCI BAR access.
- Restrict MSR access.
- No kexec_load().
- Certain ACPI restrictions.
- Restrict debugfs interface to ASUS WMI.

http://lkml.iu.edu/hypermail/linux/kernel/1704.0/02933.html 

Is it possible to reflect this in the script?

#### <img src="https://avatars.githubusercontent.com/u/67428?u=cc677701e49dca0be4cdc6ea10bc60b52a181e4e&v=4" width="50">[jelly](https://github.com/jelly) commented at [2019-07-22 12:18](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/23#issuecomment-513767366):

The kernel lockdown patch has not been merged yet and I'm not sure if it's possible to enable these hardening functionality without the patch.

Also the linked patch is out of a date, there is a newer revision implemented as LSM https://lore.kernel.org/linux-security-module/20190404003249.14356-1-matthewgarrett@google.com/T/#m50dd383459d65d52d80c90f36af860a7c10f364c

#### <img src="https://avatars.githubusercontent.com/u/11277437?v=4" width="50">[rubeecube](https://github.com/rubeecube) commented at [2019-07-22 12:27](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/23#issuecomment-513770393):

Ok, I'm new to this and didn't know that.
Thanks

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2019-07-23 12:15](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/23#issuecomment-514184160):

Some distros like Fedora or Ubuntu are using lockdown kernel patches for a long time.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-08-12 08:27](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/23#issuecomment-520338183):

Hello everyone!

@bokobok, some time ago I looked through the lockdown patchset in Ubuntu kernel tree.
I marked the kernel options enforced by lockdown with a special comment in the script:
```
# refers to LOCK_DOWN_KERNEL
```
For more details please see https://github.com/a13xp0p0v/kconfig-hardened-check/commit/796a22935ab5cd3ddcf19c4ea85411d9bf04fef6

When the lockdown patchset is finally merged, I will look through the commits once again and update the script.

@jelly @Bernhard40, thanks for your commentary.

#### <img src="https://avatars.githubusercontent.com/u/67428?u=cc677701e49dca0be4cdc6ea10bc60b52a181e4e&v=4" width="50">[jelly](https://github.com/jelly) commented at [2019-08-12 18:27](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/23#issuecomment-520540892):

It's getting close to mainline http://kernsec.org/pipermail/linux-security-module-archive/2019-August/015795.html


-------------------------------------------------------------------------------

# [\#22 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/22) `merged`: #20 fix: use right quotes in json output

#### <img src="https://avatars.githubusercontent.com/u/4029800?u=86702d3f2d50ee01ef1c572ef26b1ea1318f28da&v=4" width="50">[adrianopol](https://github.com/adrianopol) opened issue at [2019-07-07 19:27](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/22):

#20: fix quotes for --json




-------------------------------------------------------------------------------

# [\#21 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/21) `merged`: add --json option

#### <img src="https://avatars.githubusercontent.com/u/4029800?u=86702d3f2d50ee01ef1c572ef26b1ea1318f28da&v=4" width="50">[adrianopol](https://github.com/adrianopol) opened issue at [2019-06-21 19:57](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/21):

With `--json` output will be formatted as array of arrays:

`[['CONFIG_BUG', 'y', 'defconfig', 'self_protection', 'OK'], ['CONFIG_STRICT_KERNEL_RWX', 'y', 'defconfig', 'self_protection', 'OK'], ...`

#### <img src="https://avatars.githubusercontent.com/u/4029800?u=86702d3f2d50ee01ef1c572ef26b1ea1318f28da&v=4" width="50">[adrianopol](https://github.com/adrianopol) commented at [2019-06-24 09:24](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/21#issuecomment-504931635):

Fixed.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-06-24 11:11](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/21#issuecomment-504965369):

Thank you!
Merged.


-------------------------------------------------------------------------------

# [\#20 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/20) `closed`: JSON output

#### <img src="https://avatars.githubusercontent.com/u/964610?u=7e6b8dd82339fe0349e7359908accf5543d95b8d&v=4" width="50">[Wenzel](https://github.com/Wenzel) opened issue at [2019-06-10 14:11](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/20):

Hi,

I would like to integrate your project into a Python script which would check the security settings automatically and provide a report.

Would it be possible to have an easily parsable JSON output ?
Otherwise processing with your data will be very difficult, if you are not human.

Thanks !

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-06-11 10:03](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/20#issuecomment-500775436):

Hello @Wenzel 

> I would like tot integrate your project into a Python script which would check the security settings automatically and provide a report.

Nice!

> Would it be possible to have an easily parsable JSON output ?
Otherwise processing with your data will be very difficult, if you are not human.

It sounds reasonable. I'll have a look in my free time.
If you already know how to implement it, the pull request is welcome!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-06-24 11:12](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/20#issuecomment-504965591):

Hello @Wenzel and @nettrino,

@adrianopol has added the JSON output feature (#21), please check the `--json` argument.

#### <img src="https://avatars.githubusercontent.com/u/964610?u=7e6b8dd82339fe0349e7359908accf5543d95b8d&v=4" width="50">[Wenzel](https://github.com/Wenzel) commented at [2019-07-07 12:51](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/20#issuecomment-508997348):

Hi @a13xp0p0v , @adrianopol ,

I would like to reopen this issue because I just tested the `--json` flag, and the output produced is not valid JSON.

`piping in jq`
![Screenshot_20190707_144843](https://user-images.githubusercontent.com/964610/60768633-84977d00-a0c6-11e9-978a-ebbb65e9ed11.png)


Output example for `./kconfig-hardened-check.py -c /boot/config-5.1.12-300.fc30.x86_64 --json`
~~~
[['CONFIG_BUG', 'y', 'defconfig', 'self_protection', 'OK'], ['CONFIG_STRICT_KERNEL_RWX', 'y', 'defconfig', 'self_protection', 'OK'], ['CONFIG_STACKPROTECTOR_STRONG', 'y', 'defconfig', 'self_protection', 'OK'], ['CONFIG_SLUB_DEBUG', 'y', 'defconfig', 'self_protection', 'OK'], ['CONFIG_STRICT_MODULE_RWX', 'y', 'defconfig', 'self_protection', 'OK'], ['CONFIG_PAGE_TABLE_ISOLATION', 'y', 'defconfig', 'self_protection', 'OK'], ['CONFIG_RANDOMIZE_MEMORY', 'y', 'defconfig', 'self_protection', 'OK'], ['CONFIG_RANDOMIZE_BASE', 'y', 'defconfig', 'self_protection', 'OK'], ['CONFIG_RETPOLINE', 'y', 'defconfig', 'self_protection', 'OK'], ['CONFIG_X86_SMAP', 'y', 'defconfig', 'self_protection', 'OK'], ['CONFIG_X86_INTEL_UMIP', 'y', 'defconfig', 'self_protection', 'OK'], ['CONFIG_SYN_COOKIES', 'y', 'defconfig', 'self_protection', 'OK'], ['CONFIG_VMAP_STACK', 'y', 'defconfig', 'self_protection', 'OK'], ['CONFIG_THREAD_INFO_IN_TASK', 'y', 'defconfig', 'self_protection', 'OK'], ['CONFIG_BUG_ON_DATA_CORRUPTION', 'y', 'kspp', 'self_protection', 'OK'], ['CONFIG_DEBUG_WX', 'y', 'kspp', 'self_protection', 'OK'], ['CONFIG_SCHED_STACK_END_CHECK', 'y', 'kspp', 'self_protection', 'FAIL: "is not set"'], ['CONFIG_SLAB_FREELIST_HARDENED', 'y', 'kspp', 'self_protection', 'OK'], ['CONFIG_SLAB_FREELIST_RANDOM', 'y', 'kspp', 'self_protection', 'OK'], ['CONFIG_FORTIFY_SOURCE', 'y', 'kspp', 'self_protection', 'OK'], ['CONFIG_GCC_PLUGINS', 'y', 'kspp', 'self_protection', 'FAIL: not found'], ['CONFIG_GCC_PLUGIN_RANDSTRUCT', 'y', 'kspp', 'self_protection', 'FAIL: not found'], ['CONFIG_GCC_PLUGIN_STRUCTLEAK', 'y', 'kspp', 'self_protection', 'FAIL: not found'], ['CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL', 'y', 'kspp', 'self_protection', 'FAIL: not found'], ['CONFIG_GCC_PLUGIN_LATENT_ENTROPY', 'y', 'kspp', 'self_protection', 'FAIL: not found'], ['CONFIG_DEBUG_LIST', 'y', 'kspp', 'self_protection', 'OK'], ['CONFIG_DEBUG_SG', 'y', 'kspp', 'self_protection', 'FAIL: "is not set"'], ['CONFIG_DEBUG_CREDENTIALS', 'y', 'kspp', 'self_protection', 'FAIL: "is not set"'], ['CONFIG_DEBUG_NOTIFIERS', 'y', 'kspp', 'self_protection', 'FAIL: "is not set"'], ['CONFIG_PAGE_POISONING', 'y', 'kspp', 'self_protection', 'FAIL: "is not set"'], ['CONFIG_HARDENED_USERCOPY', 'y', 'kspp', 'self_protection', 'OK'], ['CONFIG_HARDENED_USERCOPY_FALLBACK', 'is not set', 'kspp', 'self_protection', 'FAIL: "y"'], ['CONFIG_MODULE_SIG', 'y', 'kspp', 'self_protection', 'OK'], ['CONFIG_MODULE_SIG_ALL', 'y', 'kspp', 'self_protection', 'OK'], ['CONFIG_MODULE_SIG_SHA512', 'y', 'kspp', 'self_protection', 'FAIL: "is not set"'], ['CONFIG_MODULE_SIG_FORCE', 'y', 'kspp', 'self_protection', 'FAIL: "is not set"'], ['CONFIG_DEFAULT_MMAP_MIN_ADDR', '65536', 'kspp', 'self_protection', 'OK'], ['CONFIG_REFCOUNT_FULL', 'y', 'kspp', 'self_protection', 'FAIL: "is not set"'], ['CONFIG_LOCK_DOWN_KERNEL', 'y', 'clipos', 'self_protection', 'OK'], ['CONFIG_SECURITY_DMESG_RESTRICT', 'y', 'clipos', 'self_protection', 'FAIL: "is not set"'], ['CONFIG_DEBUG_VIRTUAL', 'y', 'clipos', 'self_protection', 'FAIL: "is not set"'], ['CONFIG_STATIC_USERMODEHELPER', 'y', 'clipos', 'self_protection', 'FAIL: "is not set"'], ['CONFIG_SLAB_MERGE_DEFAULT', 'is not set', 'clipos', 'self_protection', 'FAIL: "y"'], ['CONFIG_GCC_PLUGIN_RANDSTRUCT_PERFORMANCE', 'is not set', 'clipos', 'self_protection', 'FAIL: CONFIG_GCC_PLUGIN_RANDSTRUCT is needed'], ['CONFIG_GCC_PLUGIN_STACKLEAK', 'y', 'clipos', 'self_protection', 'FAIL: not found'], ['CONFIG_STACKLEAK_METRICS', 'is not set', 'clipos', 'self_protection', 'FAIL: CONFIG_GCC_PLUGIN_STACKLEAK is needed'], ['CONFIG_STACKLEAK_RUNTIME_DISABLE', 'is not set', 'clipos', 'self_protection', 'FAIL: CONFIG_GCC_PLUGIN_STACKLEAK is needed'], ['CONFIG_RANDOM_TRUST_CPU', 'is not set', 'clipos', 'self_protection', 'FAIL: "y"'], ['CONFIG_MICROCODE', 'y', 'clipos', 'self_protection', 'OK'], ['CONFIG_IOMMU_SUPPORT', 'y', 'clipos', 'self_protection', 'OK'], ['CONFIG_INTEL_IOMMU', 'y', 'clipos', 'self_protection', 'OK'], ['CONFIG_INTEL_IOMMU_SVM', 'y', 'clipos', 'self_protection', 'OK'], ['CONFIG_INTEL_IOMMU_DEFAULT_ON', '
y', 'clipos', 'self_protection', 'FAIL: "is not set"'], ['CONFIG_AMD_IOMMU', 'y', 'my', 'self_protection', 'OK'], ['CONFIG_AMD_IOMMU_V2', 'y', 'my', 'self_protection', 'FAIL: "m"'], ['CONFIG_SLUB_DEBUG_ON', 'y', 'my', 'self_protection', 'FAIL: "is not set"'], ['CONFIG_SECURITY_LOADPIN', 'y', 'my', 'self_protection', 'FAIL: "is not set"'], ['CONFIG_RESET_ATTACK_MITIGATION', 'y', 'my', 'self_protection', 'FAIL: "is not set"'], ['CONFIG_PAGE_POISONING_NO_SANITY', 'is not set', 'my', 'self_protection', 'FAIL: CONFIG_PAGE_POISONING is needed'], ['CONFIG_PAGE_POISONING_ZERO', 'is not set', 'my', 'self_protection', 'FAIL: CONFIG_PAGE_POISONING is needed'], ['CONFIG_SECURITY', 'y', 'defconfig', 'security_policy', 'OK'], ['CONFIG_SECURITY_YAMA', 'y', 'kspp', 'security_policy', 'OK'], ['CONFIG_SECCOMP', 'y', 'defconfig', 'cut_attack_surface', 'OK'], ['CONFIG_SECCOMP_FILTER', 'y', 'defconfig', 'cut_attack_surface', 'OK'], ['CONFIG_STRICT_DEVMEM', 'y', 'defconfig', 'cut_attack_surface', 'OK'], ['CONFIG_MODULES', 'is not set', 'kspp', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_DEVMEM', 'is not set', 'kspp', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_IO_STRICT_DEVMEM', 'y', 'kspp', 'cut_attack_surface', 'OK'], ['CONFIG_ACPI_CUSTOM_METHOD', 'is not set', 'kspp', 'cut_attack_surface', 'FAIL: "m"'], ['CONFIG_COMPAT_BRK', 'is not set', 'kspp', 'cut_attack_surface', 'OK'], ['CONFIG_DEVKMEM', 'is not set', 'kspp', 'cut_attack_surface', 'OK'], ['CONFIG_COMPAT_VDSO', 'is not set', 'kspp', 'cut_attack_surface', 'OK'], ['CONFIG_BINFMT_MISC', 'is not set', 'kspp', 'cut_attack_surface', 'FAIL: "m"'], ['CONFIG_INET_DIAG', 'is not set', 'kspp', 'cut_attack_surface', 'FAIL: "m"'], ['CONFIG_KEXEC', 'is not set', 'kspp', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_PROC_KCORE', 'is not set', 'kspp', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_LEGACY_PTYS', 'is not set', 'kspp', 'cut_attack_surface', 'OK'], ['CONFIG_HIBERNATION', 'is not set', 'kspp', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_LEGACY_VSYSCALL_NONE', 'y', 'kspp', 'cut_attack_surface', 'FAIL: "is not set"'], ['CONFIG_IA32_EMULATION', 'is not set', 'kspp', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_X86_X32', 'is not set', 'kspp', 'cut_attack_surface', 'OK'], ['CONFIG_MODIFY_LDT_SYSCALL', 'is not set', 'kspp', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_X86_PTDUMP', 'is not set', 'grsecurity', 'cut_attack_surface', 'OK'], ['CONFIG_ZSMALLOC_STAT', 'is not set', 'grsecurity', 'cut_attack_surface', 'OK'], ['CONFIG_PAGE_OWNER', 'is not set', 'grsecurity', 'cut_attack_surface', 'OK'], ['CONFIG_DEBUG_KMEMLEAK', 'is not set', 'grsecurity', 'cut_attack_surface', 'OK'], ['CONFIG_BINFMT_AOUT', 'is not set', 'grsecurity', 'cut_attack_surface', 'OK: not found'], ['CONFIG_KPROBES', 'is not set', 'grsecurity', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_UPROBES', 'is not set', 'grsecurity', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_GENERIC_TRACER', 'is not set', 'grsecurity', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_PROC_VMCORE', 'is not set', 'grsecurity', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_PROC_PAGE_MONITOR', 'is not set', 'grsecurity', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_USELIB', 'is not set', 'grsecurity', 'cut_attack_surface', 'OK'], ['CONFIG_CHECKPOINT_RESTORE', 'is not set', 'grsecurity', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_USERFAULTFD', 'is not set', 'grsecurity', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_HWPOISON_INJECT', 'is not set', 'grsecurity', 'cut_attack_surface', 'FAIL: "m"'], ['CONFIG_MEM_SOFT_DIRTY', 'is not set', 'grsecurity', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_DEVPORT', 'is not set', 'grsecurity', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_DEBUG_FS', 'is not set', 'grsecurity', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_NOTIFIER_ERROR_INJECTION', 'is not set', 'grsecurity', 'cut_attack_surface', 'OK'], ['CONFIG_ACPI_TABLE_UPGRADE', 'is not set', 'lockdown', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_ACPI_APEI_EINJ', 'is not set', 'lockdown', 'cut_attack_surface', 'FAIL: "m"'], ['CONFIG_PROFILING', 'is not set', '
lockdown', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_BPF_SYSCALL', 'is not set', 'lockdown', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_MMIOTRACE_TEST', 'is not set', 'lockdown', 'cut_attack_surface', 'OK'], ['CONFIG_KSM', 'is not set', 'clipos', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_IKCONFIG', 'is not set', 'clipos', 'cut_attack_surface', 'OK'], ['CONFIG_KALLSYMS', 'is not set', 'clipos', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_X86_VSYSCALL_EMULATION', 'is not set', 'clipos', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_MAGIC_SYSRQ', 'is not set', 'clipos', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_KEXEC_FILE', 'is not set', 'clipos', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_USER_NS', 'is not set', 'clipos', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_LDISC_AUTOLOAD', 'is not set', 'clipos', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_MMIOTRACE', 'is not set', 'my', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_LIVEPATCH', 'is not set', 'my', 'cut_attack_surface', 'OK'], ['CONFIG_IP_DCCP', 'is not set', 'my', 'cut_attack_surface', 'OK'], ['CONFIG_IP_SCTP', 'is not set', 'my', 'cut_attack_surface', 'FAIL: "m"'], ['CONFIG_FTRACE', 'is not set', 'my', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_BPF_JIT', 'is not set', 'my', 'cut_attack_surface', 'FAIL: "y"'], ['CONFIG_ARCH_MMAP_RND_BITS', '32', 'clipos', 'userspace_protection', 'FAIL: "28"']]
~~~

Could you rework the PR and check the JSON output ?
I think it might be a trivial fix, like double quotes instead of simple quotes:
![Screenshot_20190707_145217](https://user-images.githubusercontent.com/964610/60768672-e0620600-a0c6-11e9-80f8-4454265c50fc.png)


Thanks !

#### <img src="https://avatars.githubusercontent.com/u/964610?u=7e6b8dd82339fe0349e7359908accf5543d95b8d&v=4" width="50">[Wenzel](https://github.com/Wenzel) commented at [2019-07-07 12:55](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/20#issuecomment-508997636):

It should be more robust to use `json.dump(obj)` or `json.dumps(string)` instead of printing your own JSON.
https://github.com/a13xp0p0v/kconfig-hardened-check/blob/master/kconfig-hardened-check.py#L377

#### <img src="https://avatars.githubusercontent.com/u/4029800?u=86702d3f2d50ee01ef1c572ef26b1ea1318f28da&v=4" width="50">[adrianopol](https://github.com/adrianopol) commented at [2019-07-07 19:28](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/20#issuecomment-509024571):

Fixed. Thanks.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-07-08 14:12](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/20#issuecomment-509241942):

@Wenzel, thanks for the report.
@adrianopol, thanks for the fix, merged.
Double-checked it in json validator, now it should be fine.


-------------------------------------------------------------------------------

# [\#19 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/19) `closed`: Compare with clipos recommendations

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) opened issue at [2019-06-01 12:08](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/19):

Hi Alexander,

I monitoring an interesting project ([CLIP OS ](https://github.com/clipos)) in my country and some options should be compared with your project.

Here are some options that are missing or different from kconfig-hardened-check :

```
CONFIG_AUDIT=y
CONFIG_IKCONFIG=n
CONFIG_KALLSYMS=n
CONFIG_SLAB_HARDENED=y
CONFIG_SLAB_CANARY=y
CONFIG_SLAB_SANITIZE=y
CONFIG_SLAB_SANITIZE_VERIFY=y
CONFIG_GCC_PLUGIN_RANDSTRUCT_PERFORMANCE=n
CONFIG_LOCAL_INIT=n
CONFIG_X86_VSYSCALL_EMULATION=n
CONFIG_MICROCODE=y
CONFIG_X86_MSR=y
CONFIG_KSM=n
CONFIG_MTRR=y
CONFIG_X86_PAT=y
CONFIG_ARCH_RANDOM=y
CONFIG_X86_INTEL_MPX=n
CONFIG_X86_INTEL_MEMORY_PROTECTION_KEYS=n
CONFIG_CRASH_DUMP=n
CONFIG_COREDUMP=n
CONFIG_TCG_TPM=n
CONFIG_RANDOM_TRUST_CPU=n
CONFIG_IOMMU_SUPPORT=y
CONFIG_INTEL_IOMMU=y
CONFIG_INTEL_IOMMU_SVM=y
CONFIG_INTEL_IOMMU_DEFAULT_ON=y
CONFIG_MAGIC_SYSRQ=n
CONFIG_DEBUG_KERNEL=y
CONFIG_DEBUG_VIRTUAL=y
CONFIG_SLUB_DEBUG_ON=n
CONFIG_PANIC_ON_OOPS=y
CONFIG_PANIC_TIMEOUT=-1
CONFIG_INTEL_TXT=n
CONFIG_FORTIFY_SOURCE_STRICT_STRING=n
CONFIG_STATIC_USERMODEHELPER_PATH=""
CONFIG_SECURITY_SELINUX_BOOTPARAM=n
CONFIG_INTEGRITY=n
CONFIG_SECURITY_PERF_EVENTS_RESTRICT=y
CONFIG_PAGE_SANITIZE_VERIFY=y
CONFIG_SECURITY_TIOCSTI_RESTRICT=y
CONFIG_LOCK_DOWN_MANDATORY=y
CONFIG_STACKLEAK_TRACK_MIN_SIZE=100
CONFIG_STACKLEAK_METRICS=n
CONFIG_STACKLEAK_RUNTIME_DISABLE=n
```

Details of the options are available here:
https://docs.clip-os.org/clipos/kernel.html#configuration

Best regards,

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2019-06-01 12:12](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/19#issuecomment-497939852):

Even if I'm not a fan of black magic (see [this](https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/issues/3)), the CONFIG_MICROCODE=y option is now essential.

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2019-06-02 11:33](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/19#issuecomment-498022889):

Some of those options are available only in linux-hardened patchset thus not applicable here. Others like CONFIG_INTEGRITY=n or CONFIG_INTEL_TXT=n are specific to clipos and general recommendations would be the opposite.

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2019-06-02 15:13](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/19#issuecomment-498039692):

Yes, you're right, I did a quick extraction. 
Are there any options you think are interesting?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-06-03 10:23](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/19#issuecomment-498201117):

Cool! @HacKurx, learning the CLIP OS config is a nice idea.

Thanks for the link, I'll check the options from their documentation and choose relevant for the script.

Do you have their full kernel config for adding to `config_files`?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-06-03 18:16](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/19#issuecomment-498368130):

Hi @HacKurx and @Bernhard40,
I've added new checks based on the CLIP OS recommendations.

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2019-06-03 19:02](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/19#issuecomment-498384402):

Hi @a13xp0p0v,

Thanks you :)

> Do you have their full kernel config for adding to config_files?

The configuration is automatically generated by a script in their own kernel source:
https://github.com/clipos/src_platform_config-linux-hardware/tree/master/
https://github.com/clipos/src_external_linux

I can ask @tsautereau-anssi for confirm it.

Best regards,

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2019-06-04 10:20](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/19#issuecomment-498612884):

@a13xp0p0v `CONFIG_X86_MSR` could also be set to `m` which I think should be ok.

At least Ubuntu, Debian, Archlinux and opensSUSE have it set this way.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-06-04 22:12](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/19#issuecomment-498862822):

>@a13xp0p0v CONFIG_X86_MSR could also be set to m which I think should be ok.
At least Ubuntu, Debian, Archlinux and opensSUSE have it set this way.

@Bernhard40, thanks for pointing this out.
I double-checked and dropped this recommendation - IMO it's wrong.
CONFIG_X86_MSR provides access from the userspace to the x86 MSRs via char devices.
Kernel doesn't need it for mitigating CPU bugs.

I've created an issue with a question for the CLIP OS project:
https://github.com/clipos/src_platform_config-linux-hardware/issues/1


-------------------------------------------------------------------------------

# [\#18 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/18) `merged`: Update pentoo config link

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) opened issue at [2019-06-01 12:02](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/18):






-------------------------------------------------------------------------------

# [\#17 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/17) `merged`: Update and add config

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) opened issue at [2019-05-12 15:09](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/17):

Hi Alexander,

Here are some updates and the addition of two distributions.

I let you choose ;)

Best regards,

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-05-17 15:13](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/17#issuecomment-493490338):

Hello @HacKurx,
Thanks for the update!
I'm merging it.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-05-17 15:20](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/17#issuecomment-493492947):

@HacKurx, may I ask you to add/update information in the `links.txt` as well?
Thanks!

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2019-05-25 16:59](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/17#issuecomment-495933123):

Hello @a13xp0p0v,

Thank's for the merge. Some configuration files do not have a url (debian, ubuntu, rhel), I had to extract the configuration from the kernel package.
I am willing to maintain all config occasionally.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-05-27 14:39](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/17#issuecomment-496234113):

Nice, thanks!

I mean some of your new configs now have out-of-date links in `links.txt`.
For example, Alpine, Arch and Pentoo. Could you please update the links?


-------------------------------------------------------------------------------

# [\#16 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/16) `closed`: After kspp settings server if freezed

#### <img src="https://avatars.githubusercontent.com/u/3471772?u=8db711eeb856b86264fa6d1e6887577d76af09ad&v=4" width="50">[bryn1u](https://github.com/bryn1u) opened issue at [2019-04-11 12:37](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/16):

Hey guys,

When i setup server Centos 7 with kspp settings (config below) and i install www hosting panels like Cpanel, CWP panel or ISPmanager and then reboot server, many services are freezed. My network is disabled i cant run with command systemct start network, i cant  reboot server and etc... when i push these commend nothing happen, just waiting and waiting.

My KSPP config:

[+] config check is finished: 'OK' - 62 / 'FAIL' - 41
[root@proton kconfig-hardened-check]# ls
config_files  kconfig-hardened-check.py  LICENSE  README.md
[root@proton kconfig-hardened-check]# ./kconfig-hardened-check.py -c /boot/config-5.0.4 > kspp_setting
[root@proton kconfig-hardened-check]# cat kspp_setting 
[+] Trying to detect architecture in "/boot/config-5.0.4"...
[+] Detected architecture: X86_64
[+] Checking "/boot/config-5.0.4" against hardening preferences...
  option name                            | desired val | decision |       reason       ||        check result        
  ===================================================================================================================
  CONFIG_BUG                             |      y      |defconfig |  self_protection   ||             OK             
  CONFIG_STRICT_KERNEL_RWX               |      y      |defconfig |  self_protection   ||             OK             
  CONFIG_STACKPROTECTOR_STRONG           |      y      |defconfig |  self_protection   ||             OK             
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
  CONFIG_THREAD_INFO_IN_TASK             |      y      |defconfig |  self_protection   ||             OK             
  CONFIG_BUG_ON_DATA_CORRUPTION          |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_DEBUG_WX                        |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_SCHED_STACK_END_CHECK           |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_SLAB_FREELIST_HARDENED          |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_SLAB_FREELIST_RANDOM            |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_FORTIFY_SOURCE                  |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_GCC_PLUGINS                     |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_GCC_PLUGIN_RANDSTRUCT           |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_GCC_PLUGIN_STRUCTLEAK           |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_GCC_PLUGIN_LATENT_ENTROPY       |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_DEBUG_LIST                      |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_DEBUG_SG                        |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_DEBUG_CREDENTIALS               |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_DEBUG_NOTIFIERS                 |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_PAGE_POISONING                  |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_HARDENED_USERCOPY               |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_HARDENED_USERCOPY_FALLBACK      | is not set  |   kspp   |  self_protection   ||             OK             
  CONFIG_MODULE_SIG                      |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_MODULE_SIG_ALL                  |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_MODULE_SIG_SHA512               |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_MODULE_SIG_FORCE                |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_DEFAULT_MMAP_MIN_ADDR           |    65536    |   kspp   |  self_protection   ||             OK             
  CONFIG_REFCOUNT_FULL                   |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_GCC_PLUGIN_STACKLEAK            |      y      |    my    |  self_protection   ||             OK             
  CONFIG_LOCK_DOWN_KERNEL                |      y      |    my    |  self_protection   ||      FAIL: not found       
  CONFIG_SLUB_DEBUG_ON                   |      y      |    my    |  self_protection   ||             OK             
  CONFIG_SECURITY_DMESG_RESTRICT         |      y      |    my    |  self_protection   ||             OK             
  CONFIG_STATIC_USERMODEHELPER           |      y      |    my    |  self_protection   ||     FAIL: "is not set"     
  CONFIG_SECURITY_LOADPIN                |      y      |    my    |  self_protection   ||     FAIL: "is not set"     
  CONFIG_RESET_ATTACK_MITIGATION         |      y      |    my    |  self_protection   ||             OK             
  CONFIG_SLAB_MERGE_DEFAULT              | is not set  |    my    |  self_protection   ||         FAIL: "y"          
  CONFIG_PAGE_POISONING_NO_SANITY        | is not set  |    my    |  self_protection   ||             OK             
  CONFIG_PAGE_POISONING_ZERO             | is not set  |    my    |  self_protection   ||             OK             
  CONFIG_SECURITY                        |      y      |defconfig |  security_policy   ||             OK             
  CONFIG_SECURITY_YAMA                   |      y      |   kspp   |  security_policy   ||             OK             
  CONFIG_SECURITY_SELINUX_DISABLE        | is not set  |   kspp   |  security_policy   ||             OK             
  CONFIG_SECCOMP                         |      y      |defconfig | cut_attack_surface ||             OK             
  CONFIG_SECCOMP_FILTER                  |      y      |defconfig | cut_attack_surface ||             OK             
  CONFIG_STRICT_DEVMEM                   |      y      |defconfig | cut_attack_surface ||             OK             
  CONFIG_MODULES                         | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_DEVMEM                          | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_IO_STRICT_DEVMEM                |      y      |   kspp   | cut_attack_surface ||     FAIL: "is not set"     
  CONFIG_ACPI_CUSTOM_METHOD              | is not set  |   kspp   | cut_attack_surface ||         FAIL: "m"          
  CONFIG_COMPAT_BRK                      | is not set  |   kspp   | cut_attack_surface ||             OK             
  CONFIG_DEVKMEM                         | is not set  |   kspp   | cut_attack_surface ||             OK             
  CONFIG_COMPAT_VDSO                     | is not set  |   kspp   | cut_attack_surface ||             OK             
  CONFIG_BINFMT_MISC                     | is not set  |   kspp   | cut_attack_surface ||         FAIL: "m"          
  CONFIG_INET_DIAG                       | is not set  |   kspp   | cut_attack_surface ||         FAIL: "m"          
  CONFIG_KEXEC                           | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_PROC_KCORE                      | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_LEGACY_PTYS                     | is not set  |   kspp   | cut_attack_surface ||             OK             
  CONFIG_HIBERNATION                     | is not set  |   kspp   | cut_attack_surface ||             OK             
  CONFIG_LEGACY_VSYSCALL_NONE            |      y      |   kspp   | cut_attack_surface ||     FAIL: "is not set"     
  CONFIG_IA32_EMULATION                  | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_X86_X32                         | is not set  |   kspp   | cut_attack_surface ||             OK             
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
  CONFIG_NOTIFIER_ERROR_INJECTION        | is not set  |grsecurity| cut_attack_surface ||             OK             
  CONFIG_ACPI_TABLE_UPGRADE              | is not set  | lockdown | cut_attack_surface ||         FAIL: "y"          
  CONFIG_ACPI_APEI_EINJ                  | is not set  | lockdown | cut_attack_surface ||         FAIL: "m"          
  CONFIG_PROFILING                       | is not set  | lockdown | cut_attack_surface ||         FAIL: "y"          
  CONFIG_BPF_SYSCALL                     | is not set  | lockdown | cut_attack_surface ||         FAIL: "y"          
  CONFIG_MMIOTRACE_TEST                  | is not set  | lockdown | cut_attack_surface ||       OK: not found        
  CONFIG_MMIOTRACE                       | is not set  |    my    | cut_attack_surface ||             OK             
  CONFIG_KEXEC_FILE                      | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_LIVEPATCH                       | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_USER_NS                         | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_IP_DCCP                         | is not set  |    my    | cut_attack_surface ||         FAIL: "m"          
  CONFIG_IP_SCTP                         | is not set  |    my    | cut_attack_surface ||         FAIL: "m"          
  CONFIG_FTRACE                          | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_BPF_JIT                         | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_ARCH_MMAP_RND_BITS              |     32      |    my    |userspace_protection||         FAIL: "28"         

[+] config check is finished: 'OK' - 62 / 'FAIL' - 41


Someone can help me with this, i would be graceful ?
Could be impact because of this ?
CONFIG_GCC_PLUGINS | y | kspp | self_protection || OK
CONFIG_GCC_PLUGIN_RANDSTRUCT | y | kspp | self_protection || OK
CONFIG_GCC_PLUGIN_STRUCTLEAK | y | kspp | self_protection || OK
CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL | y | kspp | self_protection || OK
CONFIG_GCC_PLUGIN_LATENT_ENTROPY | y | kspp | self_protection || OK

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2019-04-11 19:26](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/16#issuecomment-482272466):

Could you post `dmesg` output?

#### <img src="https://avatars.githubusercontent.com/u/3471772?u=8db711eeb856b86264fa6d1e6887577d76af09ad&v=4" width="50">[bryn1u](https://github.com/bryn1u) commented at [2019-04-14 13:50](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/16#issuecomment-482980574):

Hey,

Sure.
I put my KSPP config again but as a screen: https://ufile.io/epovx3h9
Second part of KSPP config:  https://ufile.io/n4087vqn

Output from dmesg:
dmesg 1 - https://ufile.io/2reh95ag
dmesg 2 - https://ufile.io/mkt1sv73

Thanks,

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-04-14 20:45](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/16#issuecomment-483056865):

Hello @bryn1u,

As I can understand, you are trying to run Centos 7 with the mainline kernel (5.0.7).
I would recommend you to move by smaller steps.

First -- update your kernel, but use `make oldconfig` with the original kernel config from Centos 7.
Maybe something will break even after this step.

And then try to enable hardening options one by one performing your functional test after each change.
You can speed up this procedure using bisection method (between the initial and final configs).

@Bernhard40, any other advices?


-------------------------------------------------------------------------------

# [\#15 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/15) `closed`: After used KSPP settings, modules ext4, xfs, iptables are disabled.

#### <img src="https://avatars.githubusercontent.com/u/3471772?u=8db711eeb856b86264fa6d1e6887577d76af09ad&v=4" width="50">[bryn1u](https://github.com/bryn1u) opened issue at [2019-03-22 13:09](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/15):

Hello a13xp0p0v :))

Im using centos 7 and i have a weird problem after kernel compilation. Below is my config kernel with KSPP options enabled.
![kernel1](https://user-images.githubusercontent.com/3471772/54824577-a271db00-4cab-11e9-92fc-4974a17b41d1.png)
![kernel2](https://user-images.githubusercontent.com/3471772/54824582-a69df880-4cab-11e9-9c34-604be7280fd1.png)
![kernel3](https://user-images.githubusercontent.com/3471772/54824586-ab62ac80-4cab-11e9-98af-5b5c98baa232.png)

I have no idea why after kernel compiling, modules like for example ext4, xfs and iptables are disabled. I can't login to the system because ext4 module is disable. The only way is to compiling permanently not as a module. But iptables still dosen't work. Which options are responsible for these "issues" ?
Thanks for help :)


#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2019-03-23 17:18](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/15#issuecomment-475888038):

It could be caused by `CONFIG_STATIC_USERMODEHELPER`. This option needs userspace support which is pretty much non-existent in distros, don't use it.

#### <img src="https://avatars.githubusercontent.com/u/3471772?u=8db711eeb856b86264fa6d1e6887577d76af09ad&v=4" width="50">[bryn1u](https://github.com/bryn1u) commented at [2019-03-23 20:07](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/15#issuecomment-475900478):

Thanks Bernhard40. I disabled usermodhelper and it works.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-03-24 11:35](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/15#issuecomment-475950377):

Hello!

@Bernhard40, thanks for your help!

@bryn1u, I remember we have discussed with you that STATIC_USERMODEHELPER and SECURITY_LOADPIN influence module loading -- in #8.

That's why the script has the following comments:
```
checklist.append(OptCheck('STATIC_USERMODEHELPER', 'y', 'my', 'self_protection')) # needs userspace support (systemd)
checklist.append(OptCheck('SECURITY_LOADPIN', 'y', 'my', 'self_protection')) # needs userspace support
```


-------------------------------------------------------------------------------

# [\#14 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/14) `closed`: User namespace useful especially when running containers

#### <img src="https://avatars.githubusercontent.com/u/1397088?v=4" width="50">[jcberthon](https://github.com/jcberthon) opened issue at [2019-03-19 14:59](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/14):

Maybe I'm wrong, but at least with Kernel 5.0 USER_NS is activated by default, so "is not set" or "y" should be equivalent. At the moment, it fails because it is "y" on my configuration.

I know that activating USER_NS can cut the attack surface if it is not needed on a system. But on my system which are running containers, I want to have USER_NS activated. True this is not pure hardening of the Kernel, but if we take into account the whole kernel including the possibilities to use it to make containers, then USER_NS should be part of the whole hardening.

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2019-03-19 18:02](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/14#issuecomment-474500985):

> Maybe I'm wrong, but at least with Kernel 5.0 USER_NS is activated by default, so "is not set" or "y" should be equivalent. At the moment, it fails because it is "y" on my configuration.

"is not set" (disabled) is the opposite of "y" (enabled). The fail for "y" is desired outcome.

> I know that activating USER_NS can cut the attack surface if it is not needed on a system. But on my system which are running containers, I want to have USER_NS activated. True this is not pure hardening of the Kernel, but if we take into account the whole kernel including the possibilities to use it to make containers, then USER_NS should be part of the whole hardening.

You have it backwards. **Disabling** USER_NS [cuts the attack surface](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings#sysctls) and is part of kernel hardening. USER_NS (unprivileged) are considered inherently insecure and unfixable.

#### <img src="https://avatars.githubusercontent.com/u/1397088?v=4" width="50">[jcberthon](https://github.com/jcberthon) commented at [2019-03-19 21:20](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/14#issuecomment-474589104):

Thanks for clarifying the first point.

Concerning the second point, I know that username space could increase the attack surface (heck I recall there was like 1,5-2 years ago a privilege escalation flaw with user ns - albeit mitigated when using SELinux), that's especially true if the functionality is not used.

Anyway as the site you mention implicitly state, you can still compile it in and use the sysctl knob to disable it depending on your threat model and your usage of the kernel. So your application could test the sysctl knob rather than the kernel config. e.g. for people using Ubuntu but following the guideline (and because they do not need it), they can disable it in sysctl. When running your script, they should see that it is correctly disabled. What do you think?

_Note that when someone requires to run containers, user ns can be a good evil. It increases some risk but diminished others. It is a trade off which depends on one's threat model. I mean that I clearly prefer to run my containers as non-root user with as little capabilities as possible, so I would not need user namespaces. But I'm also maintaining a CI/CD environment based on Docker, and there it is pretty hard to deny users the use of root inside spawned containers. I can control capabilities, seccomp and SELinux, but not the root user. There I really need user namespace, I have no other choice._

Do you have a source for user ns being considered unfixable?

Anyway, I understand your reasoning for marking user ns as insecure, so I would not be offended if you would decide to close this issue. Of course I would appreciate you take my suggestion into account :-)

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2019-03-19 21:32](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/14#issuecomment-474592962):

its not just one like 2 years ago, userns is an endless stream of privilege escalation flaws exposed by root designed functionality accessible to any unprivileged user inside a user namespace over and over again.

In my personal opinion this should remain as is, being an error, and if your personal threat model doesn't care about user_ns you can just ignore the result of kconfig-hardened-check :cat:

#### <img src="https://avatars.githubusercontent.com/u/1397088?v=4" width="50">[jcberthon](https://github.com/jcberthon) commented at [2019-03-19 22:44](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/14#issuecomment-474613483):

Alright, and thanks for the feedback.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-03-20 06:49](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/14#issuecomment-474708180):

Hello everyone,

I'm a bit late for the discussion.

@jcberthon, thanks for your message.
Yes, the `CONFIG_USER_NS` option provides some isolation between the userspace programs, but the script recommends disabling it to cut the attack surface __of the kernel__.
Let me give the links describing the rationale:
  
  1. A nice LWN article about the corresponding LKML discussion: https://lwn.net/Articles/673597/
  2. A twitter thread about USER_NS and security: https://twitter.com/robertswiecki/status/1095447678949953541

@jcberthon, you are right, USER_NS can be disabled using the sysctl - it is even mentioned in the script source code:
```
checklist.append(OptCheck('USER_NS', 'is not set', 'my', 'cut_attack_surface')) # user.max_user_namespaces=0
```

(by the way, adding the ability to check kernel boot parameters and sysctl would be really nice)

Thanks for your discussion, I think I should add some clarification of `cut_attack_surface` to the README.

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2019-03-20 12:25](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/14#issuecomment-474807051):

> (by the way, adding the ability to check kernel boot parameters and sysctl would be really nice)

I'm not sure if it's good idea for this project to start scanning the running system for security features. I would vote for keeping it simple and just check chosen config file.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-03-20 13:23](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/14#issuecomment-474826371):

> > (by the way, adding the ability to check kernel boot parameters and sysctl would be really nice)
> 
> I'm not sure if it's good idea for this project to start scanning the running system for security features. I would vote for keeping it simple and just check chosen config file.

I agree, I don't like the privileged scanning of a system from the script too.
I mean the script could analyze additional files with the needed information together with the kernel config.
For example, right now we can say nothing about side-channel attack mitigations.

#### <img src="https://avatars.githubusercontent.com/u/1397088?v=4" width="50">[jcberthon](https://github.com/jcberthon) commented at [2019-03-20 23:09](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/14#issuecomment-475063272):

Thank you for the interesting read and for the updated README.


-------------------------------------------------------------------------------

# [\#13 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/13) `closed`: False positive and false negatives

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) opened issue at [2019-03-09 19:13](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/13):

`PAGE_POISONING_NO_SANITY` and `PAGE_POISONING_ZERO` depend on `PAGE_POISONING`. Checking distro config which doesn't enable `PAGE_POISONING` (like Fedora) will show `OK: not found` for the first two even as it's far from ok in this case.

Currently script checks only for `MODULE_SIG_SHA512`. Some distros (like Fedora) may use `SHA256` which I think should be fine as well even if KSPP chose different example.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-03-11 16:27](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/13#issuecomment-471614645):

Hello @Bernhard40,
Thanks for your report, let's discuss it.

> PAGE_POISONING_NO_SANITY and PAGE_POISONING_ZERO depend on PAGE_POISONING. Checking distro config which doesn't enable PAGE_POISONING (like Fedora) will show OK: not found for the first two even as it's far from ok in this case.

Yes, they are dependent on PAGE_POISONING.
These options make this feature weaker, so the script is checking that they are __disabled__.
When the PAGE_POISONING is disabled, the error count is incremented anyway.
I don't think that checking PAGE_POISONING_NO_SANITY and PAGE_POISONING_ZERO should behave differently in that case.

> Currently script checks only for MODULE_SIG_SHA512. Some distros (like Fedora) may use SHA256 which I think should be fine as well even if KSPP chose different example.

The MODULE_SIG_SHA512 option is the KSPP recommendation, it is explicitly indicated by the script.
Distros may have various reasons to do it differently.
One day the script will support the error annotations (the idea is described here: https://github.com/a13xp0p0v/kconfig-hardened-check/pull/9#issuecomment-453810119)

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2019-03-12 00:07](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/13#issuecomment-471790830):

> Yes, they are dependent on PAGE_POISONING.
> These options make this feature weaker, so the script is checking that they are disabled.
> When the PAGE_POISONING is disabled, the error count is incremented anyway.
> I don't think that checking PAGE_POISONING_NO_SANITY and PAGE_POISONING_ZERO should behave differently in that case.

Consider distro which have PAGE_POISONING=n. In check it gets:
```
CONFIG_PAGE_POISONING                  |      y      |   kspp   |  self_protection   ||     FAIL: "is not set" 
CONFIG_PAGE_POISONING_NO_SANITY        | is not set  |    my    |  self_protection   ||       OK: not found
CONFIG_PAGE_POISONING_ZERO             | is not set  |    my    |  self_protection   ||       OK: not found
```
The sum is: 1xFAIL + 2xOK

Now, consider distro which has PAGE_POISONING=y, PAGE_POISONING_NO_SANITY=y, PAGE_POISONING_ZERO=y. In check it gets:
```
CONFIG_PAGE_POISONING                  |      y      |   kspp   |  self_protection   ||             OK
CONFIG_PAGE_POISONING_NO_SANITY        | is not set  |    my    |  self_protection   ||         FAIL: "y"
CONFIG_PAGE_POISONING_ZERO             | is not set  |    my    |  self_protection   ||         FAIL: "y"
```
The sum is: 2xFAIL + 1xOK

The check shows that distro which disables PAGE_POISONING completely is better than one which enables its weaker version! Specifically for fedora it's 52 errors with the former (actual config) vs 53 errors with the latter.

> The MODULE_SIG_SHA512 option is the KSPP recommendation, it is explicitly indicated by the script.

I read this recommendation as _sign your modules_ rather than _sign your modules using SHA512_. The KSPP page says [But if CONFIG_MODULE=y is needed, at least they must be signed with a per-build key](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings#CONFIGs). Below they show an example with SHA512. I highly doubt they meant SHA512 explicitly and nothing else. IMO they just used one example because iterating it for SHA256/SHA384 would be rather redundant. You may ask Kees about what he had in mind when he wrote this.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-03-12 15:31](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/13#issuecomment-472049899):

> The check shows that distro which disables PAGE_POISONING completely is better than one which enables its weaker version! Specifically for fedora it's 52 errors with the former (actual config) vs 53 errors with the latter.

Right. Please have a look how I've solved this issue.
 - I've implemented the AND check: 555b588e7b8a620ee57d53ef771e3b128590de45.
 - It's now used for PAGE_POISONING_NO_SANITY and PAGE_POISONING_ZERO - they are not checked if PAGE_POISONING is off: a314e4f1df3893864e398ea8565fefdfc036169b.
 - The same approach for HARDENED_USERCOPY_FALLBACK: c83dc6c7c804987999296afba385b2349bdda9ac.
 - And I improved the output of final results: 43920b20672cd603f7d5e02544a951eec914636b. Now OKs are counted too.

> You may ask Kees about what he had in mind when he wrote this.

Ok, I will remember that. There are several things which can be added to KSPP wiki. I'll work on that later.

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2019-03-12 17:53](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/13#issuecomment-472112024):

> It's now used for PAGE_POISONING_NO_SANITY and PAGE_POISONING_ZERO - they are not checked if PAGE_POISONING is off:

You could also always mark them as failed in that case like `FAIL: "dependency missing"`. That would prevent FAIL count from increasing when enabling only PAGE_POISONING.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-03-12 21:54](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/13#issuecomment-472196588):

> You could also always mark them as failed in that case like FAIL: "dependency missing"

@Bernhard40, nice idea, thank you.
Implemented in d9aca2d28e9f95266bca2da09625d7d2c885a6b2.


-------------------------------------------------------------------------------

# [\#12 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/12) `closed`: CONFIG_MODULE_SIG_FORCE shouldn't be checked if CONFIG_MODULES is not set

#### <img src="https://avatars.githubusercontent.com/u/990588?v=4" width="50">[hannob](https://github.com/hannob) opened issue at [2019-03-03 12:35](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/12):

I have a minimal kernel without modules for a server. I get a warning about CONFIG_MODULE_SIG_FORCE, which should not apply for a kernel without module support.

For several other module-related options the script behaves correctly (saying 'CONFIG_MODULES: OK ("is not set")' indicating this does not apply), but for CONFIG_MODULE_SIG_FORCE it does not do so.

Output is:
```
  CONFIG_MODULE_SIG_FORCE                |      y      |   kspp   |  self_protection   ||      FAIL: not found       
```

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-03-04 13:42](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/12#issuecomment-469256961):

Fixed.
Thank you @hannob.


-------------------------------------------------------------------------------

# [\#11 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/11) `closed`: Feature request: Check CONFIG_RESET_ATTACK_MITIGATION

#### <img src="https://avatars.githubusercontent.com/u/990588?v=4" width="50">[hannob](https://github.com/hannob) opened issue at [2019-03-02 08:17](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/11):

Thanks for this tool.

I'd propose to add a check for CONFIG_RESET_ATTACK_MITIGATION.
This is a feature that on modern systems will set a flag on boot that signals the BIOS to wipe the memory if an unclean shutdown happened. This can protect against some forms of cold boot attacks where you reboot into another system and try to read out the memory from the previous run.

Here's the Kernel submission with some explanation:
https://lwn.net/Articles/730006/

It's also explained in this talk:
https://www.youtube.com/watch?v=RqvPZnLkP70 (around minute 35)

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2019-03-02 12:47](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/11#issuecomment-468917523):

This option needs userspace support, otherwise it's not recommended for use:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a5c03c31af2291f13689d11760c0b59fb70c9a5a

https://bugzilla.redhat.com/show_bug.cgi?id=1532058

#### <img src="https://avatars.githubusercontent.com/u/990588?v=4" width="50">[hannob](https://github.com/hannob) commented at [2019-03-03 12:33](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/11#issuecomment-469018559):

Interesting, is there any userspace tool to do this? Or is this basically unsupported in current systems?

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2019-03-03 12:49](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/11#issuecomment-469019815):

@hannob I wanted to look into this for systemd, but forgot for quite a while. thanks for reminding me, back then there was no userspace support, theoretically you could add a systemd service but doing it _properly_ is bit more tricky. I'm putting this back onto my todo list and take a dive into how to properly implement this into systemd itself at a place that could guarantee that all other services etc. are already properly shut down.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-03-04 14:52](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/11#issuecomment-469280355):

Hello @hannob @Bernhard40 @anthraxx,

`RESET_ATTACK_MITIGATION` is a nice option, I will add this check to the script with a comment about userspace support.

That case will be similar to the `STATIC_USERMODEHELPER` option, which needs the userspace support as well (but, as I know, enabling it currently breaks systemd workflow on Ubuntu).

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-03-04 18:29](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/11#issuecomment-469362767):

Hm... By the way Ubuntu 18 has `RESET_ATTACK_MITIGATION` enabled.

#### <img src="https://avatars.githubusercontent.com/u/543852?v=4" width="50">[anthonyryan1](https://github.com/anthonyryan1) commented at [2024-08-15 15:40](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/11#issuecomment-2291565641):

5 years later...

Has anyone got the userland support for this feature up and running yet?

I'm interested in solutions for either OpenRC or systemd. There's plenty of mentions of the kconfig option, but I can't find any mention of the userland half of this feature.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2025-07-28 08:14](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/11#issuecomment-3126064023):

@anthonyryan1, it looks like multiple GNU/Linux distros already have this option enabled:
```
$ grep -r RESET_ATTACK_MITIGATION kernel_hardening_checker/config_files/distros/|grep "=y"
kernel_hardening_checker/config_files/distros/Debian_13_Trixie_aarch64.config:CONFIG_RESET_ATTACK_MITIGATION=y
kernel_hardening_checker/config_files/distros/Oracle_Linux_10_(UEK-NEXT)_aarch64.config:CONFIG_RESET_ATTACK_MITIGATION=y
kernel_hardening_checker/config_files/distros/Ubuntu_25.04_Oracular_aarch64.config:CONFIG_RESET_ATTACK_MITIGATION=y
kernel_hardening_checker/config_files/distros/Arch_hardened_x86_64.config:CONFIG_RESET_ATTACK_MITIGATION=y
kernel_hardening_checker/config_files/distros/Azure_Linux_x86_64.config:CONFIG_RESET_ATTACK_MITIGATION=y
kernel_hardening_checker/config_files/distros/nixpkgs-linux_hardened.config:CONFIG_RESET_ATTACK_MITIGATION=y
kernel_hardening_checker/config_files/distros/Debian_13_Trixie_x86_64.config:CONFIG_RESET_ATTACK_MITIGATION=y
kernel_hardening_checker/config_files/distros/Ubuntu_24.04_LTS_Noble_riscv64.config:CONFIG_RESET_ATTACK_MITIGATION=y
kernel_hardening_checker/config_files/distros/Ubuntu_25.04_Plucky_x86_64.config:CONFIG_RESET_ATTACK_MITIGATION=y
kernel_hardening_checker/config_files/distros/Ubuntu_20.04_LTS_Focal_x86_64.config:CONFIG_RESET_ATTACK_MITIGATION=y
kernel_hardening_checker/config_files/distros/Ubuntu_20.04_LTS_Focal_aarch64.config:CONFIG_RESET_ATTACK_MITIGATION=y
```

#### <img src="https://avatars.githubusercontent.com/u/543852?v=4" width="50">[anthonyryan1](https://github.com/anthonyryan1) commented at [2025-07-28 16:54](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/11#issuecomment-3128140781):

@a13xp0p0v  The thing I'm referring to is the heavily suggested userland component  [described in the kernel config](https://github.com/torvalds/linux/blob/v6.12/drivers/firmware/efi/Kconfig#L176-L187):

"This should only be enabled when userland is configured to  clear the MemoryOverwriteRequest flag on clean shutdown after secrets have been evicted, since otherwise it will trigger even on clean reboots."

I'm curious if that userland component even exists?

From a security perspective, we're not doing anything wrong by enabling the feature. It'll still clear the RAM during a reset attack. But we're also clearing the RAM on every clean reboot, which is rather slow with 1 TB of RAM in a machine.

I believe we're applying the mitigation to clean reboots and shutdowns, and not just reset attacks as described without the userland component.

#### <img src="https://avatars.githubusercontent.com/u/543852?v=4" width="50">[anthonyryan1](https://github.com/anthonyryan1) commented at [2025-07-28 17:05](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/11#issuecomment-3128178600):

To elaborate a little further, during a clean shutdown, as long as we have  `CONFIG_INIT_ON_FREE_DEFAULT_ON=y` (which we recommend here) the memory was already cleared. So `CONFIG_RESET_ATTACK_MITIGATION=y` without the userland component will zero the RAM two full times.

If we didn't enable `CONFIG_INIT_ON_FREE_DEFAULT_ON` then `CONFIG_RESET_ATTACK_MITIGATION` would ensure the memory is wiped at least once on shutdown.


-------------------------------------------------------------------------------

# [\#10 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/10) `closed`: Add support for x86_32, arm, and arm64 architectures

#### <img src="https://avatars.githubusercontent.com/u/1051156?u=82b8caad104296ef90ffe2f5807dc34d82c31c2b&v=4" width="50">[tyhicks](https://github.com/tyhicks) opened issue at [2019-01-14 19:37](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/10):

(This is a continuation of #9)

Some hardening recommendations are dependent on the processor architecture. For example, the KSPP recommendations differ between [x86_32](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings#x86_32) and [x86_64](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings#x86_64).

This pull request adds the ability to reason about the architecture when constructing the checklist. It also teaches the script about `x86_32`, `arm`, and `arm64` specific config recommendations.

I verified that all the example configs in `config_files/` show the same number of config check failures before and after these changes are applied. Of course, the ordering of the options are changed since the ordering used to construct the checklist has been changed.

Some changes since #9 include:
- Drop kernel version detection from the pull request
- Rename `detect_arch_and_version()` to `detect_arch_from_config()`
- Look for `CONFIG_X86_32` and `CONFIG_X86_64` when detecting `x86` sub architecture
- Restrict the accepted `-a <ARCHITECTURE>` values to those found in `SUPPORTED_ARCHS`

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-01-14 20:58](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/10#issuecomment-454158772):

Hello @tyhicks , thanks a lot for the follow-up! Let me propose some improvements.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-01-14 21:45](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/10#issuecomment-454173475):

@tyhicks , thanks for your work again!
Let me propose one more idea. What do you think about splitting [KSPP recommended settings](http://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings) onto 4 arch-specific configs in `./config_files/`?

#### <img src="https://avatars.githubusercontent.com/u/1051156?u=82b8caad104296ef90ffe2f5807dc34d82c31c2b&v=4" width="50">[tyhicks](https://github.com/tyhicks) commented at [2019-01-17 18:04](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/10#issuecomment-455270114):

Yes, I can add 4 arch-specific configs in `./config_files/`.

#### <img src="https://avatars.githubusercontent.com/u/1051156?u=82b8caad104296ef90ffe2f5807dc34d82c31c2b&v=4" width="50">[tyhicks](https://github.com/tyhicks) commented at [2019-01-17 23:44](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/10#issuecomment-455373860):

I've rebased on top of your current tree, fixed up a few things, added what I think you were asking for in the arch-specific KSPP files, and force pushed to this branch.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-01-18 12:12](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/10#issuecomment-455526516):

Ouch. 
@tyhicks , excuse me please!
I've made a code review 3 days ago, but didn't hit "submit" button, so it is "pending" :(
I've just realized that you haven't seen my review when I looked at your rebased branch.
My fault.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-01-18 13:01](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/10#issuecomment-455538355):

If you don't have time/desire, I can pick up your branch and polish it myself.
Thank you again!

#### <img src="https://avatars.githubusercontent.com/u/1051156?u=82b8caad104296ef90ffe2f5807dc34d82c31c2b&v=4" width="50">[tyhicks](https://github.com/tyhicks) commented at [2019-01-18 23:16](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/10#issuecomment-455718260):

> If you don't have time/desire, I can pick up your branch and polish it myself.

I won't mind if you do the polishing yourself.

> Thank you again!

No problem. Thanks for all the review comments.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-01-24 08:02](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/10#issuecomment-457102717):

Hello @tyhicks ,

I've finished with arch support based on your work.
Do you like it?
Do you have any comments or requests?
Thanks!

#### <img src="https://avatars.githubusercontent.com/u/1051156?u=82b8caad104296ef90ffe2f5807dc34d82c31c2b&v=4" width="50">[tyhicks](https://github.com/tyhicks) commented at [2019-01-24 15:34](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/10#issuecomment-457240527):

Thanks for finishing out the work. It looks very good to me. I'll make use of the changes over the next week or so and submit new pull requests if I spot anything wrong/missing. Thanks again!


-------------------------------------------------------------------------------

# [\#9 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/9) `closed`: Teach the script about target architecture and kernel version

#### <img src="https://avatars.githubusercontent.com/u/1051156?u=82b8caad104296ef90ffe2f5807dc34d82c31c2b&v=4" width="50">[tyhicks](https://github.com/tyhicks) opened issue at [2019-01-12 00:16](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/9):

Some recommendations are dependent on the processor architecture and/or the kernel version. For example, the KSPP recommendations differ between [x86_32](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings#x86_32) and [x86_64](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings#x86_64). Additionally, option names change over time such as when `CONFIG_CC_STACKPROTECTOR_STRONG` was [renamed](https://kernsec.org/wiki/index.php?title=Kernel_Self_Protection_Project%2FRecommended_Settings&diff=3983&oldid=3976).

This pull request adds the ability to reason about the architecture and version when constructing the checklist. It also teaches the script about `x86_32`, `arm`, and `arm64` specific config recommendations.

#### <img src="https://avatars.githubusercontent.com/u/1051156?u=82b8caad104296ef90ffe2f5807dc34d82c31c2b&v=4" width="50">[tyhicks](https://github.com/tyhicks) commented at [2019-01-12 00:18](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/9#issuecomment-453698919):

I verified that all the example configs in `config_files/` show the same number of config check failures before and after these changes are applied. Of course, the ordering of the options are changed since the ordering used to construct the checklist has been changed.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-01-12 17:49](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/9#issuecomment-453767322):

Hello @tyhicks ,

Thank you very much for this pull request! Great!

I briefly looked through the patches and I would like to discuss the approach with you before we proceed.

1. Generally I like the way you introduce SUPPORTED_ARCHS. I also like that the script will have this '-a' argument, it's a good idea. I will look closer to this code.

2. It looks to me that introducing kernel versions will bring more troubles than profit.
In fact all these options have a special version when they appeared in the mainline. Some of them were renamed as well. So if we make the script aware of kernel versions, we will have to add full knowledge about them, but I don't think that it's useful.
IMO it's better to check the config against the recent mainline options and support renamed ones using the OR operator. If the user checks some old config with the script, we will print the errors for hardening options which appeared later, and it is nice. Maybe that will even encourage the user to update the kernel for getting these new hardening features.
What do you think?

May I ask you to extract arch support into a separate pull request? We will work further to merge it.

Thanks again for your time!

#### <img src="https://avatars.githubusercontent.com/u/1051156?u=82b8caad104296ef90ffe2f5807dc34d82c31c2b&v=4" width="50">[tyhicks](https://github.com/tyhicks) commented at [2019-01-12 19:48](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/9#issuecomment-453775979):

> Thank you very much for this pull request! Great!

Glad that you find it useful. I plan to use the script and these changes to audit all of the Ubuntu kernel configs and enable reasonable hardening options that aren't yet enabled.

> It looks to me that introducing kernel versions will bring more troubles than profit.
In fact all these options have a special version when they appeared in the mainline. Some of them were renamed as well. So if we make the script aware of kernel versions, we will have to add full knowledge about them, but I don't think that it's useful.
IMO it's better to check the config against the recent mainline options and support renamed ones using the OR operator. If the user checks some old config with the script, we will print the errors for hardening options which appeared later, and it is nice. Maybe that will even encourage the user to update the kernel for getting these new hardening features.
What do you think?

To be honest, I expected that you'd dislike the kernel version checking. I am on the fence about its usefulness, as well. It currently doesn't add much functionality on top of what `OR()` already provides. My long term thought was to extend minimum version checks to all the options (it really isn't too difficult to do that) so that I could then run the script on old Ubuntu kernel configs, such as the `3.13` kernel in Ubuntu 14.04 LTS, and get clean output that doesn't have a bunch of false negatives for that old kernel.

Maybe I'll just drop the version checking now and, in the future, propose some type of external overrides file that lets me ignore the false negatives when running against a given version of an old kernel. Additionally, this would let me specify overrides for certain options that we simply can't enable in a general purpose distro kernel.

> May I ask you to extract arch support into a separate pull request? We will work further to merge it.

Certainly. It might not happen today but I'll get a new PR up very soon.

#### <img src="https://avatars.githubusercontent.com/u/1051156?u=82b8caad104296ef90ffe2f5807dc34d82c31c2b&v=4" width="50">[tyhicks](https://github.com/tyhicks) commented at [2019-01-12 19:51](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/9#issuecomment-453776169):

@a13xp0p0v I have a slightly unrelated question about the script that I'll ask here since I mentioned using this script with our Ubuntu kernel configs. What does `ubuntu18` mean in the `decision` column of the script output? I assume that you're talking about Ubuntu 18.04 LTS but it feels like `kspp` should be used for nearly all of those rows instead of `ubuntu18` as I consider the KSPP project as the "upstream" that makes these recommendations.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-01-13 08:03](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/9#issuecomment-453810119):

> Glad that you find it useful. I plan to use the script and these changes to audit all of the Ubuntu kernel configs and enable reasonable hardening options that aren't yet enabled.

Nice. I want this script to serve all your needs out of the box.

> To be honest, I expected that you'd dislike the kernel version checking. I am on the fence about its usefulness, as well. It currently doesn't add much functionality on top of what `OR()` already provides. My long term thought was to extend minimum version checks to all the options (it really isn't too difficult to do that) so that I could then run the script on old Ubuntu kernel configs, such as the `3.13` kernel in Ubuntu 14.04 LTS, and get clean output that doesn't have a bunch of false negatives for that old kernel.

Ok, I see. In other words we need some functionality for categorizing and muting script errors, right?

I face a similar task as well and currently I solve it manually:
1. check some kernel config using the script;
2. copy errors from the report to a separate file and annotate each error. Examples:
    - this option doesn't exist in that old kernel version,
    - enabling/disabling this option breaks the user requirement (e.g. some users need HIBERNATION),
    - enabling/disabling this option breaks some code (e.g. enabling STATIC_USERMODEHELPER breaks systemd workflow on Ubuntu 18),
    - this option is not enabled since the feature is controlled via kernel command line param (e.g. CONFIG_LEGACY_VSYSCALL_NONE is not set, but the kernel command line has vsyscall=none),
    - and finally some errors are marked with TODO.

> Maybe I'll just drop the version checking now and, in the future, propose some type of external overrides file that lets me ignore the false negatives when running against a given version of an old kernel. Additionally, this would let me specify overrides for certain options that we simply can't enable in a general purpose distro kernel.

Yes, let's create that!

I see two approaches:
  - Support the formatted comments in the kernel config. The script will parse them and mute/annotate the errors in its report.
  - Support formatted annotations in a separate file. We will run `./kconfig-hardened-check.py -c config -a annotations` and have a pretty report.

What do you think?

> > May I ask you to extract arch support into a separate pull request? We will work further to merge it.
> 
> Certainly. It might not happen today but I'll get a new PR up very soon.

Thank you! Take your time, we are not in a hurry.

> I have a slightly unrelated question about the script that I'll ask here since I mentioned using this script with our Ubuntu kernel configs. What does ubuntu18 mean in the decision column of the script output? I assume that you're talking about Ubuntu 18.04 LTS but it feels like kspp should be used for nearly all of those rows instead of ubuntu18 as I consider the KSPP project as the "upstream" that makes these recommendations.

The `decision` column helps me to maintain the list of recommendations.

The values in `decision` column have this "rank" for me:
  1. ubuntu18
  2. kspp
  3. grsecurity and lockdown
  4. my

So I use:
  - `ubuntu18` for hardening recommendations already adopted by Ubuntu 18.04 LTS,
  - `kspp` for hardening recommendations that are listed in KSPP recommended settings but __not__ adopted by Ubuntu 18.04 LTS,
  - `grsecurity` for `cut_attack_surface` recommendations from their patch which are __not__ in KSPP recommended settings list,
  - `lockdown` for `cut_attack_surface` functionality from the lockdown patch series which is __not__ mentioned in KSPP recommended settings list,
  - `my` for hardening recommendations which I consider reasonable, but others don't mention.

Thanks for your question, I think I should document that in the README.

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2019-01-13 12:31](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/9#issuecomment-453825869):

@a13xp0p0v isn't better to make `kspp` as base for recommendations instead of `ubuntu18`? As @tyhicks mentioned the current order takes it backwards . The alternative would be to use `defconfig` here. I understand that `ubuntu18` is your personal choice but it's highly opinioniated.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2019-01-14 13:35](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/9#issuecomment-454006535):

@Bernhard40 , thanks for a reasonable comment. I will use `defconfig` as the basis.

#### <img src="https://avatars.githubusercontent.com/u/1051156?u=82b8caad104296ef90ffe2f5807dc34d82c31c2b&v=4" width="50">[tyhicks](https://github.com/tyhicks) commented at [2019-01-14 19:38](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/9#issuecomment-454133942):

Closing this pull request in favor of #10


-------------------------------------------------------------------------------

# [\#8 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/8) `closed`: couldn't mount to /sysroot after compile kernel with KSPP options.

#### <img src="https://avatars.githubusercontent.com/u/3471772?u=8db711eeb856b86264fa6d1e6887577d76af09ad&v=4" width="50">[bryn1u](https://github.com/bryn1u) opened issue at [2018-12-17 15:33](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/8):

Hello Alexander,

After kernel compilation im getting issue "unknow filesystem type ext4", "Failed to mount /sysroot"
I was wondering which KSSP feature could be responsible for it ? I was trying many times and always getting the same issue as i mentioned. Sceenshot 
https://www.centos.org/forums/download/file.php?id=2571
It looks like my initramfs doesn't have the kernel module for ext4 but why.

Im using Centos 7 with gcc 7.2

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-12-18 11:55](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/8#issuecomment-448195919):

Hello @bryn1u ,

I don't know the reason of such behavior on Centos.
Distros can have various issues because of the kernel hardening options, for example systemd on Ubuntu-18 has troubles with kernel modules unloading because of CONFIG_STATIC_USERMODEHELPER.

It would be great if you find the reason and share the result.
I would recommend you to use binary search to do it faster.

#### <img src="https://avatars.githubusercontent.com/u/3471772?u=8db711eeb856b86264fa6d1e6887577d76af09ad&v=4" width="50">[bryn1u](https://github.com/bryn1u) commented at [2018-12-18 22:12](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/8#issuecomment-448390343):

Hey,

I checked many options and recompiled kernel many times to find some answers, but it looks like everything works like a charm. I was doing everything based on Centos 7 with devtoolset-7 enabled to get never version of gcc like 7.2.  With CONFIG_SECURITY_LOADPIN  enabled im not able to load any module and getting "operation not permitted". Im guessing it's supposed to be like that. 
@a13xp0p0v 
Don't you know if ubuntu developers will enable KSPP options to the ubuntu kernel ? Or only manual compilation is available to get more security features ?
Thanks !

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-12-19 11:57](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/8#issuecomment-448569306):

> With CONFIG_SECURITY_LOADPIN enabled im not able to load any module and getting "operation not permitted". Im guessing it's supposed to be like that.

Thanks for information!

That's the description of CONFIG_SECURITY_LOADPIN:
`Any files read through the kernel file reading interface (kernel modules, firmware, kexec images, security policy) can be pinned to the first filesystem used for loading. When enabled, any files that come from other filesystems will be rejected.`

I guess in your case the first modules are loaded from the ramdisk, and later loading from root filesystem fails.

>Don't you know if ubuntu developers will enable KSPP options to the ubuntu kernel ? Or only manual compilation is available to get more security features ?

It's slow but steady process. More and more kernel hardening options are enabled by distros.

#### <img src="https://avatars.githubusercontent.com/u/3471772?u=8db711eeb856b86264fa6d1e6887577d76af09ad&v=4" width="50">[bryn1u](https://github.com/bryn1u) commented at [2018-12-22 12:38](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/8#issuecomment-449567219):

Hello
I have a weir problem. After successfully compiled kernel i can't use iptables:

> 
> [root@localhost ~]# iptables -L
> iptables v1.4.21: can't initialize iptables table `filter': Table does not exist (do you need to insmod?)
> Perhaps iptables or your kernel needs to be upgraded.

What am i doing wrong ?

Kernel KSSP options:

```
option name                            | desired val | decision |       reason       ||        check result        
  ===================================================================================================================
  CONFIG_BUG                             |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_PAGE_TABLE_ISOLATION            |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_RETPOLINE                       |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_X86_64                          |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_X86_SMAP                        |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_X86_INTEL_UMIP                  |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_STRICT_KERNEL_RWX               |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_DEBUG_WX                        |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_RANDOMIZE_BASE                  |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_RANDOMIZE_MEMORY                |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_STACKPROTECTOR_STRONG           |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_VMAP_STACK                      |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_THREAD_INFO_IN_TASK             |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_SCHED_STACK_END_CHECK           |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_SLUB_DEBUG                      |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_SLAB_FREELIST_HARDENED          |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_SLAB_FREELIST_RANDOM            |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_HARDENED_USERCOPY               |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_FORTIFY_SOURCE                  |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_LOCK_DOWN_KERNEL                |      y      | ubuntu18 |  self_protection   ||      FAIL: not found       
  CONFIG_STRICT_MODULE_RWX               |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_MODULE_SIG                      |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_MODULE_SIG_ALL                  |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_MODULE_SIG_SHA512               |      y      | ubuntu18 |  self_protection   ||     FAIL: "is not set"     
  CONFIG_SYN_COOKIES                     |      y      | ubuntu18 |  self_protection   ||             OK             
  CONFIG_DEFAULT_MMAP_MIN_ADDR           |    65536    | ubuntu18 |  self_protection   ||             OK             
  CONFIG_BUG_ON_DATA_CORRUPTION          |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_PAGE_POISONING                  |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_GCC_PLUGINS                     |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_GCC_PLUGIN_RANDSTRUCT           |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_GCC_PLUGIN_STRUCTLEAK           |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_GCC_PLUGIN_LATENT_ENTROPY       |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_REFCOUNT_FULL                   |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_DEBUG_LIST                      |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_DEBUG_SG                        |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_DEBUG_CREDENTIALS               |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_DEBUG_NOTIFIERS                 |      y      |   kspp   |  self_protection   ||             OK             
  CONFIG_MODULE_SIG_FORCE                |      y      |   kspp   |  self_protection   ||     FAIL: "is not set"     
  CONFIG_HARDENED_USERCOPY_FALLBACK      | is not set  |   kspp   |  self_protection   ||         FAIL: "y"          
  CONFIG_GCC_PLUGIN_STACKLEAK            |      y      |    my    |  self_protection   ||      FAIL: not found       
  CONFIG_SLUB_DEBUG_ON                   |      y      |    my    |  self_protection   ||             OK             
  CONFIG_SECURITY_DMESG_RESTRICT         |      y      |    my    |  self_protection   ||             OK             
  CONFIG_STATIC_USERMODEHELPER           |      y      |    my    |  self_protection   ||             OK             
  CONFIG_SECURITY_LOADPIN                |      y      |    my    |  self_protection   ||     FAIL: "is not set"     
  CONFIG_PAGE_POISONING_NO_SANITY        | is not set  |    my    |  self_protection   ||             OK             
  CONFIG_PAGE_POISONING_ZERO             | is not set  |    my    |  self_protection   ||             OK             
  CONFIG_SLAB_MERGE_DEFAULT              | is not set  |    my    |  self_protection   ||             OK             
  CONFIG_SECURITY                        |      y      | ubuntu18 |  security_policy   ||             OK             
  CONFIG_SECURITY_YAMA                   |      y      | ubuntu18 |  security_policy   ||             OK             
  CONFIG_SECURITY_SELINUX_DISABLE        | is not set  | ubuntu18 |  security_policy   ||             OK             
  CONFIG_SECCOMP                         |      y      | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_SECCOMP_FILTER                  |      y      | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_STRICT_DEVMEM                   |      y      | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_ACPI_CUSTOM_METHOD              | is not set  | ubuntu18 | cut_attack_surface ||         FAIL: "m"          
  CONFIG_COMPAT_BRK                      | is not set  | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_DEVKMEM                         | is not set  | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_COMPAT_VDSO                     | is not set  | ubuntu18 | cut_attack_surface ||       OK: not found        
  CONFIG_X86_PTDUMP                      | is not set  | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_ZSMALLOC_STAT                   | is not set  | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_PAGE_OWNER                      | is not set  | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_DEBUG_KMEMLEAK                  | is not set  | ubuntu18 | cut_attack_surface ||             OK             
  CONFIG_BINFMT_AOUT                     | is not set  | ubuntu18 | cut_attack_surface ||       OK: not found        
  CONFIG_MMIOTRACE_TEST                  | is not set  | ubuntu18 | cut_attack_surface ||       OK: not found        
  CONFIG_IO_STRICT_DEVMEM                |      y      |   kspp   | cut_attack_surface ||             OK             
  CONFIG_LEGACY_VSYSCALL_NONE            |      y      |   kspp   | cut_attack_surface ||             OK             
  CONFIG_BINFMT_MISC                     | is not set  |   kspp   | cut_attack_surface ||         FAIL: "m"          
  CONFIG_INET_DIAG                       | is not set  |   kspp   | cut_attack_surface ||         FAIL: "m"          
  CONFIG_KEXEC                           | is not set  |   kspp   | cut_attack_surface ||             OK             
  CONFIG_PROC_KCORE                      | is not set  |   kspp   | cut_attack_surface ||             OK             
  CONFIG_LEGACY_PTYS                     | is not set  |   kspp   | cut_attack_surface ||             OK             
  CONFIG_IA32_EMULATION                  | is not set  |   kspp   | cut_attack_surface ||             OK             
  CONFIG_X86_X32                         | is not set  |   kspp   | cut_attack_surface ||             OK             
  CONFIG_MODIFY_LDT_SYSCALL              | is not set  |   kspp   | cut_attack_surface ||         FAIL: "y"          
  CONFIG_HIBERNATION                     | is not set  |   kspp   | cut_attack_surface ||             OK             
  CONFIG_KPROBES                         | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"          
  CONFIG_UPROBES                         | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"          
  CONFIG_GENERIC_TRACER                  | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"          
  CONFIG_PROC_VMCORE                     | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"          
  CONFIG_PROC_PAGE_MONITOR               | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"          
  CONFIG_USELIB                          | is not set  |grsecurity| cut_attack_surface ||             OK             
  CONFIG_CHECKPOINT_RESTORE              | is not set  |grsecurity| cut_attack_surface ||             OK             
  CONFIG_USERFAULTFD                     | is not set  |grsecurity| cut_attack_surface ||             OK             
  CONFIG_HWPOISON_INJECT                 | is not set  |grsecurity| cut_attack_surface ||             OK             
  CONFIG_MEM_SOFT_DIRTY                  | is not set  |grsecurity| cut_attack_surface ||       OK: not found        
  CONFIG_DEVPORT                         | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"          
  CONFIG_DEBUG_FS                        | is not set  |grsecurity| cut_attack_surface ||         FAIL: "y"          
  CONFIG_NOTIFIER_ERROR_INJECTION        | is not set  |grsecurity| cut_attack_surface ||             OK             
  CONFIG_ACPI_TABLE_UPGRADE              | is not set  | lockdown | cut_attack_surface ||         FAIL: "y"          
  CONFIG_ACPI_APEI_EINJ                  | is not set  | lockdown | cut_attack_surface ||         FAIL: "m"          
  CONFIG_PROFILING                       | is not set  | lockdown | cut_attack_surface ||         FAIL: "y"          
  CONFIG_BPF_SYSCALL                     | is not set  | lockdown | cut_attack_surface ||         FAIL: "y"          
  CONFIG_MMIOTRACE                       | is not set  |    my    | cut_attack_surface ||             OK             
  CONFIG_KEXEC_FILE                      | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_LIVEPATCH                       | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_USER_NS                         | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_IP_DCCP                         | is not set  |    my    | cut_attack_surface ||         FAIL: "m"          
  CONFIG_IP_SCTP                         | is not set  |    my    | cut_attack_surface ||         FAIL: "m"          
  CONFIG_FTRACE                          | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_BPF_JIT                         | is not set  |    my    | cut_attack_surface ||         FAIL: "y"          
  CONFIG_ARCH_MMAP_RND_BITS              |     32      |    my    |userspace_protection||         FAIL: "28"         

[-] config check is NOT PASSED: 29 errors

```

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-12-25 12:27](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/8#issuecomment-449846419):

Hello @bryn1u ,
The error message which you posted makes me think that your issue is about kernel modules loading.
I would recommend you to look at the kernel log for more information and bisect again to find the reason.


-------------------------------------------------------------------------------

# [\#7 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/7) `closed`: Removing security features during kernel compilation.

#### <img src="https://avatars.githubusercontent.com/u/3471772?u=8db711eeb856b86264fa6d1e6887577d76af09ad&v=4" width="50">[bryn1u](https://github.com/bryn1u) opened issue at [2018-12-05 13:21](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/7):

Hey,

Im trying do my best with security options based on your script. I have a litte problems with few options. 

When im adding these options:
```
# Enable GCC Plugins
CONFIG_GCC_PLUGINS=y

# Gather additional entropy at boot time for systems that may not have appropriate entropy sources.
CONFIG_GCC_PLUGIN_LATENT_ENTROPY=y

# Force all structures to be initialized before they are passed to other functions.
CONFIG_GCC_PLUGIN_STRUCTLEAK=y
CONFIG_GCC_PLUGIN_STRUCTLEAK_BYREF_ALL=y

# Randomize the layout of system structures. This may have dramatic performance impact, so
# use with caution or also use CONFIG_GCC_PLUGIN_RANDSTRUCT_PERFORMANCE=y
CONFIG_GCC_PLUGIN_RANDSTRUCT=y
```
And make a "make -j 8 deb-pkg" on ubuntu or "make -j8 bzImage ...." on centos, these options are removing immediately from ".config" in kernel-4.19.6 . I have no idea what's going on. Could you tell me what am i doing wrong ?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-12-05 21:08](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/7#issuecomment-444648549):

Hello @bryn1u ,

Kconfig disables these options automatically because your gcc doesn't support plugins.
If you have gcc-7 on Ubuntu, try to install gcc-7-plugin-dev package. It should help.

And thanks for your question. I'll add this information to README.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-12-05 21:31](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/7#issuecomment-444656696):

Added 478e5f266df05b5f75badef59914c8b0e71e3e0e

#### <img src="https://avatars.githubusercontent.com/u/3471772?u=8db711eeb856b86264fa6d1e6887577d76af09ad&v=4" width="50">[bryn1u](https://github.com/bryn1u) commented at [2018-12-06 21:08](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/7#issuecomment-445030219):

Hello,

Now it works :) thanks ! I have one question about CONFIG_GCC_PLUGIN_STACKLEAK . This is the one option which is removing during compilation. Is it any way to enable it or isn't it available in kernel-4.19.7 yet ?
Thanks again :)

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-12-07 06:59](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/7#issuecomment-445141837):

Yes, CONFIG_GCC_PLUGIN_STACKLEAK will be available in Linux 4.20.


-------------------------------------------------------------------------------

# [\#6 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/6) `closed`: Removed long lines on output + minor fix

#### <img src="https://avatars.githubusercontent.com/u/7037785?u=6ac77234884c153e7fd38e3732be16d9760509ea&v=4" width="50">[c0rv4x](https://github.com/c0rv4x) opened issue at [2018-07-30 14:38](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/6):

I removed long lines from `print` and `format` functions.
Also i edited function `get_option_state` now uses `dict.get` method to extract a key from dict with default value 

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-07-30 20:09](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/6#issuecomment-408993713):

Applied!
Thank you @iad42 !


-------------------------------------------------------------------------------

# [\#5 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/5) `closed`: Oop refactoring

#### <img src="https://avatars.githubusercontent.com/u/7037785?u=6ac77234884c153e7fd38e3732be16d9760509ea&v=4" width="50">[c0rv4x](https://github.com/c0rv4x) opened issue at [2018-07-28 21:49](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/5):

Made the program a liitle bit more OOP.

I created a UserConfig class to store the state of the user's config.
Outputter class is responsible for outputting major results (however, not all the prints are there)
OR and OptConifg were moved to a separate file
Checklist got its own class with a method `check(config)` that performs all the checks from the checklist against user's config

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-07-30 09:43](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/5#issuecomment-408807705):

The last commit adds a ```__pycache__``` directory with bython bytecode cache files, that commit should be amended

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-07-30 09:50](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/5#issuecomment-408809392):

Cool that you invest time with this, but personally speaking I'm bit mixed here what the justification/gain is to introduce the complexity and split other then "but oop and modules". Right now it's quite handy to just have the whole thing in a single file that could be copied to /usr/bin dir f.e. and I don't think its expected that lots lots lots of additional modules and python functions are needed beyond this.

Otherwise, if the project goes the path to make it more modular, then it should at least also have setup.py dist file (you may want to add one) so it can actually be distributed and used properly as a module and by distros for packaging python.

My 2 cents is that a single file isn't too bad after considering the current scope and content

#### <img src="https://avatars.githubusercontent.com/u/7037785?u=6ac77234884c153e7fd38e3732be16d9760509ea&v=4" width="50">[c0rv4x](https://github.com/c0rv4x) commented at [2018-07-30 10:36](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/5#issuecomment-408821023):

You are right about `__pycache__`, that is my fault.

As for sticking to a single file, i clearly see your point and agree with you. However, OOP style is obviously easier to extend and easier to read. As long as the author (a13xp0p0v) is expecting the tool to grow, i consider that we should stick to an easier form of code in terms of adding code rather that terms of easy-to-run. 

Also, thanks for the note on setup.py file, i will surely fix that problem!

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-07-30 10:42](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/5#issuecomment-408822137):

Hello @iad42 and @anthraxx ,

Yes, Anatoly, thanks for your time! Your PR made me review the script and gave some new ideas.
I see now what we can improve:
 1. currently parsing config file, filling 'OptCheck.state' values in 'checklist' and performing actual checks all mixed in check_config_file(). It would be nice to split them. What approaches do you see?
 2. there are two global vars now: 'checklist' and 'debug_mode'. I see that some of design drawbacks are connected with that fact. It would be cool to get rid of them during the refactoring.
 3. the script is quite small now, I like that all the functionality stays in a single file.
 4. @iad42 , I like how you cut the long lines in printing the output. I want to merge it. Can you put the final ')' on the second line, like that:
```
print('  CONFIG_{:<32}|{:^13}|{:^10}|{:^20}||{:^28}'.format(
            opt.name, opt.expected, opt.decision, opt.reason, opt.result))
```

Thanks!

#### <img src="https://avatars.githubusercontent.com/u/7037785?u=6ac77234884c153e7fd38e3732be16d9760509ea&v=4" width="50">[c0rv4x](https://github.com/c0rv4x) commented at [2018-07-30 14:39](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/5#issuecomment-408886952):

@a13xp0p0v 

I created a separate pull request https://github.com/a13xp0p0v/kconfig-hardened-check/pull/6 for the 4th bullet point on your list. Also i added a tiny fix for working with dict


-------------------------------------------------------------------------------

# [\#4 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4) `closed`: Add more config files

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) opened issue at [2018-07-20 20:31](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4):

Hello @a13xp0p0v,

Just like I promised.

Best regards.

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2018-07-23 19:03](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4#issuecomment-407166514):

Don't we overdo with the number of configs here? This project allows everyone for checking any config they want themselves so what is the point of storing them here? One or two as example is enough. Most of them will be outdated sooner or later anyway.

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-07-23 19:18](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4#issuecomment-407170808):

Yeah I agree, also they are outdated quite fast and who maintains the configs?
To compare and test stuff, it would make sense to have a small amount of general purpose configs like ubuntu, debian and have some hardened examples like kspp, archlinux-hardened and others. I don't think it is or should be the scope of the project to collect them all

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2018-07-24 12:11](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4#issuecomment-407384626):

Hello,

Allow me first of all to take stock of the results:

**pentoo-hardened-2018.0rc7.config** = **30 errors** (config of iso image)
**Archlinux-hardened.config** = 33 errors (config available via **gitweb**)
Qubes-latest.config = 38 errors (config of linux package)
**Alpinelinux-edge.config** = 44 errors (config available via **gitweb**)
Fedora-Rawhide.config = 48 errors (config of linux package)
**Archlinux-Testing.config** = 49 errors (config available via **gitweb**)
debian-sid-amd64.config = 49 errors (config of linux package)
Kali-linux.config = 49 errors (config of linux package)
Owl-3.1config = 50 errors (config of linux package)
Parrot-security-4.1.config = 52 errors (config of linux package)
ubuntu-bionic-generic.config = 52 errors (config of linux package)
**oracle-uek5.config** = 54 errors (config available via **gitweb**)
Mageia-cauldron.config = 57 errors (config of linux package)
**SLE15.config** = 58 errors (config available via **gitweb**)
**Opensuse-git.config** = 62 errors (config available via **gitweb**)
Trisquel-Flidas.config = 63 errors (config of linux package)

All config available via **gitweb** are easy to maintain with a bash script.
Then for some I didn't use the stable branch but the development branch to have an up-to-date config.

So I lets @a13xp0p0v choose what he prefers.

But I wish in any case to maintain pentoo-hardened in view of its result :smiley:

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-07-24 23:06](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4#issuecomment-407580227):

Hello @HacKurx @anthraxx @Bernhard40 ,

Yes, we don't have a goal to collect all the configs and update them.
At the same time I appreciate @HacKurx efforts.

So what do you think about this solution:
1. drop the configs of minor distributions (Owl-3.1config, Kali-linux.config, Parrot-security-4.1.config, Mageia-cauldron.config, Trisquel-Flidas.config);
2. add the concrete release/version to the config file names ("sid" and "rawhide" are bad version names since they just mean "unstable", right?);
3. add a links.txt with the available links to the configs.

Does it sound reasonable to you?

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2018-07-25 11:41](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4#issuecomment-407725269):

Yeah, keeping well know distros and non-rolling release kernels make sense.

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2018-07-25 19:28](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4#issuecomment-407868315):

Hello @a13xp0p0v ,

> Does it sound reasonable to you?

Yeah, okay, I'll take care of it.

@Bernhard40 

> Yeah, keeping well know distros and non-rolling release kernels make sense.

I know, but for old kernels we need use more OR class. Example: CONFIG_DEBUG_SET_MODULE_RONX, CONFIG_DEBUG_KERNEL, CONFIG_DEBUG_RODATA.

In addition certain points must be corrected, as for example the recommendation "CONFIG_LKDTM" is impossible to respect without breaking the recommendation of Grsecurity on DEBUG_FS.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-07-27 21:29](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4#issuecomment-408543338):

Hello @HacKurx , thanks for your work.

1. I've commented out the LKDTM rule. You are right about it.

2. I'll check what we can do about CONFIG_DEBUG_SET_MODULE_RONX, CONFIG_DEBUG_KERNEL, CONFIG_DEBUG_RODATA. 

3. I've merged some of your commits, so now 'config' directory has: 
 -  Alpinelinux-edge.config (I want to keep it)
 -  Archlinux-hardened.config (ditto)
 -  debian-stretch.config
 -  oracle-uek5.config
 -  SLE15.config
 -  ubuntu-bionic-generic.config

May I ask you to do a bit more work to make it excellent?
 - could you check the links for Alpine Linux in your links.txt? They both give similar result.
 - could you find links for debian-stretch and ubuntu-bionic configs?
 - could you add configs for some stable versions of Pentoo Hardened and openSUSE?
If so, in the result we will have some consistence between links.txt and config files.

Thank you a lot!

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2018-07-28 06:57](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4#issuecomment-408587814):

Hello @a13xp0p0v ,

> could you check the links for Alpine Linux in your links.txt? They both give similar result.

Because the edge version currently uses the same kernel as the stable 3.8 version.

> could you find links for debian-stretch and ubuntu-bionic configs?

Not sure, but I'll look.

> could you add configs for some stable versions of Pentoo Hardened and openSUSE?

Yes of course the links are in the file.

I'll take care of it soon.
Thank you too. Best regards.

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2018-08-01 21:45](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4#issuecomment-409734659):

Hello @a13xp0p0v ,

> I'll check what we can do about CONFIG_DEBUG_SET_MODULE_RONX, CONFIG_DEBUG_KERNEL, CONFIG_DEBUG_RODATA.

Thank you, I just saw your changes regarding that. If you want to be thorough then you should also do the same for :
```
PAGE_TABLE_ISOLATION             = PAX_PER_CPU_PGD, MEMORY_UDEREF_MELTDOWN
RANDOMIZE_BASE, RANDOMIZE_MEMORY = PAX_ASLR
HARDENED_USERCOPY                = PAX_USERCOPY
GCC_PLUGIN_RANDSTRUCT            = GRKERNSEC_RANDSTRUCT
GCC_PLUGIN_STRUCTLEAK            = PAX_MEMORY_STRUCTLEAK
GCC_PLUGIN_STRUCTLEAK_BYREF_ALL  = PAX_MEMORY_STRUCTLEAK ?
GCC_PLUGIN_LATENT_ENTROPY        = PAX_LATENT_ENTROPY
REFCOUNT_FULL                    = PAX_REFCOUNT
GCC_PLUGIN_STACKLEAK             = PAX_MEMORY_STACKLEAK
SECURITY_YAMA                    = GRKERNSEC
```

It's be a good friendly gesture.

I'm still looking for some points and I'm quite busy but I always take care of them.

Regards.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-08-03 20:52](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4#issuecomment-410373163):

Hi @HacKurx ,

> PAGE_TABLE_ISOLATION             = PAX_PER_CPU_PGD, MEMORY_UDEREF_MELTDOWN

Umm... Where can I learn more about these options?

> RANDOMIZE_BASE, RANDOMIZE_MEMORY = PAX_ASLR

No, I'm absolutely sure that KASLR != PAX_ASLR.

> HARDENED_USERCOPY                = PAX_USERCOPY
> GCC_PLUGIN_RANDSTRUCT            = GRKERNSEC_RANDSTRUCT
> GCC_PLUGIN_STRUCTLEAK            = PAX_MEMORY_STRUCTLEAK
> GCC_PLUGIN_STRUCTLEAK_BYREF_ALL  = PAX_MEMORY_STRUCTLEAK ?
> GCC_PLUGIN_LATENT_ENTROPY        = PAX_LATENT_ENTROPY
> REFCOUNT_FULL                    = PAX_REFCOUNT
> GCC_PLUGIN_STACKLEAK             = PAX_MEMORY_STACKLEAK

Have you seen my Linux Kernel Defence Map?
https://github.com/a13xp0p0v/linux-kernel-defence-map
Please have a look, I've displayed the origins of these features (and praised grsecurity) in that map.

> SECURITY_YAMA                    = GRKERNSEC

Excuse me, I don't see the connection between these options. Can you share more details?

Thank you!

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2018-08-04 14:56](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4#issuecomment-410455183):

Hi @a13xp0p0v ,

> Umm... Where can I learn more about these options?

```
 config PAGE_TABLE_ISOLATION
        bool "Remove the kernel mapping in user mode"
        default y
-       depends on X86_64 && SMP
+       depends on X86_64 && SMP && !PAX_PER_CPU_PGD && BROKEN
        help
          This enforces a strict kernel and user space isolation, in order
          to close hardware side channels on kernel address information.
```

and 

```
+config PAX_MEMORY_UDEREF_MELTDOWN
+       bool "Prevent i386 Meltdown attacks (READ HELP!)"
+       default n
+       depends on X86_32 && PAX_MEMORY_UDEREF
+       help
+         By saying Y here, UDEREF will be enhanced to fully close off
+         Meltdown attacks against the kernel.  This will prevent the
+         creation of expand-down segments and will limit all TLS segments
+         to the end of the userland address space.
...
```
If you want to know more, you just have to convince a large company (google? microsoft ^^) to finance their research in a public way :innocent:

> No, I'm absolutely sure that KASLR != PAX_ASLR.

Oops I confused PAX_RANDUSTACK(depends on PAX_ASLR) and PAX_RANDKSTACK.

> Excuse me, I don't see the connection between these options. Can you share more details?

```
 config SECURITY_YAMA
        bool "Yama support"
-       depends on SECURITY
+       depends on SECURITY && !GRKERNSEC
        default n
```

Because not compatible.

> Have you seen my Linux Kernel Defence Map?

Great ! I'll look into it.

For the rest I couldn't find a link for the complete debian and ubuntu configurations. The reason is that the files are generated automatically:
https://salsa.debian.org/kernel-team/linux/tree/master/debian/config
https://salsa.debian.org/kernel-team/linux/raw/master/debian/config/amd64/config

What about CRYPTO_SPECK, what do you think?

Thanks you to again.

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2018-08-04 16:14](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4#issuecomment-410460070):

> If you want to know more, you just have to convince a large company (google? microsoft ^^) to finance their research in a public way 😇

So, until that happens there is no point for adding support for options which almost no one can use.

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2018-08-04 17:30](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4#issuecomment-410465146):

>  So, until that happens there is no point for adding support for options which almost no one can use.

So you want to create a false error to the persons who uses it?
KSPP's advances come from grsecurity don't forget it.
Besides the old versions are still a source of inspiration, right?

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2018-08-04 17:53](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4#issuecomment-410466573):

If someone uses grsecurity private code then they should seek support from grsecurity which they pay for, not from volunteers working for free.

Old versions are dead, nothing we can do about it.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-08-04 20:51](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4#issuecomment-410476855):

Hello @HacKurx and @Bernhard40 ,

Please don't start another holy war about grsecurity.
- Yes, Brad and PaX Team are genius.
- Yes, a lot of KSPP work is inspired by (and sometimes copied from) grsecurity. The map shows that fact explicitly.
- Yes, almost all the mainline kernel self protection features are not compatible with grsecurity (and even marked as BROKEN).

@HacKurx , it's great that you have access to the recent grsecurity patches, lucky you. 
I don't have it, and I guess they will never give it to me.
So I would like to focus on the mainline kconfig options. Moreover, grsecurity users really don't need this funny script at all.

Thanks for understanding.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-08-08 12:36](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4#issuecomment-411389774):

Hello @HacKurx ,

I've merged the rest of your PR with some fixes I previously mentioned.
Thank you very much.

Closing it now.

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2018-08-08 21:57](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/4#issuecomment-411565682):

Hello @a13xp0p0v ,

> it's great that you have access to the recent grsecurity patches

Well, not really. It's complicated... Let's just say that I have elements that you don't have and that out of respect I didn't publish them. Spender and Pipacs have always answered my questions which is not the case with Linus for example (at the terrorist attack in my country I asked him to rename the version name to "Pray for Paris") but he didn't even take the time to answer...

> So I would like to focus on the mainline kconfig options.

Ok no problem. Rest assured I am not here for divide. I do not forget that if we discuss together it is above all because we appreciate at security in linux ;)

> I've merged the rest of your PR with some fixes I previously mentioned.

Great, thank you. I haven't found much interesting since.

Best regards.


-------------------------------------------------------------------------------

# [\#3 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/3) `closed`: Add Grsecurity recommendation on BINFMT_AOUT

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) opened issue at [2018-07-18 18:52](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/3):

Hi,

Recommendation starting from grsecurity-2.2.0-2.6.32.22-201009241805.patch.
Sorry, Linux historical interest is not secure ;)

Sorry for the tabulations in my code :D

Regards,

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2018-07-18 19:14](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/3#issuecomment-406043222):

I'm curious, does anyone seen kernel with that option enabled in last 10 years?

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2018-07-18 19:49](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/3#issuecomment-406052730):

Today his is not the case but it is necessary to warn users better about the old code that is dangerous and that Linus will never want to delete.

Because otherwise I'm sure he's got geeks who'll activate him for fun...

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2018-07-18 20:13](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/3#issuecomment-406059551):

@Bernhard40 to be precise (extraction from linux-4.18-rc5) shows that it's still using a little. The equipment on ARM being more recent.

m68k/configs/mvme147_defconfig:CONFIG_BINFMT_AOUT=m
m68k/configs/apollo_defconfig:CONFIG_BINFMT_AOUT=m
m68k/configs/multi_defconfig:CONFIG_BINFMT_AOUT=m
m68k/configs/amiga_defconfig:CONFIG_BINFMT_AOUT=m
m68k/configs/bvme6000_defconfig:CONFIG_BINFMT_AOUT=m
m68k/configs/hp300_defconfig:CONFIG_BINFMT_AOUT=m
m68k/configs/atari_defconfig:CONFIG_BINFMT_AOUT=m
m68k/configs/q40_defconfig:CONFIG_BINFMT_AOUT=m
m68k/configs/mac_defconfig:CONFIG_BINFMT_AOUT=m
m68k/configs/sun3_defconfig:CONFIG_BINFMT_AOUT=m
m68k/configs/sun3x_defconfig:CONFIG_BINFMT_AOUT=m
m68k/configs/mvme16x_defconfig:CONFIG_BINFMT_AOUT=m

arm/configs/iop32x_defconfig:CONFIG_BINFMT_AOUT=y
arm/configs/badge4_defconfig:CONFIG_BINFMT_AOUT=m
arm/configs/corgi_defconfig:CONFIG_BINFMT_AOUT=m
arm/configs/neponset_defconfig:CONFIG_BINFMT_AOUT=y
arm/configs/imote2_defconfig:CONFIG_BINFMT_AOUT=m
arm/configs/lart_defconfig:CONFIG_BINFMT_AOUT=y
arm/configs/ebsa110_defconfig:CONFIG_BINFMT_AOUT=y
arm/configs/hackkit_defconfig:CONFIG_BINFMT_AOUT=y
arm/configs/ezx_defconfig:CONFIG_BINFMT_AOUT=m
arm/configs/jornada720_defconfig:CONFIG_BINFMT_AOUT=y
arm/configs/rpc_defconfig:CONFIG_BINFMT_AOUT=y
arm/configs/nuc960_defconfig:CONFIG_BINFMT_AOUT=y
arm/configs/nuc950_defconfig:CONFIG_BINFMT_AOUT=y
arm/configs/spitz_defconfig:CONFIG_BINFMT_AOUT=m
arm/configs/footbridge_defconfig:CONFIG_BINFMT_AOUT=y
arm/configs/netwinder_defconfig:CONFIG_BINFMT_AOUT=y
arm/configs/iop13xx_defconfig:CONFIG_BINFMT_AOUT=y
arm/configs/iop33x_defconfig:CONFIG_BINFMT_AOUT=y

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2018-07-19 19:02](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/3#issuecomment-406381446):

No thanks to you @a13xp0p0v 

I have corrected as requested, I hope it will suit you.
I've done everything since the github editor which explains the many commit.

Too bad kconfig is so limited with conditions because it would be nice to have a menu to choose its security level (basic, custom, paranoid) when configuring the linux kernel.

So I took my inspiration from grsec to make something simpler:
https://github.com/HacKurx/public-sharing/blob/master/disables_unsecured_options.patch

Thanks, best regards.

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-07-19 20:43](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/3#issuecomment-406408269):

@HacKurx btw, i have seen you added Arch Linux config: there is a hardened arch kernel as well with more protective options.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-07-19 21:08](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/3#issuecomment-406414918):

Hello @HacKurx,

Cool thanks, I'll merge it soon!

I only will not take dropping "not found" from OK status, since it is important information:
explicit "is not set" is different from the option absence in the config file, I want it to be displayed in the script output.

Thanks again!
Till soon.

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2018-07-20 11:56](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/3#issuecomment-406579032):

@anthraxx 
> there is a hardened arch kernel as well with more protective options.

Yes indeed. It's fixed.

@a13xp0p0v 

I will have fun adding main distributions config but it would be necessary to create a folder not to pollute it.
This will allow an easy comparison to be made.

What do you think of that?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-07-20 12:26](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/3#issuecomment-406585795):

Yes, moving configs into a separate directory is a good idea.

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2018-07-20 14:59](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/3#issuecomment-406627110):

It's done.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-07-20 18:10](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/3#issuecomment-406683275):

Hello @HacKurx,
Thanks for your work, it's merged (except "not found" dropping).
Nice!

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2018-07-20 18:54](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/3#issuecomment-406695869):

Thank you to you too.
I will complete the config_files folder because the results are very interesting :)

See you soon. Best regards,


-------------------------------------------------------------------------------

# [\#2 PR](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2) `closed`: Feature/improvements

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) opened issue at [2018-06-20 22:14](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2):

Improve the source to make it easier to iterate over options by making the checks and all kernel config options a dictionary. Additionally implement logical operator to support or conditional checks.

Refactor option parsing to use pythons argparse

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-06-20 22:16](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-398915150):

At the end lots of lines changed, please ask anything you want to suggest any changes you would like to see. Even through the changes look massive, I believe they will pay out and make some stuff easier to maintain and access for potential future features.

I'm happy to take any feedback :cat:

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-06-21 20:50](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-399239396):

Thank you very much for your time spent on that!
I like the ideas behind your changes and I want to merge them in the end.

Currently I have 2 concerns about the changes:
1. the commits are really big, I would like to split them. From the top of my head, we can split infrastructure changes from new checks, etc.
2. we should consider the case: MODULES or (MODULE_SIG and MODULE_SIG_ALL and MODULE_SIG_SHA512).

How much time would you like to spend on this? I don't have a right to ask you for more.
At least I see your ideas and I can split (and learn) the commits myself.

Thank you, again.

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-06-21 23:13](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-399271969):

All of this sounds reasonable to me! I already spent some time on this and I'm sure I may contribute in the future as well so I would be super happy to change the commits as long as it satisfies you!
I will split out the DEVMEM and STACKPROTECTOR changes and see if I can split at even more. Should be easy with rebase edit.

Latter case you described should easily be possible with an AND class that is like the OR class, everything else should work out of the box.

Cheers
Levente

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) commented at [2018-06-22 20:50](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-399578012):

Just FYI, in Linux 4.18 `CC_STACKPROTECTOR_STRONG` [was renamed](https://github.com/torvalds/linux/blob/v4.18-rc1/arch/Kconfig#L585) to `STACKPROTECTOR_STRONG` and `CC_STACKPROTECTOR_AUTO` is gone.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-06-25 16:27](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-400013145):

Thanks for the info, @Bernhard40. I'll update the STACKPROTECTOR config option when 4.18 is released.

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-06-25 22:47](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-400119687):

@a13xp0p0v I have splitted up the commits as much as made sense, can you please take a look? Really don't fear nitpicking, I'm used to do open-source :yum: 

PS: this also handles STACKPROTECTOR_STRONG by using the OR operator.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-06-26 21:26](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-400467818):

Thanks a lot for your work, @anthraxx !
I'll review this version in a couple of days.
Till soon.

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-07-09 18:23](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-403574284):

@a13xp0p0v round 2, fight! :cat:

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-07-14 09:00](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-405010041):

Well I personally don't think it's a good idea to parse and check one line separately and don't really see why It can't be a dict. Curious how you want to check AND and OR logic on other opts if the config it not fully parsed yet. Personally, parsing it yet again for such logic sounds like non optimal algorithm/approach to me.

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-07-14 09:02](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-405010151):

Why not just check for existence before assigning parsed_options[config] and call it a day?

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-07-14 20:05](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-405046688):

Ah, yes, I see.
You are right. AND & OR logic can't be implemented if we check the config file line by line.
Moreover, separating parsing the file and checks should be a good design solution.

So the first commit in the series is fine.
I would only ask to add the assertion to get_option_state() and call this function outside the Opt class method (just use the Opt.name from outside).
I would also ask to reorder the series:
  1. all arch changes and renaming;
  2. AND & OR;
  3. new rules.

If you have no time/motivation for that work, I will do it myself.

Thanks again, @anthraxx. I'm glad to have your attention to this project.

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-07-14 20:57](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-405049389):

Yay! No worries, I like to discuss solutions and opinions as collaborative work and exchange is much more effective!
I would be happy to make the changes as you requested, will push an update and rebased version very soon.
Cheers 🍻

#### <img src="https://avatars.githubusercontent.com/u/4661917?u=bb7aeb3c77839cea055b49b80168666b36315f3d&v=4" width="50">[theLOICofFRANCE](https://github.com/theLOICofFRANCE) commented at [2018-07-19 19:14](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-406384461):

I don't know if you're doing it, but CONFIG_ARCH_MMAP_RND_BITS should be replaced by: 
```
CONFIG_ARCH_MMAP_RND_BITS_MIN=28
CONFIG_ARCH_MMAP_RND_BITS_MAX=32
```

found in Linux kernels: 4.5–4.17, 4.18-rc+HEAD

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-07-19 20:44](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-406408491):

@HacKurx no, i really want to get this PR through finally. After that me, you or whoever can make that CONFIG_ARCH_MMAP_RND_BITS change.

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-07-19 20:48](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-406409433):

@a13xp0p0v I have made the adjustments you wanted to see:
- get_option_state is moved out of the class and assigned before checking
- reordered all commits (wow, this was quite some work >.>)

I really hope we can get this in soon, I'm still there to make any changes if you request some but quite a lot of time already went in to make you happy :cat: :cat:

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-07-19 20:56](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-406411723):

Hello @anthraxx 

Cool, thanks for your work, I'm going to do the review soon.
Yes, we've already spent plenty of time on that, because it's not so easy: this PR changes almost everything :)

Anyway, I like your ideas, they will be merged in the end.

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-07-19 20:58](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-406412140):

@a13xp0p0v Yay thanks, don't get me wrong I really like to work with you on this and i really enjoy it very much. Also I'm 100% on your side to get commits that make it into the tree proper, I just wanted to get that the rework conflicted a lot off my chest :smile:

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-07-19 21:15](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-406416764):

@a13xp0p0v just in case you already pulled my branch, please re-pull as there was a typo in the STACKPROTECTOR option, sorry. tested and reviewd every single commit independent from each other again

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-07-20 18:09](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-406683207):

Hello @anthraxx,

I've cherry-picked all your architecture improvements and added some minor fixes (please have a look).
You've done a great job, I appreciate it!

Now we are ready to merge your OR and AND support.
I have some questions, could you answer please?

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-07-21 08:12](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-406779757):

These are used to print the table and use the very first option of a logical class to represent the group by showing the first entries name and expected value

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-07-24 22:00](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-407566128):

Hello @anthraxx ,
Thanks for your explanation.
It took me some time to realize that self.opts[0] is the option which that OR-check is about.
I.e. OR class use case is: OR(<X_is_hardened>, <X_is_disabled>)

I've merged your OR class with my minor fixes.

I don't think that we need AND right now. Rationale: our config checks are already implicitly connected with AND; if any of them fails, the error count increments anyway. Do you agree?

I also have a question about your STACKPROTECTOR commit.
As I see in the kernel git history, the "CC_" prefix is dropped from both STACKPROTECTOR and STACKPROTECTOR_STRONG. So how about having:
```
-    checklist.append(OptCheck('CC_STACKPROTECTOR',       'y', 'ubuntu18', 'self_protection'))
-    checklist.append(OptCheck('CC_STACKPROTECTOR_STRONG','y', 'ubuntu18', 'self_protection'))
+    checklist.append(OR(OptCheck('CC_STACKPROTECTOR',    'y', 'ubuntu18', 'self_protection'), \
+                        OptCheck('STACKPROTECTOR',       'y', 'ubuntu18', 'self_protection')))
+    checklist.append(OR(OptCheck('CC_STACKPROTECTOR_STRONG','y', 'ubuntu18', 'self_protection'), \
+                        OptCheck('STACKPROTECTOR_STRONG','y', 'ubuntu18', 'self_protection')))
```

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-07-24 22:41](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-407575301):

@a13xp0p0v Hmm true, it is for >= 4.18 but for all kernels before 4.18 this would generate an error where non should be. Having CC_STACKPROTECTOR_STRONG without CC_STACKPROTECTOR is a totally correct setting pre 4.18 which would yield to an error.
Its shitty, but the more generally compatible way would be to combine the different "correct sets" with the logical class to just have a single checklist.append for STACKPROTECTOR

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-07-24 23:19](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-407582510):

And how about this?
```
-    checklist.append(OptCheck('CC_STACKPROTECTOR',       'y', 'ubuntu18', 'self_protection'))
-    checklist.append(OptCheck('CC_STACKPROTECTOR_STRONG','y', 'ubuntu18', 'self_protection'))
+    checklist.append(OR(OptCheck('CC_STACKPROTECTOR_STRONG','y', 'ubuntu18', 'self_protection'), \
+                        OptCheck('STACKPROTECTOR_STRONG','y', 'ubuntu18', 'self_protection')))
```

It fits your logic "be strong or fail".
At the same time it fits the case of old configs, where there is no CC_STACKPROTECTOR, right?

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-07-25 07:05](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-407655722):

yeah, i think that should work :smiley_cat:

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-07-25 11:45](https://github.com/a13xp0p0v/kernel-hardening-checker/pull/2#issuecomment-407726202):

Done with STACKPROTECTOR and MODULES.
@anthraxx we have finished with this pull request.
Thanks for your excellent work :thumbsup:


-------------------------------------------------------------------------------

# [\#1 Issue](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/1) `closed`: Couple ideas

#### <img src="https://avatars.githubusercontent.com/u/32568352?v=4" width="50">[Bernhard40](https://github.com/Bernhard40) opened issue at [2018-06-20 13:19](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/1):

Shouldn't [NAMESPACES](https://github.com/a13xp0p0v/kconfig-hardened-check/blob/master/kconfig-hardened-check.py#L94) be replaced by `USER_NS`? AFAIK only user namespaces have security concerns, others are fine. Disabling them all will negatively affect many applications which use various namespaces for sandboxing.

Since linux 4.16 there is `CC_STACKPROTECTOR_AUTO` kconfig which effectively replaces [CC_STACKPROTECTOR_STRONG](https://github.com/a13xp0p0v/kconfig-hardened-check/blob/master/kconfig-hardened-check.py#L54) and make it false negative in script.

Script doesn't check for [DEVMEM](https://github.com/a13xp0p0v/kconfig-hardened-check/blob/master/kspp-recommendations.config#L18) which when set to `n` make [STRICT_DEVMEM](https://github.com/a13xp0p0v/kconfig-hardened-check/blob/master/kconfig-hardened-check.py#L38) and [IO_STRICT_DEVMEM](https://github.com/a13xp0p0v/kconfig-hardened-check/blob/master/kconfig-hardened-check.py#L65) false negative.



#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-06-20 13:23](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/1#issuecomment-398746587):

I already nearly finished a PR for the DEVMEM and CC_STACKPROTECTOR_* case by adding context aware logic to the option checks.
Pull request incoming later today, it extends the options with logical operators like OR()

#### <img src="https://avatars.githubusercontent.com/u/203012?u=939d6d3b5ff0b9e46e911d8792a40c20408574e2&v=4" width="50">[anthraxx](https://github.com/anthraxx) commented at [2018-06-20 19:14](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/1#issuecomment-398864576):

@a13xp0p0v please no force push, that creates weird merge diffs when working on something :smile_cat:

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-06-20 20:43](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/1#issuecomment-398890140):

@Bernhard40 , thanks a lot for the ideas. I agree. Just fixed the namespaces mistake.
@anthraxx , thanks, cool! Waiting for your PR.
And, yes, no more force push from me.

#### <img src="https://avatars.githubusercontent.com/u/1419667?u=de82e29061c3ef5f1c19f95528f8a82b08051fd2&v=4" width="50">[a13xp0p0v](https://github.com/a13xp0p0v) commented at [2018-07-04 15:38](https://github.com/a13xp0p0v/kernel-hardening-checker/issues/1#issuecomment-402512111):

Closing, since @anthraxx PR will resolve it.


-------------------------------------------------------------------------------


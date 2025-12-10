+++
title = "How I solved a linux kernel memory leak bug"
date = 2025-12-09

[extra]
image = "thumb.png"
+++


As part of my [linux kernel mentorship program](https://mehdibenhadjkhelifa.github.io/posts/kernel-mentorship), We have to try and solve bugs reported by {% sidenote(ref="syzbot") %} syzbot is an automated fuzzing system that is one way of getting linux kernel bugs reported to the linux kernel community to fix {% end %}which is no easy feat for some unfamiliar folks that are just getting started to hack their ways into the kernel like myself. Nonetheless, that didn't stop me from trying as many bugs {% sidenote(ref="that didn't feel out of reach for me") %} mainly avoided kernel bugs that touch the core of any subsystem since those are for more experts of said subsystem which are more trusted by the maintainers to fix those issues.{% end %} as I can.

##  Why a memory leak bug?

Syzbot has many types of bugs that it reports. To note a few, it can report bugs triggered by the `BUG()` and `WARN()` family of macros used across the kernel,slab-use-after-free using the {%sidenote(ref="KASAN")%}Kernel Address Sanitizer {% end %}, uninit values using the {% sidenote(ref="KMSAN")%}Kernel Memory Sanitizer {% end %}, memory leaks with Kmemleak and many more. In the limited time that I had during the mentorship, I have attempted many types of bugs to try and deduce a pattern. Spoiler, there are no patterns (almost).But there is a {%sidenote(ref="degree of difficulty for each type")%}of course it also depends on the specific bug but this is a more of a generalized view{% end %}. From my little experience around those bugs and for the available skills that I have, I found that memory leaks and KMSAN bugs are usually easier than other bugs given that you are very comfortable with gdb and that's mainly because concurrency isn't the cause of said bug most of the time or at least for most of the ones that I have attempted.For those reasons I have attempted memory leak and KMSAN bugs more than others after the initial phase of exploration.

## First steps to fixing a bug

First, you should choose a bug of a subsystem that you are most familiar with. If you have no familiarity with no subsystem, I highly recommend trying to contribute to the selftests of such subsystem, read some documentation or {%sidenote(ref="read a relative book to that subsystem")%}In the context of kernel development, reading books is just good to give you a history or a more generalized view of the code base.Since the kernel is always updating and changing, it's hard for books keep being update to date for what is currently available in the source code.{% end %}if it isn't a highly updated one and then try to fix a related bug to that subsystem.This isn't a rule but it really helps and makes it easier to navigate and understand some of the moving parts at least those that are around the bug that you are trying to solve.
Second, you need to be able to reproduced your chosen bug locally. If you don't have the hardware or for one reason or another , using the syz/C reproducers didn't trigger the bug, you should {%sidenote(ref="abort working on a fix said bug")%}Here I'm only talking about us fellow mentees and beginners. Other experienced contributors and experts of a subsystem might attempt to fix a bug without a reproducer and have their fix tested for them.{%end%}.
Finally, Try to look at other similar bugs that are of same type for the same subsystem which are fixed. Read the related email, the patch and the discussion between maintainers and the author of the patch. That also is a really good way to help you have an idea of how to approach your bug and maybe on how to also fix it. 

## Our case study

The syzbot bug in question here is the [`memory leak in hfs_init_fs_context`](https://syzkaller.appspot.com/bug?extid=ad45f827c88778ff7df6). Since as I mentionned in [my mentorship post](https://mehdibenhadjkhelifa.github.io/posts/kernel-mentorship), I have read the OSTEP book which gave me a general idea of how filesystems work. So naturally, most of my syzbot bug attempts were in the mm and fs subsystems. Previous attempts have failed mainly due to someone else submitting a fix before I can quickly craft one myself due to my lack of experience.

### Reproducing the bug && examining the crash

At the start of my mentorship, I have [live streamed](https://www.youtube.com/watch?v=W5ZRkI_fGv0&t=3621s) my initial phases of setting up syzkaller locally and trying to reproduce a bug following [an older mentee's linkedin post](https://www.linkedin.com/pulse/proof-execution-reproducing-syzbot-bugs-local-kernel-moon-hee-lee-081bc/).You can look at that to see how to do that if you are unfamiliar. So using QEMU to run the provided kernel from the syzbot bug and running the reproducer, I get the exact crash as the one reported by syzbot. Same results also from running the reproducer on a built kernel using the .config file provided from the syzbot bug page. Let's look at the relevant parts of the crash with the decoded stack trace:

```hl_lines=4,hl_lines=16-20
[   97.750949][ T5859] kmemleak: 1 new suspected memory leaks (see /sys/kernel/debug/kmemleak)
[  103.909124][ T5859] kmemleak: 1 new suspected memory leaks (see /sys/kernel/debug/kmemleak)
BUG: memory leak
unreferenced object 0xffff888111778c00 (size 512):
  comm "syz.0.17", pid 6092, jiffies 4294942644
  hex dump (first 32 bytes):
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
  backtrace (crc eb1d7412):
    kmemleak_alloc_recursive include/linux/kmemleak.h:44 [inline]
    slab_post_alloc_hook [mm/slub.c:4979] [inline]
    slab_alloc_node [mm/slub.c:5284 [inline]
    __kmalloc_cache_noprof+0x3a6/0x5b0 [mm/slub.c:5762]
    kmalloc_noprof [include/linux/slab.h:957] [inline]
    kzalloc_noprof [include/linux/slab.h:1094] [inline]
    hfs_init_fs_context+0x24/0xd0 [fs/hfs/super.c:411]
    alloc_fs_context+0x214/0x430 [fs/fs_context.c:315]
    do_new_mount [fs/namespace.c:3707] [inline]
    path_mount+0x93c/0x12e0 [fs/namespace.c:4037]
    do_mount [fs/namespace.c:4050] [inline]
    __do_sys_mount [fs/namespace.c:4238] [inline]
    __se_sys_mount [fs/namespace.c:4215] [inline]
    __x64_sys_mount+0x1a2/0x1e0 [fs/namespace.c:4215]
    do_syscall_x64 [arch/x86/entry/syscall_64.c:63] [inline]
    do_syscall_64+0xa4/0xfa0 [arch/x86/entry/syscall_64.c:94]
    entry_SYSCALL_64_after_hwframe+0x77/0x7f
```

The first highlighted line indicate that the size of such memory leak is of 512 bytes and the following highlighted lines indicate that this buffer of memory is allocated upon doing a mounting of an hfs type filesystem and more specifically in initializing the filesystem context in `hfs/super.c` line 411. 
### Initial code investigation

Based on the indicators mentionned in the crash report, let's have a look at the surrounding code in `hfs/super.c` first.
{%marginnote() %} [`fs/hfs/super.c:411`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/hfs/super.c?id=4ea7c1717f3f2344f7a1cdab4f5875cfa89c87a9#n411){%end%}
```c,hl_lines=5,hl_lines=9
static int hfs_init_fs_context(struct fs_context *fc)
{
	struct hfs_sb_info *hsb;

	hsb = kzalloc(sizeof(struct hfs_sb_info), GFP_KERNEL);
	if (!hsb)
		return -ENOMEM;

	fc->s_fs_info = hsb;
	fc->ops = &hfs_context_ops;

	if (fc->purpose != FS_CONTEXT_FOR_RECONFIGURE) {
		/* initialize options with defaults */
		hsb->s_uid = current_uid();
		hsb->s_gid = current_gid();
		hsb->s_file_umask = 0133;
		hsb->s_dir_umask = 0022;
		hsb->s_type = cpu_to_be32(0x3f3f3f3f); /* == '????' */
		hsb->s_creator = cpu_to_be32(0x3f3f3f3f); /* == '????' */
		hsb->s_quiet = 0;
		hsb->part = -1;
		hsb->session = -1;
	}

	return 0;
}
```

We can see that the leaked memory is a `hfs_sb_info` struct allocated on the first highlighted line which is also the 411 line mentionned in the report and {%sidenote(ref="is of 512 bytes")%}I manually checked `sizeof(struct hfs_sb_info)`{%end%}. Also we notice that the ownership of the pointer to the allocated memory buffer for that struct is transfered to the filesystem context struct.The function responsible for cleaning up the hfs context is the [`hfs_free_fc()`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/hfs/super.c?id=4ea7c1717f3f2344f7a1cdab4f5875cfa89c87a9#n395) So my initial thoughts here were, would it be that the error path that is being fuzzed didn't include a call to the cleanup function? Here we needed some gdb digging.
### Using gdb to demystify the cause of the bug

First I setup a breakpoint at `hfs_free_fc()` to check if it's being called or not and it indeed was being called. The issue though becomes clearer as the pointer `fc->s_fs_info` is `NULL`.
This means that the ownership of said pointer has been moved again or was assigned `NULL` before it's actual cleanup. My next step is to find out where exactly was the `fc->s_fs_info` been assigned to `NULL`. Consequently, I setup a breakpoint within the `hfs_init_fs_context()` to follow the calls that succeed  it while always inspecting the memory/value of `fc->s_fs_info` to check where it gets `NULL`. Doing so, I got to the function `sget_fc()` that does the transfer of ownership and setting `fc->s_fs_info` to `NULL`.The following is the related call stack(simplified) and the mentionned code.

```crash
sget_fc [fs/super.c:733]
sget_bdev [fs/super.c:1405]
get_tree_bdev_flags [fs/super.c:1677]
vfs_get_tree [fs/super.c:1751]
fc_mount [fs/namespace.c:1208]
do_new_mount_fc [fs/namespace.c:3651]
do_new_mount [fs/namespace.c:3727]
path_mount [fs/namespace.c:4037]
do_mount [fs/namespace.c:4050]
....
```

{%marginnote()%}[`fs/super.c:774`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/super.c?id=4ea7c1717f3f2344f7a1cdab4f5875cfa89c87a9#n774){%end%}
```c,hl_lines=7,hl_lines=15
struct super_block *sget_fc(struct fs_context *fc,
			    int (*test)(struct super_block *, struct fs_context *),
			    int (*set)(struct super_block *, struct fs_context *))
{
	struct super_block *s = NULL;
	/* snip */
	s->s_fs_info = fc->s_fs_info;
	err = set(s, fc);
	if (err) {
		s->s_fs_info = NULL;
		spin_unlock(&sb_lock);
		destroy_unused_super(s);
		return ERR_PTR(err);
	}
	fc->s_fs_info = NULL;
	s->s_type = fc->fs_type;
	s->s_iflags |= fc->s_iflags;
	strscpy(s->s_id, s->s_type->name, sizeof(s->s_id));
	/* snip */
}
```

At this point,I have already seen that `vfs_get_tree()` in the call stack was returning an error from earlier attempts and that the error propagation starts from the `get_tree_bdev_flags()` function. So I needed to follow the flow of execution in that function after the allocation of a new superblock in `sget_fc()` to see exactly what function caused the error and how it was handled. 
{%marginnote()%}[`fs/super.c:1659`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/super.c?id=4ea7c1717f3f2344f7a1cdab4f5875cfa89c87a9#n1659){%end%}
```c,hl_lines=15,hl_lines=17,hl_lines=19
int get_tree_bdev_flags(struct fs_context *fc,
		int (*fill_super)(struct super_block *sb,
				  struct fs_context *fc), unsigned int flags)
{
	struct super_block *s;
	/* snip */
	if (s->s_root) {
		/* Don't summarily change the RO/RW state. */
		if ((fc->sb_flags ^ s->s_flags) & SB_RDONLY) {
			warnf(fc, "%pg: Can't mount, would change RO state", s->s_bdev);
			deactivate_locked_super(s);
			return -EBUSY;
		}
	} else {
		error = setup_bdev_super(s, fc->sb_flags, fc);
		if (!error)
			error = fill_super(s, fc);
		if (error) {
			deactivate_locked_super(s);
			return error;
		}
		s->s_flags |= SB_ACTIVE;
	}
	/* snip */
}
```
`setup_bdev_super()` as highlighted here is the function inside `get_tree_bdev_flags()` which {%sidenote(ref="returns an error")%}Other calls that caused the error in the `setup_bdev_super()` function were skipped since most of them either propagate the error or cleanup related structures to the block device.And so the more reasonable fix for this bug would either be at the `get_tree_bdev_flags()` level or above.{%end%}.So I jumped to `deactivate_locked_super()` which should handle such error and found that it does call the fs-specific function of killing a superblock, but in the case of the `HFS`, the function pointer is assigned to a generic shutdown function which doesn't handle the freeing of the superblock struct. Below is the mentionned code.
{%marginnote()%}[`fs/super.c:468`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/super.c?id=4ea7c1717f3f2344f7a1cdab4f5875cfa89c87a9#n468){%end%}
```c,hl_lines=6
void deactivate_locked_super(struct super_block *s)
{
	struct file_system_type *fs = s->s_type;
	if (atomic_dec_and_test(&s->s_active)) {
		shrinker_free(s->s_shrink);
		fs->kill_sb(s);

		kill_super_notify(s);

		/*
		 * Since list_lru_destroy() may sleep, we cannot call it from
		 * put_super(), where we hold the sb_lock. Therefore we destroy
		 * the lru lists right now.
		 */
		list_lru_destroy(&s->s_dentry_lru);
		list_lru_destroy(&s->s_inode_lru);

		put_filesystem(fs);
		put_super(s);
	} else {
		super_unlock_excl(s);
	}
}
```
{%marginnote()%}[`fs/hfs/super.c:434`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/hfs/super.c?id=4ea7c1717f3f2344f7a1cdab4f5875cfa89c87a9#n434){%end%}
```c,hl_lines=4
static struct file_system_type hfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "hfs",
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
	.init_fs_context = hfs_init_fs_context,
};
```
{%marginnote()%}[`fs/super.c:1718`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/fs/super.c?id=4ea7c1717f3f2344f7a1cdab4f5875cfa89c87a9#n1718){%end%}
```c
void kill_block_super(struct super_block *sb)
{
	struct block_device *bdev = sb->s_bdev;

	generic_shutdown_super(sb);
	if (bdev) {
		sync_blockdev(bdev);
		bdev_fput(sb->s_bdev_file);
	}
}

```
### Attempting a fix

Here is where I made my first not technical but logical mistake. I assumed that since `hfs_free_fc()` was being called with a {%sidenote(ref="`NULL`")%}important to note here that the `hfs_free_fc()` didn't have any checks for `fc->s_fs_info` being `NULL` and was calling `kfree()` on it{% end %} from a higher calling function (`do_new_mount()`), the suitable fix here was to return the ownership of the `s_fs_info`  from the super block to the filesystem context just above the `deactivate_locker_super()` function so that it will to be freed.I also took into consideration that other filesystems can have the same issue here and so by doing this at a core level would also be fixing it for any other filesystem that would've suffered from the same bug.
### Why is it a mistake && the actual fix
This fix did indeed fix this specific bug and the reproducer generated no more errors,it was [pointed out to me by maintainers quickly](https://lore.kernel.org/all/20251118165553.GF2441659@ZenIV/) that this approach was a mistake. They have clarified that once the ownership is moved, [it cannot be returned](https://lore.kernel.org/all/20251118163509.GE2441659@ZenIV/) . And that `fill_super()` for each filesystem is the one responsible for freeing such struct which I then clarrified that in this error path, it isn't even called. So the more logical route that they have recommended to make a fix was to instead write a function that handles the freeing of the super block struct + have the generic shutdown of the super block function being called and then assign it's function pointer to `kill_sb` which is called to kill the super block for each specific filesystem. On top of that,other functions handling that freeing of memory was removed since `kill_sb` is always called to cleanup. So after iteration and discussion with maintainers, We have come up with a [patch](https://lore.kernel.org/all/20251201222843.82310-2-mehdi.benhadjkhelifa@gmail.com/) that has been reviewed and is waiting to be merged in at the time of writing this post.

## Closing remarks && suggestions for future mentees

[Discussion](https://lore.kernel.org/all/8727342f9a168c7e8008178e165a5a14fa7f470d.camel@ibm.com/) with maintainers has led to the suspicion that other filesystems could also be affected with the same bug and I have already worked with the maintainer of HFS and HFS+ on a similar [patch](https://lore.kernel.org/all/20251201222843.82310-3-mehdi.benhadjkhelifa@gmail.com/) for HFS+. Fixing this bug in other filesystems will be my avenue of contributions for the following release cycles.

Furthermore, These patches have been run through religious testing by me and the maintainer of `HFS/HFS+` using many tools including xfstests,selftests,... which is a must for any bug fix before sending it.

My advice for any mentee that is working on a syzbot bug is to:

1. **Work on an actual fix, Not a suppression of the bug**: this might be obvious but I noticed that some of my fellow mentees do this and have been pushed back for it. Not only does it hurt your reputation in the linux kernel community, but it also shows that you either don't grasp the impact of having such changes in the kernel or that you don't understand what you are doing. So avoid propagating the error and not handling it, removing the bug triggers such as `BUG()` or `WARN()` or any other simple suppressing methods.
2. **Fixing with intention**: Having an idea of the cause and pin pointing the issue to a degree of accuracy is highly recommended to get the attention of maintainers to help you get to the actual fix. If you are just throwing bluff and hoping for help or a fix, you will be ignored.
3. **Testing is most important** : Having worked on a fix, You should not *only* test with the reproducer that triggers the bug. This relates to my first point too. After seeing that the bug no longer triggers with the reproducer and you are confident of the fix. Run any suitable tests that you can. This includes selftests, specific subsystem tests that are separate from the mainline tree, making a module yourself and doing a fault injection check and any other things that makes you more sure of the robustness of your change. This will highly affect how your patch will be treated by the linux community and if it is even worth to be looked at since lack of testing results in a lack of trust. And such testing is expect from contributors and assumed by maintainers.


I hope that at least some people and some future mentees benefited from this bug walkthrough and  I would like to thank my mentors [shuah](https://www.linkedin.com/in/shuah-khan/),[david](https://www.linkedin.com/in/david-hunter-34a10371/) and [khalid](https://www.linkedin.com/in/khalidaziz/) for their guidance,the welcoming linux kernel community and maintainers for their help.  

Without this support, kickstarting such bug huntings would have been much harder.

*Happy hacking everyone!*

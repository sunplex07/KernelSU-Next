/*
 * keeps every KernelSU-Next manager release working on this kernel:
 * - each manager (and its bundled ksud) gets the uapi version it was built
 *   for, so the uapi equality checks in the manager and ksud pass
 * - v2/v3 app_profile layouts (managers v1.x-v3.2) are converted
 * - feature/sepolicy calls whose meaning changed are refused, not misread
 * - v1.x managers get their prctl(0xDEADBEEF) interface back
 *
 * prior art: KernelSU-Next v1.1.1 kernel/core_hook.c (prctl interface),
 * the allowlist loader's migrate_profile (profile v2/v3 -> v4).
 */

#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "ksu.h"
#include "klog.h" // IWYU pragma: keep
#include "uapi/supercall.h"
#include "uapi/app_profile.h"
#include "uapi/feature.h"
#include "supercall/compat.h"
#include "supercall/internal.h"
#include "manager/manager_identity.h"
#include "manager/throne_tracker.h"
#include "policy/allowlist.h"
#include "policy/app_profile.h"
#include "policy/feature.h"
#include "runtime/ksud.h"
#include "runtime/ksud_boot.h"
#include "sulog/event.h"
#include "hook/hook_manager.h"

/*
 * manager versionCode = 30000 + KernelSU-Next commit count. commit counts
 * where the uapi version changed: 3188 -> 1, 3189 -> 2, 3258 -> 3, 3260 -> 4,
 * 3319 -> 5, 3391 -> 6 (uapi/supercall.h history).
 */
#define VC_UAPI1 33188
#define VC_UAPI2 33189
#define VC_UAPI3 33258
#define VC_UAPI4 33260
#define VC_UAPI5 33319
#define VC_UAPI6 33391
/* feature id 2 was "enhanced security" before it became sulog */
#define VC_ENHANCED_SECURITY_START 32784
#define VC_ENHANCED_SECURITY_END 32941
/* the sepolicy ioctl took {cmd, arg} before {data_len, data} */
#define VC_SEPOLICY_DATA_LEN 33103

static atomic_t ksud_scanned = ATOMIC_INIT(0);

static u32 exe_version_code(void)
{
	struct file *exe;
	char *buf, *path;
	u32 vc = 0;

	if (!current->mm)
		return 0;
	exe = get_mm_exe_file(current->mm);
	if (!exe)
		return 0;

	buf = kmalloc(PATH_MAX, GFP_KERNEL);
	if (!buf)
		goto out;
	path = d_path(&exe->f_path, buf, PATH_MAX);
	if (IS_ERR(path))
		goto out_free;

	if (!strcmp(path, KSUD_PATH)) {
		/* /data/adb/ksud is a copy of some manager's libksud.so */
		loff_t size = i_size_read(file_inode(exe));

		vc = ksu_manager_version_code_for_ksud(size);
		/* early boot: managers aren't scanned yet, do it once now */
		if (!vc && !atomic_xchg(&ksud_scanned, 1)) {
			track_throne(false);
			vc = ksu_manager_version_code_for_ksud(size);
		}
	} else {
		/* a manager running its bundled libksud.so directly */
		vc = ksu_manager_version_code_for_path(path);
	}

out_free:
	kfree(buf);
out:
	fput(exe);
	return vc;
}

u32 ksu_caller_version_code(void)
{
	uid_t uid = current_uid().val;

	if (is_uid_manager(uid))
		return ksu_manager_version_code(uid);
	if (uid == 0)
		return exe_version_code();
	return 0;
}

static u32 uapi_for_version_code(u32 vc)
{
	if (vc < VC_UAPI1)
		return 0;
	if (vc < VC_UAPI2)
		return 1;
	if (vc < VC_UAPI3)
		return 2;
	if (vc < VC_UAPI4)
		return 3;
	if (vc < VC_UAPI5)
		return 4;
	if (vc < VC_UAPI6)
		return 5;
	/* 6 only adds a symbol lookup ioctl + preinit flag nobody needs here */
	return 6;
}

u32 ksu_compat_uapi_version(void)
{
	u32 uapi = uapi_for_version_code(ksu_caller_version_code());

	return uapi ? uapi : KERNEL_SU_UAPI_VERSION;
}

size_t ksu_compat_profile_size(u32 version)
{
	BUILD_BUG_ON(offsetof(struct app_profile, rp_config.profile.flags) !=
		     KSU_APP_PROFILE_SIZE_PRE_V4);

	if (version == 2 || version == 3)
		return KSU_APP_PROFILE_SIZE_PRE_V4;
	return sizeof(struct app_profile);
}

int ksu_compat_upgrade_profile(u32 version, struct app_profile *profile)
{
	struct app_profile *cur;

	if (version != 2 && version != 3)
		return -EINVAL;

	ksu_upgrade_app_profile(version, profile);

	/* keep flags a newer manager set, an old one can't see them */
	if (profile->allow_su) {
		rcu_read_lock();
		cur = ksu_get_app_profile(profile->curr_uid);
		rcu_read_unlock();
		if (cur) {
			if (cur->allow_su)
				profile->rp_config.profile.flags = cur->rp_config.profile.flags;
			ksu_put_app_profile(cur);
		}
	}
	return 0;
}

bool ksu_compat_feature_hidden(u32 feature_id)
{
	u32 vc;

	if (feature_id != KSU_FEATURE_SULOG)
		return false;
	vc = ksu_caller_version_code();
	return vc >= VC_ENHANCED_SECURITY_START && vc < VC_ENHANCED_SECURITY_END;
}

bool ksu_compat_old_sepolicy_payload(void)
{
	u32 vc = ksu_caller_version_code();

	return vc && vc < VC_SEPOLICY_DATA_LEN;
}

/*
 * opening a manager makes it copy its own libksud.so to /data/adb/ksud. with
 * several managers installed, only the newest may do that, so opening an old
 * one doesn't downgrade the ksud that runs at boot. prior art: BakaSU
 * hook/setuid_hook.c ksu_set_ksud_status().
 */
static void set_ksud_immutable(bool immutable)
{
	const struct cred *old_cred = override_creds(ksu_cred);
	struct inode *inode;
	struct path path;

	if (kern_path(KSUD_PATH, 0, &path))
		goto out;

	inode = d_inode(path.dentry);
	if (!!IS_IMMUTABLE(inode) != immutable && !mnt_want_write(path.mnt)) {
		inode_lock(inode);
		if (immutable)
			inode->i_flags |= S_IMMUTABLE;
		else
			inode->i_flags &= ~S_IMMUTABLE;
		inode_unlock(inode);
		mnt_drop_write(path.mnt);
		pr_info(KSUD_PATH " %s\n", immutable ? "locked for an older manager" : "unlocked");
	}
	path_put(&path);
out:
	revert_creds(old_cred);
}

void ksu_compat_on_manager_launch(uid_t uid)
{
	u32 vc = ksu_manager_version_code(uid);
	u32 newest = ksu_manager_max_version_code();

	if (!vc || !newest)
		return;
	set_ksud_immutable(vc < newest);
}

/* v1.x prctl interface */
#define KERNEL_SU_OPTION 0xDEADBEEF
#define CMD_GRANT_ROOT 0
#define CMD_BECOME_MANAGER 1
#define CMD_GET_VERSION 2
#define CMD_GET_ALLOW_LIST 5
#define CMD_GET_DENY_LIST 6
#define CMD_REPORT_EVENT 7
#define CMD_SET_SEPOLICY 8
#define CMD_CHECK_SAFEMODE 9
#define CMD_GET_APP_PROFILE 10
#define CMD_SET_APP_PROFILE 11
#define CMD_UID_GRANTED_ROOT 12
#define CMD_UID_SHOULD_UMOUNT 13
#define CMD_IS_SU_ENABLED 14
#define CMD_ENABLE_SU 15
#define CMD_GET_MANAGER_UID 16
#define CMD_HOOK_MODE 0xC0DEAD1A
#define LEGACY_LIST_MAX 128

static void reply_ok(unsigned long arg5)
{
	u32 ok = KERNEL_SU_OPTION;

	if (copy_to_user((void __user *)arg5, &ok, sizeof(ok)))
		pr_err("legacy prctl: reply failed\n");
}

static int legacy_get_profile(unsigned long arg)
{
	char __user *up = (char __user *)arg;
	struct app_profile *p;
	u32 version = 2;
	uid_t uid;
	int ret = 0;

	if (copy_from_user(&uid, up + offsetof(struct app_profile, curr_uid), sizeof(uid)))
		return -EFAULT;

	rcu_read_lock();
	p = ksu_get_app_profile(uid);
	rcu_read_unlock();
	if (!p)
		return -ENOENT;

	if (copy_to_user(up, p, KSU_APP_PROFILE_SIZE_PRE_V4) ||
	    copy_to_user(up, &version, sizeof(version)))
		ret = -EFAULT;
	ksu_put_app_profile(p);
	return ret;
}

static int legacy_set_profile(unsigned long arg)
{
	struct app_profile *p = kzalloc(sizeof(*p), GFP_KERNEL);
	int ret;

	if (!p)
		return -ENOMEM;

	if (copy_from_user(p, (void __user *)arg, KSU_APP_PROFILE_SIZE_PRE_V4)) {
		ret = -EFAULT;
		goto out;
	}

	ret = ksu_compat_upgrade_profile(p->version, p);
	if (ret)
		goto out;

	ret = ksu_set_app_profile(p);
	if (!ret) {
		ksu_persistent_allow_list();
#ifdef KSU_KPROBES_HOOK
		ksu_mark_running_process();
#endif
	}
out:
	kfree(p);
	return ret;
}

static void legacy_get_list(unsigned long arg2, unsigned long arg3,
			    unsigned long arg4, unsigned long arg5)
{
	int *array = kmalloc_array(LEGACY_LIST_MAX, sizeof(int), GFP_KERNEL);
	u16 len = 0;
	u32 count;

	if (!array)
		return;

	ksu_get_allow_list(array, LEGACY_LIST_MAX, &len, NULL, arg2 == CMD_GET_ALLOW_LIST);
	count = len;
	if (!copy_to_user((void __user *)arg4, &count, sizeof(count)) &&
	    !copy_to_user((void __user *)arg3, array, sizeof(int) * count))
		reply_ok(arg5);
	kfree(array);
}

int ksu_handle_legacy_prctl(int option, unsigned long arg2, unsigned long arg3,
			    unsigned long arg4, unsigned long arg5)
{
	bool from_root, from_manager;

	if ((u32)option != KERNEL_SU_OPTION)
		return -ENOSYS;

	/* to anyone else this stays a plain unknown prctl (-EINVAL), as before */
	if (arg2 == CMD_GRANT_ROOT) {
		__u32 uid = current_uid().val, euid = current_euid().val;
		int ret;

		if (!allowed_for_su())
			return -ENOSYS;
		ret = escape_with_root_profile();
		ksu_sulog_emit_grant_root(ret, uid, euid, GFP_KERNEL);
		if (!ret)
			reply_ok(arg5);
		return 0;
	}

	from_root = current_uid().val == 0;
	from_manager = is_manager();
	if (!from_root && !from_manager)
		return -ENOSYS;

	switch (arg2) {
	case CMD_BECOME_MANAGER:
		if (from_manager)
			reply_ok(arg5);
		break;
	case CMD_GET_VERSION: {
		u32 version = KERNEL_SU_VERSION, flags = 0;

		if (copy_to_user((void __user *)arg3, &version, sizeof(version)))
			break;
		if (arg4 && copy_to_user((void __user *)arg4, &flags, sizeof(flags)))
			break;
		reply_ok(arg5);
		break;
	}
	case CMD_GET_ALLOW_LIST:
	case CMD_GET_DENY_LIST:
		legacy_get_list(arg2, arg3, arg4, arg5);
		break;
	case CMD_REPORT_EVENT:
		if (from_root)
			ksu_handle_report_event((u32)arg3);
		break;
	case CMD_SET_SEPOLICY:
		/* old {cmd, arg} encoding, this kernel can't parse it */
		break;
	case CMD_CHECK_SAFEMODE:
		if (ksu_is_safe_mode())
			reply_ok(arg5);
		break;
	case CMD_GET_APP_PROFILE:
		if (from_manager && !legacy_get_profile(arg3))
			reply_ok(arg5);
		break;
	case CMD_SET_APP_PROFILE:
		if (from_manager && !legacy_set_profile(arg3))
			reply_ok(arg5);
		break;
	case CMD_UID_GRANTED_ROOT:
	case CMD_UID_SHOULD_UMOUNT: {
		uid_t uid = (uid_t)arg3;
		bool val = arg2 == CMD_UID_GRANTED_ROOT ? ksu_is_allow_uid(uid)
						      : ksu_uid_should_umount(uid);

		if (!copy_to_user((void __user *)arg4, &val, sizeof(val)))
			reply_ok(arg5);
		break;
	}
	case CMD_IS_SU_ENABLED: {
		u64 value = 0;
		bool supported = false, enabled;

		ksu_get_feature(KSU_FEATURE_SU_COMPAT, &value, &supported);
		enabled = value != 0;
		if (!copy_to_user((void __user *)arg3, &enabled, sizeof(enabled)))
			reply_ok(arg5);
		break;
	}
	case CMD_ENABLE_SU:
		if (!ksu_set_feature(KSU_FEATURE_SU_COMPAT, arg3 ? 1 : 0))
			reply_ok(arg5);
		break;
	case CMD_GET_MANAGER_UID: {
		uid_t appid = ksu_get_manager_appid();

		if (!copy_to_user((void __user *)arg3, &appid, sizeof(appid)))
			reply_ok(arg5);
		break;
	}
	case CMD_HOOK_MODE: {
#ifdef KSU_KPROBES_HOOK
		static const char mode[] = "Kprobes";
#else
		static const char mode[] = "Manual";
#endif
		if (!copy_to_user((void __user *)arg3, mode, sizeof(mode)))
			reply_ok(arg5);
		break;
	}
	default:
		break;
	}
	return 0;
}

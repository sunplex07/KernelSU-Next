#ifndef __KSU_H_KSU_MANAGER
#define __KSU_H_KSU_MANAGER

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/types.h>

#define KSU_INVALID_APPID -1
#define KSU_PER_USER_RANGE 100000

#ifdef CONFIG_KSU_DISABLE_MANAGER
static inline bool ksu_is_manager_appid_valid()
{
    return true;
}

static inline bool is_manager()
{
    return current_uid().val == 0;
}

static inline bool is_uid_manager(uid_t uid)
{
    return uid == 0;
}

static inline uid_t ksu_get_manager_appid()
{
    return 0;
}

static inline void ksu_set_manager_appid(uid_t appid)
{
    (void)appid;
}

static inline void ksu_invalidate_manager_uid()
{
}

static inline u32 ksu_manager_version_code(uid_t uid)
{
    (void)uid;
    return 0;
}

static inline u32 ksu_manager_version_code_for_path(const char *path)
{
    (void)path;
    return 0;
}

static inline u32 ksu_manager_version_code_for_ksud(loff_t size)
{
    (void)size;
    return 0;
}

static inline u32 ksu_manager_max_version_code(void)
{
    return 0;
}
#else
/*
 * every installed apk signed with the manager key is a manager, whatever its
 * package name: official, spoofed builds with random names, or several of
 * them side by side. see manager/throne_tracker.c.
 */
bool ksu_is_manager_appid_valid(void);
bool is_uid_manager(uid_t uid);

static inline bool is_manager(void)
{
	return unlikely(is_uid_manager(current_uid().val));
}

/* the caller's own appid if it's a manager, otherwise any manager's */
uid_t ksu_get_manager_appid(void);
/* extra appid set by root (CHANGE_MANAGER_UID) or the debug param */
void ksu_set_manager_appid(uid_t appid);
void ksu_invalidate_manager_uid(void);

/* versionCode from packages.list, 0 if unknown */
u32 ksu_manager_version_code(uid_t uid);
/* manager whose apk dir holds this file (its bundled libksud.so) */
u32 ksu_manager_version_code_for_path(const char *path);
/* manager whose bundled libksud.so has this size (/data/adb/ksud is a copy) */
u32 ksu_manager_version_code_for_ksud(loff_t size);
/* highest versionCode among installed managers */
u32 ksu_manager_max_version_code(void);
#endif

#endif

#ifndef __KSU_H_SUPERCALL_COMPAT
#define __KSU_H_SUPERCALL_COMPAT

#include <linux/types.h>
#include "uapi/app_profile.h"

/* v2/v3 app_profile: the v4 layout without root_profile.flags */
#define KSU_APP_PROFILE_SIZE_PRE_V4 776

/* versionCode of the manager (or its bundled ksud) making this call, 0 if unknown */
u32 ksu_caller_version_code(void);
/* uapi the caller was built for, native if unknown */
u32 ksu_compat_uapi_version(void);

size_t ksu_compat_profile_size(u32 version);
int ksu_compat_upgrade_profile(u32 version, struct app_profile *profile);

/* feature ids whose meaning changed for the caller's version */
bool ksu_compat_feature_hidden(u32 feature_id);
/* caller still sends the old {cmd, arg} sepolicy payload */
bool ksu_compat_old_sepolicy_payload(void);

int ksu_handle_report_event(u32 event);

/* manager app process starting: guard /data/adb/ksud against downgrades */
void ksu_compat_on_manager_launch(uid_t uid);

/* prctl(0xDEADBEEF, ...) interface of v1.x managers */
int ksu_handle_legacy_prctl(int option, unsigned long arg2, unsigned long arg3,
			    unsigned long arg4, unsigned long arg5);

#endif

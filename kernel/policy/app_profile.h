#ifndef __KSU_H_APP_PROFILE
#define __KSU_H_APP_PROFILE

#include "uapi/app_profile.h" // IWYU pragma: keep

/* A KernelSU-private thread flag, deliberately far above the kernel's own TIF
 * bits (which end at 24 on 4.4/arm64) so it cannot collide. thread_info.flags
 * is 'unsigned long' here, so bit 63 is addressable. */
#define TIF_KSU_DISABLE_ESCAPE_WITH_ROOT 63

// Escalate current process to root with the appropriate profile
int escape_with_root_profile(void);

void escape_to_root_for_init(void);

#endif

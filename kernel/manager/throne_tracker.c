#include "ksu.h"
#include "linux/cred.h"
#include "linux/namei.h"
#include "util.h"
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>

#include "policy/allowlist.h"
#include "manager/apk_sign.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_identity.h"
#include "manager/throne_tracker.h"

/*
 * multi-manager tracking, adapted from BakaSU (github.com/Baka-SU/BakaSU,
 * commit f7dcc82be5): every base.apk under /data/app signed with the manager
 * key is a manager, whatever its package name. the set is rebuilt on each
 * packages.list change and swapped in with rcu, so readers never see an
 * empty set mid-rescan.
 */

static DEFINE_MUTEX(throne_tracker_mutex);

#define DATA_PATH_LEN 384 // 384 is enough for /data/app/<package>/base.apk
#define KSU_MAX_MANAGERS 8
#define KSUD_LIB_SUBPATH "/lib/arm64/libksud.so"

#define SYSTEM_PACKAGES_LIST_PATH "/data/system/packages.list"
#define PACKAGES_LINE_MAX 512

struct ksu_manager_entry {
	u32 appid;
	u32 version_code;
	loff_t ksud_size;
	char package[KSU_MAX_PACKAGE_NAME];
	char apk_dir[DATA_PATH_LEN];
};

struct ksu_manager_set {
	struct rcu_head rcu;
	int count;
	struct ksu_manager_entry e[KSU_MAX_MANAGERS];
};

static struct ksu_manager_set __rcu *ksu_managers;
/* extra appid set by root (CHANGE_MANAGER_UID) or the debug param */
static int ksu_extra_appid = KSU_INVALID_APPID;

bool is_uid_manager(uid_t uid)
{
	u32 appid = uid % KSU_PER_USER_RANGE;
	struct ksu_manager_set *s;
	bool found = false;
	int i;

	if (unlikely(READ_ONCE(ksu_extra_appid) == (int)appid))
		return true;

	rcu_read_lock();
	s = rcu_dereference(ksu_managers);
	if (s) {
		for (i = 0; i < s->count; i++) {
			if (s->e[i].appid == appid) {
				found = true;
				break;
			}
		}
	}
	rcu_read_unlock();
	return found;
}

bool ksu_is_manager_appid_valid(void)
{
	struct ksu_manager_set *s;
	bool valid;

	if (READ_ONCE(ksu_extra_appid) != KSU_INVALID_APPID)
		return true;
	rcu_read_lock();
	s = rcu_dereference(ksu_managers);
	valid = s && s->count > 0;
	rcu_read_unlock();
	return valid;
}

uid_t ksu_get_manager_appid(void)
{
	struct ksu_manager_set *s;
	uid_t appid = KSU_INVALID_APPID;
	int extra;

	if (is_manager())
		return current_uid().val % KSU_PER_USER_RANGE;

	extra = READ_ONCE(ksu_extra_appid);
	if (extra != KSU_INVALID_APPID)
		return extra;

	rcu_read_lock();
	s = rcu_dereference(ksu_managers);
	if (s && s->count > 0)
		appid = s->e[0].appid;
	rcu_read_unlock();
	return appid;
}

void ksu_set_manager_appid(uid_t appid)
{
	WRITE_ONCE(ksu_extra_appid, (int)appid);
}

void ksu_invalidate_manager_uid(void)
{
	WRITE_ONCE(ksu_extra_appid, KSU_INVALID_APPID);
}

u32 ksu_manager_version_code(uid_t uid)
{
	u32 appid = uid % KSU_PER_USER_RANGE;
	struct ksu_manager_set *s;
	u32 vc = 0;
	int i;

	rcu_read_lock();
	s = rcu_dereference(ksu_managers);
	if (s) {
		for (i = 0; i < s->count; i++) {
			if (s->e[i].appid == appid) {
				vc = s->e[i].version_code;
				break;
			}
		}
	}
	rcu_read_unlock();
	return vc;
}

u32 ksu_manager_version_code_for_path(const char *path)
{
	struct ksu_manager_set *s;
	u32 vc = 0;
	int i;

	rcu_read_lock();
	s = rcu_dereference(ksu_managers);
	if (s) {
		for (i = 0; i < s->count; i++) {
			size_t len = strlen(s->e[i].apk_dir);

			if (len && !strncmp(path, s->e[i].apk_dir, len) && path[len] == '/') {
				vc = s->e[i].version_code;
				break;
			}
		}
	}
	rcu_read_unlock();
	return vc;
}

u32 ksu_manager_version_code_for_ksud(loff_t size)
{
	struct ksu_manager_set *s;
	u32 vc = 0;
	int i;

	if (size <= 0)
		return 0;

	rcu_read_lock();
	s = rcu_dereference(ksu_managers);
	if (s) {
		for (i = 0; i < s->count; i++) {
			if (s->e[i].ksud_size == size && s->e[i].version_code > vc)
				vc = s->e[i].version_code;
		}
	}
	rcu_read_unlock();
	return vc;
}

u32 ksu_manager_max_version_code(void)
{
	struct ksu_manager_set *s;
	u32 vc = 0;
	int i;

	rcu_read_lock();
	s = rcu_dereference(ksu_managers);
	if (s) {
		for (i = 0; i < s->count; i++) {
			if (s->e[i].version_code > vc)
				vc = s->e[i].version_code;
		}
	}
	rcu_read_unlock();
	return vc;
}

struct uid_data {
	struct list_head list;
	u32 uid;
	u32 version_code;
	char package[KSU_MAX_PACKAGE_NAME];
};

struct data_path {
	char dirpath[DATA_PATH_LEN];
	int depth;
	struct list_head list;
};

/* signature results per base.apk path; a path never changes content */
struct apk_sig_cache {
	struct list_head list;
	bool is_manager;
	bool seen;
	char path[];
};

static LIST_HEAD(apk_sig_cache_list);

struct my_dir_context {
	struct dir_context ctx;
	struct list_head *data_path_list;
	char *parent_dir;
	void *private_data;
	int depth;
};

// https://docs.kernel.org/filesystems/porting.html
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define FILLDIR_RETURN_TYPE bool
#define FILLDIR_ACTOR_CONTINUE true
#define FILLDIR_ACTOR_STOP false
#else
#define FILLDIR_RETURN_TYPE int
#define FILLDIR_ACTOR_CONTINUE 0
#define FILLDIR_ACTOR_STOP -EINVAL
#endif

extern bool is_manager_apk(char *path);

static bool maybe_manager_apk_dir(const char *path)
{
#ifdef KSU_MANAGER_PACKAGE
	_Static_assert(sizeof(KSU_MANAGER_PACKAGE) < KSU_MAX_PACKAGE_NAME, "KSU_MANAGER_PACKAGE too long!");
	char pkg[KSU_MAX_PACKAGE_NAME];
	if (get_pkg_from_apk_dir_path(pkg, path) < 0) {
		pr_err("Failed to get package name from apk dir path: %s\n", path);
		return false;
	}

	// pkg is `<real package>`
	return strncmp(pkg, KSU_MANAGER_PACKAGE, sizeof(KSU_MANAGER_PACKAGE)) == 0;
#else
	return true;
#endif
}

FILLDIR_RETURN_TYPE my_actor(struct dir_context *ctx, const char *name,
							int namelen, loff_t off, u64 ino,
							unsigned int d_type)
{
	struct my_dir_context *my_ctx =
		container_of(ctx, struct my_dir_context, ctx);
	char dirpath[DATA_PATH_LEN];

	if (!strncmp(name, "..", namelen) || !strncmp(name, ".", namelen))
		return FILLDIR_ACTOR_CONTINUE; // Skip "." and ".."

	if (d_type == DT_DIR && namelen >= 8 && !strncmp(name, "vmdl", 4) &&
		!strncmp(name + namelen - 4, ".tmp", 4)) {
		pr_info("Skipping directory: %.*s\n", namelen, name);
		return FILLDIR_ACTOR_CONTINUE; // Skip staging package
	}

	if (snprintf(dirpath, DATA_PATH_LEN, "%s/%.*s", my_ctx->parent_dir, namelen,
				name) >= DATA_PATH_LEN) {
		pr_err("Path too long: %s/%.*s\n", my_ctx->parent_dir, namelen, name);
		return FILLDIR_ACTOR_CONTINUE;
	}

	if (d_type == DT_DIR && my_ctx->depth > 0) {
		struct data_path *data = kzalloc(sizeof(struct data_path), GFP_KERNEL);

		if (!data) {
			pr_err("Failed to allocate memory for %s\n", dirpath);
			return FILLDIR_ACTOR_CONTINUE;
		}

		strscpy(data->dirpath, dirpath, DATA_PATH_LEN);
		data->depth = my_ctx->depth - 1;
		list_add_tail(&data->list, my_ctx->data_path_list);
	} else {
		if ((namelen == 8) && (strncmp(name, "base.apk", namelen) == 0)) {
			if (maybe_manager_apk_dir(my_ctx->parent_dir))
				strscpy((char *)my_ctx->private_data, dirpath, DATA_PATH_LEN);
			return FILLDIR_ACTOR_STOP;
		}
	}

	return FILLDIR_ACTOR_CONTINUE;
}

static bool cached_is_manager_apk(char *path)
{
	struct apk_sig_cache *c;
	size_t len = strlen(path);

	list_for_each_entry (c, &apk_sig_cache_list, list) {
		if (!strcmp(c->path, path)) {
			c->seen = true;
			return c->is_manager;
		}
	}

	c = kzalloc(sizeof(*c) + len + 1, GFP_KERNEL);
	if (!c)
		return is_manager_apk(path);
	memcpy(c->path, path, len + 1);
	c->is_manager = is_manager_apk(path);
	c->seen = true;
	list_add_tail(&c->list, &apk_sig_cache_list);
	pr_info("checked base.apk at path: %s, is_manager: %d\n", path, c->is_manager);
	return c->is_manager;
}

static loff_t ksud_lib_size(const char *apk_dir)
{
	char *path = kasprintf(GFP_KERNEL, "%s" KSUD_LIB_SUBPATH, apk_dir);
	struct path p;
	loff_t size = 0;

	if (!path)
		return 0;
	if (!kern_path(path, LOOKUP_FOLLOW, &p)) {
		size = i_size_read(d_inode(p.dentry));
		path_put(&p);
	}
	kfree(path);
	return size;
}

static void add_manager(struct ksu_manager_set *set, const char *apk_dir,
			struct list_head *uid_data)
{
	char pkg[KSU_MAX_PACKAGE_NAME];
	struct uid_data *np;
	int i;

	if (get_pkg_from_apk_dir_path(pkg, apk_dir) < 0) {
		pr_err("Failed to get package name from apk dir path: %s\n", apk_dir);
		return;
	}
#ifdef KSU_MANAGER_PACKAGE
	if (strcmp(pkg, KSU_MANAGER_PACKAGE))
		return;
#endif

	list_for_each_entry (np, uid_data, list) {
		if (strncmp(np->package, pkg, KSU_MAX_PACKAGE_NAME))
			continue;

		for (i = 0; i < set->count; i++) {
			if (set->e[i].appid == np->uid)
				return;
		}
		if (set->count >= KSU_MAX_MANAGERS) {
			pr_warn("too many managers, ignoring %s\n", pkg);
			return;
		}

		set->e[set->count].appid = np->uid;
		set->e[set->count].version_code = np->version_code;
		strscpy(set->e[set->count].package, pkg, KSU_MAX_PACKAGE_NAME);
		strscpy(set->e[set->count].apk_dir, apk_dir, DATA_PATH_LEN);
		set->e[set->count].ksud_size = ksud_lib_size(apk_dir);
		set->count++;
		return;
	}
}

static void search_managers(const char *path, int depth, struct list_head *uid_data,
			    struct ksu_manager_set *set)
{
	int i;
	struct list_head data_path_list;
	INIT_LIST_HEAD(&data_path_list);
	unsigned long data_app_magic = 0;
	struct apk_sig_cache *c, *cn;

	list_for_each_entry (c, &apk_sig_cache_list, list)
		c->seen = false;

	// First depth
	struct data_path data;
	strscpy(data.dirpath, path, DATA_PATH_LEN);
	data.depth = depth;
	list_add_tail(&data.list, &data_path_list);

	char candidate_path[DATA_PATH_LEN];

	for (i = depth; i >= 0; i--) {
		struct data_path *pos, *n;

		list_for_each_entry_safe (pos, n, &data_path_list, list) {
			struct my_dir_context ctx = { .ctx.actor = my_actor,
										.data_path_list = &data_path_list,
										.parent_dir = pos->dirpath,
										.private_data = candidate_path,
										.depth = pos->depth };
			struct file *file = ksu_filp_open_nonotify(pos->dirpath, O_RDONLY | O_NOFOLLOW | O_NOATIME);
			if (IS_ERR(file)) {
				pr_err("Failed to open directory: %s, err: %ld\n",
					pos->dirpath, PTR_ERR(file));
				goto skip_iterate;
			}

			// grab magic on first folder, which is /data/app
			if (!data_app_magic) {
				if (file->f_inode->i_sb->s_magic) {
					data_app_magic = file->f_inode->i_sb->s_magic;
					pr_info("%s: dir: %s got magic! 0x%lx\n", __func__,
							pos->dirpath, data_app_magic);
				} else {
					filp_close(file, NULL);
					goto skip_iterate;
				}
			}

			if (file->f_inode->i_sb->s_magic != data_app_magic) {
				pr_info("%s: skip: %s magic: 0x%lx expected: 0x%lx\n",
						__func__, pos->dirpath,
						file->f_inode->i_sb->s_magic, data_app_magic);
				filp_close(file, NULL);
				goto skip_iterate;
			}

			candidate_path[0] = 0;
			iterate_dir(file, &ctx.ctx);
			filp_close(file, NULL);

			// apk is opened only after the dir walk is done
			if (candidate_path[0] && cached_is_manager_apk(candidate_path))
				add_manager(set, pos->dirpath, uid_data);

		skip_iterate:
			list_del(&pos->list);
			if (pos != &data)
				kfree(pos);
		}
	}

	// drop results for apks that are gone
	list_for_each_entry_safe (c, cn, &apk_sig_cache_list, list) {
		if (!c->seen) {
			list_del(&c->list);
			kfree(c);
		}
	}
}

static bool is_uid_exist(uid_t uid, char *package, void *data)
{
	struct list_head *list = (struct list_head *)data;
	struct uid_data *np;

	bool exist = false;
	list_for_each_entry (np, list, list) {
		if (np->uid == uid % PER_USER_RANGE &&
			strncmp(np->package, package, KSU_MAX_PACKAGE_NAME) == 0) {
			exist = true;
			break;
		}
	}
	return exist;
}

static struct uid_data *find_installed(struct list_head *uid_data, const char *pkg, u32 appid)
{
	struct uid_data *np;

	list_for_each_entry (np, uid_data, list) {
		if (np->uid == appid && !strncmp(np->package, pkg, KSU_MAX_PACKAGE_NAME))
			return np;
	}
	return NULL;
}

static bool dir_exists(const char *dir)
{
	struct path p;

	if (kern_path(dir, 0, &p))
		return false;
	path_put(&p);
	return true;
}

/* carry over managers that are still installed but the scan missed */
static void keep_still_installed(struct ksu_manager_set *set, struct ksu_manager_set *old,
				 struct list_head *uid_data, bool check_dir)
{
	struct uid_data *np;
	int i, j;

	if (!old)
		return;

	for (i = 0; i < old->count; i++) {
		bool present = false;

		for (j = 0; j < set->count; j++) {
			if (set->e[j].appid == old->e[i].appid) {
				present = true;
				break;
			}
		}
		if (present || set->count >= KSU_MAX_MANAGERS)
			continue;

		np = find_installed(uid_data, old->e[i].package, old->e[i].appid);
		if (!np || (check_dir && !dir_exists(old->e[i].apk_dir)))
			continue;

		set->e[set->count] = old->e[i];
		set->e[set->count].version_code = np->version_code;
		set->count++;
	}
}

static void log_changes(struct ksu_manager_set *set, struct ksu_manager_set *old)
{
	int i, j;

	for (i = 0; i < set->count; i++) {
		bool known = false;

		for (j = 0; old && j < old->count; j++) {
			if (old->e[j].appid == set->e[i].appid) {
				known = true;
				break;
			}
		}
		if (!known)
			pr_info("Crowning manager: %s(uid=%u, version=%u)\n", set->e[i].package,
				set->e[i].appid, set->e[i].version_code);
	}

	for (j = 0; old && j < old->count; j++) {
		bool kept = false;

		for (i = 0; i < set->count; i++) {
			if (set->e[i].appid == old->e[j].appid) {
				kept = true;
				break;
			}
		}
		if (!kept)
			pr_info("manager %s(uid=%u) is uninstalled, invalidate it!\n",
				old->e[j].package, old->e[j].appid);
	}
}

/* packages.list fields: name uid debuggable datadir seinfo gids profileable versioncode ... */
static bool parse_packages_line(char *line, struct uid_data *data)
{
	char *tmp = line;
	char *field;
	int idx = 0;

	while ((field = strsep(&tmp, " ")) != NULL) {
		switch (idx) {
		case 0:
			if (!*field)
				return false;
			strscpy(data->package, field, sizeof(data->package));
			break;
		case 1:
			if (kstrtou32(field, 10, &data->uid))
				return false;
			break;
		case 7:
			if (kstrtou32(field, 10, &data->version_code))
				data->version_code = 0;
			return true;
		}
		idx++;
	}
	return idx > 1;
}

void track_throne(bool prune_only)
{
	mutex_lock(&throne_tracker_mutex);
	const struct cred *old_cred = override_creds(ksu_cred);
	struct file *fp = filp_open(SYSTEM_PACKAGES_LIST_PATH, O_RDONLY, 0);
	if (IS_ERR(fp)) {
		pr_err("%s: open " SYSTEM_PACKAGES_LIST_PATH " failed: %ld\n", __func__,
			PTR_ERR(fp));
		goto out_revert_cred;
	}

	struct list_head uid_list;
	INIT_LIST_HEAD(&uid_list);

	char chr = 0;
	loff_t pos = 0;
	loff_t line_start = 0;
	/* lines must reach the versionCode field, keep it off the stack */
	char *buf = kmalloc(PACKAGES_LINE_MAX, GFP_KERNEL);
	if (!buf) {
		filp_close(fp, 0);
		goto out_revert_cred;
	}
	for (;;) {
		ssize_t count = kernel_read(fp, &chr, sizeof(chr), &pos);
		if (count != sizeof(chr))
			break;
		if (chr != '\n')
			continue;

		count = kernel_read(fp, buf, PACKAGES_LINE_MAX - 1, &line_start);
		if (count <= 0) {
			break;
		}
		buf[count] = '\0';
		char *nl = strchr(buf, '\n');
		if (nl)
			*nl = '\0';

		struct uid_data *data = kzalloc(sizeof(struct uid_data), GFP_KERNEL);
		if (!data) {
			kfree(buf);
			filp_close(fp, 0);
			goto out;
		}

		if (!parse_packages_line(buf, data)) {
			kfree(data);
			pr_err("update_uid: bad packages.list line\n");
			break;
		}
		list_add_tail(&data->list, &uid_list);
		// reset line start
		line_start = pos;
	}
	kfree(buf);
	filp_close(fp, 0);

	/* only ever written under throne_tracker_mutex */
	struct ksu_manager_set *old = rcu_dereference_protected(ksu_managers, 1);
	struct ksu_manager_set *set = kzalloc(sizeof(*set), GFP_KERNEL);

	if (!set)
		goto prune;

	if (prune_only) {
		// drop uninstalled managers, refresh version codes
		keep_still_installed(set, old, &uid_list, false);
	} else {
#ifdef KSU_MANAGER_PACKAGE
		pr_info("Searching manager " KSU_MANAGER_PACKAGE "...\n");
#else
		pr_info("Searching managers...\n");
#endif
		search_managers("/data/app", 2, &uid_list, set);
		keep_still_installed(set, old, &uid_list, true);
		pr_info("Search manager finished, %d manager(s)\n", set->count);
	}

	log_changes(set, old);
	rcu_assign_pointer(ksu_managers, set);
	if (old)
		kfree_rcu(old, rcu);

prune:
	// then prune the allowlist
	ksu_prune_allowlist(is_uid_exist, &uid_list);
out:
	// free uid_list
	{
		struct uid_data *np, *n;

		list_for_each_entry_safe (np, n, &uid_list, list) {
			list_del(&np->list);
			kfree(np);
		}
	}
out_revert_cred:
	revert_creds(old_cred);
	mutex_unlock(&throne_tracker_mutex);
}

void __init ksu_throne_tracker_init()
{
	struct apk_sig_cache *c, *n;

	list_for_each_entry_safe (c, n, &apk_sig_cache_list, list) {
		list_del(&c->list);
		kfree(c);
	}
}

void __exit ksu_throne_tracker_exit()
{
	// nothing to do
}

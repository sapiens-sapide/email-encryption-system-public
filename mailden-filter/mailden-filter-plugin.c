/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */
/* hacked by sapiens.sapide */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "safe-mkstemp.h"
#include "mail-user.h"
#include "mail-storage-private.h"
#include "istream.h"
#include "istream-seekable.h"
#include "istream-ext-filter.h"
#include "ostream-ext-filter.h"
#include "mailden-filter-plugin.h"

/* After buffer grows larger than this, create a temporary file to /tmp
   where to read the mail. */
#define MAIL_MAX_MEMORY_BUFFER (1024*128)

#define MAILDEN_FILTER_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mailden_filter_mail_module)
#define MAILDEN_FILTER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mailden_filter_storage_module)
#define MAILDEN_FILTER_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, mailden_filter_user_module)

struct mailden_filter_user {
	union mail_user_module_context module_ctx;

	const char *socket_path, *args;
	const char *out_socket_path, *out_args;
};

const char *mailden_filter_plugin_version = DOVECOT_ABI_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(mailden_filter_user_module,
				  &mail_user_module_register);
static MODULE_CONTEXT_DEFINE_INIT(mailden_filter_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(mailden_filter_mail_module,
				  &mail_module_register);


//stan

//end of stan

static int mailden_filter_mail_save_begin(struct mail_save_context *ctx, struct istream *input)
{

    struct mailbox *box = ctx->transaction->box;
	struct mailden_filter_user *muser = MAILDEN_FILTER_USER_CONTEXT(box->storage->user);
	union mailbox_module_context *mbox = MAILDEN_FILTER_CONTEXT(box);
	struct ostream *output;
    
	if (mbox->super.save_begin(ctx, input) < 0) return -1;
	
    output = o_stream_create_ext_filter(ctx->data.output, muser->out_socket_path, muser->out_args);
	ctx->data.output = output;
    
	return 0;
}

static int seekable_fd_callback(const char **path_r, void *context)
{

    struct mail_user *user = context;
	string_t *path;
	int fd;

	path = t_str_new(128);
	mail_user_set_get_temp_prefix(path, user->set);
	fd = safe_mkstemp(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1) {
		i_error("safe_mkstemp(%s) failed: %m", str_c(path));
		return -1;
	}

	/* we just want the fd, unlink it */
	if (unlink(str_c(path)) < 0) {
		/* shouldn't happen.. */
		i_error("unlink(%s) failed: %m", str_c(path));
		i_close_fd(&fd);
		return -1;
	}

	*path_r = str_c(path);
	return fd;
}

static int mailden_filter_istream_opened(struct mail *_mail, struct istream **stream)
{

    struct mail_private *mail = (struct mail_private *)_mail;
	struct mail_user *user = _mail->box->storage->user;
	struct mailden_filter_user *muser = MAILDEN_FILTER_USER_CONTEXT(user);
	union mail_module_context *mmail = MAILDEN_FILTER_MAIL_CONTEXT(mail);
	struct istream *input, *inputs[2];
    
	input = *stream;
    
	*stream = i_stream_create_ext_filter(input, muser->socket_path, muser->args);
	i_stream_unref(&input);

	inputs[0] = *stream;
	inputs[1] = NULL;
	*stream = i_stream_create_seekable(inputs, MAIL_MAX_MEMORY_BUFFER, seekable_fd_callback, user);
	i_stream_unref(&inputs[0]);

	return mmail->super.istream_opened(_mail, stream);
}

static void mailden_filter_mailbox_allocated(struct mailbox *box)
{

    struct mailbox_vfuncs *v = box->vlast;
	struct mailden_filter_user *muser = MAILDEN_FILTER_USER_CONTEXT(box->storage->user);
	union mailbox_module_context *mbox;
	enum mail_storage_class_flags class_flags = box->storage->class_flags;

	mbox = p_new(box->pool, union mailbox_module_context, 1);
	mbox->super = *v;
	box->vlast = &mbox->super;

	MODULE_CONTEXT_SET_SELF(box, mailden_filter_storage_module, mbox);

	if ((class_flags & MAIL_STORAGE_CLASS_FLAG_OPEN_STREAMS) == 0 &&
	    (class_flags & MAIL_STORAGE_CLASS_FLAG_BINARY_DATA) != 0 &&
	    muser->out_socket_path != NULL)
		v->save_begin = mailden_filter_mail_save_begin;
}

static void mailden_filter_mail_allocated(struct mail *_mail)
{

    struct mail_private *mail = (struct mail_private *)_mail;
	struct mailden_filter_user *muser = MAILDEN_FILTER_USER_CONTEXT(_mail->box->storage->user);
	struct mail_vfuncs *v = mail->vlast;
	union mail_module_context *mmail;

	mmail = p_new(mail->pool, union mail_module_context, 1);
	mmail->super = *v;
	mail->vlast = &mmail->super;

	if (muser->socket_path != NULL)
		v->istream_opened = mailden_filter_istream_opened;
	MODULE_CONTEXT_SET_SELF(mail, mailden_filter_mail_module, mmail);
}

static void
mailden_filter_parse_setting(struct mail_user *user, const char *name,
			  const char **socket_path_r, const char **args_r)
{

    const char *value, *p;

	value = mail_user_plugin_getenv(user, name);
	if (value == NULL)
		return;

	p = strchr(value, ' ');
	if (p == NULL) {
		*socket_path_r = p_strdup(user->pool, value);
		*args_r = "";
	} else {
		*socket_path_r = p_strdup_until(user->pool, value, p);
		*args_r = p_strdup(user->pool, p + 1);
	}
	if (**socket_path_r != '/') {
		/* relative to base_dir */
		*socket_path_r = p_strdup_printf(user->pool, "%s/%s",
			user->set->base_dir, *socket_path_r);
	}
	if (user->mail_debug) {
		i_debug("mailden_filter: Filtering %s via socket %s",
			name, *socket_path_r);
	}
}


static void mailden_filter_mail_user_created(struct mail_user *user)
{

    struct mail_user_vfuncs *v = user->vlast;
	struct mailden_filter_user *muser;

	muser = p_new(user->pool, struct mailden_filter_user, 1);
	muser->module_ctx.super = *v;
	user->vlast = &muser->module_ctx.super;
    
	mailden_filter_parse_setting(user, "mailden_filter", &muser->socket_path, &muser->args);
	mailden_filter_parse_setting(user, "mailden_filter_out", &muser->out_socket_path, &muser->out_args);
    
	if (user->mail_debug && muser->socket_path == NULL && muser->out_socket_path == NULL) {
		i_debug("mailden_filter and mailden_filter_out settings missing, ignoring mailden_filter plugin");
	}

    // arguments passed to decrypt_mail binary
    if (mail_user_plugin_getenv(user,"plain_pass") != NULL) {
        muser->args = p_strconcat(user->pool, mail_user_plugin_getenv(user,"email"), " ", mail_user_plugin_getenv(user,"plain_pass"), NULL);
    } else {
    muser->args = p_strconcat(user->pool, mail_user_plugin_getenv(user,"email"), " ", "n", NULL);
    }
    
    // arguments passed to encrypt_mail binary
    //muser->out_args = mail_user_plugin_getenv(user,"email");
    
 
	MODULE_CONTEXT_SET(user, mailden_filter_user_module, muser);

}

static struct mail_storage_hooks mailden_filter_mail_storage_hooks = {
	.mail_user_created = mailden_filter_mail_user_created,
	.mailbox_allocated = mailden_filter_mailbox_allocated,
	.mail_allocated = mailden_filter_mail_allocated
};

void mailden_filter_plugin_init(struct module *module)
{

    mail_storage_hooks_add(module, &mailden_filter_mail_storage_hooks);
}

/***** implémentation selon « C en action »
struct mail_storage_hooks *plugin_init (struct module *module){
    static struct mail_storage_hooks mailden_filter_mail_storage_hooks = {
        .mail_user_created = mailden_filter_mail_user_created,
        .mailbox_allocated = mailden_filter_mailbox_allocated,
        .mail_allocated = mailden_filter_mail_allocated
    };
    return mailden_filter_mail_storage_hooks;
}
******/

void mailden_filter_plugin_deinit(void)
{
    mail_storage_hooks_remove(&mailden_filter_mail_storage_hooks);
}

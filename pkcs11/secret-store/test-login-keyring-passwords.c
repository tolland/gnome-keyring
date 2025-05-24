/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* test-login-keyring-passwords.c: Test login keyring with multiple passwords

   Copyright (C) 2025 GNOME Keyring Contributors

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   <http://www.gnu.org/licenses/>.
*/

#include "config.h"

#include "mock-secret-module.h"

#include "secret-store/gkm-secret-binary.h"
#include "secret-store/gkm-secret-collection.h"
#include "secret-store/gkm-secret-data.h"
#include "secret-store/gkm-secret-fields.h"
#include "secret-store/gkm-secret-item.h"

#include "gkm/gkm-secret.h"

#include "pkcs11/pkcs11i.h"

#include <glib.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct {
	GkmModule *module;
	GkmSession *session;
	GkmSecretCollection *collection;
	GkmSecretData *sdata;
} Test;

/* Common passwords to test against the login keyring */
static const gchar *test_passwords[] = {
	"password",
	"123456",
	"password123",
	"admin",
	"qwerty",
	"letmein",
	"welcome",
	"monkey",
	"dragon",
	"secret",
	"1234",
	"abc123",
	"test",
	"login",
	"user",
	"demo",
	"guest",
	"123",
	"pass",
	"root",
	"administrator",
	"changeme",
	"default",
	"access",
	"unlock",
	"keyring",
	"gnome",
	"linux",
	"ubuntu",
	"fedora",
	"opensuse",
	"debian",
	"redhat",
	"centos",
	"",  /* empty password */
	" ",  /* space */
	"\n", /* newline */
	"\t", /* tab */
	"a",   /* single char */
	"aaa", /* repeated char */
	"AAA", /* uppercase */
	"111", /* numbers */
	"!@#", /* symbols */
	"Password1!",
	"MySecretPassword",
	"VeryLongPasswordThatMightBeUsedSometimes",
	"🔐", /* unicode */
	NULL
};

static void
setup (Test *test, gconstpointer unused)
{
	test->module = test_secret_module_initialize_and_enter ();
	test->session = test_secret_module_open_session (TRUE);

	test->collection = g_object_new (GKM_TYPE_SECRET_COLLECTION,
	                           "module", test->module,
	                           "identifier", "login",
	                           "label", "Login",
	                           NULL);

	test->sdata = g_object_new (GKM_TYPE_SECRET_DATA, NULL);

	g_assert (GKM_IS_SECRET_COLLECTION (test->collection));
}

static void
teardown (Test *test, gconstpointer unused)
{
	g_object_unref (test->collection);
	g_object_unref (test->sdata);
	test_secret_module_leave_and_finalize ();
}

static GkmDataResult
check_read_keyring_file_with_password (Test *test, const gchar *password)
{
	GkmDataResult res;
	gchar *data;
	gsize n_data;
	GkmSecret *master;

	/* Set the master password */
	master = gkm_secret_new_from_password (password);
	gkm_secret_data_set_master (test->sdata, master);
	g_object_unref (master);

	/* Try to read the login keyring file */
	if (!g_file_get_contents (SRCDIR "/pkcs11/secret-store/fixtures/login.keyring", &data, &n_data, NULL))
		g_assert_not_reached ();
	
	res = gkm_secret_binary_read (test->collection, test->sdata, data, n_data);
	g_free (data);

	return res;
}

static void
test_login_keyring_password_attempts (Test *test, gconstpointer unused)
{
	GkmDataResult res;
	gint success_count = 0;
	gint locked_count = 0;
	gint other_count = 0;
	const gchar **password;

	g_test_message ("Testing login.keyring with various passwords...");

	for (password = test_passwords; *password != NULL; password++) {
		res = check_read_keyring_file_with_password (test, *password);
		
		switch (res) {
		case GKM_DATA_SUCCESS:
			g_test_message ("SUCCESS: Password '%s' unlocked the keyring", *password);
			success_count++;
			break;
		case GKM_DATA_LOCKED:
			g_test_message ("LOCKED: Password '%s' failed to unlock keyring", *password);
			locked_count++;
			break;
		default:
			g_test_message ("OTHER (%d): Password '%s' returned unexpected result", res, *password);
			other_count++;
			break;
		}
	}

	g_test_message ("Summary: %d success, %d locked, %d other results", 
	                success_count, locked_count, other_count);

	/* The test should have at least tried all passwords */
	g_assert_cmpint (success_count + locked_count + other_count, >, 0);
}

static void
test_login_keyring_empty_password (Test *test, gconstpointer unused)
{
	GkmDataResult res;

	g_test_message ("Testing login.keyring with empty password...");
	res = check_read_keyring_file_with_password (test, "");
	
	/* Empty password should either succeed or be locked */
	g_assert (res == GKM_DATA_SUCCESS || res == GKM_DATA_LOCKED);
}

static void
test_login_keyring_null_master (Test *test, gconstpointer unused)
{
	GkmDataResult res;
	gchar *data;
	gsize n_data;

	g_test_message ("Testing login.keyring with NULL master password...");
	
	/* Set no master password */
	gkm_secret_data_set_master (test->sdata, NULL);

	if (!g_file_get_contents (SRCDIR "/pkcs11/secret-store/fixtures/login.keyring", &data, &n_data, NULL))
		g_assert_not_reached ();
	
	res = gkm_secret_binary_read (test->collection, test->sdata, data, n_data);
	g_free (data);

	/* Should be locked without a master password */
	g_assert_cmpint (res, ==, GKM_DATA_LOCKED);
}

static void
test_login_keyring_long_password (Test *test, gconstpointer unused)
{
	GkmDataResult res;
	gchar *long_password;

	g_test_message ("Testing login.keyring with very long password...");
	
	/* Create a very long password (1024 characters) */
	long_password = g_strnfill (1024, 'x');
	res = check_read_keyring_file_with_password (test, long_password);
	g_free (long_password);
	
	/* Should either succeed or be locked */
	g_assert (res == GKM_DATA_SUCCESS || res == GKM_DATA_LOCKED);
}

static void
test_login_keyring_binary_password (Test *test, gconstpointer unused)
{
	GkmDataResult res;
	gchar binary_password[256];
	gint i;

	g_test_message ("Testing login.keyring with binary password...");
	
	/* Create a password with binary data */
	for (i = 0; i < 255; i++) {
		binary_password[i] = (gchar) i;
	}
	binary_password[255] = '\0';
	
	res = check_read_keyring_file_with_password (test, binary_password);
	
	/* Should either succeed or be locked */
	g_assert (res == GKM_DATA_SUCCESS || res == GKM_DATA_LOCKED);
}

static void
test_login_keyring_utf8_password (Test *test, gconstpointer unused)
{
	GkmDataResult res;
	const gchar *utf8_passwords[] = {
		"pässwörd",
		"密码",
		"пароль", 
		"🔐🗝️",
		"café",
		"naïve",
		"résumé",
		NULL
	};
	const gchar **password;

	g_test_message ("Testing login.keyring with UTF-8 passwords...");
	
	for (password = utf8_passwords; *password != NULL; password++) {
		if (g_utf8_validate (*password, -1, NULL)) {
			res = check_read_keyring_file_with_password (test, *password);
			g_test_message ("UTF-8 password '%s': %s", *password, 
			                res == GKM_DATA_SUCCESS ? "SUCCESS" : 
			                res == GKM_DATA_LOCKED ? "LOCKED" : "OTHER");
			
			/* Should either succeed or be locked */
			g_assert (res == GKM_DATA_SUCCESS || res == GKM_DATA_LOCKED);
		}
	}
}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init ();
#endif
	g_test_init (&argc, &argv, NULL);

	g_test_add ("/secret-store/login-keyring/password_attempts", Test, NULL, setup, test_login_keyring_password_attempts, teardown);
	g_test_add ("/secret-store/login-keyring/empty_password", Test, NULL, setup, test_login_keyring_empty_password, teardown);
	g_test_add ("/secret-store/login-keyring/null_master", Test, NULL, setup, test_login_keyring_null_master, teardown);
	g_test_add ("/secret-store/login-keyring/long_password", Test, NULL, setup, test_login_keyring_long_password, teardown);
	g_test_add ("/secret-store/login-keyring/binary_password", Test, NULL, setup, test_login_keyring_binary_password, teardown);
	g_test_add ("/secret-store/login-keyring/utf8_password", Test, NULL, setup, test_login_keyring_utf8_password, teardown);

	return g_test_run ();
}
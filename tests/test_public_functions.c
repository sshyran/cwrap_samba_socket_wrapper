#include "torture.h"

#include <errno.h>
#include <stdio.h>
#include <cmocka.h>
#include <unistd.h>
#include <stdlib.h>

#include <socket_wrapper.h>

static int setup_enabled(void **state)
{
	torture_setup_socket_dir(state);

	return 0;
}

static int teardown_enabled(void **state)
{
	torture_teardown_socket_dir(state);

	return 0;
}

static int setup_disabled(void **state)
{
	(void) state; /* unused */

	unsetenv("SOCKET_WRAPPER_DIR");
	unsetenv("SOCKET_WRAPPER_DEFAULT_IFACE");
	unsetenv("SOCKET_WRAPPER_PCAP_FILE");

	return 0;
}

static int teardown_disabled(void **state)
{
	(void) state; /* unused */

	return 0;
}

static void test_call_enabled_true(void **state)
{
	char *s = getenv("SOCKET_WRAPPER_DIR");

	(void) state; /* unused */

	assert_true(socket_wrapper_enabled());
	assert_true(s != NULL);
}

static void test_call_enabled_false(void **state)
{
	char *s = getenv("SOCKET_WRAPPER_DIR");

	(void) state; /* unused */

	assert_false(socket_wrapper_enabled());
	assert_false(s != NULL);
}

static void test_call_indicate_no_inet_fd(void **state)
{
	int rc;
	int s = -1;

	(void) state; /* unused */

	socket_wrapper_indicate_no_inet_fd(987654321);
	socket_wrapper_indicate_no_inet_fd(-1);

	rc = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (rc >= 0) {
		s = rc;
		rc = 0;
	}
	assert_return_code(rc, errno);

	socket_wrapper_indicate_no_inet_fd(987654321);
	socket_wrapper_indicate_no_inet_fd(-1);
	socket_wrapper_indicate_no_inet_fd(s);
	socket_wrapper_indicate_no_inet_fd(0);
	socket_wrapper_indicate_no_inet_fd(1);
	socket_wrapper_indicate_no_inet_fd(2);
}

int main(void) {
	int rc;

	const struct CMUnitTest max_sockets_tests[] = {
		cmocka_unit_test_setup_teardown(test_call_enabled_true,
						setup_enabled,
						teardown_enabled),
		cmocka_unit_test_setup_teardown(test_call_enabled_false,
						setup_disabled,
						teardown_disabled),
		cmocka_unit_test_setup_teardown(test_call_indicate_no_inet_fd,
						setup_enabled,
						teardown_enabled),
		cmocka_unit_test_setup_teardown(test_call_indicate_no_inet_fd,
						setup_disabled,
						teardown_disabled),
	};

	rc = cmocka_run_group_tests(max_sockets_tests, NULL, NULL);

	return rc;
}

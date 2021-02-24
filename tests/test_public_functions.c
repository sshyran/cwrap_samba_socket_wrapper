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

int main(void) {
	int rc;

	const struct CMUnitTest max_sockets_tests[] = {
		cmocka_unit_test_setup_teardown(test_call_enabled_true,
						setup_enabled,
						teardown_enabled),
		cmocka_unit_test_setup_teardown(test_call_enabled_false,
						setup_disabled,
						teardown_disabled),
	};

	rc = cmocka_run_group_tests(max_sockets_tests, NULL, NULL);

	return rc;
}

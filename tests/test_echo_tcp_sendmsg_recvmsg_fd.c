#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "config.h"
#include "torture.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

static int setup_echo_srv_tcp_ipv4(void **state)
{
	torture_setup_echo_srv_tcp_ipv4(state);

	return 0;
}

static int teardown(void **state)
{
	torture_teardown_echo_srv(state);

	return 0;
}

struct test_fd {
	int fd;
	struct torture_address sock_addr;
	struct torture_address peer_addr;
};

static int test_fill_test_fd(struct test_fd *tfd, int fd)
{
	struct torture_address saddr = {
		.sa_socklen = sizeof(struct sockaddr_storage),
	};
	struct torture_address paddr = {
		.sa_socklen = sizeof(struct sockaddr_storage),
	};
	int ret;

	*tfd = (struct test_fd) { .fd = fd, };

	ret = getsockname(fd, &saddr.sa.s, &saddr.sa_socklen);
	if (ret == -1 && errno == ENOTSOCK) {
		return 0;
	}
	if (ret == -1) {
		return ret;
	}

	ret = getpeername(fd, &paddr.sa.s, &paddr.sa_socklen);
	if (ret == -1) {
		return ret;
	}

	tfd->sock_addr = saddr;
	tfd->peer_addr = paddr;
	return 0;
}

static void _assert_torture_address_equal(const struct torture_address *ga,
					  const struct torture_address *ea,
					  const char * const file,
					  const int line)
{
	_assert_int_equal(ga->sa_socklen, ea->sa_socklen, file, line);
	if (ga->sa_socklen == 0) {
		return;
	}
	_assert_memory_equal(&ga->sa, &ea->sa, ga->sa_socklen, file, line);
}

#define assert_test_fd_equal(gfd, efd) \
	_assert_test_fd_equal(gfd, efd, __FILE__, __LINE__)

static void _assert_test_fd_equal(const struct test_fd *gfd,
				  const struct test_fd *efd,
				  const char * const file,
				  const int line)
{
	if (efd->fd == -1) {
		_assert_int_equal(gfd->fd, -1, file, line);
		return;
	}

	_assert_int_not_equal(gfd->fd, -1, file, line);

	_assert_torture_address_equal(&gfd->sock_addr, &efd->sock_addr, file, line);
	_assert_torture_address_equal(&gfd->peer_addr, &efd->peer_addr, file, line);
}

static void test_tcp_sendmsg_recvmsg_fd_array(const int *fds, size_t num_fds)
{
	struct test_fd tfds[num_fds];
	size_t idx;
	int sv[2];
	int child_fd, parent_fd;
	pid_t pid;
	int rc;

	for (idx = 0; idx < num_fds; idx++) {
		rc = test_fill_test_fd(&tfds[idx], fds[idx]);
		assert_int_equal(rc, 0);
	}

	/* create unix domain socket stream */
	rc = socketpair(AF_LOCAL, SOCK_STREAM, 0, sv);
	assert_int_not_equal(rc, -1);

	parent_fd = sv[0];
	child_fd = sv[1];

	pid = fork();
	assert_int_not_equal(pid, -1);

	if (pid == 0) {
		/* Child */
		struct msghdr child_msg;
		int recv_fd_array[num_fds];
		char cmsgbuf[CMSG_SPACE(sizeof(int)*num_fds)];
		struct cmsghdr *cmsg;
		ssize_t ret;
		char byte = { 0, };
		struct iovec iov;

		iov.iov_base = &byte;
		iov.iov_len = 1;

		memset(&child_msg, 0, sizeof(child_msg));
		child_msg.msg_iov = &iov;
		child_msg.msg_iovlen = 1;
		child_msg.msg_control = cmsgbuf;
		child_msg.msg_controllen = sizeof(cmsgbuf);

		rc = recvmsg(child_fd, &child_msg, 0);
		assert_int_equal(rc, iov.iov_len);
		assert_int_equal(byte, '!');

		cmsg = CMSG_FIRSTHDR(&child_msg);
		assert_non_null(cmsg);
		assert_int_equal(cmsg->cmsg_type, SCM_RIGHTS);

		memcpy(recv_fd_array, CMSG_DATA(cmsg), sizeof(int)*num_fds);
		for (idx = 0; idx < num_fds; idx++) {
			assert_int_not_equal(recv_fd_array[idx], -1);
		}

		for (idx = 0; idx < num_fds; idx++) {
			struct test_fd recv_tfd = { .fd = -1, };

			ret = test_fill_test_fd(&recv_tfd, recv_fd_array[idx]);
			assert_int_equal(ret, 0);

			assert_test_fd_equal(&recv_tfd, &tfds[idx]);
		}

		for (idx = 0; idx < num_fds; idx++) {
			int recv_fd = recv_fd_array[idx];
			char send_buf[64] = {0,};
			char recv_buf[64] = {0,};

			if (tfds[idx].sock_addr.sa_socklen == 0) {
				/*
				 * skip fds not belonging to
				 * a socket.
				 */
				continue;
			}

			snprintf(send_buf, sizeof(send_buf), "packet");

			ret = write(recv_fd,
				    send_buf,
				    sizeof(send_buf));
			assert_int_not_equal(ret, -1);

			ret = read(recv_fd,
				   recv_buf,
				   sizeof(recv_buf));
			assert_int_not_equal(ret, -1);

			assert_memory_equal(send_buf, recv_buf, sizeof(send_buf));
		}

		exit(0);
	} else {
		/* Parent */
		struct msghdr parent_msg;
		struct cmsghdr *cmsg;
		char cmsgbuf[CMSG_SPACE(sizeof(int)*num_fds)];
		int pass_fd_array[num_fds];
		char byte = '!';
		struct iovec iov;
		int cs;

		for (idx = 0; idx < num_fds; idx++) {
			pass_fd_array[idx] = tfds[idx].fd;
		}

		iov.iov_base = &byte;
		iov.iov_len = 1;

		memset(&parent_msg, 0, sizeof(parent_msg));
		parent_msg.msg_iov = &iov;
		parent_msg.msg_iovlen = 1;
		parent_msg.msg_control = cmsgbuf;
		parent_msg.msg_controllen = sizeof(cmsgbuf);

		cmsg = CMSG_FIRSTHDR(&parent_msg);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int)*num_fds);

		/* place previously connected socket fd as ancillary data */
		memcpy(CMSG_DATA(cmsg), pass_fd_array, sizeof(int)*num_fds);
		parent_msg.msg_controllen = cmsg->cmsg_len;

		rc = sendmsg(parent_fd, &parent_msg, 0);
		assert_int_not_equal(rc, -1);

		alarm(5);	    /* 5 seconds timeout for the child */
		waitpid(pid, &cs, 0);
		if (WIFEXITED(cs)) {
			assert_int_equal(WEXITSTATUS(cs), 0);
		}
	}
}

static void test_tcp_sendmsg_recvmsg_fd_same(size_t num_fds)
{
	struct torture_address addr = {
		.sa_socklen = sizeof(struct sockaddr_in),
	};
	int pass_sock_fd;
	int fd_array[num_fds];
	size_t idx;
	int rc;

	/* create socket file descriptor to be passed */
	pass_sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert_int_not_equal(pass_sock_fd, -1);

	addr.sa.in.sin_family = AF_INET;
	addr.sa.in.sin_port = htons(torture_server_port());

	rc = inet_pton(addr.sa.in.sin_family,
		       torture_server_address(AF_INET),
		       &addr.sa.in.sin_addr);
	assert_int_equal(rc, 1);

	rc = connect(pass_sock_fd, &addr.sa.s, addr.sa_socklen);
	assert_int_equal(rc, 0);

	for (idx = 0; idx < num_fds; idx++) {
		fd_array[idx] = pass_sock_fd;
	}

	test_tcp_sendmsg_recvmsg_fd_array(fd_array, num_fds);

	close(pass_sock_fd);
}

static void test_tcp_sendmsg_recvmsg_fd_1(void **state)
{
	(void) state; /* unused */
	test_tcp_sendmsg_recvmsg_fd_same(1);
}

static void test_tcp_sendmsg_recvmsg_fd_2s(void **state)
{
	(void) state; /* unused */
	test_tcp_sendmsg_recvmsg_fd_same(2);
}

static void test_tcp_sendmsg_recvmsg_fd_3s(void **state)
{
	(void) state; /* unused */
	test_tcp_sendmsg_recvmsg_fd_same(3);
}

static void test_tcp_sendmsg_recvmsg_fd_4s(void **state)
{
	(void) state; /* unused */
	test_tcp_sendmsg_recvmsg_fd_same(4);
}

static void test_tcp_sendmsg_recvmsg_fd_5s(void **state)
{
	(void) state; /* unused */
	test_tcp_sendmsg_recvmsg_fd_same(5);
}

static void test_tcp_sendmsg_recvmsg_fd_6s(void **state)
{
	(void) state; /* unused */
	test_tcp_sendmsg_recvmsg_fd_same(6);
}

int main(void) {
	int rc;

	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_tcp_sendmsg_recvmsg_fd_1,
				 setup_echo_srv_tcp_ipv4,
				 teardown),
		cmocka_unit_test_setup_teardown(test_tcp_sendmsg_recvmsg_fd_2s,
				 setup_echo_srv_tcp_ipv4,
				 teardown),
		cmocka_unit_test_setup_teardown(test_tcp_sendmsg_recvmsg_fd_3s,
				 setup_echo_srv_tcp_ipv4,
				 teardown),
		cmocka_unit_test_setup_teardown(test_tcp_sendmsg_recvmsg_fd_4s,
				 setup_echo_srv_tcp_ipv4,
				 teardown),
		cmocka_unit_test_setup_teardown(test_tcp_sendmsg_recvmsg_fd_5s,
				 setup_echo_srv_tcp_ipv4,
				 teardown),
		cmocka_unit_test_setup_teardown(test_tcp_sendmsg_recvmsg_fd_6s,
				 setup_echo_srv_tcp_ipv4,
				 teardown),
	};

	rc = cmocka_run_group_tests(tests, NULL, NULL);

	return rc;
}

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

static void test_tcp_sendmsg_recvmsg_fd(void **state)
{
	struct torture_address addr = {
		.sa_socklen = sizeof(struct sockaddr_in),
	};
	int pass_sock_fd;
	int sv[2];
	int child_fd, parent_fd;
	pid_t pid;
	int rc;

	(void) state; /* unused */

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

	/* create unix domain socket stream */
	rc = socketpair(AF_LOCAL, SOCK_STREAM, 0, sv);
	assert_int_not_equal(rc, -1);

	parent_fd = sv[0];
	child_fd = sv[1];

	pid = fork();
	assert_int_not_equal(pid, -1);

	if (pid == 0) {
		/* Child */
		struct torture_address peer_addr = {
			.sa_socklen = sizeof(struct sockaddr_in),
		};
		struct msghdr child_msg;
		char cmsgbuf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr *cmsg;
		int rcv_sock_fd, port;
		ssize_t ret;
		char send_buf[64] = {0};
		char recv_buf[64] = {0};
		char ipstr[INET_ADDRSTRLEN];
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

		memcpy(&rcv_sock_fd, CMSG_DATA(cmsg), sizeof(rcv_sock_fd));
		assert_int_not_equal(rcv_sock_fd, -1);

		/* extract peer info from received socket fd */
		ret = getpeername(rcv_sock_fd, &peer_addr.sa.s, &peer_addr.sa_socklen);
		assert_int_not_equal(ret, -1);

		port = ntohs(peer_addr.sa.in.sin_port);
		inet_ntop(AF_INET, &peer_addr.sa.in.sin_addr, ipstr, sizeof(ipstr));

		/* check whether it is the same socket previously connected */
		assert_string_equal(ipstr, torture_server_address(AF_INET));
		assert_int_equal(port, torture_server_port());

		snprintf(send_buf, sizeof(send_buf), "packet");

		ret = write(rcv_sock_fd,
			    send_buf,
			    sizeof(send_buf));
		assert_int_not_equal(ret, -1);

		ret = read(rcv_sock_fd,
			   recv_buf,
			   sizeof(recv_buf));
		assert_int_not_equal(ret, -1);

		assert_memory_equal(send_buf, recv_buf, sizeof(send_buf));

		exit(0);
	} else {
		/* Parent */
		struct msghdr parent_msg;
		struct cmsghdr *cmsg;
		char cmsgbuf[CMSG_SPACE(sizeof(pass_sock_fd))];
		char byte = '!';
		struct iovec iov;
		int cs;

		(void) state; /* unused */

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
		cmsg->cmsg_len = CMSG_LEN(sizeof(pass_sock_fd));

		/* place previously connected socket fd as ancillary data */
		memcpy(CMSG_DATA(cmsg), &pass_sock_fd, sizeof(pass_sock_fd));
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

int main(void) {
	int rc;

	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_tcp_sendmsg_recvmsg_fd,
				 setup_echo_srv_tcp_ipv4,
				 teardown)
	};

	rc = cmocka_run_group_tests(tests, NULL, NULL);

	return rc;
}

/* This example is placed in the public domain. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>

static int data_attr_cb2(const struct nlattr *attr, void *data)
{
	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, RTAX_MAX) < 0)
		return MNL_CB_OK;

	if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
		perror("mnl_attr_validate");
		return MNL_CB_ERROR;
	}
	return MNL_CB_OK;
}

static void attributes_show_ipv4(struct nlattr *tb[])
{
	if (tb[RTA_TABLE]) {
		printf("table=%u ", mnl_attr_get_u32(tb[RTA_TABLE]));
	}
	if (tb[RTA_DST]) {
		struct in_addr *addr = mnl_attr_get_payload(tb[RTA_DST]);
		printf("dst=%s ", inet_ntoa(*addr));
	}
	if (tb[RTA_SRC]) {
		struct in_addr *addr = mnl_attr_get_payload(tb[RTA_SRC]);
		printf("src=%s ", inet_ntoa(*addr));
	}
	if (tb[RTA_OIF]) {
		printf("oif=%u ", mnl_attr_get_u32(tb[RTA_OIF]));
	}
	if (tb[RTA_FLOW]) {
		printf("flow=%u ", mnl_attr_get_u32(tb[RTA_FLOW]));
	}
	if (tb[RTA_PREFSRC]) {
		struct in_addr *addr = mnl_attr_get_payload(tb[RTA_PREFSRC]);
		printf("prefsrc=%s ", inet_ntoa(*addr));
	}
	if (tb[RTA_GATEWAY]) {
		struct in_addr *addr = mnl_attr_get_payload(tb[RTA_GATEWAY]);
		printf("gw=%s ", inet_ntoa(*addr));
	}
	if (tb[RTA_METRICS]) {
		int i;
		struct nlattr *tbx[RTAX_MAX+1] = {};

		mnl_attr_parse_nested(tb[RTA_METRICS], data_attr_cb2, tbx);

		for (i=0; i<RTAX_MAX; i++) {
			if (tbx[i]) {
				printf("metrics[%d]=%u ",
					i, mnl_attr_get_u32(tbx[i]));
			}
		}
	}
	printf("\n");
}

/* like inet_ntoa(), not reentrant */
static const char *inet6_ntoa(struct in6_addr in6)
{
	static char buf[INET6_ADDRSTRLEN];

	return inet_ntop(AF_INET6, &in6.s6_addr, buf, sizeof(buf));
}

static void attributes_show_ipv6(struct nlattr *tb[])
{
	if (tb[RTA_TABLE]) {
		printf("table=%u ", mnl_attr_get_u32(tb[RTA_TABLE]));
	}
	if (tb[RTA_DST]) {
		struct in6_addr *addr = mnl_attr_get_payload(tb[RTA_DST]);
		printf("dst=%s ", inet6_ntoa(*addr));
	}
	if (tb[RTA_SRC]) {
		struct in6_addr *addr = mnl_attr_get_payload(tb[RTA_SRC]);
		printf("src=%s ", inet6_ntoa(*addr));
	}
	if (tb[RTA_OIF]) {
		printf("oif=%u ", mnl_attr_get_u32(tb[RTA_OIF]));
	}
	if (tb[RTA_FLOW]) {
		printf("flow=%u ", mnl_attr_get_u32(tb[RTA_FLOW]));
	}
	if (tb[RTA_PREFSRC]) {
		struct in6_addr *addr = mnl_attr_get_payload(tb[RTA_PREFSRC]);
		printf("prefsrc=%s ", inet6_ntoa(*addr));
	}
	if (tb[RTA_GATEWAY]) {
		struct in6_addr *addr = mnl_attr_get_payload(tb[RTA_GATEWAY]);
		printf("gw=%s ", inet6_ntoa(*addr));
	}
	if (tb[RTA_METRICS]) {
		int i;
		struct nlattr *tbx[RTAX_MAX+1] = {};

		mnl_attr_parse_nested(tb[RTA_METRICS], data_attr_cb2, tbx);

		for (i=0; i<RTAX_MAX; i++) {
			if (tbx[i]) {
				printf("metrics[%d]=%u ",
					i, mnl_attr_get_u32(tbx[i]));
			}
		}
	}
	printf("\n");
}

static int data_ipv4_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case RTA_TABLE:
	case RTA_DST:
	case RTA_SRC:
	case RTA_OIF:
	case RTA_FLOW:
	case RTA_PREFSRC:
	case RTA_GATEWAY:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case RTA_METRICS:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int data_ipv6_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case RTA_TABLE:
	case RTA_OIF:
	case RTA_FLOW:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case RTA_DST:
	case RTA_SRC:
	case RTA_PREFSRC:
	case RTA_GATEWAY:
		if (mnl_attr_validate2(attr, MNL_TYPE_BINARY,
					sizeof(struct in6_addr)) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case RTA_METRICS:
		if (mnl_attr_validate(attr, MNL_TYPE_NESTED) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int data_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[RTA_MAX+1] = {};
	struct rtmsg *rm = mnl_nlmsg_get_payload(nlh);

	/* protocol family = AF_INET | AF_INET6 */
	printf("family=%u ", rm->rtm_family);

	/* destination CIDR, eg. 24 or 32 for IPv4 */
	printf("dst_len=%u ", rm->rtm_dst_len);

	/* source CIDR */
	printf("src_len=%u ", rm->rtm_src_len);

	/* type of service (TOS), eg. 0 */
	printf("tos=%u ", rm->rtm_tos);

	/* table id:
	 *	RT_TABLE_UNSPEC		= 0
	 *
	 * 	... user defined values ...
	 *
	 *	RT_TABLE_COMPAT		= 252
	 *	RT_TABLE_DEFAULT	= 253
	 *	RT_TABLE_MAIN		= 254
	 *	RT_TABLE_LOCAL		= 255
	 *	RT_TABLE_MAX		= 0xFFFFFFFF
	 *
	 * Synonimous attribute: RTA_TABLE.
	 */
	printf("table=%u ", rm->rtm_table);

	/* type:
	 * 	RTN_UNSPEC	= 0
	 * 	RTN_UNICAST	= 1
	 * 	RTN_LOCAL	= 2
	 * 	RTN_BROADCAST	= 3
	 *	RTN_ANYCAST	= 4
	 *	RTN_MULTICAST	= 5
	 *	RTN_BLACKHOLE	= 6
	 *	RTN_UNREACHABLE	= 7
	 *	RTN_PROHIBIT	= 8
	 *	RTN_THROW	= 9
	 *	RTN_NAT		= 10
	 *	RTN_XRESOLVE	= 11
	 *	__RTN_MAX	= 12
	 */
	printf("type=%u ", rm->rtm_type);

	/* scope:
	 * 	RT_SCOPE_UNIVERSE	= 0   : everywhere in the universe
	 *
	 *      ... user defined values ...
	 *
	 * 	RT_SCOPE_SITE		= 200
	 * 	RT_SCOPE_LINK		= 253 : destination attached to link
	 * 	RT_SCOPE_HOST		= 254 : local address
	 * 	RT_SCOPE_NOWHERE	= 255 : not existing destination
	 */
	printf("scope=%u ", rm->rtm_scope);

	/* protocol:
	 * 	RTPROT_UNSPEC	= 0
	 * 	RTPROT_REDIRECT = 1
	 * 	RTPROT_KERNEL	= 2 : route installed by kernel
	 * 	RTPROT_BOOT	= 3 : route installed during boot
	 * 	RTPROT_STATIC	= 4 : route installed by administrator
	 *
	 * Values >= RTPROT_STATIC are not interpreted by kernel, they are
	 * just user-defined.
	 */
	printf("proto=%u ", rm->rtm_protocol);

	/* flags:
	 * 	RTM_F_NOTIFY	= 0x100: notify user of route change
	 * 	RTM_F_CLONED	= 0x200: this route is cloned
	 * 	RTM_F_EQUALIZE	= 0x400: Multipath equalizer: NI
	 * 	RTM_F_PREFIX	= 0x800: Prefix addresses
	 */
	printf("flags=%x\n", rm->rtm_flags);

	switch(rm->rtm_family) {
	case AF_INET:
		mnl_attr_parse(nlh, sizeof(*rm), data_ipv4_attr_cb, tb);
		attributes_show_ipv4(tb);
		break;
	case AF_INET6:
		mnl_attr_parse(nlh, sizeof(*rm), data_ipv6_attr_cb, tb);
		attributes_show_ipv6(tb);
		break;
	}

	return MNL_CB_OK;
}

static int mnl_socket_poll(struct mnl_socket *nl)
{
	struct pollfd pfds[1];

	while (1) {
		pfds[0].fd	= mnl_socket_get_fd(nl);
		pfds[0].events	= POLLIN | POLLERR;
		pfds[0].revents = 0;

		if (poll(pfds, 1, -1) < 0 && errno != -EINTR)
			return -1;

		if (pfds[0].revents & POLLIN)
			return 0;
		if (pfds[0].revents & POLLERR)
			return -1;
	}
}

int main(int argc, char *argv[])
{
	struct mnl_socket *nl;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nl_mmap_hdr *hdr;
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	ssize_t len;
	void *ptr;
	int ret;
	unsigned int seq, portid;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <inet|inet6>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_GETROUTE;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = seq = time(NULL);
	rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));

	if (strcmp(argv[1], "inet") == 0)
		rtm->rtm_family = AF_INET;
	else if (strcmp(argv[1], "inet6") == 0)
		rtm->rtm_family = AF_INET6;

	nl = mnl_socket_open(NETLINK_ROUTE);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_set_ring(nl, 0, 0) < 0) {
		perror("mnl_socket_set_ring");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	portid = mnl_socket_get_portid(nl);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	while (1) {
		ret = mnl_socket_poll(nl);
		if (ret < 0) {
			perror("mnl_socket_poll");
			exit(EXIT_FAILURE);
		}

		while (1) {
			hdr = mnl_socket_get_frame(nl, MNL_RING_RX);

			if (hdr->nm_status == NL_MMAP_STATUS_VALID) {
				ptr = (void *)hdr + NL_MMAP_HDRLEN;
				len = hdr->nm_len;
				if (len == 0)
					goto next;
			} else if (hdr->nm_status == NL_MMAP_STATUS_COPY) {
				len = recv(mnl_socket_get_fd(nl),
					   buf, sizeof(buf), MSG_DONTWAIT);
				if (len <= 0)
					break;
				ptr = buf;
			} else
				break;

			ret = mnl_cb_run(ptr, len, seq, portid, data_cb, NULL);
			if (ret <= MNL_CB_STOP)
				goto end;
next:
			hdr->nm_status = NL_MMAP_STATUS_UNUSED;
			mnl_socket_advance_ring(nl, MNL_RING_RX);
		}
	}
end:
	if (ret == -1) {
		perror("error");
		exit(EXIT_FAILURE);
	}

	mnl_socket_close(nl);

	return 0;
}

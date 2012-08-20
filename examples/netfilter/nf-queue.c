/* This example is placed in the public domain. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#ifndef aligned_be64
#define aligned_be64 u_int64_t __attribute__((aligned(8)))
#endif

#include <linux/netfilter/nfnetlink_queue.h>

static int parse_attr_cb(const struct nlattr *attr, void *data)
{
        const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, NFQA_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFQA_MARK:
	case NFQA_IFINDEX_INDEV:
	case NFQA_IFINDEX_OUTDEV:
	case NFQA_IFINDEX_PHYSINDEV:
	case NFQA_IFINDEX_PHYSOUTDEV:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFQA_TIMESTAMP:
		if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,
		    sizeof(struct nfqnl_msg_packet_timestamp)) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFQA_HWADDR:
		if (mnl_attr_validate2(attr, MNL_TYPE_UNSPEC,
		    sizeof(struct nfqnl_msg_packet_hw)) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFQA_PAYLOAD:
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

static int queue_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[NFQA_MAX+1] = {};
	struct nfqnl_msg_packet_hdr *ph = NULL;
	uint32_t id = 0;

	mnl_attr_parse(nlh, sizeof(struct nfgenmsg), parse_attr_cb, tb);
	if (tb[NFQA_PACKET_HDR]) {
		ph = mnl_attr_get_payload(tb[NFQA_PACKET_HDR]);
		id = ntohl(ph->packet_id);
	}
	printf("packet received (id=%u hw=0x%04x hook=%u)\n",
		id, ntohs(ph->hw_protocol), ph->hook);

	return MNL_CB_OK + id;
}

static struct nlmsghdr *
nfq_build_cfg_pf_request(struct mnl_socket *nl, uint8_t command)
{
	struct nl_mmap_hdr *hdr;

	hdr = mnl_socket_get_frame(nl, MNL_RING_TX);
	if (hdr->nm_status != NL_MMAP_STATUS_UNUSED)
		return NULL;
	mnl_socket_advance_ring(nl, MNL_RING_TX);

	struct nlmsghdr *nlh = mnl_nlmsg_put_header((void *)hdr + NL_MMAP_HDRLEN);
	nlh->nlmsg_type	= (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;

	struct nfqnl_msg_config_cmd cmd = {
		.command = command,
		.pf = htons(AF_INET),
	};
	mnl_attr_put(nlh, NFQA_CFG_CMD, sizeof(cmd), &cmd);

	hdr->nm_len    = nlh->nlmsg_len;
	hdr->nm_status = NL_MMAP_STATUS_VALID;
	return nlh;
}

static struct nlmsghdr *
nfq_build_cfg_request(struct mnl_socket *nl, uint8_t command, int queue_num)
{
	struct nl_mmap_hdr *hdr;

	hdr = mnl_socket_get_frame(nl, MNL_RING_TX);
	if (hdr->nm_status != NL_MMAP_STATUS_UNUSED)
		return NULL;
	mnl_socket_advance_ring(nl, MNL_RING_TX);

	struct nlmsghdr *nlh = mnl_nlmsg_put_header((void *)hdr + NL_MMAP_HDRLEN);
	nlh->nlmsg_type	= (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(queue_num);

	struct nfqnl_msg_config_cmd cmd = {
		.command = command,
		.pf = htons(AF_INET),
	};
	mnl_attr_put(nlh, NFQA_CFG_CMD, sizeof(cmd), &cmd);

	hdr->nm_len    = nlh->nlmsg_len;
	hdr->nm_status = NL_MMAP_STATUS_VALID;
	return nlh;
}

static struct nlmsghdr *
nfq_build_cfg_params(struct mnl_socket *nl, uint8_t mode, int range, int queue_num)
{
	struct nl_mmap_hdr *hdr;

	hdr = mnl_socket_get_frame(nl, MNL_RING_TX);
	if (hdr->nm_status != NL_MMAP_STATUS_UNUSED)
		return NULL;
	mnl_socket_advance_ring(nl, MNL_RING_TX);

	struct nlmsghdr *nlh = mnl_nlmsg_put_header((void *)hdr + NL_MMAP_HDRLEN);
	nlh->nlmsg_type	= (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(queue_num);

	struct nfqnl_msg_config_params params = {
		.copy_range = htonl(range),
		.copy_mode = mode,
	};
	mnl_attr_put(nlh, NFQA_CFG_PARAMS, sizeof(params), &params);

	hdr->nm_len    = nlh->nlmsg_len;
	hdr->nm_status = NL_MMAP_STATUS_VALID;
	return nlh;
}

static struct nlmsghdr *
nfq_build_verdict(struct mnl_socket *nl, int id, int queue_num, int verd)
{
	struct nl_mmap_hdr *hdr;

	hdr = mnl_socket_get_frame(nl, MNL_RING_TX);
	if (hdr->nm_status != NL_MMAP_STATUS_UNUSED)
		return NULL;
	mnl_socket_advance_ring(nl, MNL_RING_TX);

	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;

	nlh = mnl_nlmsg_put_header((void *)hdr + NL_MMAP_HDRLEN);
	nlh->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(queue_num);

	struct nfqnl_msg_verdict_hdr vh = {
		.verdict = htonl(verd),
		.id = htonl(id),
	};
	mnl_attr_put(nlh, NFQA_VERDICT_HDR, sizeof(vh), &vh);

	hdr->nm_len    = nlh->nlmsg_len;
	hdr->nm_status = NL_MMAP_STATUS_VALID;
	return nlh;
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
	char buf[16384];
	struct nl_mmap_hdr *hdr;
	struct nlmsghdr *nlh;
	ssize_t len;
	void *ptr;
	int ret;
	unsigned int portid, queue_num;

	if (argc != 2) {
		printf("Usage: %s [queue_num]\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	queue_num = atoi(argv[1]);

	nl = mnl_socket_open(NETLINK_NETFILTER);
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

	nlh = nfq_build_cfg_pf_request(nl, NFQNL_CFG_CMD_PF_UNBIND);

	if (mnl_socket_sendto(nl, NULL, 0) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	nlh = nfq_build_cfg_pf_request(nl, NFQNL_CFG_CMD_PF_BIND);

	if (mnl_socket_sendto(nl, NULL, 0) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	nlh = nfq_build_cfg_request(nl, NFQNL_CFG_CMD_BIND, queue_num);

	if (mnl_socket_sendto(nl, NULL, 0) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	nlh = nfq_build_cfg_params(nl, NFQNL_COPY_PACKET, 0xFFFF, queue_num);

	if (mnl_socket_sendto(nl, NULL, 0) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	while (1) {
		uint32_t id;

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
					goto release;
			} else if (hdr->nm_status == NL_MMAP_STATUS_COPY) {
				len = recv(mnl_socket_get_fd(nl),
					   buf, sizeof(buf), MSG_DONTWAIT);
				if (len <= 0)
					break;
				ptr = buf;
			} else
				break;

			ret = mnl_cb_run(ptr, len, 0, portid, queue_cb, NULL);
			if (ret < 0){
				perror("mnl_cb_run");
				exit(EXIT_FAILURE);
			}

			id = ret - MNL_CB_OK;
			nlh = nfq_build_verdict(nl, id, queue_num, NF_ACCEPT);
			if (mnl_socket_sendto(nl, NULL, 0) < 0) {
				perror("mnl_socket_send");
				exit(EXIT_FAILURE);
			}
release:
			hdr->nm_status = NL_MMAP_STATUS_UNUSED;
			mnl_socket_advance_ring(nl, MNL_RING_RX);
		}
	}

	mnl_socket_close(nl);

	return 0;
}


#ifndef _NFCT_OBJECT_H_
#define _NFCT_OBJECT_H_

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>


struct nfct_handle {
	struct nfnl_handle		*nfnlh;
	struct nfnl_subsys_handle	*nfnlssh_ct;
	struct nfnl_subsys_handle	*nfnlssh_exp;

	
	struct nfnl_callback		nfnl_cb_ct;
	struct nfnl_callback		nfnl_cb_exp;

	int			(*cb)(enum nf_conntrack_msg_type type, 
				      struct nf_conntrack *ct,
				      void *data);

	int			(*cb2)(const struct nlmsghdr *nlh,
				       enum nf_conntrack_msg_type type,
				       struct nf_conntrack *ct,
				       void *data);

	int			(*expect_cb)(enum nf_conntrack_msg_type type, 
					     struct nf_expect *exp,
					     void *data);

	
	int			(*expect_cb2)(const struct nlmsghdr *nlh,
					      enum nf_conntrack_msg_type type, 
					      struct nf_expect *exp,
					      void *data);
};

struct __data_container {
	struct nfct_handle *h;
	enum nf_conntrack_msg_type type;
	void *data;
};


union __nfct_l4_src {
	
	u_int16_t 		all;
	struct {
		u_int16_t 	port;
	} tcp;
	struct {
		u_int16_t 	port;
	} udp;
	struct {
		u_int16_t 	id;
	} icmp;
	struct {
		u_int16_t 	port;
	} sctp;
	struct {
		u_int16_t 	port;
	} dccp;
};

union __nfct_l4_dst {
	
	u_int16_t 		all;
	struct {
		u_int16_t 	port;
	} tcp;
	struct {
		u_int16_t 	port;
	} udp;
	struct {
		u_int8_t 	type, code;
	} icmp;
	struct {
		u_int16_t 	port;
	} sctp;
	struct {
		u_int16_t 	port;
	} dccp;
};

union __nfct_address {
	u_int32_t 		v4;
	struct in6_addr 	v6;
};

struct __nfct_tuple {
	union __nfct_address	src;
	union __nfct_address 	dst;

	u_int8_t		l3protonum;
	u_int8_t		protonum;
	union __nfct_l4_src	l4src;
	union __nfct_l4_dst	l4dst;
};

#define __DIR_ORIG 		0
#define __DIR_REPL 		1
#define __DIR_MAX		__DIR_REPL+1
#define __DIR_MASTER 		2

union __nfct_protoinfo {
	struct {
		u_int8_t 		state;
		struct {
			u_int8_t 	value;
			u_int8_t 	mask;
		} flags[__DIR_MAX];
		u_int8_t		wscale[__DIR_MAX];
	} tcp;
	struct {
		u_int8_t 		state;
		u_int32_t 		vtag[__DIR_MAX];
	} sctp;
	struct {
		u_int8_t 		state;
		u_int8_t		role;
		u_int64_t		handshake_seq;
	} dccp;
};

struct __nfct_counters {
	u_int64_t 	packets;
	u_int64_t 	bytes;
};

struct __nfct_nat {
	u_int32_t 		min_ip, max_ip;
	union __nfct_l4_src 	l4min, l4max;
};

struct nfct_tuple_head {
	struct __nfct_tuple 	orig;

#define __NFCT_BITSET			3
	u_int32_t               set[__NFCT_BITSET];
};

struct nf_conntrack {
	struct nfct_tuple_head 	head;
	struct __nfct_tuple	repl;
	struct __nfct_tuple	master;

	u_int32_t 	timeout;
	u_int32_t	mark;
	u_int32_t	secmark;
	u_int32_t 	status;
	u_int32_t	use;
	u_int32_t	id;
	u_int16_t	zone;

	char 		helper_name[NFCT_HELPER_NAME_MAX];
	char		*secctx;

	union __nfct_protoinfo 	protoinfo;
	struct __nfct_counters 	counters[__DIR_MAX];
	struct __nfct_nat 	snat;
	struct __nfct_nat 	dnat;

	struct {
		u_int32_t 	correction_pos;
		u_int32_t 	offset_before;
		u_int32_t 	offset_after;
	} natseq[__DIR_MAX];

	struct {
		u_int64_t	start;
		u_int64_t	stop;
	} timestamp;

	void *helper_info;
	size_t helper_info_len;

	struct nfct_bitmask *connlabels;
	struct nfct_bitmask *connlabels_mask;
};


struct nfct_filter {

	enum nfct_filter_logic 	logic[NFCT_FILTER_MAX];

#define __FILTER_L4PROTO_MAX	255
	u_int32_t 		l4proto_map[IPPROTO_MAX/32];
	u_int32_t		l4proto_len;

	struct {
#define __FILTER_PROTO_MAX	16
		u_int16_t 	map;
		u_int16_t	len;
	} l4proto_state[IPPROTO_MAX];

#define __FILTER_ADDR_SRC 0
#define __FILTER_ADDR_DST 1

	u_int32_t 		l3proto_elems[2];
	struct {
#define __FILTER_ADDR_MAX	127
		u_int32_t 	addr;
		u_int32_t 	mask;
	} l3proto[2][__FILTER_ADDR_MAX];

	u_int32_t 		l3proto_elems_ipv6[2];
	struct {
#define __FILTER_IPV6_MAX	20
		u_int32_t 	addr[4];
		u_int32_t 	mask[4];
	} l3proto_ipv6[2][__FILTER_IPV6_MAX];

	u_int32_t 		set[1];
};


struct nfct_filter_dump {
	struct nfct_filter_dump_mark	mark;
	u_int8_t			l3num;
	u_int32_t			set;
};


#define __NFCT_EXPECTFN_MAX	24	

struct nf_expect {
	struct nfct_tuple_head	master;
	struct nfct_tuple_head	expected;
	struct nfct_tuple_head	mask;
	struct nfct_tuple_head	nat;

	u_int32_t 		timeout;
	u_int32_t 		id;
	u_int16_t		zone;
	u_int32_t		flags;
	u_int32_t		class;
	char 			helper_name[NFCT_HELPER_NAME_MAX];
	u_int32_t		nat_dir;
	char			expectfn[__NFCT_EXPECTFN_MAX];

	u_int32_t 		set[1];
};

struct nfct_bitmask {
	unsigned int words;
	uint32_t bits[];
};

struct nfct_labelmap;

#endif

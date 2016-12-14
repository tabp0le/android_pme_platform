/*
 * (C) 2005-2011 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _LIBNETFILTER_CONNTRACK_H_
#define _LIBNETFILTER_CONNTRACK_H_

#include <netinet/in.h>
#include <libnfnetlink/linux_nfnetlink.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_conntrack/linux_nfnetlink_conntrack.h> 

#ifdef __cplusplus
extern "C" {
#endif

enum {
	CONNTRACK = NFNL_SUBSYS_CTNETLINK,
	EXPECT = NFNL_SUBSYS_CTNETLINK_EXP
};

#define NFCT_ALL_CT_GROUPS (NF_NETLINK_CONNTRACK_NEW|NF_NETLINK_CONNTRACK_UPDATE|NF_NETLINK_CONNTRACK_DESTROY)

struct nfct_handle;

extern struct nfct_handle *nfct_open(u_int8_t, unsigned);
extern struct nfct_handle *nfct_open_nfnl(struct nfnl_handle *nfnlh,
					  u_int8_t subsys_id,
					  unsigned int subscriptions);
extern int nfct_close(struct nfct_handle *cth);

extern int nfct_fd(struct nfct_handle *cth);
extern const struct nfnl_handle *nfct_nfnlh(struct nfct_handle *cth);



#include <sys/types.h>

struct nf_conntrack;

enum nf_conntrack_attr {
	ATTR_ORIG_IPV4_SRC = 0,			
	ATTR_IPV4_SRC = ATTR_ORIG_IPV4_SRC,	
	ATTR_ORIG_IPV4_DST,			
	ATTR_IPV4_DST = ATTR_ORIG_IPV4_DST,	
	ATTR_REPL_IPV4_SRC,			
	ATTR_REPL_IPV4_DST,			
	ATTR_ORIG_IPV6_SRC = 4,			
	ATTR_IPV6_SRC = ATTR_ORIG_IPV6_SRC,	
	ATTR_ORIG_IPV6_DST,			
	ATTR_IPV6_DST = ATTR_ORIG_IPV6_DST,	
	ATTR_REPL_IPV6_SRC,			
	ATTR_REPL_IPV6_DST,			
	ATTR_ORIG_PORT_SRC = 8,			
	ATTR_PORT_SRC = ATTR_ORIG_PORT_SRC,	
	ATTR_ORIG_PORT_DST,			
	ATTR_PORT_DST = ATTR_ORIG_PORT_DST,	
	ATTR_REPL_PORT_SRC,			
	ATTR_REPL_PORT_DST,			
	ATTR_ICMP_TYPE = 12,			
	ATTR_ICMP_CODE,				
	ATTR_ICMP_ID,				
	ATTR_ORIG_L3PROTO,			
	ATTR_L3PROTO = ATTR_ORIG_L3PROTO,	
	ATTR_REPL_L3PROTO = 16,			
	ATTR_ORIG_L4PROTO,			
	ATTR_L4PROTO = ATTR_ORIG_L4PROTO,	
	ATTR_REPL_L4PROTO,			
	ATTR_TCP_STATE,				
	ATTR_SNAT_IPV4 = 20,			
	ATTR_DNAT_IPV4,				
	ATTR_SNAT_PORT,				
	ATTR_DNAT_PORT,				
	ATTR_TIMEOUT = 24,			
	ATTR_MARK,				
	ATTR_ORIG_COUNTER_PACKETS,		
	ATTR_REPL_COUNTER_PACKETS,		
	ATTR_ORIG_COUNTER_BYTES = 28,		
	ATTR_REPL_COUNTER_BYTES,		
	ATTR_USE,				
	ATTR_ID,				
	ATTR_STATUS = 32,			
	ATTR_TCP_FLAGS_ORIG,			
	ATTR_TCP_FLAGS_REPL,			
	ATTR_TCP_MASK_ORIG,			
	ATTR_TCP_MASK_REPL = 36,		
	ATTR_MASTER_IPV4_SRC,			
	ATTR_MASTER_IPV4_DST,			
	ATTR_MASTER_IPV6_SRC,			
	ATTR_MASTER_IPV6_DST = 40,		
	ATTR_MASTER_PORT_SRC,			
	ATTR_MASTER_PORT_DST,			
	ATTR_MASTER_L3PROTO,			
	ATTR_MASTER_L4PROTO = 44,		
	ATTR_SECMARK,				
	ATTR_ORIG_NAT_SEQ_CORRECTION_POS,	
	ATTR_ORIG_NAT_SEQ_OFFSET_BEFORE,	
	ATTR_ORIG_NAT_SEQ_OFFSET_AFTER = 48,	
	ATTR_REPL_NAT_SEQ_CORRECTION_POS,	
	ATTR_REPL_NAT_SEQ_OFFSET_BEFORE,	
	ATTR_REPL_NAT_SEQ_OFFSET_AFTER,		
	ATTR_SCTP_STATE = 52,			
	ATTR_SCTP_VTAG_ORIG,			
	ATTR_SCTP_VTAG_REPL,			
	ATTR_HELPER_NAME,			
	ATTR_DCCP_STATE = 56,			
	ATTR_DCCP_ROLE,				
	ATTR_DCCP_HANDSHAKE_SEQ,		
	ATTR_TCP_WSCALE_ORIG,			
	ATTR_TCP_WSCALE_REPL = 60,		
	ATTR_ZONE,				
	ATTR_SECCTX,				
	ATTR_TIMESTAMP_START,			
	ATTR_TIMESTAMP_STOP = 64,		
	ATTR_HELPER_INFO,			
	ATTR_CONNLABELS,			
	ATTR_CONNLABELS_MASK,			
	ATTR_MAX
};

enum nf_conntrack_attr_grp {
	ATTR_GRP_ORIG_IPV4 = 0,			
	ATTR_GRP_REPL_IPV4,			
	ATTR_GRP_ORIG_IPV6,			
	ATTR_GRP_REPL_IPV6,			
	ATTR_GRP_ORIG_PORT = 4,			
	ATTR_GRP_REPL_PORT,			
	ATTR_GRP_ICMP,				
	ATTR_GRP_MASTER_IPV4,			
	ATTR_GRP_MASTER_IPV6 = 8,		
	ATTR_GRP_MASTER_PORT,			
	ATTR_GRP_ORIG_COUNTERS,			
	ATTR_GRP_REPL_COUNTERS,			
	ATTR_GRP_ORIG_ADDR_SRC = 12,		
	ATTR_GRP_ORIG_ADDR_DST,			
	ATTR_GRP_REPL_ADDR_SRC,			
	ATTR_GRP_REPL_ADDR_DST,			
	ATTR_GRP_MAX
};

struct nfct_attr_grp_ipv4 {
	u_int32_t src, dst;
};

struct nfct_attr_grp_ipv6 {
	u_int32_t src[4], dst[4];
};

struct nfct_attr_grp_port {
	u_int16_t sport, dport;
};

struct nfct_attr_grp_icmp {
	u_int16_t id;
	u_int8_t code, type;
};

struct nfct_attr_grp_ctrs {
	u_int64_t packets;
	u_int64_t bytes;
};

union nfct_attr_grp_addr {
	u_int32_t ip;
	u_int32_t ip6[4];
	u_int32_t addr[4];
};

enum nf_conntrack_msg_type {
	NFCT_T_UNKNOWN = 0,

	NFCT_T_NEW_BIT = 0,
	NFCT_T_NEW = (1 << NFCT_T_NEW_BIT),

	NFCT_T_UPDATE_BIT = 1,
	NFCT_T_UPDATE = (1 << NFCT_T_UPDATE_BIT),

	NFCT_T_DESTROY_BIT = 2,
	NFCT_T_DESTROY = (1 << NFCT_T_DESTROY_BIT),

	NFCT_T_ALL = NFCT_T_NEW | NFCT_T_UPDATE | NFCT_T_DESTROY,

	NFCT_T_ERROR_BIT = 31,
	NFCT_T_ERROR = (1 << NFCT_T_ERROR_BIT),
};

extern struct nf_conntrack *nfct_new(void);
extern void nfct_destroy(struct nf_conntrack *ct);

struct nf_conntrack *nfct_clone(const struct nf_conntrack *ct);

extern __attribute__((deprecated)) size_t nfct_sizeof(const struct nf_conntrack *ct);

extern __attribute__((deprecated)) size_t nfct_maxsize(void);

enum {
	NFCT_SOPT_UNDO_SNAT,
	NFCT_SOPT_UNDO_DNAT,
	NFCT_SOPT_UNDO_SPAT,
	NFCT_SOPT_UNDO_DPAT,
	NFCT_SOPT_SETUP_ORIGINAL,
	NFCT_SOPT_SETUP_REPLY,
	__NFCT_SOPT_MAX,
};
#define NFCT_SOPT_MAX (__NFCT_SOPT_MAX - 1)

enum {
	NFCT_GOPT_IS_SNAT,
	NFCT_GOPT_IS_DNAT,
	NFCT_GOPT_IS_SPAT,
	NFCT_GOPT_IS_DPAT,
	__NFCT_GOPT_MAX,
};
#define NFCT_GOPT_MAX (__NFCT_GOPT_MAX - 1)

extern int nfct_setobjopt(struct nf_conntrack *ct, unsigned int option);
extern int nfct_getobjopt(const struct nf_conntrack *ct, unsigned int option);


extern int nfct_callback_register(struct nfct_handle *h,
				  enum nf_conntrack_msg_type type,
				  int (*cb)(enum nf_conntrack_msg_type type,
				  	    struct nf_conntrack *ct,
					    void *data),
				  void *data);

extern void nfct_callback_unregister(struct nfct_handle *h);


extern int nfct_callback_register2(struct nfct_handle *h,
				   enum nf_conntrack_msg_type type,
				   int (*cb)(const struct nlmsghdr *nlh,
				   	     enum nf_conntrack_msg_type type,
				  	     struct nf_conntrack *ct,
					     void *data),
				   void *data);

extern void nfct_callback_unregister2(struct nfct_handle *h);

enum {
	NFCT_CB_FAILURE = -1,   
	NFCT_CB_STOP = 0,       
	NFCT_CB_CONTINUE = 1,   
	NFCT_CB_STOLEN = 2,     
};

struct nfct_bitmask;

struct nfct_bitmask *nfct_bitmask_new(unsigned int maxbit);
struct nfct_bitmask *nfct_bitmask_clone(const struct nfct_bitmask *);
unsigned int nfct_bitmask_maxbit(const struct nfct_bitmask *);

void nfct_bitmask_set_bit(struct nfct_bitmask *, unsigned int bit);
int nfct_bitmask_test_bit(const struct nfct_bitmask *, unsigned int bit);
void nfct_bitmask_unset_bit(struct nfct_bitmask *, unsigned int bit);
void nfct_bitmask_destroy(struct nfct_bitmask *);

struct nfct_labelmap;

struct nfct_labelmap *nfct_labelmap_new(const char *mapfile);
void nfct_labelmap_destroy(struct nfct_labelmap *map);
const char *nfct_labelmap_get_name(struct nfct_labelmap *m, unsigned int bit);
int nfct_labelmap_get_bit(struct nfct_labelmap *m, const char *name);

extern void nfct_set_attr(struct nf_conntrack *ct,
			  const enum nf_conntrack_attr type,
			  const void *value);

extern void nfct_set_attr_u8(struct nf_conntrack *ct,
			     const enum nf_conntrack_attr type,
			     u_int8_t value);

extern void nfct_set_attr_u16(struct nf_conntrack *ct,
			      const enum nf_conntrack_attr type,
			      u_int16_t value);

extern void nfct_set_attr_u32(struct nf_conntrack *ct,
			      const enum nf_conntrack_attr type,
			      u_int32_t value);

extern void nfct_set_attr_u64(struct nf_conntrack *ct,
			      const enum nf_conntrack_attr type,
			      u_int64_t value);

extern void nfct_set_attr_l(struct nf_conntrack *ct,
			    const enum nf_conntrack_attr type,
			    const void *value,
			    size_t len);

extern const void *nfct_get_attr(const struct nf_conntrack *ct,
				 const enum nf_conntrack_attr type);

extern u_int8_t nfct_get_attr_u8(const struct nf_conntrack *ct,
				 const enum nf_conntrack_attr type);

extern u_int16_t nfct_get_attr_u16(const struct nf_conntrack *ct,
				   const enum nf_conntrack_attr type);

extern u_int32_t nfct_get_attr_u32(const struct nf_conntrack *ct,
				   const enum nf_conntrack_attr type);

extern u_int64_t nfct_get_attr_u64(const struct nf_conntrack *ct,
				   const enum nf_conntrack_attr type);

extern int nfct_attr_is_set(const struct nf_conntrack *ct,
			    const enum nf_conntrack_attr type);

extern int nfct_attr_is_set_array(const struct nf_conntrack *ct,
				  const enum nf_conntrack_attr *type_array,
				  int size);

extern int nfct_attr_unset(struct nf_conntrack *ct,
			   const enum nf_conntrack_attr type);

extern void nfct_set_attr_grp(struct nf_conntrack *ct,
			      const enum nf_conntrack_attr_grp type,
			      const void *value);
extern int nfct_get_attr_grp(const struct nf_conntrack *ct,
			     const enum nf_conntrack_attr_grp type,
			     void *data);

extern int nfct_attr_grp_is_set(const struct nf_conntrack *ct,
				const enum nf_conntrack_attr_grp type);

extern int nfct_attr_grp_unset(struct nf_conntrack *ct,
			       const enum nf_conntrack_attr_grp type);


enum {
	NFCT_O_PLAIN,
	NFCT_O_DEFAULT = NFCT_O_PLAIN,
	NFCT_O_XML,
	NFCT_O_MAX
};

enum {
	NFCT_OF_SHOW_LAYER3_BIT = 0,
	NFCT_OF_SHOW_LAYER3 = (1 << NFCT_OF_SHOW_LAYER3_BIT),

	NFCT_OF_TIME_BIT = 1,
	NFCT_OF_TIME = (1 << NFCT_OF_TIME_BIT),

	NFCT_OF_ID_BIT = 2,
	NFCT_OF_ID = (1 << NFCT_OF_ID_BIT),

	NFCT_OF_TIMESTAMP_BIT = 3,
	NFCT_OF_TIMESTAMP = (1 << NFCT_OF_TIMESTAMP_BIT),
};

extern int nfct_snprintf(char *buf, 
			 unsigned int size,
			 const struct nf_conntrack *ct,
			 const unsigned int msg_type,
			 const unsigned int out_type,
			 const unsigned int out_flags);

extern int nfct_snprintf_labels(char *buf,
				unsigned int size,
				const struct nf_conntrack *ct,
				const unsigned int msg_type,
				const unsigned int out_type,
				const unsigned int out_flags,
				struct nfct_labelmap *map);

extern int nfct_compare(const struct nf_conntrack *ct1,
			const struct nf_conntrack *ct2);

enum {
	NFCT_CMP_ALL = 0,
	NFCT_CMP_ORIG = (1 << 0),
	NFCT_CMP_REPL = (1 << 1),
	NFCT_CMP_TIMEOUT_EQ = (1 << 2),
	NFCT_CMP_TIMEOUT_GT = (1 << 3),
	NFCT_CMP_TIMEOUT_GE = (NFCT_CMP_TIMEOUT_EQ | NFCT_CMP_TIMEOUT_GT),
	NFCT_CMP_TIMEOUT_LT = (1 << 4),
	NFCT_CMP_TIMEOUT_LE = (NFCT_CMP_TIMEOUT_EQ | NFCT_CMP_TIMEOUT_LT),
	NFCT_CMP_MASK = (1 << 5),
	NFCT_CMP_STRICT = (1 << 6),
};

extern int nfct_cmp(const struct nf_conntrack *ct1,
		    const struct nf_conntrack *ct2,
		    unsigned int flags);


enum nf_conntrack_query {
	NFCT_Q_CREATE,
	NFCT_Q_UPDATE,
	NFCT_Q_DESTROY,
	NFCT_Q_GET,
	NFCT_Q_FLUSH,
	NFCT_Q_DUMP,
	NFCT_Q_DUMP_RESET,
	NFCT_Q_CREATE_UPDATE,
	NFCT_Q_DUMP_FILTER,
	NFCT_Q_DUMP_FILTER_RESET,
};

extern int nfct_query(struct nfct_handle *h,
		      const enum nf_conntrack_query query,
		      const void *data);

extern int nfct_send(struct nfct_handle *h,
		     const enum nf_conntrack_query query,
		     const void *data);

extern int nfct_catch(struct nfct_handle *h);

enum {
	NFCT_CP_ALL = 0,
	NFCT_CP_ORIG = (1 << 0),
	NFCT_CP_REPL = (1 << 1),
	NFCT_CP_META = (1 << 2),
	NFCT_CP_OVERRIDE = (1 << 3),
};

extern void nfct_copy(struct nf_conntrack *dest,
		      const struct nf_conntrack *source,
		      unsigned int flags);

extern void nfct_copy_attr(struct nf_conntrack *ct1,
			   const struct nf_conntrack *ct2,
			   const enum nf_conntrack_attr type);


struct nfct_filter;

extern struct nfct_filter *nfct_filter_create(void);
extern void nfct_filter_destroy(struct nfct_filter *filter);

struct nfct_filter_proto {
	u_int16_t proto;
	u_int16_t state;
};
struct nfct_filter_ipv4 {
	u_int32_t addr;
	u_int32_t mask;
};
struct nfct_filter_ipv6 {
	u_int32_t addr[4];
	u_int32_t mask[4];
};

enum nfct_filter_attr {
	NFCT_FILTER_L4PROTO = 0,	
	NFCT_FILTER_L4PROTO_STATE,	
	NFCT_FILTER_SRC_IPV4,		
	NFCT_FILTER_DST_IPV4,		
	NFCT_FILTER_SRC_IPV6,		
	NFCT_FILTER_DST_IPV6,		
	NFCT_FILTER_MAX
};

extern void nfct_filter_add_attr(struct nfct_filter *filter,
				 const enum nfct_filter_attr attr,
				 const void *value);

extern void nfct_filter_add_attr_u32(struct nfct_filter *filter,
				     const enum nfct_filter_attr attr,
				     const u_int32_t value);

enum nfct_filter_logic {
	NFCT_FILTER_LOGIC_POSITIVE,
	NFCT_FILTER_LOGIC_NEGATIVE,
	NFCT_FILTER_LOGIC_MAX
};

extern int nfct_filter_set_logic(struct nfct_filter *filter,
				 const enum nfct_filter_attr attr,
				 const enum nfct_filter_logic logic);

extern int nfct_filter_attach(int fd, struct nfct_filter *filter);
extern int nfct_filter_detach(int fd);


struct nfct_filter_dump;

struct nfct_filter_dump_mark {
	u_int32_t val;
	u_int32_t mask;
};

enum nfct_filter_dump_attr {
	NFCT_FILTER_DUMP_MARK = 0,	
	NFCT_FILTER_DUMP_L3NUM,		
	NFCT_FILTER_DUMP_MAX
};

struct nfct_filter_dump *nfct_filter_dump_create(void);

void nfct_filter_dump_destroy(struct nfct_filter_dump *filter);

void nfct_filter_dump_set_attr(struct nfct_filter_dump *filter_dump,
			       const enum nfct_filter_dump_attr type,
			       const void *data);

void nfct_filter_dump_set_attr_u8(struct nfct_filter_dump *filter_dump,
				  const enum nfct_filter_dump_attr type,
				  u_int8_t data);


extern __attribute__((deprecated)) int
nfct_build_conntrack(struct nfnl_subsys_handle *ssh,
				void *req,
				size_t size,
				u_int16_t type,
				u_int16_t flags,
				const struct nf_conntrack *ct);

extern __attribute__((deprecated))
int nfct_parse_conntrack(enum nf_conntrack_msg_type msg,
				const struct nlmsghdr *nlh, 
				struct nf_conntrack *ct);

extern __attribute__((deprecated))
int nfct_build_query(struct nfnl_subsys_handle *ssh,
			    const enum nf_conntrack_query query,
			    const void *data,
			    void *req,
			    unsigned int size);


extern int nfct_nlmsg_build(struct nlmsghdr *nlh, const struct nf_conntrack *ct);
extern int nfct_nlmsg_parse(const struct nlmsghdr *nlh, struct nf_conntrack *ct);
extern int nfct_payload_parse(const void *payload, size_t payload_len, uint16_t l3num, struct nf_conntrack *ct);


struct nf_expect;

enum nf_expect_attr {
	ATTR_EXP_MASTER = 0,	
	ATTR_EXP_EXPECTED,	
	ATTR_EXP_MASK,		
	ATTR_EXP_TIMEOUT,	
	ATTR_EXP_ZONE,		
	ATTR_EXP_FLAGS,		
	ATTR_EXP_HELPER_NAME,	
	ATTR_EXP_CLASS,		
	ATTR_EXP_NAT_TUPLE,	
	ATTR_EXP_NAT_DIR,	
	ATTR_EXP_FN,		
	ATTR_EXP_MAX
};

extern struct nf_expect *nfexp_new(void);
extern void nfexp_destroy(struct nf_expect *exp);

extern struct nf_expect *nfexp_clone(const struct nf_expect *exp);

extern size_t nfexp_sizeof(const struct nf_expect *exp);

extern size_t nfexp_maxsize(void);


extern int nfexp_callback_register(struct nfct_handle *h,
				   enum nf_conntrack_msg_type type,
				   int (*cb)(enum nf_conntrack_msg_type type,
				  	     struct nf_expect *exp,
					     void *data),
				   void *data);

extern void nfexp_callback_unregister(struct nfct_handle *h);

extern int nfexp_callback_register2(struct nfct_handle *h,
				    enum nf_conntrack_msg_type type,
				    int (*cb)(const struct nlmsghdr *nlh,
				    	      enum nf_conntrack_msg_type type,
					      struct nf_expect *exp,
					      void *data),
				    void *data);

extern void nfexp_callback_unregister2(struct nfct_handle *h);

extern void nfexp_set_attr(struct nf_expect *exp,
			   const enum nf_expect_attr type,
			   const void *value);

extern void nfexp_set_attr_u8(struct nf_expect *exp,
			      const enum nf_expect_attr type,
			      u_int8_t value);

extern void nfexp_set_attr_u16(struct nf_expect *exp,
			       const enum nf_expect_attr type,
			       u_int16_t value);

extern void nfexp_set_attr_u32(struct nf_expect *exp,
			       const enum nf_expect_attr type,
			       u_int32_t value);

extern const void *nfexp_get_attr(const struct nf_expect *exp,
				  const enum nf_expect_attr type);

extern u_int8_t nfexp_get_attr_u8(const struct nf_expect *exp,
				  const enum nf_expect_attr type);

extern u_int16_t nfexp_get_attr_u16(const struct nf_expect *exp,
				    const enum nf_expect_attr type);

extern u_int32_t nfexp_get_attr_u32(const struct nf_expect *exp,
				    const enum nf_expect_attr type);

extern int nfexp_attr_is_set(const struct nf_expect *exp,
			     const enum nf_expect_attr type);

extern int nfexp_attr_unset(struct nf_expect *exp,
			    const enum nf_expect_attr type);

extern int nfexp_query(struct nfct_handle *h,
		       const enum nf_conntrack_query qt,
		       const void *data);

extern int nfexp_snprintf(char *buf, 
			  unsigned int size,
			  const struct nf_expect *exp,
			  const unsigned int msg_type,
			  const unsigned int out_type,
			  const unsigned int out_flags);

extern int nfexp_cmp(const struct nf_expect *exp1,
		     const struct nf_expect *exp2,
		     unsigned int flags);

extern int nfexp_send(struct nfct_handle *h,
		      const enum nf_conntrack_query qt,
		      const void *data);

extern int nfexp_catch(struct nfct_handle *h);

extern __attribute__((deprecated))
int nfexp_build_expect(struct nfnl_subsys_handle *ssh,
			      void *req,
			      size_t size,
			      u_int16_t type,
			      u_int16_t flags,
			      const struct nf_expect *exp);

extern __attribute__((deprecated))
int nfexp_parse_expect(enum nf_conntrack_msg_type type,
			      const struct nlmsghdr *nlh,
			      struct nf_expect *exp);

extern __attribute__((deprecated))
int nfexp_build_query(struct nfnl_subsys_handle *ssh,
			     const enum nf_conntrack_query qt,
			     const void *data,
			     void *buffer,
			     unsigned int size);


extern int nfexp_nlmsg_build(struct nlmsghdr *nlh, const struct nf_expect *exp);
extern int nfexp_nlmsg_parse(const struct nlmsghdr *nlh, struct nf_expect *exp);

enum ip_conntrack_status {
	
	IPS_EXPECTED_BIT = 0,
	IPS_EXPECTED = (1 << IPS_EXPECTED_BIT),

	
	IPS_SEEN_REPLY_BIT = 1,
	IPS_SEEN_REPLY = (1 << IPS_SEEN_REPLY_BIT),

	
	IPS_ASSURED_BIT = 2,
	IPS_ASSURED = (1 << IPS_ASSURED_BIT),

	
	IPS_CONFIRMED_BIT = 3,
	IPS_CONFIRMED = (1 << IPS_CONFIRMED_BIT),

	
	IPS_SRC_NAT_BIT = 4,
	IPS_SRC_NAT = (1 << IPS_SRC_NAT_BIT),

	
	IPS_DST_NAT_BIT = 5,
	IPS_DST_NAT = (1 << IPS_DST_NAT_BIT),

	
	IPS_NAT_MASK = (IPS_DST_NAT | IPS_SRC_NAT),

	
	IPS_SEQ_ADJUST_BIT = 6,
	IPS_SEQ_ADJUST = (1 << IPS_SEQ_ADJUST_BIT),

	
	IPS_SRC_NAT_DONE_BIT = 7,
	IPS_SRC_NAT_DONE = (1 << IPS_SRC_NAT_DONE_BIT),

	IPS_DST_NAT_DONE_BIT = 8,
	IPS_DST_NAT_DONE = (1 << IPS_DST_NAT_DONE_BIT),

	
	IPS_NAT_DONE_MASK = (IPS_DST_NAT_DONE | IPS_SRC_NAT_DONE),

	
	IPS_DYING_BIT = 9,
	IPS_DYING = (1 << IPS_DYING_BIT),

	
	IPS_FIXED_TIMEOUT_BIT = 10,
	IPS_FIXED_TIMEOUT = (1 << IPS_FIXED_TIMEOUT_BIT),

	
	IPS_TEMPLATE_BIT = 11,
	IPS_TEMPLATE = (1 << IPS_TEMPLATE_BIT),

	
	IPS_UNTRACKED_BIT = 12,
	IPS_UNTRACKED = (1 << IPS_UNTRACKED_BIT),
};

#define NF_CT_EXPECT_PERMANENT          0x1
#define NF_CT_EXPECT_INACTIVE           0x2
#define NF_CT_EXPECT_USERSPACE          0x4


#define IP_CT_TCP_FLAG_WINDOW_SCALE             0x01

#define IP_CT_TCP_FLAG_SACK_PERM                0x02

#define IP_CT_TCP_FLAG_CLOSE_INIT               0x04

#define IP_CT_TCP_FLAG_BE_LIBERAL               0x08

#define NFCT_DIR_ORIGINAL 0
#define NFCT_DIR_REPLY 1
#define NFCT_DIR_MAX NFCT_DIR_REPLY+1

#define NFCT_HELPER_NAME_MAX	16

#ifdef __cplusplus
}
#endif

#endif	

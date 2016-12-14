/*
 * (C) 2005-2011 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdlib.h>
#include <string.h> 
#include <errno.h>
#include <assert.h>

#include "internal/internal.h"

/**
 * \mainpage
 *
 * libnetfilter_conntrack is a userspace library providing a programming
 * interface (API) to the in-kernel connection tracking state table. The
 * library libnetfilter_conntrack has been previously known as
 * libnfnetlink_conntrack and libctnetlink. This library is currently used by
 * conntrack-tools among many other applications.
 *
 * libnetfilter_conntrack homepage is:
 *      http://netfilter.org/projects/libnetfilter_conntrack/
 *
 * \section Dependencies
 * libnetfilter_conntrack requires libnfnetlink and a kernel that includes the
 * nf_conntrack_netlink subsystem (i.e. 2.6.14 or later, >= 2.6.18 recommended).
 *
 * \section Main Features
 *  - listing/retrieving entries from the kernel connection tracking table.
 *  - inserting/modifying/deleting entries from the kernel connection tracking
 *    table.
 *  - listing/retrieving entries from the kernel expect table.
 *  - inserting/modifying/deleting entries from the kernel expect table.
 * \section Git Tree
 * The current development version of libnetfilter_conntrack can be accessed at
 * https://git.netfilter.org/cgi-bin/gitweb.cgi?p=libnetfilter_conntrack.git
 *
 * \section Privileges
 * You need the CAP_NET_ADMIN capability in order to allow your application
 * to receive events from and to send commands to kernel-space, excepting
 * the conntrack table dumping operation.
 *
 * \section using Using libnetfilter_conntrack
 * To write your own program using libnetfilter_conntrack, you should start by
 * reading the doxygen documentation (start by \link LibrarySetup \endlink page)
 * and check examples available under utils/ in the libnetfilter_conntrack
 * source code tree. You can compile these examples by invoking `make check'.
 *
 * \section Authors
 * libnetfilter_conntrack has been almost entirely written by Pablo Neira Ayuso.
 *
 * \section python Python Binding
 * pynetfilter_conntrack is a Python binding of libnetfilter_conntrack written
 * by Victor Stinner. You can visit his official web site at
 * http://software.inl.fr/trac/trac.cgi/wiki/pynetfilter_conntrack.
 */


struct nf_conntrack *nfct_new(void)
{
	struct nf_conntrack *ct;

	ct = malloc(sizeof(struct nf_conntrack));
	if (!ct)
		return NULL;

	memset(ct, 0, sizeof(struct nf_conntrack));

	return ct;
}

void nfct_destroy(struct nf_conntrack *ct)
{
	assert(ct != NULL);
	if (ct->secctx)
		free(ct->secctx);
	if (ct->helper_info)
		free(ct->helper_info);
	if (ct->connlabels)
		nfct_bitmask_destroy(ct->connlabels);
	if (ct->connlabels_mask)
		nfct_bitmask_destroy(ct->connlabels_mask);
	free(ct);
	ct = NULL; 
}

size_t nfct_sizeof(const struct nf_conntrack *ct)
{
	assert(ct != NULL);
	return sizeof(*ct);
}

size_t nfct_maxsize(void)
{
	return sizeof(struct nf_conntrack);
}

struct nf_conntrack *nfct_clone(const struct nf_conntrack *ct)
{
	struct nf_conntrack *clone;

	assert(ct != NULL);

	if ((clone = nfct_new()) == NULL)
		return NULL;
	nfct_copy(clone, ct, NFCT_CP_OVERRIDE);

	return clone;
}

int nfct_setobjopt(struct nf_conntrack *ct, unsigned int option)
{
	assert(ct != NULL);

	if (unlikely(option > NFCT_SOPT_MAX)) {
		errno = EOPNOTSUPP;
		return -1;
	}

	return __setobjopt(ct, option);
}

int nfct_getobjopt(const struct nf_conntrack *ct, unsigned int option)
{
	assert(ct != NULL);

	if (unlikely(option > NFCT_GOPT_MAX)) {
		errno = EOPNOTSUPP;
		return -1;
	}

	return __getobjopt(ct, option);
}



int nfct_callback_register(struct nfct_handle *h,
			   enum nf_conntrack_msg_type type,
			   int (*cb)(enum nf_conntrack_msg_type type,
			   	     struct nf_conntrack *ct, 
				     void *data),
			   void *data)
{
	struct __data_container *container;

	assert(h != NULL);

	container = malloc(sizeof(struct __data_container));
	if (!container)
		return -1;
	memset(container, 0, sizeof(struct __data_container));

	h->cb = cb;
	container->h = h;
	container->type = type;
	container->data = data;

	h->nfnl_cb_ct.call = __callback;
	h->nfnl_cb_ct.data = container;
	h->nfnl_cb_ct.attr_count = CTA_MAX;

	nfnl_callback_register(h->nfnlssh_ct, 
			       IPCTNL_MSG_CT_NEW,
			       &h->nfnl_cb_ct);

	nfnl_callback_register(h->nfnlssh_ct,
			       IPCTNL_MSG_CT_DELETE,
			       &h->nfnl_cb_ct);

	return 0;
}

void nfct_callback_unregister(struct nfct_handle *h)
{
	assert(h != NULL);

	nfnl_callback_unregister(h->nfnlssh_ct, IPCTNL_MSG_CT_NEW);
	nfnl_callback_unregister(h->nfnlssh_ct, IPCTNL_MSG_CT_DELETE);

	h->cb = NULL;
	free(h->nfnl_cb_ct.data);

	h->nfnl_cb_ct.call = NULL;
	h->nfnl_cb_ct.data = NULL;
	h->nfnl_cb_ct.attr_count = 0;
}

int nfct_callback_register2(struct nfct_handle *h,
			    enum nf_conntrack_msg_type type,
			    int (*cb)(const struct nlmsghdr *nlh,
			    	      enum nf_conntrack_msg_type type,
				      struct nf_conntrack *ct, 
				      void *data),
			   void *data)
{
	struct __data_container *container;

	assert(h != NULL);

	container = calloc(sizeof(struct __data_container), 1);
	if (container == NULL)
		return -1;

	h->cb2 = cb;
	container->h = h;
	container->type = type;
	container->data = data;

	h->nfnl_cb_ct.call = __callback;
	h->nfnl_cb_ct.data = container;
	h->nfnl_cb_ct.attr_count = CTA_MAX;

	nfnl_callback_register(h->nfnlssh_ct, 
			       IPCTNL_MSG_CT_NEW,
			       &h->nfnl_cb_ct);

	nfnl_callback_register(h->nfnlssh_ct,
			       IPCTNL_MSG_CT_DELETE,
			       &h->nfnl_cb_ct);

	return 0;
}

void nfct_callback_unregister2(struct nfct_handle *h)
{
	assert(h != NULL);

	nfnl_callback_unregister(h->nfnlssh_ct, IPCTNL_MSG_CT_NEW);
	nfnl_callback_unregister(h->nfnlssh_ct, IPCTNL_MSG_CT_DELETE);

	h->cb2 = NULL;
	free(h->nfnl_cb_ct.data);

	h->nfnl_cb_ct.call = NULL;
	h->nfnl_cb_ct.data = NULL;
	h->nfnl_cb_ct.attr_count = 0;
}



void
nfct_set_attr_l(struct nf_conntrack *ct, const enum nf_conntrack_attr type,
		const void *value, size_t len)
{
	assert(ct != NULL);
	assert(value != NULL);

	if (unlikely(type >= ATTR_MAX))
		return;

	if (set_attr_array[type]) {
		set_attr_array[type](ct, value, len);
		set_bit(type, ct->head.set);
	}
}

void nfct_set_attr(struct nf_conntrack *ct,
		   const enum nf_conntrack_attr type, 
		   const void *value)
{
	
	nfct_set_attr_l(ct, type, value, 0);
}

void nfct_set_attr_u8(struct nf_conntrack *ct,
		      const enum nf_conntrack_attr type, 
		      u_int8_t value)
{
	nfct_set_attr_l(ct, type, &value, sizeof(u_int8_t));
}

void nfct_set_attr_u16(struct nf_conntrack *ct,
		       const enum nf_conntrack_attr type, 
		       u_int16_t value)
{
	nfct_set_attr_l(ct, type, &value, sizeof(u_int16_t));
}

void nfct_set_attr_u32(struct nf_conntrack *ct,
		       const enum nf_conntrack_attr type, 
		       u_int32_t value)
{
	nfct_set_attr_l(ct, type, &value, sizeof(u_int32_t));
}

void nfct_set_attr_u64(struct nf_conntrack *ct,
		       const enum nf_conntrack_attr type, 
		       u_int64_t value)
{
	nfct_set_attr_l(ct, type, &value, sizeof(u_int64_t));
}

const void *nfct_get_attr(const struct nf_conntrack *ct,
			  const enum nf_conntrack_attr type)
{
	assert(ct != NULL);

	if (unlikely(type >= ATTR_MAX)) {
		errno = EINVAL;
		return NULL;
	}

	if (!test_bit(type, ct->head.set)) {
		errno = ENODATA;
		return NULL;
	}

	assert(get_attr_array[type]);

	return get_attr_array[type](ct);
}

u_int8_t nfct_get_attr_u8(const struct nf_conntrack *ct,
			  const enum nf_conntrack_attr type)
{
	const u_int8_t *ret = nfct_get_attr(ct, type);
	return ret == NULL ? 0 : *ret;
}

u_int16_t nfct_get_attr_u16(const struct nf_conntrack *ct,
			    const enum nf_conntrack_attr type)
{
	const u_int16_t *ret = nfct_get_attr(ct, type);
	return ret == NULL ? 0 : *ret;
}

u_int32_t nfct_get_attr_u32(const struct nf_conntrack *ct,
			    const enum nf_conntrack_attr type)
{
	const u_int32_t *ret = nfct_get_attr(ct, type);
	return ret == NULL ? 0 : *ret;
}

u_int64_t nfct_get_attr_u64(const struct nf_conntrack *ct,
			    const enum nf_conntrack_attr type)
{
	const u_int64_t *ret = nfct_get_attr(ct, type);
	return ret == NULL ? 0 : *ret;
}

int nfct_attr_is_set(const struct nf_conntrack *ct,
		     const enum nf_conntrack_attr type)
{
	assert(ct != NULL);

	if (unlikely(type >= ATTR_MAX)) {
		errno = EINVAL;
		return -1;
	}
	return test_bit(type, ct->head.set);
}

int nfct_attr_is_set_array(const struct nf_conntrack *ct,
			   const enum nf_conntrack_attr *type_array,
			   int size)
{
	int i;

	assert(ct != NULL);

	for (i=0; i<size; i++) {
		if (unlikely(type_array[i] >= ATTR_MAX)) {
			errno = EINVAL;
			return -1;
		}
		if (!test_bit(type_array[i], ct->head.set))
			return 0;
	}
	return 1;
}

int nfct_attr_unset(struct nf_conntrack *ct,
		    const enum nf_conntrack_attr type)
{
	assert(ct != NULL);

	if (unlikely(type >= ATTR_MAX)) {
		errno = EINVAL;
		return -1;
	}
	unset_bit(type, ct->head.set);

	return 0;
}

void nfct_set_attr_grp(struct nf_conntrack *ct,
		       const enum nf_conntrack_attr_grp type,
		       const void *data)
{
	assert(ct != NULL);

	if (unlikely(type >= ATTR_GRP_MAX))
		return;

	if (set_attr_grp_array[type]) {
		set_attr_grp_array[type](ct, data);
		set_bitmask_u32(ct->head.set,
				attr_grp_bitmask[type].bitmask, __NFCT_BITSET);
	}
}

int nfct_get_attr_grp(const struct nf_conntrack *ct,
		      const enum nf_conntrack_attr_grp type,
		      void *data)
{
	assert(ct != NULL);

	if (unlikely(type >= ATTR_GRP_MAX)) {
		errno = EINVAL;
		return -1;
	}
	switch(attr_grp_bitmask[type].type) {
	case NFCT_BITMASK_AND:
		if (!test_bitmask_u32(ct->head.set,
				      attr_grp_bitmask[type].bitmask,
				      __NFCT_BITSET)) {
			errno = ENODATA;
			return -1;
		}
		break;
	case NFCT_BITMASK_OR:
		if (!test_bitmask_u32_or(ct->head.set,
					 attr_grp_bitmask[type].bitmask,
					 __NFCT_BITSET)) {
			errno = ENODATA;
			return -1;
		}
		break;
	}
	assert(get_attr_grp_array[type]);
	get_attr_grp_array[type](ct, data);
	return 0;
}

int nfct_attr_grp_is_set(const struct nf_conntrack *ct,
			 const enum nf_conntrack_attr_grp type)
{
	assert(ct != NULL);

	if (unlikely(type >= ATTR_GRP_MAX)) {
		errno = EINVAL;
		return -1;
	}
	switch(attr_grp_bitmask[type].type) {
	case NFCT_BITMASK_AND:
		if (test_bitmask_u32(ct->head.set,
				     attr_grp_bitmask[type].bitmask,
				     __NFCT_BITSET)) {
			return 1;
		}
		break;
	case NFCT_BITMASK_OR:
		if (test_bitmask_u32_or(ct->head.set,
					attr_grp_bitmask[type].bitmask,
					__NFCT_BITSET)) {
			return 1;
		}
		break;
	}
	return 0;
}

int nfct_attr_grp_unset(struct nf_conntrack *ct,
			const enum nf_conntrack_attr_grp type)
{
	assert(ct != NULL);

	if (unlikely(type >= ATTR_GRP_MAX)) {
		errno = EINVAL;
		return -1;
	}
	unset_bitmask_u32(ct->head.set, attr_grp_bitmask[type].bitmask,
			  __NFCT_BITSET);

	return 0;
}



int nfct_build_conntrack(struct nfnl_subsys_handle *ssh,
			 void *req,
			 size_t size,
			 u_int16_t type,
			 u_int16_t flags,
			 const struct nf_conntrack *ct)
{
	assert(ssh != NULL);
	assert(req != NULL);
	assert(ct != NULL);

	return __build_conntrack(ssh, req, size, type, flags, ct);
}

static int
__build_query_ct(struct nfnl_subsys_handle *ssh,
		 const enum nf_conntrack_query qt,
		 const void *data, void *buffer, unsigned int size)
{
	struct nfnlhdr *req = buffer;
	const u_int32_t *family = data;

	assert(ssh != NULL);
	assert(data != NULL);
	assert(req != NULL);

	memset(req, 0, size);

	switch(qt) {
	case NFCT_Q_CREATE:
		__build_conntrack(ssh, req, size, IPCTNL_MSG_CT_NEW, NLM_F_REQUEST|NLM_F_CREATE|NLM_F_ACK|NLM_F_EXCL, data);
		break;
	case NFCT_Q_UPDATE:
		__build_conntrack(ssh, req, size, IPCTNL_MSG_CT_NEW, NLM_F_REQUEST|NLM_F_ACK, data);
		break;
	case NFCT_Q_DESTROY:
		__build_conntrack(ssh, req, size, IPCTNL_MSG_CT_DELETE, NLM_F_REQUEST|NLM_F_ACK, data);
		break;
	case NFCT_Q_GET:
		__build_conntrack(ssh, req, size, IPCTNL_MSG_CT_GET, NLM_F_REQUEST|NLM_F_ACK, data);
		break;
	case NFCT_Q_FLUSH:
		nfnl_fill_hdr(ssh, &req->nlh, 0, *family, 0, IPCTNL_MSG_CT_DELETE, NLM_F_REQUEST|NLM_F_ACK);
		break;
	case NFCT_Q_DUMP:
		nfnl_fill_hdr(ssh, &req->nlh, 0, *family, 0, IPCTNL_MSG_CT_GET, NLM_F_REQUEST|NLM_F_DUMP);
		break;
	case NFCT_Q_DUMP_RESET:
		nfnl_fill_hdr(ssh, &req->nlh, 0, *family, 0, IPCTNL_MSG_CT_GET_CTRZERO, NLM_F_REQUEST|NLM_F_DUMP);
		break;
	case NFCT_Q_CREATE_UPDATE:
		__build_conntrack(ssh, req, size, IPCTNL_MSG_CT_NEW, NLM_F_REQUEST|NLM_F_CREATE|NLM_F_ACK, data);
		break;
	case NFCT_Q_DUMP_FILTER:
		nfnl_fill_hdr(ssh, &req->nlh, 0, AF_UNSPEC, 0, IPCTNL_MSG_CT_GET, NLM_F_REQUEST|NLM_F_DUMP);
		__build_filter_dump(req, size, data);
		break;
	case NFCT_Q_DUMP_FILTER_RESET:
		nfnl_fill_hdr(ssh, &req->nlh, 0, AF_UNSPEC, 0, IPCTNL_MSG_CT_GET_CTRZERO, NLM_F_REQUEST|NLM_F_DUMP);
		__build_filter_dump(req, size, data);
		break;
	default:
		errno = ENOTSUP;
		return -1;
	}
	return 1;
}

int nfct_build_query(struct nfnl_subsys_handle *ssh,
		     const enum nf_conntrack_query qt,
		     const void *data,
		     void *buffer,
		     unsigned int size)
{
	return __build_query_ct(ssh, qt, data, buffer, size);
}

int nfct_parse_conntrack(enum nf_conntrack_msg_type type,
			 const struct nlmsghdr *nlh,
			 struct nf_conntrack *ct)
{
	unsigned int flags;
	int len = nlh->nlmsg_len;
	struct nfgenmsg *nfhdr = NLMSG_DATA(nlh);
	struct nfattr *cda[CTA_MAX];

	assert(nlh != NULL);
	assert(ct != NULL);

	len -= NLMSG_LENGTH(sizeof(struct nfgenmsg));
	if (len < 0) {
		errno = EINVAL;
		return NFCT_T_ERROR;
	}

	flags = __parse_message_type(nlh);
	if (!(flags & type))
		return 0;

	nfnl_parse_attr(cda, CTA_MAX, NFA_DATA(nfhdr), len);

	__parse_conntrack(nlh, cda, ct);

	return flags;
}



int nfct_query(struct nfct_handle *h,
	       const enum nf_conntrack_query qt,
	       const void *data)
{
	size_t size = 4096;	
	union {
		char buffer[size];
		struct nfnlhdr req;
	} u;

	assert(h != NULL);
	assert(data != NULL);

	if (__build_query_ct(h->nfnlssh_ct, qt, data, &u.req, size) == -1)
		return -1;

	return nfnl_query(h->nfnlh, &u.req.nlh);
}

int nfct_send(struct nfct_handle *h,
	      const enum nf_conntrack_query qt,
	      const void *data)
{
	size_t size = 4096;	
	union {
		char buffer[size];
		struct nfnlhdr req;
	} u;

	assert(h != NULL);
	assert(data != NULL);

	if (__build_query_ct(h->nfnlssh_ct, qt, data, &u.req, size) == -1)
		return -1;

	return nfnl_send(h->nfnlh, &u.req.nlh);
}


int nfct_catch(struct nfct_handle *h)
{
	assert(h != NULL);

	return nfnl_catch(h->nfnlh);
}



/**
 * nfct_snprintf - print a conntrack object to a buffer
 * \param buf buffer used to build the printable conntrack
 * \param size size of the buffer
 * \param ct pointer to a valid conntrack object
 * \param message_type print message type (NFCT_T_UNKNOWN, NFCT_T_NEW,...)
 * \param output_type print type (NFCT_O_DEFAULT, NFCT_O_XML, ...)
 * \param flags extra flags for the output type (NFCT_OF_LAYER3)
 *
 * If you are listening to events, probably you want to display the message 
 * type as well. In that case, set the message type parameter to any of the
 * known existing types, ie. NFCT_T_NEW, NFCT_T_UPDATE, NFCT_T_DESTROY.
 * If you pass NFCT_T_UNKNOWN, the message type will not be output. 
 *
 * Currently, the output available are:
 * 	- NFCT_O_DEFAULT: default /proc-like output
 * 	- NFCT_O_XML: XML output
 *
 * The output flags are:
 * 	- NFCT_OF_SHOW_LAYER3: include layer 3 information in the output, 
 * 	this is *only* required by NFCT_O_DEFAULT.
 * 	- NFCT_OF_TIME: display current time.
 * 	- NFCT_OF_ID: display the ID number.
 * 	- NFCT_OF_TIMESTAMP: display creation and (if exists) deletion time.
 *
 * To use NFCT_OF_TIMESTAMP, you have to:
 * \verbatim
 *  $ echo 1 > /proc/sys/net/netfilter/nf_conntrack_timestamp
\endverbatim
 * This requires a Linux kernel >= 2.6.38.
 *
 * Note that NFCT_OF_TIME displays the current time when nfct_snprintf() has
 * been called. Thus, it can be used to know when a flow was destroy if you
 * print the message just after you receive the destroy event. If you want
 * more accurate timestamping, use NFCT_OF_TIMESTAMP.
 *
 * This function returns the size of the information that _would_ have been 
 * written to the buffer, even if there was no room for it. Thus, the
 * behaviour is similar to snprintf.
 */
int nfct_snprintf(char *buf,
		  unsigned int size,
		  const struct nf_conntrack *ct,
		  unsigned int msg_type,
		  unsigned int out_type,
		  unsigned int flags)
{
	assert(buf != NULL);
	assert(size > 0);
	assert(ct != NULL);

	return __snprintf_conntrack(buf, size, ct, msg_type, out_type, flags, NULL);
}

int nfct_snprintf_labels(char *buf,
			 unsigned int size,
			 const struct nf_conntrack *ct,
			 unsigned int msg_type,
			 unsigned int out_type,
			 unsigned int flags,
			 struct nfct_labelmap *map)
{
	return __snprintf_conntrack(buf, size, ct, msg_type, out_type, flags, map);
}

int nfct_compare(const struct nf_conntrack *ct1, 
		 const struct nf_conntrack *ct2)
{
	assert(ct1 != NULL);
	assert(ct2 != NULL);

	return __compare(ct1, ct2, NFCT_CMP_ALL);
}

int nfct_cmp(const struct nf_conntrack *ct1, 
	     const struct nf_conntrack *ct2,
	     unsigned int flags)
{
	assert(ct1 != NULL);
	assert(ct2 != NULL);

	return __compare(ct1, ct2, flags);
}

void nfct_copy(struct nf_conntrack *ct1,
	       const struct nf_conntrack *ct2,
	       unsigned int flags)
{
	int i;

	assert(ct1 != NULL);
	assert(ct2 != NULL);

	if (flags & NFCT_CP_OVERRIDE) {
		__copy_fast(ct1, ct2);
		return;
	}
	if (flags == NFCT_CP_ALL) {
		for (i=0; i<ATTR_MAX; i++) {
			if (test_bit(i, ct2->head.set)) {
				assert(copy_attr_array[i]);
				copy_attr_array[i](ct1, ct2);
				set_bit(i, ct1->head.set);
			}
		}
		return;
	}

	static const int cp_orig_mask[] = {
		ATTR_ORIG_IPV4_SRC,
		ATTR_ORIG_IPV4_DST,
		ATTR_ORIG_IPV6_SRC,
		ATTR_ORIG_IPV6_DST,
		ATTR_ORIG_PORT_SRC,
		ATTR_ORIG_PORT_DST,
		ATTR_ICMP_TYPE,
		ATTR_ICMP_CODE,
		ATTR_ICMP_ID,
		ATTR_ORIG_L3PROTO,
		ATTR_ORIG_L4PROTO,
	};
	#define __CP_ORIG_MAX sizeof(cp_orig_mask)/sizeof(int)

	if (flags & NFCT_CP_ORIG) {
		for (i=0; i<__CP_ORIG_MAX; i++) {
			if (test_bit(cp_orig_mask[i], ct2->head.set)) {
				assert(copy_attr_array[i]);
				copy_attr_array[cp_orig_mask[i]](ct1, ct2);
				set_bit(cp_orig_mask[i], ct1->head.set);
			}
		}
	}

	static const int cp_repl_mask[] = {
		ATTR_REPL_IPV4_SRC,
		ATTR_REPL_IPV4_DST,
		ATTR_REPL_IPV6_SRC,
		ATTR_REPL_IPV6_DST,
		ATTR_REPL_PORT_SRC,
		ATTR_REPL_PORT_DST,
		ATTR_REPL_L3PROTO,
		ATTR_REPL_L4PROTO,
	};
	#define __CP_REPL_MAX sizeof(cp_repl_mask)/sizeof(int)

	if (flags & NFCT_CP_REPL) {
		for (i=0; i<__CP_REPL_MAX; i++) {
			if (test_bit(cp_repl_mask[i], ct2->head.set)) {
				assert(copy_attr_array[i]);
				copy_attr_array[cp_repl_mask[i]](ct1, ct2);
				set_bit(cp_repl_mask[i], ct1->head.set);
			}
		}
	}

	if (flags & NFCT_CP_META) {
		for (i=ATTR_TCP_STATE; i<ATTR_MAX; i++) {
			if (test_bit(i, ct2->head.set)) {
				assert(copy_attr_array[i]),
				copy_attr_array[i](ct1, ct2);
				set_bit(i, ct1->head.set);
			}
		}
	}
}

void nfct_copy_attr(struct nf_conntrack *ct1,
		    const struct nf_conntrack *ct2,
		    const enum nf_conntrack_attr type)
{
	if (test_bit(type, ct2->head.set)) {
		assert(copy_attr_array[type]);
		copy_attr_array[type](ct1, ct2);
		set_bit(type, ct1->head.set);
	}
}



struct nfct_filter *nfct_filter_create(void)
{
	return calloc(sizeof(struct nfct_filter), 1);
}

void nfct_filter_destroy(struct nfct_filter *filter)
{
	assert(filter != NULL);
	free(filter);
	filter = NULL;
}

void nfct_filter_add_attr(struct nfct_filter *filter,
			  const enum nfct_filter_attr type, 
			  const void *value)
{
	assert(filter != NULL);
	assert(value != NULL);

	if (unlikely(type >= NFCT_FILTER_MAX))
		return;

	if (filter_attr_array[type]) {
		filter_attr_array[type](filter, value);
		set_bit(type, filter->set);
	}
}

void nfct_filter_add_attr_u32(struct nfct_filter *filter,
			      const enum nfct_filter_attr type,
			      u_int32_t value)
{
	nfct_filter_add_attr(filter, type, &value);
}

int nfct_filter_set_logic(struct nfct_filter *filter,
			  const enum nfct_filter_attr type,
			  const enum nfct_filter_logic logic)
{
	if (unlikely(type >= NFCT_FILTER_MAX)) {
		errno = ENOTSUP;
                return -1;
	}

	if (filter->logic[type]) {
		errno = EBUSY;
		return -1;
	}

	filter->logic[type] = logic;

	return 0;
}

int nfct_filter_attach(int fd, struct nfct_filter *filter)
{
	assert(filter != NULL);

	return __setup_netlink_socket_filter(fd, filter);
}

int nfct_filter_detach(int fd)
{
	int val = 0;

	return setsockopt(fd, SOL_SOCKET, SO_DETACH_FILTER, &val, sizeof(val));
}



struct nfct_filter_dump *nfct_filter_dump_create(void)
{
	return calloc(sizeof(struct nfct_filter_dump), 1);
}

void nfct_filter_dump_destroy(struct nfct_filter_dump *filter)
{
	assert(filter != NULL);
	free(filter);
	filter = NULL;
}

void nfct_filter_dump_set_attr(struct nfct_filter_dump *filter_dump,
			       const enum nfct_filter_dump_attr type,
			       const void *value)
{
	assert(filter_dump != NULL);
	assert(value != NULL);

	if (unlikely(type >= NFCT_FILTER_DUMP_MAX))
		return;

	if (set_filter_dump_attr_array[type]) {
		set_filter_dump_attr_array[type](filter_dump, value);
		filter_dump->set |= (1 << type);
	}
}

void nfct_filter_dump_set_attr_u8(struct nfct_filter_dump *filter_dump,
				  const enum nfct_filter_dump_attr type,
				  u_int8_t value)
{
	nfct_filter_dump_set_attr(filter_dump, type, &value);
}



const char *nfct_labelmap_get_name(struct nfct_labelmap *m, unsigned int bit)
{
	return __labelmap_get_name(m, bit);
}

int nfct_labelmap_get_bit(struct nfct_labelmap *m, const char *name)
{
	return __labelmap_get_bit(m, name);
}

struct nfct_labelmap *nfct_labelmap_new(const char *mapfile)
{
	return __labelmap_new(mapfile);
}

void nfct_labelmap_destroy(struct nfct_labelmap *map)
{
	__labelmap_destroy(map);
}



struct nfct_bitmask *nfct_bitmask_new(unsigned int max)
{
	struct nfct_bitmask *b;
	unsigned int bytes, words;

	if (max > 0xffff)
		return NULL;

	words = DIV_ROUND_UP(max+1, 32);
	bytes = words * sizeof(b->bits[0]);

	b = malloc(sizeof(*b) + bytes);
	if (b) {
		memset(b->bits, 0, bytes);
		b->words = words;
	}
	return b;
}

struct nfct_bitmask *nfct_bitmask_clone(const struct nfct_bitmask *b)
{
	unsigned int bytes = b->words * sizeof(b->bits[0]);
	struct nfct_bitmask *copy;

	bytes += sizeof(*b);

	copy = malloc(bytes);
	if (copy)
		memcpy(copy, b, bytes);
	return copy;
}

void nfct_bitmask_set_bit(struct nfct_bitmask *b, unsigned int bit)
{
	unsigned int bits = b->words * 32;
	if (bit < bits)
		set_bit(bit, b->bits);
}

int nfct_bitmask_test_bit(const struct nfct_bitmask *b, unsigned int bit)
{
	unsigned int bits = b->words * 32;
	return bit < bits && test_bit(bit, b->bits);
}

void nfct_bitmask_unset_bit(struct nfct_bitmask *b, unsigned int bit)
{
	unsigned int bits = b->words * 32;
	if (bit < bits)
		unset_bit(bit, b->bits);
}

unsigned int nfct_bitmask_maxbit(const struct nfct_bitmask *b)
{
	return (b->words * 32) - 1;
}

void nfct_bitmask_destroy(struct nfct_bitmask *b)
{
	free(b);
}


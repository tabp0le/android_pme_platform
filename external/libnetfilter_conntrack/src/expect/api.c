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


struct nf_expect *nfexp_new(void)
{
	struct nf_expect *exp;

	exp = malloc(sizeof(struct nf_expect));
	if (!exp)
		return NULL;

	memset(exp, 0, sizeof(struct nf_expect));

	return exp;
}

void nfexp_destroy(struct nf_expect *exp)
{
	assert(exp != NULL);
	free(exp);
	exp = NULL; 
}

size_t nfexp_sizeof(const struct nf_expect *exp)
{
	assert(exp != NULL);
	return sizeof(*exp);
}

size_t nfexp_maxsize(void)
{
	return sizeof(struct nf_expect);
}

struct nf_expect *nfexp_clone(const struct nf_expect *exp)
{
	struct nf_expect *clone;

	assert(exp != NULL);

	if ((clone = nfexp_new()) == NULL)
		return NULL;
	memcpy(clone, exp, sizeof(*exp));

	return clone;
}

int nfexp_cmp(const struct nf_expect *exp1, const struct nf_expect *exp2,
	      unsigned int flags)
{
        assert(exp1 != NULL);
        assert(exp2 != NULL);

        return __cmp_expect(exp1, exp2, flags);
}



int nfexp_callback_register(struct nfct_handle *h,
			    enum nf_conntrack_msg_type type,
			    int (*cb)(enum nf_conntrack_msg_type type,
			   	      struct nf_expect *exp, 
				      void *data),
			   void *data)
{
	struct __data_container *container;

	assert(h != NULL);

	container = malloc(sizeof(struct __data_container));
	if (!container)
		return -1;
	memset(container, 0, sizeof(struct __data_container));

	h->expect_cb = cb;
	container->h = h;
	container->type = type;
	container->data = data;

	h->nfnl_cb_exp.call = __callback;
	h->nfnl_cb_exp.data = container;
	h->nfnl_cb_exp.attr_count = CTA_EXPECT_MAX;

	nfnl_callback_register(h->nfnlssh_exp, 
			       IPCTNL_MSG_EXP_NEW,
			       &h->nfnl_cb_exp);

	nfnl_callback_register(h->nfnlssh_exp,
			       IPCTNL_MSG_EXP_DELETE,
			       &h->nfnl_cb_exp);

	return 0;
}

void nfexp_callback_unregister(struct nfct_handle *h)
{
	assert(h != NULL);

	nfnl_callback_unregister(h->nfnlssh_exp, IPCTNL_MSG_EXP_NEW);
	nfnl_callback_unregister(h->nfnlssh_exp, IPCTNL_MSG_EXP_DELETE);

	h->expect_cb = NULL;
	free(h->nfnl_cb_exp.data);

	h->nfnl_cb_exp.call = NULL;
	h->nfnl_cb_exp.data = NULL;
	h->nfnl_cb_exp.attr_count = 0;
}

int nfexp_callback_register2(struct nfct_handle *h,
			     enum nf_conntrack_msg_type type,
			     int (*cb)(const struct nlmsghdr *nlh,
			     	       enum nf_conntrack_msg_type type,
			   	       struct nf_expect *exp, 
				       void *data),
			     void *data)
{
	struct __data_container *container;

	assert(h != NULL);

	container = malloc(sizeof(struct __data_container));
	if (!container)
		return -1;
	memset(container, 0, sizeof(struct __data_container));

	h->expect_cb2 = cb;
	container->h = h;
	container->type = type;
	container->data = data;

	h->nfnl_cb_exp.call = __callback;
	h->nfnl_cb_exp.data = container;
	h->nfnl_cb_exp.attr_count = CTA_EXPECT_MAX;

	nfnl_callback_register(h->nfnlssh_exp, 
			       IPCTNL_MSG_EXP_NEW,
			       &h->nfnl_cb_exp);

	nfnl_callback_register(h->nfnlssh_exp,
			       IPCTNL_MSG_EXP_DELETE,
			       &h->nfnl_cb_exp);

	return 0;
}

void nfexp_callback_unregister2(struct nfct_handle *h)
{
	assert(h != NULL);

	nfnl_callback_unregister(h->nfnlssh_exp, IPCTNL_MSG_EXP_NEW);
	nfnl_callback_unregister(h->nfnlssh_exp, IPCTNL_MSG_EXP_DELETE);

	h->expect_cb2 = NULL;
	free(h->nfnl_cb_exp.data);

	h->nfnl_cb_exp.call = NULL;
	h->nfnl_cb_exp.data = NULL;
	h->nfnl_cb_exp.attr_count = 0;
}



void nfexp_set_attr(struct nf_expect *exp,
		    const enum nf_expect_attr type, 
		    const void *value)
{
	assert(exp != NULL);
	assert(value != NULL);

	if (type >= ATTR_EXP_MAX)
		return;

	if (set_exp_attr_array[type]) {
		set_exp_attr_array[type](exp, value);
		set_bit(type, exp->set);
	}
}

void nfexp_set_attr_u8(struct nf_expect *exp,
		       const enum nf_expect_attr type, 
		       u_int8_t value)
{
	nfexp_set_attr(exp, type, &value);
}

void nfexp_set_attr_u16(struct nf_expect *exp,
			const enum nf_expect_attr type, 
			u_int16_t value)
{
	nfexp_set_attr(exp, type, &value);
}

void nfexp_set_attr_u32(struct nf_expect *exp,
			const enum nf_expect_attr type, 
			u_int32_t value)
{
	nfexp_set_attr(exp, type, &value);
}

const void *nfexp_get_attr(const struct nf_expect *exp,
			   const enum nf_expect_attr type)
{
	assert(exp != NULL);

	if (type >= ATTR_EXP_MAX) {
		errno = EINVAL;
		return NULL;
	}

	if (!test_bit(type, exp->set)) {
		errno = ENODATA;
		return NULL;
	}

	return get_exp_attr_array[type](exp);
}

u_int8_t nfexp_get_attr_u8(const struct nf_expect *exp,
			   const enum nf_expect_attr type)
{
	const u_int8_t *ret = nfexp_get_attr(exp, type);
	return ret == NULL ? 0 : *ret;
}

u_int16_t nfexp_get_attr_u16(const struct nf_expect *exp,
			     const enum nf_expect_attr type)
{
	const u_int16_t *ret = nfexp_get_attr(exp, type);
	return ret == NULL ? 0 : *ret;
}

u_int32_t nfexp_get_attr_u32(const struct nf_expect *exp,
			    const enum nf_expect_attr type)
{
	const u_int32_t *ret = nfexp_get_attr(exp, type);
	return ret == NULL ? 0 : *ret;
}

int nfexp_attr_is_set(const struct nf_expect *exp,
		      const enum nf_expect_attr type)
{
	assert(exp != NULL);

	if (type >= ATTR_EXP_MAX) {
		errno = EINVAL;
		return -1;
	}
	return test_bit(type, exp->set);
}

int nfexp_attr_unset(struct nf_expect *exp,
		     const enum nf_expect_attr type)
{
	assert(exp != NULL);

	if (type >= ATTR_EXP_MAX) {
		errno = EINVAL;
		return -1;
	}
	unset_bit(type, exp->set);

	return 0;
}



int nfexp_build_expect(struct nfnl_subsys_handle *ssh,
		       void *req,
		       size_t size,
		       u_int16_t type,
		       u_int16_t flags,
		       const struct nf_expect *exp)
{
	assert(ssh != NULL);
	assert(req != NULL);
	assert(exp != NULL);

	return __build_expect(ssh, req, size, type, flags, exp);
}

static int
__build_query_exp(struct nfnl_subsys_handle *ssh,
		  const enum nf_conntrack_query qt,
		  const void *data, void *buffer, unsigned int size)
{
	struct nfnlhdr *req = buffer;
	const u_int8_t *family = data;

	assert(ssh != NULL);
	assert(data != NULL);
	assert(req != NULL);

	memset(req, 0, size);

	switch(qt) {
	case NFCT_Q_CREATE:
		__build_expect(ssh, req, size, IPCTNL_MSG_EXP_NEW, NLM_F_REQUEST|NLM_F_CREATE|NLM_F_ACK|NLM_F_EXCL, data);
		break;
	case NFCT_Q_CREATE_UPDATE:
		__build_expect(ssh, req, size, IPCTNL_MSG_EXP_NEW, NLM_F_REQUEST|NLM_F_CREATE|NLM_F_ACK, data);
		break;
	case NFCT_Q_GET:
		__build_expect(ssh, req, size, IPCTNL_MSG_EXP_GET, NLM_F_REQUEST|NLM_F_ACK, data);
		break;
	case NFCT_Q_DESTROY:
		__build_expect(ssh, req, size, IPCTNL_MSG_EXP_DELETE, NLM_F_REQUEST|NLM_F_ACK, data);
		break;
	case NFCT_Q_FLUSH:
		nfnl_fill_hdr(ssh, &req->nlh, 0, *family, 0, IPCTNL_MSG_EXP_DELETE, NLM_F_REQUEST|NLM_F_ACK);
		break;
	case NFCT_Q_DUMP:
		nfnl_fill_hdr(ssh, &req->nlh, 0, *family, 0, IPCTNL_MSG_EXP_GET, NLM_F_REQUEST|NLM_F_DUMP);
		break;
	default:
		errno = ENOTSUP;
		return -1;
	}
	return 1;
}

int nfexp_build_query(struct nfnl_subsys_handle *ssh,
		      const enum nf_conntrack_query qt,
		      const void *data,
		      void *buffer,
		      unsigned int size)
{
	return __build_query_exp(ssh, qt, data, buffer, size);
}

int nfexp_parse_expect(enum nf_conntrack_msg_type type,
		       const struct nlmsghdr *nlh,
		       struct nf_expect *exp)
{
	unsigned int flags;
	int len = nlh->nlmsg_len;
	struct nfgenmsg *nfhdr = NLMSG_DATA(nlh);
	struct nfattr *cda[CTA_EXPECT_MAX];

	assert(nlh != NULL);
	assert(exp != NULL);

	len -= NLMSG_LENGTH(sizeof(struct nfgenmsg));
	if (len < 0) {
		errno = EINVAL;
		return NFCT_T_ERROR;
	}

	flags = __parse_expect_message_type(nlh);
	if (!(flags & type))
		return 0;

	nfnl_parse_attr(cda, CTA_EXPECT_MAX, NFA_DATA(nfhdr), len);

	__parse_expect(nlh, cda, exp);

	return flags;
}



int nfexp_query(struct nfct_handle *h,
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

	if (__build_query_exp(h->nfnlssh_exp, qt, data, &u.req, size) == -1)
		return -1;

	return nfnl_query(h->nfnlh, &u.req.nlh);
}

int nfexp_send(struct nfct_handle *h,
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

	if (__build_query_exp(h->nfnlssh_exp, qt, data, &u.req, size) == -1)
		return -1;

	return nfnl_send(h->nfnlh, &u.req.nlh);
}

int nfexp_catch(struct nfct_handle *h)
{
	assert(h != NULL);

	return nfnl_catch(h->nfnlh);
}



int nfexp_snprintf(char *buf,
		  unsigned int size,
		  const struct nf_expect *exp,
		  unsigned int msg_type,
		  unsigned int out_type,
		  unsigned int flags) 
{
	assert(buf != NULL);
	assert(size > 0);
	assert(exp != NULL);

	return __snprintf_expect(buf, size, exp, msg_type, out_type, flags);
}


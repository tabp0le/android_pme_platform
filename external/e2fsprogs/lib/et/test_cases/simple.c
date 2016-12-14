
#include <stdlib.h>

#define N_(a) a

static const char * const text[] = {
	N_(			"Can't read ticket file"),
	N_(			"Can't find ticket or TGT"),
	N_(			"TGT expired"),
	N_(			"Can't decode authenticator"),
	N_(			"Ticket expired"),
	N_(			"Repeated request"),
	N_(			"The ticket isn't for us"),
	N_(			"Request is inconsistent"),
	N_(			"Delta-T too big"),
	N_(			"Incorrect net address"),
	N_(			"Protocol version mismatch"),
	N_(			"Invalid message type"),
	N_(			"Message stream modified"),
	N_(			"Message out of order"),
	N_(			"Unauthorized request"),
	N_(			"Current password is null"),
	N_(			"Incorrect current password"),
	N_(			"Protocol error"),
	N_(			"Error returned by KDC"),
	N_(			"Null ticket returned by KDC"),
	N_(			"Retry count exceeded"),
	N_(			"Can't send request"),
    0
};

struct error_table {
    char const * const * msgs;
    long base;
    int n_msgs;
};
struct et_list {
    struct et_list *next;
    const struct error_table * table;
};
extern struct et_list *_et_list;

const struct error_table et_krb_error_table = { text, 39525376L, 22 };

static struct et_list link = { 0, 0 };

void initialize_krb_error_table_r(struct et_list **list);
void initialize_krb_error_table(void);

void initialize_krb_error_table(void) {
    initialize_krb_error_table_r(&_et_list);
}

void initialize_krb_error_table_r(struct et_list **list)
{
    struct et_list *et, **end;

    for (end = list, et = *list; et; end = &et->next, et = et->next)
        if (et->table->msgs == text)
            return;
    et = malloc(sizeof(struct et_list));
    if (et == 0) {
        if (!link.table)
            et = &link;
        else
            return;
    }
    et->table = &et_krb_error_table;
    et->next = 0;
    *end = et;
}

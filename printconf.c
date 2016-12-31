/*	$OpenBSD$	*/

/*
 * Copyright (c) YYYY YOUR NAME HERE <user@your.dom.ain>
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <event.h>
#include <imsg.h>
#include <stdio.h>

#include "newd.h"

void
print_config(struct newd_conf *conf)
{
	struct group *g;
	char buf[100], *bufp;

	printf("csock %s\n", conf->csock);

	if (conf->opts == 0) {
		printf("<no opt set>\n");
	} else {
		if (conf->opts & OPT_VERBOSE)
			printf("VERBOSE ");
		if (conf->opts & OPT_VERBOSE2)
			printf("VERBOSE2 ");
		if (conf->opts & OPT_NOACTION)
			printf("NOACTION ");
		printf("\n");
	}

	printf("yesno-attribute %s\n",
	    conf->yesno_attribute ? "yes" : "no");
	printf("global-yesno_attribute %s\n",
	    conf->global_yesno_attribute ? "yes" : "no");

	printf("integer-attribute %d\n", conf->integer_attribute);
	printf("global-integer-attribute %d\n", conf->global_integer_attribute);

	bufp = inet_net_ntop(AF_INET, &conf->v4address_attribute,
	    conf->v4_bits, buf, sizeof(buf));
	if (bufp != NULL)
		printf("v4address-attribute %s\n", bufp);
	bufp = inet_net_ntop(AF_INET, &conf->global_v4address_attribute,
	    conf->global_v4_bits, buf, sizeof(buf));
	if (bufp != NULL)
		printf("global-v4address-attribute %s\n", bufp);

	bufp = inet_net_ntop(AF_INET6, &conf->v6address_attribute,
	    conf->v6_bits, buf, sizeof(buf));
	if (bufp != NULL)
		printf("v6address-attribute %s\n", bufp);
	bufp = inet_net_ntop(AF_INET6, &conf->global_v6address_attribute,
	    conf->global_v6_bits, buf, sizeof(buf));
	if (bufp != NULL)
		printf("global-v6address-attribute %s\n", bufp);

	if (conf->string_attribute != NULL)
		printf("string_attribute \"%s\"\n", conf->string_attribute);
	if (conf->global_string_attribute != NULL)
		printf("global_string_attribute \"%s\"\n",
		    conf->global_string_attribute);

	LIST_FOREACH(g, &conf->group_list, entry) {
		printf("group %s {\n", g->name);
		printf("\tyesno-attribute %s\n",
		    g->yesno_attribute ? "yes" : "no");
		printf("\tgroup-yesno_attribute %s\n",
		    g->group_yesno_attribute ? "yes" : "no");

		printf("\tinteger-attribute %d\n", g->integer_attribute);
		printf("\tgroup-integer-attribute %d\n",
		    g->group_integer_attribute);

		bufp = inet_net_ntop(AF_INET, &g->v4address_attribute,
		    g->v4_bits, buf, sizeof(buf));
		if (bufp != NULL)
			printf("\tv4address-attribute %s\n", bufp);
		bufp = inet_net_ntop(AF_INET, &g->group_v4address_attribute,
		    g->group_v4_bits, buf, sizeof(buf));
		if (bufp != NULL)
			printf("\tgroup-v4address-attribute %s\n", bufp);

		bufp = inet_net_ntop(AF_INET6, &g->v6address_attribute,
		    g->v6_bits, buf, sizeof(buf));
		if (bufp != NULL)
			printf("\tv6address-attribute %s\n", bufp);
		bufp = inet_net_ntop(AF_INET6, &g->group_v6address_attribute,
		    g->group_v6_bits, buf, sizeof(buf));
		if (bufp != NULL)
			printf("\tgroup-v6address-attribute %s\n", bufp);

		if (g->string_attribute != NULL)
			printf("\tstring_attribute \"%s\"\n",
			    g->string_attribute);
		if (g->group_string_attribute != NULL)
			printf("\tgroup_string_attribute \"%s\"\n",
			    g->group_string_attribute);
		printf("}\n");
	}
}

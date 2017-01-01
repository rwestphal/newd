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

	printf("yesno %s\n", conf->yesno ? "yes" : "no");
	printf("integer %d\n", conf->integer);
	printf("text \"%s\"\n", conf->text ? conf->text : "");
	bufp = inet_net_ntop(AF_INET, &conf->v4address, conf->v4_bits, buf,
	    sizeof(buf));
	printf("v4address %s\n", bufp ? bufp : "0.0.0.0/0");
	bufp = inet_net_ntop(AF_INET6, &conf->v6address, conf->v6_bits, buf,
	    sizeof(buf));
	printf("v6address %s\n", bufp ? bufp : "::0/0");
	printf("\n");

	printf("global-yesno %s\n", conf->global_yesno ? "yes" : "no");
	printf("global-integer %d\n", conf->global_integer);
	printf("global_text \"%s\"\n",
	    conf->global_text ? conf->global_text : "");
	bufp = inet_net_ntop(AF_INET, &conf->global_v4address,
	    conf->global_v4_bits, buf, sizeof(buf));
	printf("global-v4address %s\n", bufp ? bufp : "0.0.0.0/0");
	bufp = inet_net_ntop(AF_INET6, &conf->global_v6address,
	    conf->global_v6_bits, buf, sizeof(buf));
	printf("global-v6address %s\n", bufp ? bufp : "::0/0");
	printf("\n");


	LIST_FOREACH(g, &conf->group_list, entry) {
		printf("group %s {\n", g->name);

		printf("\tyesno %s\n", g->yesno ? "yes" : "no");
		printf("\tinteger %d\n", g->integer);
		printf("\ttext \"%s\"\n", g->text ? g->text : "");
		bufp = inet_net_ntop(AF_INET, &g->v4address,
		    g->v4_bits, buf, sizeof(buf));
		printf("\tv4address %s\n", bufp ? bufp : "0.0.0.0/0");
		bufp = inet_net_ntop(AF_INET6, &g->v6address, g->v6_bits, buf,
		    sizeof(buf));
		printf("\tv6address %s\n", bufp ? bufp : "::0/0");
		printf("\n");

		printf("\tgroup-yesno %s\n", g->group_yesno ? "yes" : "no");
		printf("\tgroup-integer %d\n", g->group_integer);
		printf("\tgroup_text \"%s\"\n",
		    g->group_text ? g->group_text : "");
		bufp = inet_net_ntop(AF_INET, &g->group_v4address,
		    g->group_v4_bits, buf, sizeof(buf));
		printf("\tgroup-v4address %s\n", bufp ? bufp : "0.0.0.0/0");
		bufp = inet_net_ntop(AF_INET6, &g->group_v6address,
		    g->group_v6_bits, buf, sizeof(buf));
		printf("\tgroup-v6address %s\n", bufp ? bufp : "0.0.0.0/0");
		if (bufp != NULL)

		printf("}\n");
	}
}

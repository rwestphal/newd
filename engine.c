/*	$OpenBSD$	*/

/*
 * Copyright (c) YYYY YOUR NAME HERE <user@your.dom.ain>
 * Copyright (c) 2004, 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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

#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>

#include "newd.h"
#include "engine.h"
#include "log.h"

void		 engine_sig_handler(int sig, short, void *);
__dead void	 engine_shutdown(void);
void		 engine_dispatch_frontend(int, short, void *);
void		 engine_dispatch_main(int, short, void *);
void		 engine_showinfo_ctl(struct imsg *);

struct newd_conf	*engine_conf = NULL, *nconf = NULL;
struct imsgev		*iev_frontend;
struct imsgev		*iev_main;

/* ARGSUSED */
void
engine_sig_handler(int sig, short event, void *arg)
{
	/*
	 * signal handler rules don't apply, libevent decouples for us
	 */

	switch (sig) {
	case SIGINT:
	case SIGTERM:
		engine_shutdown();
		/* NOTREACHED */
	default:
		fatalx("unexpected signal");
	}
}

/* engine */
pid_t
engine(struct newd_conf *xconf, int pipe_main2engine[2],
    int pipe_frontend2engine[2], int pipe_main2frontend[2])
{
	struct event		 ev_sigint, ev_sigterm;
	struct passwd		*pw;
	pid_t			 pid;

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
		/* NOTREACHED */
	case 0:
		break;
	default:
		return (pid);
	}

	/* Cleanup. */

	engine_conf = xconf;

	if ((pw = getpwnam(NEWD_USER)) == NULL)
		fatal("getpwnam");

	if (chroot(pw->pw_dir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	setproctitle("engine");
	newd_process = PROC_ENGINE;
	log_procname = log_procnames[newd_process];

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	if (pledge("stdio", NULL) == -1)
		fatal("pledge");

	event_init();

	/* Setup signal handler(s). */
	signal_set(&ev_sigint, SIGINT, engine_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, engine_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/* Setup pipes. */
	close(pipe_main2engine[0]);
	close(pipe_frontend2engine[0]);
	close(pipe_main2frontend[0]);
	close(pipe_main2frontend[1]);

	if ((iev_frontend = malloc(sizeof(struct imsgev))) == NULL ||
	    (iev_main = malloc(sizeof(struct imsgev))) == NULL)
		fatal(NULL);
	imsg_init(&iev_frontend->ibuf, pipe_frontend2engine[1]);
	iev_frontend->handler = engine_dispatch_frontend;
	imsg_init(&iev_main->ibuf, pipe_main2engine[1]);
	iev_main->handler = engine_dispatch_main;

	/* Setup event handlers. */
	iev_frontend->events = EV_READ;
	event_set(&iev_frontend->ev, iev_frontend->ibuf.fd,
	    iev_frontend->events, iev_frontend->handler, iev_frontend);
	event_add(&iev_frontend->ev, NULL);

	iev_main->events = EV_READ;
	event_set(&iev_main->ev, iev_main->ibuf.fd, iev_main->events,
	    iev_main->handler, iev_main);
	event_add(&iev_main->ev, NULL);

	/* Remove unneeded stuff from config */

	event_dispatch();

	engine_shutdown();
	/* NOTREACHED */

	return (0);
}

__dead void
engine_shutdown(void)
{
	/* Close pipes. */
	msgbuf_clear(&iev_frontend->ibuf.w);
	close(iev_frontend->ibuf.fd);
	msgbuf_clear(&iev_main->ibuf.w);
	close(iev_main->ibuf.fd);

	free(iev_frontend);
	free(iev_main);
	free(engine_conf);

	log_info("engine exiting");
	_exit(0);
}

int
engine_imsg_compose_frontend(int type, pid_t pid, void *data,
    u_int16_t datalen)
{
	return (imsg_compose_event(iev_frontend, type, 0, pid, -1,
	    data, datalen));
}

/* ARGSUSED */
void
engine_dispatch_frontend(int fd, short event, void *bula)
{
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf;
	struct imsg		 imsg;
	ssize_t			 n;
	int			 shut = 0, verbose;

	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0)	/* connection closed */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0)	/* connection closed */
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("engine_dispatch_main: imsg_get error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_CTL_LOG_VERBOSE:
			/* Already checked by frontend. */
			memcpy(&verbose, imsg.data, sizeof(verbose));
			log_verbose(verbose);
			break;
		case IMSG_CTL_SHOW_ENGINE_INFO:
			engine_showinfo_ctl(&imsg);
			break;
		default:
			log_debug("engine_dispatch_frontend: unexpected "
			    "imsg %d", imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		/* this pipe is dead, so remove the event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

/* ARGSUSED */
void
engine_dispatch_main(int fd, short event, void *bula)
{
	struct imsg		 imsg;
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf;
	ssize_t			 n;
	int			 shut = 0;

	ibuf = &iev->ibuf;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0)	/* connection closed */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0)	/* connection closed */
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("engine_dispatch_main: imsg_get error");
		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_RECONF_CONF:
			if ((nconf = malloc(sizeof(struct newd_conf))) ==
			    NULL)
				fatal(NULL);
			memcpy(nconf, imsg.data, sizeof(struct newd_conf));
			LIST_INIT(&nconf->group_list);
			break;
		case IMSG_RECONF_END:
			merge_config(engine_conf, nconf);
			nconf = NULL;
			break;
		default:
			log_debug("engine_dispatch_main: unexpected imsg %d",
			    imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		/* this pipe is dead, so remove the event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
engine_showinfo_ctl(struct imsg *imsg)
{
	struct group *g;
	struct ctl_engine_info cei;
	char filter[NEWD_MAXGROUPNAME];

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_ENGINE_INFO:
		memcpy(filter, imsg->data, sizeof(filter));
		LIST_FOREACH(g, &engine_conf->group_list, entry) {
			if (filter[0] == '\0' || memcmp(filter, g->name,
			    sizeof(filter)) == 0) {
				memcpy(cei.name, g->name, sizeof(cei.name));
				cei.yesno = g->yesno;
				cei.integer = g->integer;
				cei.group_v4_bits = g->group_v4_bits;
				cei.group_v6_bits = g->group_v6_bits;
				memcpy(&cei.group_v4address,
				    &g->group_v4address,
				    sizeof(cei.group_v4address));
				memcpy(&cei.group_v6address,
				    &g->group_v6address,
				    sizeof(cei.group_v6address));

				engine_imsg_compose_frontend(
				    IMSG_CTL_SHOW_ENGINE_INFO, imsg->hdr.pid,
				    &cei, sizeof(cei));
			}
		}
		engine_imsg_compose_frontend(IMSG_CTL_END, imsg->hdr.pid, NULL,
		    0);
		break;
	default:
		log_debug("engine_showinfo_ctl: error handling imsg");
		break;
	}
}

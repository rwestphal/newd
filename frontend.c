/*	$OpenBSD$	*/

/*
 * Copyright (c) YYYY YOUR NAME HERE <user@your.dom.ain>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
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
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "newd.h"
#include "frontend.h"
#include "control.h"
#include "log.h"

__dead void	 frontend_shutdown(void);
void		 frontend_sig_handler(int, short, void *);

struct newd_conf	*frontend_conf = NULL, *nconf;
struct imsgev		*iev_main;
struct imsgev		*iev_engine;

void
frontend_sig_handler(int sig, short event, void *bula)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGINT:
	case SIGTERM:
		frontend_shutdown();
		/* NOTREACHED */
	default:
		fatalx("unexpected signal");
	}
}

pid_t
frontend(struct newd_conf *xconf, int pipe_main2frontend[2],
    int pipe_frontend2engine[2], int pipe_main2engine[2])
{
	struct event	 ev_sigint, ev_sigterm;
	struct passwd	*pw;
	pid_t		 pid;

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		return (pid);
	}

	/* Cleanup. */

	/* Create newd control socket outside chroot. */
	if (control_init(xconf->csock) == -1)
		fatalx("control socket setup failed");

	/* Set defaults. */
	frontend_conf = xconf;

	if ((pw = getpwnam(NEWD_USER)) == NULL)
		fatal("getpwnam");

	if (chroot(pw->pw_dir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	setproctitle("frontend");
	newd_process = PROC_FRONTEND;
	log_procname = log_procnames[newd_process];

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	if (pledge("stdio inet", NULL) == -1)
		fatal("pledge");

	event_init();

	/* setup signal handler */
	signal_set(&ev_sigint, SIGINT, frontend_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, frontend_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	/* Setup pipes. */
	close(pipe_main2frontend[0]);
	close(pipe_frontend2engine[1]);
	close(pipe_main2engine[0]);
	close(pipe_main2engine[1]);

	if ((iev_engine = malloc(sizeof(struct imsgev))) == NULL ||
	    (iev_main = malloc(sizeof(struct imsgev))) == NULL)
		fatal(NULL);
	imsg_init(&iev_engine->ibuf, pipe_frontend2engine[0]);
	iev_engine->handler = frontend_dispatch_engine;
	imsg_init(&iev_main->ibuf, pipe_main2frontend[1]);
	iev_main->handler = frontend_dispatch_main;

	/* Setup event handlers. */
	iev_engine->events = EV_READ;
	event_set(&iev_engine->ev, iev_engine->ibuf.fd, iev_engine->events,
	    iev_engine->handler, iev_engine);
	event_add(&iev_engine->ev, NULL);

	iev_main->events = EV_READ;
	event_set(&iev_main->ev, iev_main->ibuf.fd, iev_main->events,
	    iev_main->handler, iev_main);
	event_add(&iev_main->ev, NULL);

	/* listen on newd control socket */
	TAILQ_INIT(&ctl_conns);
	control_listen();

	event_dispatch();

	frontend_shutdown();
	/* NOTREACHED */
	return (0);
}

__dead void
frontend_shutdown(void)
{
	/* Close pipes. */
	msgbuf_write(&iev_engine->ibuf.w);
	msgbuf_clear(&iev_engine->ibuf.w);
	close(iev_engine->ibuf.fd);

	msgbuf_write(&iev_main->ibuf.w);
	msgbuf_clear(&iev_main->ibuf.w);
	close(iev_main->ibuf.fd);

	/* Clean up. */
	free(iev_engine);
	free(iev_main);
	free(frontend_conf);

	log_info("frontend exiting");
	_exit(0);
}

int
frontend_imsg_compose_main(int type, pid_t pid, void *data,
    u_int16_t datalen)
{
	return (imsg_compose_event(iev_main, type, 0, pid, -1, data,
	    datalen));
}

int
frontend_imsg_compose_engine(int type, u_int32_t peerid, pid_t pid,
    void *data, u_int16_t datalen)
{
	return (imsg_compose_event(iev_engine, type, peerid, pid, -1,
	    data, datalen));
}

void
frontend_dispatch_main(int fd, short event, void *bula)
{
	struct imsg	 imsg;
	struct group	*g;
	struct imsgev	*iev = bula;
	struct imsgbuf	*ibuf = &iev->ibuf;
	int		 n, shut = 0;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("frontend_dispatch_main: imsg_get error");
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case IMSG_RECONF_CONF:
			if ((nconf = malloc(sizeof(struct newd_conf))) ==
			    NULL)
				fatal(NULL);
			memcpy(nconf, imsg.data, sizeof(struct newd_conf));
			LIST_INIT(&nconf->group_list);
			break;
		case IMSG_RECONF_GROUP:
			if ((g = malloc(sizeof(struct group))) == NULL)
				fatal(NULL);
			memcpy(g, imsg.data, sizeof(struct group));
			LIST_INSERT_HEAD(&nconf->group_list, g, entry);
			break;
		case IMSG_RECONF_END:
			merge_config(frontend_conf, nconf);
			nconf = NULL;
			break;
		case IMSG_CTL_END:
		case IMSG_CTL_SHOW_MAIN_INFO:
			control_imsg_relay(&imsg);
			break;
		default:
			log_debug("frontend_dispatch_main: error handling "
			    "imsg %d", imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		/* This pipe is dead. Remove its event handler. */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
frontend_dispatch_engine(int fd, short event, void *bula)
{
	struct imsgev		*iev = bula;
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	int			 n, shut = 0;

	if (event & EV_READ) {
		if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
			fatal("imsg_read error");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}
	if (event & EV_WRITE) {
		if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
			fatal("msgbuf_write");
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("frontend_dispatch_engine: imsg_get error");
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case IMSG_CTL_END:
		case IMSG_CTL_SHOW_ENGINE_INFO:
			control_imsg_relay(&imsg);
			break;
		default:
			log_debug("frontend_dispatch_engine: error handling "
			    "imsg %d", imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		/* This pipe is dead. Remove its event handler. */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

void
frontend_showinfo_ctl(struct ctl_conn *c)
{
	static struct ctl_frontend_info cfi;

	cfi.opts = frontend_conf->opts;
	cfi.yesno = frontend_conf->yesno;
	cfi.integer = frontend_conf->integer;

	memcpy(cfi.global_text, frontend_conf->global_text,
	    sizeof(cfi.global_text));

	imsg_compose_event(&c->iev, IMSG_CTL_SHOW_FRONTEND_INFO, 0, 0, -1,
	    &cfi, sizeof(struct ctl_frontend_info));
}

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
#include <sys/wait.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "newd.h"
#include "frontend.h"
#include "engine.h"
#include "control.h"
#include "log.h"

void		main_sig_handler(int, short, void *);
__dead void	usage(void);
__dead void	main_shutdown(void);

void	main_dispatch_frontend(int, short, void *);
void	main_dispatch_engine(int, short, void *);

int	main_reload(void);
int	main_sendboth(enum imsg_type, void *, u_int16_t);
void	main_showinfo_ctl(struct imsg *);

int	pipe_main2frontend[2];
int	pipe_main2engine[2];
int	pipe_frontend2engine[2];

struct newd_conf	*main_conf = NULL;
struct imsgev		*iev_frontend;
struct imsgev		*iev_engine;
char			*conffile;

pid_t			 frontend_pid = 0;
pid_t			 engine_pid = 0;

/* ARGSUSED */
void
main_sig_handler(int sig, short event, void *arg)
{
	/* signal handler rules don't apply, libevent decouples for us */
	switch (sig) {
	case SIGTERM:
	case SIGINT:
		main_shutdown();
		/* NOTREACHED */
	case SIGHUP:
		if (main_reload() == -1)
			log_warnx("configuration reload failed");
		else
			log_debug("configuration reloaded");
		break;
	default:
		fatalx("unexpected signal");
		/* NOTREACHED */
	}
}

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-dnv] [-f file] [-s socket]\n",
	    __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct event		 ev_sigint, ev_sigterm, ev_sighup;
	int			 ch, opts = 0;
	int			 debug = 0;
	char			*sockname;

	conffile = CONF_FILE;
	newd_process = PROC_MAIN;
	log_procname = log_procnames[newd_process];
	sockname = NEWD_SOCKET;

	log_init(1);	/* log to stderr until daemonized */
	log_verbose(1);

	while ((ch = getopt(argc, argv, "df:ns:v")) != -1) {
		switch (ch) {
		case 'd':
			debug = 1;
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'n':
			opts |= OPT_NOACTION;
			break;
		case 's':
			sockname = optarg;
			break;
		case 'v':
			if (opts & OPT_VERBOSE)
				opts |= OPT_VERBOSE2;
			opts |= OPT_VERBOSE;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;
	if (argc > 0)
		usage();

	/*
	 * Check system environment (e.g. appropriate sysctl settings) and
	 * save anything required for future operations.
	 */

	/* parse config file */
	if ((main_conf = parse_config(conffile, opts)) == NULL) {
		exit(1);
	}
	main_conf->csock = sockname;

	if (main_conf->opts & OPT_NOACTION) {
		if (main_conf->opts & OPT_VERBOSE)
			print_config(main_conf);
		else
			fprintf(stderr, "configuration OK\n");
		exit(0);
	}

	/* Check for root privileges. */
	if (geteuid())
		errx(1, "need root privileges");

	/* Check for assigned daemon user */
	if (getpwnam(NEWD_USER) == NULL)
		errx(1, "unknown user %s", NEWD_USER);

	log_init(debug);
	log_verbose(main_conf->opts & OPT_VERBOSE);

	if (!debug)
		daemon(1, 0);

	log_info("startup");

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, pipe_main2frontend) == -1)
		fatal("main2frontend socketpair");
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, pipe_main2engine) == -1)
		fatal("main2engine socketpair");
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    PF_UNSPEC, pipe_frontend2engine) == -1)
		fatal("frontend2engine socketpair");

	/* Start children. */
	engine_pid = engine(main_conf, pipe_main2engine,
	    pipe_frontend2engine, pipe_main2frontend);
	frontend_pid = frontend(main_conf, pipe_main2frontend,
	    pipe_frontend2engine, pipe_main2engine);

	setproctitle("main");
	event_init();

	/* setup signal handler */
	signal_set(&ev_sigint, SIGINT, main_sig_handler, NULL);
	signal_set(&ev_sigterm, SIGTERM, main_sig_handler, NULL);
	signal_set(&ev_sighup, SIGHUP, main_sig_handler, NULL);
	signal_add(&ev_sigint, NULL);
	signal_add(&ev_sigterm, NULL);
	signal_add(&ev_sighup, NULL);
	signal(SIGPIPE, SIG_IGN);

	/* setup pipes to children */
	close(pipe_main2frontend[1]);
	close(pipe_main2engine[1]);
	close(pipe_frontend2engine[0]);
	close(pipe_frontend2engine[1]);

	if ((iev_frontend = malloc(sizeof(struct imsgev))) == NULL ||
	    (iev_engine = malloc(sizeof(struct imsgev))) == NULL)
		fatal(NULL);
	imsg_init(&iev_frontend->ibuf, pipe_main2frontend[0]);
	iev_frontend->handler = main_dispatch_frontend;
	imsg_init(&iev_engine->ibuf, pipe_main2engine[0]);
	iev_engine->handler = main_dispatch_engine;

	/* Setup event handlers for pipes to engine & frontend. */
	iev_frontend->events = EV_READ;
	event_set(&iev_frontend->ev, iev_frontend->ibuf.fd,
	    iev_frontend->events, iev_frontend->handler, iev_frontend);
	event_add(&iev_frontend->ev, NULL);

	iev_engine->events = EV_READ;
	event_set(&iev_engine->ev, iev_engine->ibuf.fd, iev_engine->events,
	    iev_engine->handler, iev_engine);
	event_add(&iev_engine->ev, NULL);

	/* Do any remaining initialization. */

	/* Remove no longer needed stuff from config. */

	event_dispatch();

	main_shutdown();
	/* NOTREACHED */
	return (0);
}

__dead void
main_shutdown(void)
{
	pid_t			 pid;
	int			 status;

	/* close pipes */
	msgbuf_clear(&iev_frontend->ibuf.w);
	close(iev_frontend->ibuf.fd);
	msgbuf_clear(&iev_engine->ibuf.w);
	close(iev_engine->ibuf.fd);

	control_cleanup(main_conf->csock);

	/* Shutdown/cleanup anything else needing attention. */

	log_debug("waiting for children to terminate");
	do {
		pid = wait(&status);
		if (pid == -1) {
			if (errno != EINTR && errno != ECHILD)
				fatal("wait");
		} else if (WIFSIGNALED(status))
			log_warnx("%s terminated; signal %d",
			    (pid == engine_pid) ? "engine" :
			    "frontend", WTERMSIG(status));
	} while (pid != -1 || (pid == -1 && errno == EINTR));

	free(iev_frontend);
	free(iev_engine);
	free(main_conf);

	log_info("terminating");
	exit(0);
}

/* imsg handling */
/* ARGSUSED */
void
main_dispatch_frontend(int fd, short event, void *bula)
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
			fatal("imsg_get");

		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_CTL_RELOAD:
			if (main_reload() == -1)
				log_warnx("configuration reload failed");
			else
				log_warnx("configuration reloaded");
			break;
		case IMSG_CTL_LOG_VERBOSE:
			/* Already checked by frontend. */
			memcpy(&verbose, imsg.data, sizeof(verbose));
			log_verbose(verbose);
			break;
		case IMSG_CTL_SHOW_MAIN_INFO:
			main_showinfo_ctl(&imsg);
			break;
		default:
			log_debug("main_dispatch_frontend: error handling "
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
main_dispatch_engine(int fd, short event, void *bula)
{
	struct imsgev	*iev = bula;
	struct imsgbuf  *ibuf;
	struct imsg	 imsg;
	ssize_t		 n;
	int		 shut = 0;

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
			fatal("imsg_get");

		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		default:
			log_debug("main_dispatch_engine: error handling "
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

void
main_imsg_compose_frontend(int type, pid_t pid, void *data, u_int16_t datalen)
{
	if (iev_frontend)
		imsg_compose_event(iev_frontend, type, 0, pid, -1, data,
		    datalen);
}

void
main_imsg_compose_engine(int type, pid_t pid, void *data, u_int16_t datalen)
{
	if (iev_engine)
		imsg_compose_event(iev_engine, type, 0, pid, -1, data,
		    datalen);
}

void
imsg_event_add(struct imsgev *iev)
{
	iev->events = EV_READ;
	if (iev->ibuf.w.queued)
		iev->events |= EV_WRITE;

	event_del(&iev->ev);
	event_set(&iev->ev, iev->ibuf.fd, iev->events, iev->handler, iev);
	event_add(&iev->ev, NULL);
}

int
imsg_compose_event(struct imsgev *iev, u_int16_t type, u_int32_t peerid,
    pid_t pid, int fd, void *data, u_int16_t datalen)
{
	int	ret;

	if ((ret = imsg_compose(&iev->ibuf, type, peerid,
	    pid, fd, data, datalen)) != -1)
		imsg_event_add(iev);
	return (ret);
}

int
main_reload(void)
{
	struct newd_conf *xconf;
	struct group	 *g;

	if ((xconf = parse_config(conffile, main_conf->opts)) == NULL)
		return (-1);

	/* Send fixed part of config to children. */
	if (main_sendboth(IMSG_RECONF_CONF, xconf, sizeof(*xconf)) == -1)
		return (-1);

	/* Send the group list to children. */
	LIST_FOREACH(g, &xconf->group_list, entry) {
		if (main_sendboth(IMSG_RECONF_GROUP, g, sizeof(*g)) == -1)
			return (-1);
	}

	/* Tell children the revised config is now complete. */
	if (main_sendboth(IMSG_RECONF_END, NULL, 0) == -1)
		return (-1);

	merge_config(main_conf, xconf);
	return (0);
}

int
main_sendboth(enum imsg_type type, void *buf, u_int16_t len)
{
	if (imsg_compose_event(iev_frontend, type, 0, 0, -1, buf, len) == -1)
		return (-1);
	if (imsg_compose_event(iev_engine, type, 0, 0, -1, buf, len) == -1)
		return (-1);
	return (0);
}

void
main_showinfo_ctl(struct imsg *imsg)
{
	struct ctl_main_info cmi;
	size_t n;

	switch (imsg->hdr.type) {
	case IMSG_CTL_SHOW_MAIN_INFO:
		memset(cmi.text, 0, sizeof(cmi.text));
		n = strlcpy(cmi.text, "I'm a little teapot.",
		    sizeof(cmi.text));
		if (n >= sizeof(cmi.text))
			log_debug("main_showinfo_ctl: I was cut off!");
		main_imsg_compose_frontend(IMSG_CTL_SHOW_MAIN_INFO,
		    imsg->hdr.pid, &cmi, sizeof(cmi));
		memset(cmi.text, 0, sizeof(cmi.text));
		n = strlcpy(cmi.text, "Full of sencha.",
		    sizeof(cmi.text));
		if (n >= sizeof(cmi.text))
			log_debug("main_showinfo_ctl: I was cut off!");
		main_imsg_compose_frontend(IMSG_CTL_SHOW_MAIN_INFO,
		    imsg->hdr.pid, &cmi, sizeof(cmi));
		main_imsg_compose_frontend(IMSG_CTL_END, imsg->hdr.pid, NULL,
		    0);
		break;
	default:
		log_debug("main_showinfo_ctl: error handling imsg");
		break;
	}
}

void
merge_config(struct newd_conf *conf, struct newd_conf *xconf)
{
	conf->opts = xconf->opts;

	free(xconf);
}

/*
 * fsub -- filesystem micro-benchmarks.
 */
#define DEBUG_LOG 1

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <syscall.h>

#include <pthread.h>

#include <linux/perf_event.h>

#include "dfs.h"

#include "fsub.h"
#include "pmu.h"
#include "stats.h"
#include "statsdb.h"
#include "think.h"

#ifdef DEBUG_LOG
#define DEBUG_LOG_PATH "/usr/local/src/rwdir/fsub_log.txt"
FILE* dlog;
#endif
void debug_log(char* s, ...){
	#ifdef DEBUG_LOG
	va_list args;
	va_start(args, s);
	vfprintf(dlog, s, args);
	va_end(args);
	#endif
}

static struct runparams run = {
	.opcount = 1,
	.batch_size = 16,
	.bind_cpu = -1,

	.filename_len = 12,
	.numthreads = 1,
	.single_threaddir = 0,

	.think = {
		.data_footprint = 0,
		.insn_footprint = 0,
		.nopsize = 3,
		.nops_per_block = 3,
	},

	.trap_trigger_count = -1,
	.num_traps = 1,

	.topdir = NULL,
	.densefs = 0,

	.path_depth = 1,
};

static __thread int threadnum;
static int topdirfd = AT_FDCWD;

/* format string used for "incrementing" filenames */
#define INCFILE_FMT "%05ld"

#define PREFIX_SUBDIR_NAME "sub"

/*
 * Assumes PATH_MAX space available in 'buf'; first inserts an appropriate
 * prefix for path_depths, then fills first 'len' bytes of the remainder plus
 * a NUL terminator. (Possibly more if formatting works out that way.)
 */
static void vmakename_len(char* buf, size_t len, const char* fmt, va_list va)
{
	int i, added;
	size_t pfxlen;
	char* p = buf;
	size_t remaining = PATH_MAX;

	for (i = 0; i < run.path_depth - 1; i++) {
		added = snprintf(p, remaining, "%s/", PREFIX_SUBDIR_NAME);
		p += added;
		remaining -= added;
	}

	pfxlen = snprintf(p, remaining, "%d-"INCFILE_FMT"-", threadnum, 0L);
	p += pfxlen;
	remaining -= pfxlen;

	if (fmt && *fmt) {
		added = vsnprintf(p, remaining, fmt, va);
		pfxlen += added;
		p += added;
		remaining -= added;
	}

	if (unlikely(pfxlen >= len + 1))
		len = pfxlen + 1;
	if (unlikely(len > PATH_MAX)) {
		fprintf(stderr, "Can't fit %zd characters in PATH_MAX (%d) buf\n",
		        len, PATH_MAX);
		abort();
	}

	if (pfxlen < len) {
		memset(p, 'x', len - pfxlen);
		p[len] = '\0';
	}
}

__printf(3, 4)
void makename_len(char* buf, size_t len, const char* sfx_fmt, ...)
{
	va_list va;
	va_start(va, sfx_fmt);
	vmakename_len(buf, len, sfx_fmt, va);
	va_end(va);
}

__printf(2, 3)
void makename(char* buf, const char* sfx_fmt, ...)
{
	va_list va;
	va_start(va, sfx_fmt);
	vmakename_len(buf, run.filename_len, sfx_fmt, va);
	va_end(va);
}

void altname(char* altbuf, const char* name)
{
	snprintf(altbuf, PATH_MAX+1, "%s~", name);
}

void iter_filenames(long num, void (*fn)(long num, const char* path, void* arg), void* arg,
                    const char* fmt, ...)
{
	va_list va;
	char namebuf[PATH_MAX+1];
	long i;

	va_start(va, fmt);
	vmakename_len(namebuf, run.filename_len, fmt, va);
	va_end(va);

	for (i = 0; i < num; i++) {
		fn(i, namebuf, arg);
		inc_filename(namebuf, 1);
	}
}

static void null_opnd_setup(int dirfdm, const void* gctx, struct opnd* opnd)
{
	return;
}

static void null_opnd_cleanup(int dirfd, const void* gctx, struct opnd* opnd)
{
	return;
}

static void do_null_op(int dirfd, const void* gctx, struct opnd* opnd_op)
{
	return;
}

static int parse_null_args(int argc, char** argv, void* gctx, size_t* minbuf)
{
	int opt;

	while ((opt = getopt(argc, argv, "")) != -1) {
		switch (opt) {
		default:
			fprintf(stderr, "%s takes no arguments\n", argv[0]);
			return 1;
		}
	}

	return 0;
}

static const struct op null_op = {
	.parse_args = parse_null_args,
	.run_op = do_null_op,
	.opnd_setup = null_opnd_setup,
	.opnd_cleanup = null_opnd_cleanup,
	.supports_densefs = 1,
};

static void do_getpid_op(int dirfd, const void* gctx, struct opnd* opnd)
{
	syscall(SYS_getpid);
}

/* Reuse some of "null"'s stuff... */
static const struct op getpid_op = {
	.parse_args = parse_null_args,
	.run_op = do_getpid_op,
	.opnd_setup = null_opnd_setup,
	.opnd_cleanup = null_opnd_cleanup,
	.supports_densefs = 1,
};

static const struct subcommand {
	const char* name;
	const struct op* op;
} subcommands[] = {

	{ "rename", &rename_op, },
	{ "ipoke", &ipoke_op, },
	{ "stat", &stat_op, },
	{ "creat", &creat_op, },
	{ "close", &close_op, },
	{ "mkdir", &mkdir_op, },
	{ "symlink", &symlink_op, },
	{ "link", &link_op, },
	{ "rmdir", &rmdir_op, },
	{ "readlink", &readlink_op, },
	{ "unlink", &unlink_op, },
	{ "fallocate", &fallocate_op, },
	{ "truncate", &truncate_op, },
	{ "readdir", &readdir_op, },
	{ "read", &read_op, },
	{ "write", &write_op, },
	{ "memcpy", &memcpy_op, },
	{ "null", &null_op, },
	{ "getpid", &getpid_op, },

	/* unlink-before-close? (adding to orphan list...) */
};

static const char* progname;

static void usage(FILE* out, int full)
{
	int i;

	fprintf(out, "Usage: %s [ARGS...] SUBCMD [SUBCMD_ARGS...]\n", progname);

	if (!full)
		return;

	fprintf(out, "Available subcommands:\n");
	for (i = 0; i < ARR_LEN(subcommands); i++)
		fprintf(out, "\t%s\n", subcommands[i].name);
}

struct stats {
	struct perfstat* ops;
	struct perfstat* thinks;
	struct perfstat* batches;
};

static struct stats stats;

struct chainop {
	const struct op* op;
	void* gctx;
};

struct workthread {
	pthread_t thread;
	int threadnum;
	const struct chainop* chain;
	size_t chainlen;
	int dirfd;
	size_t bufsize;
	struct stats stats;

	struct cpustats_ctx* pmu;
	struct cpustats_ctx pmu_buf;
};

static pthread_barrier_t threadbar;

static inline void barwait(void)
{
	int status = pthread_barrier_wait(&threadbar);
	if (unlikely(status && status != PTHREAD_BARRIER_SERIAL_THREAD)) {
		errno = status;
		perror_die("pthread_barrier_wait");
	}
}

/*
 * Determine the number of operations to do in the next batch, given that
 * 'done' operations have already been done.
 */
static inline long batch_ops(long done)
{
	if (run.opcount - done >= run.batch_size)
		return run.batch_size;
	else
		return run.opcount - done;
}

static void init_opfile(struct opfile* opf, const char* relpath, size_t bufsize)
{
	opf->fd = opf->pdirfd = -1;
	strcpy(opf->relpath, relpath);
	errno = posix_memalign(&opf->buf, getpagesize(), bufsize);
	if (errno)
		perror_die("posix_memalign");
	memset(opf->buf, '.', bufsize);
}

static void init_opnds(struct opnd* opnds, long numopnds, size_t bufsize)
{
	struct opnd* o;
	char f_name[PATH_MAX+1], f_alt_name[PATH_MAX+1];
	char d_name[PATH_MAX+1], d_alt_name[PATH_MAX+1];
	char l_name[PATH_MAX+1], l_alt_name[PATH_MAX+1];

	makename(f_name, "f");
	makename(f_alt_name, "f_alt");
	makename(d_name, "d");
	makename(d_alt_name, "d_alt");
	makename(l_name, "l");
	makename(l_alt_name, "l_alt");

	for (o = opnds; o < opnds + numopnds; o++) {
		init_opfile(&o->f, f_name, bufsize);
		init_opfile(&o->f_alt, f_alt_name, bufsize);
		init_opfile(&o->d, d_name, bufsize);
		init_opfile(&o->d_alt, d_alt_name, bufsize);
		init_opfile(&o->l, l_name, bufsize);
		init_opfile(&o->l_alt, l_alt_name, bufsize);

		inc_filename(f_name, 1);
		inc_filename(f_alt_name, 1);
		inc_filename(d_name, 1);
		inc_filename(d_alt_name, 1);
		inc_filename(l_name, 1);
		inc_filename(l_alt_name, 1);
	}
}

static void cleanup_opfile(struct opfile* opf, int flags)
{
	free(opf->buf);
	errno = 0;
	if (opf->pdirfd >= 0 && fsub_unlinkat(opf->pdirfd, opf->relpath, flags) && errno != ENOENT)
		perror_die("auto-cleanup unlinkat");
	errno = 0;
	if (opf->fd >= 0 && fsub_close(opf->fd))
		perror_die("auto-cleanup close");
}

static void cleanup_opnds(struct opnd* opnds, long numopnds)
{
	struct opnd* o;
	for (o = opnds; o < opnds + numopnds; o++) {
		cleanup_opfile(&o->f, 0);
		cleanup_opfile(&o->f_alt, 0);
		cleanup_opfile(&o->d, AT_REMOVEDIR);
		cleanup_opfile(&o->d_alt, AT_REMOVEDIR);
		cleanup_opfile(&o->l, 0);
		cleanup_opfile(&o->l_alt, 0);
	}
}

/*
 * Fill 'dstlen' bytes at 'dst' with a repeated pattern of 'srclen' bytes
 * copied from 'src'.  If dstlen is not a multiple of srclen, fill only as
 * many complete copies of the source pattern as fit in dstlen.  Return a
 * pointer to the next byte after the last byte filled (dst+dstlen if dst %
 * srclen == 0).
 */
void* repbytes(void* dst, size_t dstlen, const void* src, size_t srclen)
{
	void* p;
	for (p = dst; p + srclen <= dst + dstlen; p += srclen)
		memcpy(p, src, srclen);
	return p;
}

static sighandler_t orig_trapsig_hdlr;
static jmp_buf trap_recover_env;

#if defined(__x86_64__) || defined(__i386__)
#define generate_trap() do { __asm__("ud2\n"); } while (0)
#define TRAPSIG SIGILL
#else
#error generate_trap()/TRAPSIG not defined for this architecture
#endif

static void trapsig_hdlr(int sig)
{
	sighandler_t prev = signal(TRAPSIG, orig_trapsig_hdlr);
	if (prev == SIG_ERR)
		perror_die("signal(SIG_ERR)");
	else if (prev != trapsig_hdlr)
		fprintf(stderr, "Warning: trapsig handler not what was expected...?\n");

	longjmp(trap_recover_env, 1);
}

static void do_trap(void)
{
	if (!setjmp(trap_recover_env)) {
		orig_trapsig_hdlr = signal(TRAPSIG, trapsig_hdlr);
		if (orig_trapsig_hdlr == SIG_ERR)
			perror_die("signal(trapsig)");
		generate_trap();
	}
}

static int batch_start_thread_count, batch_end_thread_count;
struct perfstat batch_start, batch_end;

static void* run_thread_batches(void* arg)
{
	long ops_done, batchops, batch, i, c, traps_remaining = 0;
	struct opnd* opnds;
	struct perfstat before, afterop, afterthink;

	struct workthread* thd = arg;
	const struct chainop* chainhead = &thd->chain[0];
	const struct chainop* chaintail = &thd->chain[thd->chainlen - 1];
	struct cpustats_ctx* pmu = thd->pmu;
	struct cpustats_ctx* batch_pmu;

	assert(thd->chainlen > 0);

	/* Silence some spurious compiler warnings...sigh. */
	memset(&before, 0, sizeof(before));
	memset(&afterop, 0, sizeof(afterop));
	memset(&afterthink, 0, sizeof(afterthink));

	threadnum = thd->threadnum;

	/* Initialize perf_event counters if we're doing per-thread cpustats */
	if (pmu == &thd->pmu_buf) {
		if (init_cpustats_ctx(pmu, -1)) {
			fprintf(stderr, "Failed to initialize PMU counters\n");
			exit(1);
		}
		batch_pmu = NULL;
	} else
		batch_pmu = pmu;

	opnds = xmalloc(run.batch_size * sizeof(*opnds));

	for (batch = 0, ops_done = 0; ops_done < run.opcount; batch++) {
		batchops = batch_ops(ops_done);

		init_opnds(opnds, batchops, thd->bufsize);
		if (chainhead->op->opnd_setup) {
			for (i = 0; i < batchops; i++)
				chainhead->op->opnd_setup(thd->dirfd, chainhead->gctx, &opnds[i]);
		}

		/* Reset which-thread-am-I counters */
		__sync_fetch_and_and(&batch_start_thread_count, 0);
		__sync_fetch_and_and(&batch_end_thread_count, 0);

		barwait();

		/* First thread to leave the entry barrier starts the batch clock */
		if (!__sync_fetch_and_add(&batch_start_thread_count, 1))
			perfstat_sample(&batch_start, batch_pmu);

		for (i = 0; i < batchops; i++, ops_done++) {

			perfstat_sample(&before, pmu);

			if (unlikely(ops_done == run.trap_trigger_count))
				traps_remaining = run.num_traps;

			if (traps_remaining > 0) {
				do_trap();
				traps_remaining -= 1;
			}

			for (c = 0; c < thd->chainlen; c++)
				thd->chain[c].op->run_op(thd->dirfd, thd->chain[c].gctx, &opnds[i]);

			perfstat_sample(&afterop, pmu);

			do_think(&run.think);

			perfstat_sample(&afterthink, pmu);

			perfstat_sub(&afterop, &before, &thd->stats.ops[ops_done]);
			perfstat_sub(&afterthink, &afterop, &thd->stats.thinks[ops_done]);
		}

		/*
		 * Last thread to arrive at the exit barrier stops the batch
		 * clock and records the elapsed time.
		 */
		if (__sync_add_and_fetch(&batch_end_thread_count, 1) == run.numthreads) {
			perfstat_sample(&batch_end, batch_pmu);
			/* Only record full batches */
			if (batchops == run.batch_size)
				perfstat_sub(&batch_end, &batch_start, &stats.batches[batch]);
		}

		barwait();

		if (chaintail->op->opnd_cleanup) {
			for (i = 0; i < batchops; i++)
				chaintail->op->opnd_cleanup(thd->dirfd, chaintail->gctx, &opnds[i]);
		}
		cleanup_opnds(opnds, batchops);
	}

	xfree(opnds);

	/* Close perf_event counters */
	if (pmu == &thd->pmu_buf) {
		if (close_cpustats_ctx(pmu)) {
			fprintf(stderr, "PMU data invalid!\n");
			abort();
		}
	}

	assert(batch == run.batch_count);

	return NULL;
}

int fsub_mkdirat(int dfd, const char* path, mode_t mode)
{
	return (run.densefs ? dfs_mkdirat : mkdirat)(dfd, path, mode);
}

int fsub_openat(int dfd, const char* path, int flags, mode_t mode)
{
	if (run.densefs)
		return dfs_openat(dfd, path, flags, mode);
	else
		return openat(dfd, path, flags, mode);
}

int fsub_close(int fd)
{
	return (run.densefs ? dfs_close : close)(fd);
}

int fsub_fstat(int fd, struct stat* st)
{
	return (run.densefs ? dfs_fstat : fstat)(fd, st);
}

int fsub_fstatfs(int fd, struct statfs* st)
{
	return (run.densefs ? dfs_fstatfs : fstatfs)(fd, st);
}

int fsub_unlinkat(int dfd, const char* path, int flags)
{
	return (run.densefs ? dfs_unlinkat : unlinkat)(dfd, path, flags);
}

int fsub_linkat(int odfd, const char* oldpath, int ndfd, const char* newpath, int flags)
{
	return (run.densefs ? dfs_linkat : linkat)(odfd, oldpath, ndfd, newpath, flags);
}

ssize_t fsub_write(int fd, const void* buf, size_t size)
{
	return (run.densefs ? dfs_write : write)(fd, buf, size);
}

ssize_t fsub_pread(int fd, void* buf, size_t len, off_t offset)
{
	return (run.densefs ? dfs_pread : pread)(fd, buf, len, offset);
}

ssize_t fsub_readahead(int fd, off64_t off, size_t sz)
{
	if (run.densefs)
		return 0; /* Meh. */
	else
		return readahead(fd, off, sz);
}

int fsub_fallocate(int fd, int mode, off_t offset, off_t len)
{
	return (run.densefs ? dfs_fallocate : fallocate)(fd, mode, offset, len);
}

off_t fsub_lseek(int fd, off_t offset, int whence)
{
	return (run.densefs ? dfs_lseek : lseek)(fd, offset, whence);
}

int fsub_ftruncate(int fd, off_t length)
{
	return (run.densefs ? dfs_ftruncate : ftruncate)(fd, length);
}

int fsub_renameat(int odfd, const char* old, int ndfd, const char* new)
{
	return (run.densefs ? dfs_renameat : renameat)(odfd, old, ndfd, new);
}

static void get_threaddir_name(int num, char* buf, size_t len)
{
	if (run.single_threaddir)
		snprintf(buf, len, "all-threads");
        else
	        snprintf(buf, len, "thread%04d", num);
}

void make_subdirs(int dirfd)
{
	int i, added;
	char namebuf[PATH_MAX + 1];
	char* p = namebuf;
	size_t remaining = sizeof(namebuf);

	for (i = 0; i < run.path_depth - 1; i++) {
		added = snprintf(p, remaining, "%s/", PREFIX_SUBDIR_NAME);
		p += added;
		remaining -= added;
		if (fsub_mkdirat(dirfd, namebuf, 0755) && errno != EEXIST)
			perror_die(namebuf);
	}
}

void remove_subdirs(int dirfd)
{
	int i, added;
	char namebuf[PATH_MAX + 1];
	char* p = namebuf;
	size_t remaining = sizeof(namebuf);

	for (i = 0; i < run.path_depth - 1; i++) {
		added = snprintf(p, remaining, "%s/", PREFIX_SUBDIR_NAME);
		p += added;
		remaining -= added;
	}

	for (i = 0; i < run.path_depth - 1; i++) {
		if (fsub_unlinkat(dirfd, namebuf, AT_REMOVEDIR) && errno != ENOENT)
			perror_die(namebuf);
		namebuf[(run.path_depth - 1 - (i + 1)) * (strlen(PREFIX_SUBDIR_NAME) + 1)] = '\0';
	}
}

static int get_dirfd(int num)
{
	int fd;
	char namebuf[PATH_MAX + 1];

	get_threaddir_name(num, namebuf, sizeof(namebuf));

	if (fsub_mkdirat(topdirfd, namebuf, 0755) && errno != EEXIST)
		perror_die(namebuf);

	fd = fsub_openat(topdirfd, namebuf, O_RDONLY|O_DIRECTORY, 0);
	if (fd < 0)
		perror_die(namebuf);

	make_subdirs(fd);

	return fd;
}

static void cleanup_workdir(int dirfd, int tnum)
{
	char namebuf[PATH_MAX + 1];

	remove_subdirs(dirfd);

	get_threaddir_name(tnum, namebuf, sizeof(namebuf));
	if (fsub_unlinkat(topdirfd, namebuf, AT_REMOVEDIR) && errno != ENOENT)
		perror_die(namebuf);

	chk_close(dirfd);
}

int run_workload_threads(const struct chainop* chain, size_t chainlen, size_t bufsize)
{
	int i, cpu;
	cpu_set_t cpus;
	struct cpustats_ctx cpu_pmu;
	long numcpus = sysconf(_SC_NPROCESSORS_ONLN);
	struct workthread* wts = xmalloc(run.numthreads * sizeof(*wts));

	if (numcpus < 1) {
		fprintf(stderr, "Warning: _SC_NPROCESSORS_ONLN reports %ld, overriding with 1\n",
		        numcpus);
		numcpus = 1;
	}

	stats.ops = xmalloc(run.numthreads * run.opcount * sizeof(*stats.ops));
	stats.thinks = xmalloc(run.numthreads * run.opcount * sizeof(*stats.thinks));
	stats.batches = xmalloc((run.opcount / run.batch_size) * sizeof(*stats.batches));

	if (pthread_barrier_init(&threadbar, NULL, run.numthreads))
		perror_die("pthread_barrier_init");

	if (run.pmu_stats && run.bind_cpu >= 0 && init_cpustats_ctx(&cpu_pmu, run.bind_cpu))
		perror_die("Failed to initialize CPU PMU counters");

	for (i = 0; i < run.numthreads; i++) {
		wts[i].threadnum = i;
		wts[i].chain = chain;
		wts[i].chainlen = chainlen;
		wts[i].dirfd = get_dirfd(i);
		wts[i].bufsize = bufsize;

		wts[i].stats.ops = &stats.ops[i * run.opcount];
		wts[i].stats.thinks = &stats.thinks[i * run.opcount];

		if (run.pmu_stats)
			wts[i].pmu = run.bind_cpu >= 0 ? &cpu_pmu : &wts[i].pmu_buf;
		else
			wts[i].pmu = NULL;
	}

	for (i = 0; i < run.numthreads; i++) {
		if (pthread_create(&wts[i].thread, NULL, run_thread_batches, &wts[i]))
			perror_die("pthread_create");

		cpu = run.bind_cpu >= 0 ? run.bind_cpu : (i % numcpus);

		CPU_ZERO(&cpus);
		CPU_SET(cpu, &cpus);
		if (pthread_setaffinity_np(wts[i].thread, sizeof(cpus), &cpus))
			perror_die("pthread_setaffinity_np");
	}

	for (i = 0; i < run.numthreads; i++) {
		if (pthread_join(wts[i].thread, NULL))
			perror_die("pthread_join");

		cleanup_workdir(wts[i].dirfd, i);
	}

	if (run.pmu_stats && run.bind_cpu >= 0 && close_cpustats_ctx(&cpu_pmu))
		perror_die("Failed to close CPU PMU counters");

	if (pthread_barrier_destroy(&threadbar))
		perror_die("pthread_barrier_destroy");

	xfree(wts);

	return 0;
}

static void output_header(int argc, char* const* argv)
{
	int i;
	char* cwd;

	printf("cmdline:");
	for (i = 0; i < argc; i++)
		printf(" %s", argv[i]);
	printf("\n");

	cwd = getcwd(NULL, 0);
	printf("cwd: %s\n", cwd);
	free(cwd);
}

static int run_workload(int orig_argc, char** orig_argv)
{
	int s, c, status;
	int argc = orig_argc;
	char** argv = orig_argv;
	const char* sub;
	unsigned int chainslots = 0;
	struct chainop* chain = NULL;
	size_t minbuf, bufsize = 0;

	for (c = 0; argc > 0; c++) {
		sub = argv[0];

		if (c >= chainslots) {
			chainslots += 16;
			chain = xrealloc(chain, chainslots * sizeof(*chain));
		}

		for (s = 0; s < ARR_LEN(subcommands); s++) {
			if (!strcmp(sub, subcommands[s].name)) {
				if (run.densefs && !subcommands[s].op->supports_densefs) {
					fprintf(stderr, "Error: %s does not support densefs\n",
					        subcommands[s].name);
					exit(1);
				}

				chain[c].op = subcommands[s].op;
				chain[c].gctx = xzalloc(chain[c].op->gctx_size);

				optind = 0; /* reset getopt() */

				minbuf = 0;
				if (subcommands[s].op->parse_args(argc, argv, chain[c].gctx, &minbuf))
					exit(1);

				if (minbuf > bufsize)
					bufsize = minbuf;

				argc -= optind;
				argv += optind;

				goto break_continue;
			}
		}

		if (!strcmp(sub, "help")) {
			usage(stdout, 1);
			return 0;
		} else {
			fprintf(stderr, "'%s' is not a valid subcommand\n", sub);
			usage(stderr, 1);
			return 1;
		}
	break_continue:;
	}

	status = run_workload_threads(chain, c, bufsize);

	for (c -= 1; c >= 0; c--)
		xfree(chain[c].gctx);
	xfree(chain);

	return status;
}

static void output_phase_stats(struct statsdb* db, FILE* outfile, const char* phase,
                               const struct perfstat* stats, unsigned long threadops,
                               unsigned long numthreads, int cpu_stats, const char* dumpfile)
{
	struct perfstat_summary s;
	unsigned long total_ops = numthreads * threadops;

	if (outfile)
		report_stats(outfile, phase, stats, threadops, numthreads, cpu_stats, dumpfile);

	if (db) {
		summarize_stats(stats, total_ops, &s, cpu_stats);
		statsdb_record_phase_stats(db, phase, &s, cpu_stats);
	}
}

static void report_results(struct statsdb* db, int quiet, int argc, char* const* argv,
                           const char* dumpfile)
{
	FILE* outf = quiet ? NULL : stdout;

	if (!quiet)
		output_header(argc, argv);

	output_phase_stats(db, outf, "op", stats.ops, run.opcount, run.numthreads, run.pmu_stats,
	                   dumpfile);

	if (run.think.insn_footprint > 0 || run.think.data_footprint > 0)
		output_phase_stats(db, outf, "think", stats.thinks, run.opcount, run.numthreads,
		                   run.pmu_stats, dumpfile);

	output_phase_stats(db, outf, "batch", stats.batches, (run.opcount / run.batch_size), 1,
	                   run.pmu_stats && run.bind_cpu >= 0, dumpfile);
}

#ifndef SCHED_AUTOCOHORT
#define SCHED_AUTOCOHORT 7
#endif

int main(int argc, char** argv)
{
	int opt, status, sched_policy = -1;
	struct sched_param sched_params;
	const char* subcmd;
	struct statfs st;
	const char* dumpfile = NULL;
	const char* statsdb_desc = NULL;
	struct statsdb* statsdb = NULL;
	int quiet = 0;

	int orig_argc = argc;
	char** orig_argv = argv;
	
	#ifdef DEBUG_LOG
	dlog = fopen(DEBUG_LOG_PATH, "w");
	if (dlog == NULL){
		fprintf(stderr, "Debug log does not exist\n");
		return -1;
	}
	#endif

	progname = strrchr(argv[0], '/');
	progname = progname ? progname + 1 : argv[0];

	while ((opt = getopt(argc, argv, "+L:B:n:N:t:T:Dd:m:EC:c:S:w:W:I:i:PQ:q")) != -1) {
		switch (opt) {
		case 'L':
			run.filename_len = parse_number(optarg);
			break;

		case 'B':
			run.batch_size = parse_number(optarg);
			if (run.batch_size <= 0) {
				fprintf(stderr, "Error: batch size (-B) must positive\n");
				exit(1);
			}
			break;

		case 'n':
			run.opcount = parse_number(optarg);
			break;

		case 'N':
			run.num_traps = parse_number(optarg);
			break;

		case 'C':
			run.bind_cpu = parse_number(optarg);
			break;

		case 'c':
			run.topdir = optarg;
			break;

		case 'E':
			run.densefs = 1;
			break;

		case 'S':
			if (!strcmp(optarg, "ac")) {
				sched_policy = SCHED_AUTOCOHORT;
				sched_params.sched_priority = 0;
			} else if (!strcmp(optarg, "rr")) {
				sched_policy = SCHED_RR;
				sched_params.sched_priority = 1;
			} else if (!strcmp(optarg, "fifo")) {
				sched_policy = SCHED_FIFO;
				sched_params.sched_priority = 1;
			} else if (!strcmp(optarg, "fair")) {
				sched_policy = SCHED_OTHER;
				sched_params.sched_priority = 0;
			} else {
				fprintf(stderr, "Error: unsupported scheduling class: %s\n", optarg);
				exit(1);
			}
			break;

		case 'd':
			dumpfile = optarg;
			break;

		case 'm':
			run.path_depth = parse_number(optarg);
			if (run.path_depth < 1) {
				fprintf(stderr, "path depth (-m) must be >= 1\n");
				exit(1);
			}
			break;

		case 't':
			run.trap_trigger_count = parse_number(optarg);
			break;

		case 'T':
			run.numthreads = parse_number(optarg);
			break;

		case 'D':
			run.single_threaddir = 1;
			break;

		case 'w':
			run.think.data_footprint = parse_size(optarg, 1);
			break;

		case 'W':
			run.think.insn_footprint = parse_size(optarg, 1);
			break;

		case 'I':
			run.think.nopsize = parse_number(optarg);
			break;

		case 'i':
			run.think.nops_per_block = parse_number(optarg);
			break;

		case 'P':
			run.pmu_stats = 1;
			break;

		case 'Q':
			statsdb_desc = optarg;
			break;

		case 'q':
			quiet = 1;
			break;

		default:
			usage(stderr, 0);
			exit(1);
		}
	}
	if (run.batch_size > run.opcount)
		run.batch_size = run.opcount;

	run.batch_count = run.opcount / run.batch_size;
	if (run.opcount % run.batch_size)
		run.batch_count += 1;

	argc -= optind;
	argv += optind;
	if (argc <= 0) {
		usage(stderr, 0);
		exit(1);
	}
	subcmd = argv[0];

	raise_rlimit(RLIMIT_NOFILE);
	if (sched_policy != -1) {
		if (sched_setscheduler(0, sched_policy, &sched_params))
			perror_die("sched_setscheduler");
	}
	if (run.topdir) {
		topdirfd = fsub_openat(AT_FDCWD, run.topdir, O_RDONLY|O_DIRECTORY, 0);
		if (topdirfd < 0){
			perror_die(run.topdir);
		}
	}
	init_think(&run.think);
	/* Probably doesn't matter too much, but let's keep things deterministic. */
	srandom(42);
	if (statsdb_desc) {
		statsdb = statsdb_open(statsdb_desc);
		if (!statsdb)
			exit(1);
	}
	if (statsdb) {
		CHECK(!(topdirfd == AT_FDCWD ? statfs(".", &st) : fsub_fstatfs(topdirfd, &st)));
		statsdb_init_run(statsdb, &run, orig_argc, orig_argv, argc, argv, st.f_type);
	}
	status = run_workload(argc, argv);

	if (topdirfd != AT_FDCWD)
		fsub_close(topdirfd);

	if (!status && strcmp(subcmd, "help"))
		report_results(statsdb, quiet, orig_argc, orig_argv, dumpfile);

	if (statsdb)
		statsdb_close(statsdb);

	#ifdef DEBUG_LOG
	fclose(dlog);
	#endif
	return status;
}

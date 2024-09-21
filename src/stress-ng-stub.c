#include "stress-ng/stress-ng.h"

#define MIN_SEQUENTIAL		(0)
#define MAX_SEQUENTIAL		(1000000)
#define DEFAULT_SEQUENTIAL	(0)	/* Disabled */
#define DEFAULT_PARALLEL	(0)	/* Disabled */
#define DEFAULT_TIMEOUT		(60 * 60 * 24)
#define DEFAULT_BACKOFF		(0)
#define DEFAULT_CACHE_LEVEL     (3)

#define STRESS_SYNC_START_FLAG_WAITING		(0)
#define STRESS_SYNC_START_FLAG_STARTED		(1)
#define STRESS_SYNC_START_FLAG_RUNNING		(2)
#define STRESS_SYNC_START_FLAG_FINISHED		(3)

/* Globals */
stress_stressor_t *g_stressor_current;		/* current stressor being invoked */
int32_t g_opt_sequential = DEFAULT_SEQUENTIAL;	/* # of sequential stressors */
int32_t g_opt_parallel = DEFAULT_PARALLEL;	/* # of parallel stressors */
int32_t g_opt_permute = DEFAULT_PARALLEL;	/* # of permuted stressors */
uint64_t g_opt_timeout = TIMEOUT_NOT_SET;	/* timeout in seconds */
uint64_t g_opt_flags = OPT_FLAGS_PR_ERROR |	/* default option flags */
		       OPT_FLAGS_PR_INFO |
		       OPT_FLAGS_MMAP_MADVISE;
unsigned int g_opt_pause = 0;			/* pause between stressor invocations */
volatile bool g_stress_continue_flag = true;	/* false to exit stressor */
const char g_app_name[] = "stress-ng";		/* Name of application */
stress_shared_t *g_shared;			/* shared memory */
jmp_buf g_error_env;				/* parsing error env */
stress_put_val_t g_put_val;			/* sync data to somewhere */

/*
 *  stress_sync_state_store()
 *	store the stress_pids_t state, try and use atomic updates where
 *	possible. non-atomic state changes are OK, but can require
 *	additional re-polled read loops so are less optimal when
 *	reading state changes
 */
static inline ALWAYS_INLINE void stress_sync_state_store(stress_pid_t *s_pid, uint8_t state)
{
#if defined(HAVE_ATOMIC_STORE)
	__atomic_store(&s_pid->state, &state, __ATOMIC_SEQ_CST);
#else
	/* racy alternative */
	s_pid->state = state;
#endif
}

/*
 *  stress_start_timeout()
 *	set the timeout for SIGALRM for a stressor
 */
static void stress_start_timeout(void)
{
	if (g_opt_timeout)
		(void)alarm((unsigned int)g_opt_timeout);
}

/*
 *  stress_sync_state_load()
 *	load the stress_pid_state
 */
static inline ALWAYS_INLINE void stress_sync_state_load(stress_pid_t *s_pid, uint8_t *state)
{
#if defined(HAVE_ATOMIC_LOAD)
	__atomic_load(&s_pid->state, state, __ATOMIC_SEQ_CST);
#else
	/* racy alternative */
	*state = s_pid->state;
#endif
}

/*
 *  stress_sync_start_wait_s_pid()
 *	put process into a stop (waiting) state, will be
 *	woken up by a parent call to stress_sync_start_cont_s_pid()
 */
void stress_sync_start_wait_s_pid(stress_pid_t *s_pid)
{
	pid_t pid;

	if (!(g_opt_flags & OPT_FLAGS_SYNC_START))
		return;

	pid = s_pid->oomable_child ? s_pid->oomable_child : s_pid->pid;
	if ((pid <= 1))
		return;

	stress_sync_state_store(s_pid, STRESS_SYNC_START_FLAG_WAITING);
	if (kill(pid, SIGSTOP) < 0) {
		pr_inf("cannot stop stressor on for --sync-start, errno=%d (%s)",
			errno, strerror(errno));
	}
	stress_sync_state_store(s_pid, STRESS_SYNC_START_FLAG_RUNNING);
	stress_start_timeout();
}

/*
 *  stress_sync_start_wait()
 *	put stressor into a stop (waiting) state, will be
 *	woken up by a parent call to stress_sync_start_cont_s_pid()
 */
void stress_sync_start_wait(stress_args_t *args)
{
	pid_t pid;
	stress_pid_t *s_pid;

	if (!(g_opt_flags & OPT_FLAGS_SYNC_START))
		return;

	s_pid = &args->stats->s_pid;
	pid = s_pid->oomable_child ? s_pid->oomable_child : s_pid->pid;
	if (pid <= 1)
		return;

	stress_sync_state_store(s_pid, STRESS_SYNC_START_FLAG_WAITING);
	if (kill(pid, SIGSTOP) < 0) {
		pr_inf("%s: cannot stop stressor on for --sync-start, errno=%d (%s)",
			args->name, errno, strerror(errno));
	}
	stress_sync_state_store(s_pid, STRESS_SYNC_START_FLAG_RUNNING);
	stress_start_timeout();
}

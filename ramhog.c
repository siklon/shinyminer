#define _GNU_SOURCE
#include "cpuminer-config.h"

#ifdef WIN32
#include <windows.h>
#else
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/sysctl.h>
#endif
#endif

#include "miner.h"
#include "hashblock/ramhog.c"
#include "elist.h"

#if defined __unix__ && (!defined __APPLE__)
#include <sys/mman.h>
#include <unistd.h>
#elif defined _WIN32
#include <windows.h>
#endif

#ifdef __linux /* Linux specific policy and affinity management */
#include <sched.h>
static inline void drop_policy(void) {
    struct sched_param param;
    param.sched_priority = 0;

	sched_setscheduler(0, SCHED_OTHER, &param);
}

static inline void affine_to_cpu(int id, int cpu) {
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}
#elif defined(__FreeBSD__) /* FreeBSD specific policy and affinity management */
#include <sys/cpuset.h>
static inline void drop_policy(void)
{
}

static inline void affine_to_cpu(int id, int cpu)
{
    cpuset_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(cpuset_t), &set);
}
#else
static inline void drop_policy(void)
{
}

static inline void affine_to_cpu(int id, int cpu)
{
}
#endif

struct ramhog_pool *pramhog = NULL;
static bool enabled = false;

struct ramhog_pool *ramhog_thread_pool(uint32_t Nin, uint32_t Cin, uint32_t Iin, int numSimultaneousIn, int numWorkersIn)
{
    int i, j;
    struct ramhog_pool *pool;
    pool = (struct ramhog_pool*)calloc(1, sizeof(struct ramhog_pool));
    pool->N = Nin;
    pool->C = Cin;
    pool->I = Iin;
    pool->numSimultaneous = numSimultaneousIn;
    pool->numWorkers = numWorkersIn;
    pool->scratchpads = (uint64_t ***)calloc(pool->numSimultaneous, sizeof(uint64_t **));
    bool dispose = false;
    for(i = 0; i < pool->numSimultaneous; i++)
    {
        pool->scratchpads[i] = (uint64_t **)calloc(pool->N, sizeof(uint64_t *));
        for(j = 0; j < pool->N; j++)
        {
            #if defined __unix__ && (!defined __APPLE__) && (!defined __CYGWIN__)
            FILE *fp;
            int hugepages = -1;
            if((fp = fopen("/proc/sys/vm/nr_hugepages", "r")) != NULL)
            {
                char buf[33];
                if(fgets(buf, 32, fp) != NULL)
                {
                    hugepages = atoi(buf);
                }
                fclose(fp);
            }
            if(hugepages == -1 || hugepages < 7680 * pool->numSimultaneous)
            {
                if(!enabled)
                {
                    enabled = true;
                    applog(LOG_INFO, "To get a performance boost, hugepages must be set to %d! (It's set to %d)", 7680 * pool->numSimultaneous, hugepages < 0 ? 0 : hugepages);
                }
                pool->scratchpads[i][j] = (uint64_t*)calloc(pool->C, sizeof(uint64_t));
            }
            else
            {
                pool->scratchpads[i][j] = (uint64_t*)mmap(0, pool->C * sizeof(uint64_t), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_POPULATE | MAP_NORESERVE, 0, 0);
                if(pool->scratchpads[i][j] == MAP_FAILED)
                {
                    applog(LOG_INFO, "Hugepages: mmap(%d,%d) failed.", i, j);
                    pool->scratchpads[i][j] = (uint64_t*)calloc(pool->C, sizeof(uint64_t));
                }
                else
                {
                    if(!enabled)
                    {
                        enabled = true;
                        applog(LOG_INFO, "Hugepages enabled!");
                    }
                    madvise(pool->scratchpads[i][j], pool->C * sizeof(uint64_t), MADV_RANDOM | MADV_HUGEPAGE);
                    if(!geteuid())
                        mlock(pool, sizeof(uint64_t));
                }
            }
            #elif defined _WIN32 && (!defined __CYGWIN__)
            pool->scratchpads[i][j] = VirtualAlloc(NULL, pool->C * sizeof(uint64_t), MEM_LARGE_PAGES, PAGE_READWRITE);
            if(!pool->scratchpads[i][j])
            {
                pool->scratchpads[i][j] = (uint64_t *)calloc(pool->C, sizeof(uint64_t));
            }
            else
            {
                if(!enabled)
                {
                    enabled = true;
                    applog(LOG_INFO, "Hugepages enabled!");
                }
            }
            #else
            pool->scratchpads[i][j] = (uint64_t*)calloc(pool->C, sizeof(uint64_t));
            #endif
            if(pool->scratchpads[i][j] == NULL)
            {
                applog(LOG_INFO, "Failed to allocate scratchpad, not enough memory?");
                dispose = true;
                goto out;
            }
        }
    }
out:
    if(dispose)
    {
        ramhog_thread_pool_dispose(pool);
        pool = NULL;
    }
    return pool;
}

void ramhog_thread_pool_dispose(struct ramhog_pool *pool)
{
    int i, j;
    for (i=0; i < pool->numSimultaneous; i++)
    {
        for (j=0; j < pool->N; j++)
        {
            if(pool->scratchpads[i][j] != NULL)
                free(pool->scratchpads[i][j]);
        }
        if(pool->scratchpads[i] != NULL)
            free(pool->scratchpads[i]);
    }
    free(pool->scratchpads);
    free(pool);
}

int scanhash_ramhog(int thr_id, uint32_t *pdata, uint32_t *ptarget, uint32_t *phash, uint32_t max_nonce, unsigned long *hashes_done)
{
    int i;
    uint32_t block[20];
    uint32_t nonce = pdata[19];
    const uint32_t Htarg = ptarget[7];
    memcpy(block, pdata, 80);
    for(i = 0; i < 19; i++)
    {
        block[i] = swab32(block[i]);
    }
    while(!work_restart[thr_id].restart && nonce < max_nonce)
    {
        block[19] = swab32(nonce);
        if(!ramhog_mt(thr_id, pramhog, (uint8_t *)block, 80, (uint8_t *)phash, 32))
            goto out;
        if(phash[7] <= Htarg && fulltest(phash, ptarget)) 
        {
            *hashes_done = nonce - pdata[19] + 1;
            pdata[19] = swab32(block[19]);
            return 1;
        }
        nonce++;
    }
out:
    *hashes_done = nonce - pdata[19];
    pdata[19] = nonce;
    return 0;
}

struct ramhogargs
{
    struct list_head list;
    uint8_t workers;
    uint8_t id;
    uint8_t thr_id;
    const uint8_t *input;
    size_t input_size;
    uint32_t C;
    uint32_t N;
    uint64_t *padOuts[16];
    pthread_t thread;
};

void *ramhog_gen_pads(void *args)
{
    int i;
    struct ramhogargs *ramhogargs = (struct ramhogargs *)args;
    
    affine_to_cpu(ramhogargs->id, ramhogargs->id % ramhogargs->workers);
   
    for(i = 0; i < ramhogargs->N; i++)
    {
        if(ramhogargs->padOuts[i] != NULL)
        {
            if(ramhog_gen_pad(ramhogargs->thr_id, ramhogargs->input, ramhogargs->input_size, ramhogargs->C, i, ramhogargs->padOuts[i]))
                break;
        }
    }
    return NULL;
}

struct ramhogargs* init_ramhogargs()
{
    struct ramhogargs *args = calloc(1, sizeof(struct ramhogargs));
	INIT_LIST_HEAD(&args->list);
    return args;
}

bool ramhog_mt(int thr_id, struct ramhog_pool *pool, const uint8_t *input, size_t input_size, uint8_t *output, size_t output_size)
{
    int i;
    uint32_t padIndex = 0;
    uint64_t **scratchpads = pool->scratchpads[thr_id];
    struct ramhogargs *arglist = init_ramhogargs();
    struct ramhogargs *arg, *tmp;
    for(i = 0; i < pool->N; i++)
    {
        struct ramhogargs *args = init_ramhogargs();
        args->id = i;
        args->workers = pool->numWorkers;
        args->thr_id = thr_id;
        args->input = input;
        args->input_size = input_size;
        args->C = pool->C;
        args->N = pool->N;
        args->padOuts[i] = scratchpads[i];
        if(unlikely(pthread_create(&args->thread, NULL, ramhog_gen_pads, (void*)args)))
        {
            free(args);
            applog(LOG_INFO, "Failed to create ramhog thread");
            break;
        }
        list_add_tail(&args->list, &arglist->list);
    }
    list_for_each_entry(arg, &arglist->list, list, struct ramhogargs)
    {
        pthread_join(arg->thread, NULL);
    }
	list_for_each_entry_safe(arg, tmp, &arglist->list, list, struct ramhogargs)
	{
        list_del(&arg->list);
        free(arg);
	}
    if(ramhog_run_iterations(thr_id, input, input_size, output, output_size, pool->N, pool->C, pool->I, scratchpads))
        return false;
    return true;
}
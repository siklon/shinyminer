#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <sched.h>
#include "cpuminer-config.h"
#include "miner.h"

#include "hashblock/ramhog.c"
#include "elist.h"

struct ramhog_pool *pramhog = NULL;

struct ramhog_pool *ramhog_thread_pool(uint32_t Nin, uint32_t Cin, uint32_t Iin, int numSimultaneousIn, int numWorkersIn)
{
    int i;
    struct ramhog_pool *pool;
    pool = (struct ramhog_pool*)calloc(1, sizeof(struct ramhog_pool));
    pool->N = Nin;
    pool->C = Cin;
    pool->I = Iin;
    pool->numSimultaneous = numSimultaneousIn;
    pool->numWorkers = numWorkersIn;
    pool->scratchpads = (uint64_t ***)calloc(pool->numSimultaneous, sizeof(uint64_t **));
    bool dispose = false;
    bool enabled = false;
    for (int i=0; i < pool->numSimultaneous; i++)
    {
        pool->scratchpads[i] = (uint64_t **)calloc(pool->N, sizeof(uint64_t *));
        for (int j=0; j < pool->N; j++)
        {
            #if defined __unix__ && (!defined __APPLE__) && (!defined __CYGWIN__)
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
            }
            madvise(pool->scratchpads[i][j], pool->C * sizeof(uint64_t), MADV_RANDOM | MADV_HUGEPAGE);
            if(!geteuid())
                mlock(pool, sizeof(uint64_t));
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
    uint8_t cpu_id;
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
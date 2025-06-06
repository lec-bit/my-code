/* cpu_pelt_lib.h */
#ifndef __CPU_PELT_LIB_H
#define __CPU_PELT_LIB_H

#include <scx/common.bpf.h>

#define PELT_SCALE 1024
#define PELT_MAX_UTIL 1024  // Maximum utilization value
#define PELT_SUM_MAX 131072	// Maximum sum value (128 * 1024)
#define NSEC_PER_USEC 1000ULL
#define NSEC_PER_MSEC 1000ULL * NSEC_PER_USEC
#define MSEC_PER_SEC 1000ULL

// 存储在每个 CPU 上的负载数据
struct pelt_cpu_data {
    u64 util_sum;       // 累计值，用于计算，方便规避浮点运算
    u64 util_avg;       // 当前 CPU 的 PELT 利用率 (0 ~ 1024)
    u64 last_update_time; // 上次更新的时间戳
    u64 period_contrib; // 判断是否足够1ms的标志
};

// 存储在每个任务上的元数据 (用于计算 delta)
struct pelt_task_meta {
    u64 last_run_at;    // 任务开始运行的时间
};

// ==========================================
// BPF Map 定义 ("外挂"存储)
// ==========================================

// Per-CPU Map，用来存 CPU 的负载
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct pelt_cpu_data);
} pelt_cpu_map SEC(".maps");

// Task Storage Map，用来存任务的时间戳
// 优点：作为lib库，不需要修改原有的 struct task_ctx
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct pelt_task_meta);
} pelt_task_map SEC(".maps");

// ==========================================
// PELT 指数衰减
// ==========================================

/*
 * PELT (Per-Entity Load Tracking) helper functions
 *
 * Simplified BPF-friendly implementation of Linux kernel PELT.
 * Uses 1ms periods and exponential decay with 32ms half-life.
 */

/*
 * Apply exponential decay to a value over a number of periods.
 * Each period decays by factor of 127/128 (≈ 0.98).
 * Bounded loop for BPF verifier compliance.
 */
static __always_inline u32 pelt_decay(u32 val, u32 periods)
{
	u32 i;

	/* Bound iterations for BPF verifier (max 256 periods = 256ms) */
	bpf_for(i, 0, periods) {
		if (i >= 256)
			break;
		val = (val * 127) >> 7;
	}

	return val;
}

/*
 * PELT 核心公式:(参考p2dq中简化的PELT算法)
 */
static void update_cpu_pelt(struct pelt_cpu_data *data, u64 now, u64 delta_ns, s32 task_cpu)
{
	u64 elapsed_ns, elapsed_ms;
	u32 periods, delta_ms;
	u32 freq;
	u64 scaled_delta_ms, scaled_period_contrib;

	if (!data->last_update_time) {
		/* First update - initialize */
		data->last_update_time = now;
		data->util_sum = 0;
		data->util_avg = 0;
		data->period_contrib = 0;
		return;
	}

	elapsed_ns = now - data->last_update_time;
	elapsed_ms = elapsed_ns / NSEC_PER_MSEC;
    
	/**
	 * If less than 1ms has passed, accumulate in period_contrib and don't
	 * update timestamp until a full period has passed.
	 */
	if (elapsed_ms == 0) {
		delta_ms = delta_ns / NSEC_PER_MSEC;
		data->period_contrib += delta_ms;
		return;
	}

	periods = (u32)elapsed_ms;
	if (periods > 256)
		periods = 256;  /* Cap for verifier */

	if (data->util_sum > 0) {
		data->util_sum = pelt_decay(data->util_sum, periods);
	}

	freq = scx_bpf_cpuperf_cur(task_cpu);
	if (freq == 0)
		freq = SCX_CPUPERF_ONE;

	/*
	 * Scale period contribution by capacity and frequency
	 * This makes the PELT metric represent "work done at max CPU capacity at max freq"
	 *
	 * Formula: scaled_time = wall_time * (capacity / 1024) * (freq / 1024)
	 *         = wall_time * capacity * freq / (1024 * 1024)
	 */
	if (data->period_contrib > 0) {
		scaled_period_contrib = (data->period_contrib * freq) / 1024ULL;
		data->util_sum += scaled_period_contrib;
		data->period_contrib = 0;
	}

	delta_ms = delta_ns / NSEC_PER_MSEC;
	scaled_delta_ms = (delta_ms * freq) / 1024ULL;
	data->util_sum += scaled_delta_ms;

	if (unlikely(data->util_sum > PELT_SUM_MAX))
		data->util_sum = PELT_SUM_MAX;


	/* Calculate util_avg from util_sum */
	/* util_avg = util_sum / 128 (representing average over ~128ms window) */
	data->util_avg = data->util_sum >> 7;
	if (data->util_avg > PELT_MAX_UTIL)
		data->util_avg = PELT_MAX_UTIL;

	data->last_update_time = now;

}

// ==========================================
// 公开接口 (API)
// ==========================================

/**
 * 在 ops.running 中调用
 * 作用：记录任务开始时间
 */
void BPF_STRUCT_OPS (lib_pelt_on_running, struct task_struct *p)
{
    struct pelt_task_meta *meta;
    
    // 从 task storage 获取数据，如果没有就创建
    meta = bpf_task_storage_get(&pelt_task_map, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!meta) return;

    meta->last_run_at = bpf_ktime_get_ns();
    
    // 衰减 CPU 的负载（从上次停止到现在，CPU 可能空闲了一段时间）
    u32 key = 0;
    s32 cpu = scx_bpf_task_cpu(p);
    struct pelt_cpu_data *cpu_data = bpf_map_lookup_elem(&pelt_cpu_map, &key);
    if (cpu_data) {
        u64 now = bpf_ktime_get_ns();
        u64 idle_delta = (now - cpu_data->last_update_time) / 1000; // ns -> us
        if (idle_delta > 0) {
            update_cpu_pelt(cpu_data, now, 0, cpu);
        }
    }
}

/**
 * 在 ops.stopping 中调用
 * 作用：计算运行时间，更新 CPU 负载
 */
void BPF_STRUCT_OPS (lib_pelt_on_stopping, struct task_struct *p, bool runnable)
{
    s32 cpu = scx_bpf_task_cpu(p);
    struct pelt_task_meta *meta;
    meta = bpf_task_storage_get(&pelt_task_map, p, 0, 0);
    if (!meta) return;

    u64 now = bpf_ktime_get_ns();
    u64 delta_ns = now - meta->last_run_at;

    // 更新当前 CPU 的负载
    u32 key = 0;
    struct pelt_cpu_data *cpu_data = bpf_map_lookup_elem(&pelt_cpu_map, &key);
    if (cpu_data) {
        update_cpu_pelt(cpu_data, now, delta_ns, cpu);
    }
}

/**
 * 获取指定 CPU 的当前利用率 (0 ~ 1024)
 * 在 dispatch 或 select_cpu 时调用
 */
static u64 lib_pelt_get_cpu_util(s32 cpu)
{
    u32 key = 0;
    struct pelt_cpu_data *cpu_data = bpf_map_lookup_percpu_elem(&pelt_cpu_map, &key, cpu);
    if (!cpu_data) return 0;
    
    return cpu_data->util_avg;
}

#endif /* __CPU_PELT_LIB_H */

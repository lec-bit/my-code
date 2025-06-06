内核CFS负载均衡：

基于“相对不平衡度（Imbalance Percentage）”和“CPU 拓扑结构”的动态博弈

相对不平衡度 (`imbalance_pct`)

CFS 采取的策略是比较**当前 CPU 和目标 CPU 之间的负载差值**。内核为不同的硬件层级（Scheduling Domains，调度域）定义了不同的容忍度：

- **超线程（SMT/同一物理核）：** 迁移代价极小。内核设置的 `imbalance_pct` 通常是 **110（即 110%）**。这意味着，只要源 CPU 的负载比目标 CPU 高出 **10%**，内核就会果断把任务迁移过去。
  
- **多核（MC/同一 CPU 芯片）：** 迁移代价中等（可能共享 L3 Cache，但 L1/L2 独立）。`imbalance_pct` 通常是 **117** 或更高（负载差需达到 17% 以上才迁移）。
  
- **跨 NUMA 节点：** 迁移代价极大（内存访问延迟剧增）。`imbalance_pct` 可能高达 **125** 甚至更高（负载差需达到 25% 以上才舍得跨节点迁移任务）。
  

**CFS 的逻辑是：** 只有当两边的**负载差异**超过了迁移带来的**性能损耗**时，迁移才是划算的。

触发时机：

- **Tick 周期性均衡 (Periodic Load Balance)：** CPU 在处理时钟中断（Tick）时，偶尔瞅一眼旁边的 CPU。如果不平衡度超过了上述的 `imbalance_pct`，就拉取任务。
  
- **空闲时均衡 (Newidle Balance)：** 当一个 CPU 上的任务都跑完了，即将进入 Idle（休眠）状态前，它会极其饥渴地去检查其他 CPU，只要别的 CPU 负载比自己高（哪怕高一点点），它都会尝试把任务“偷”过来（Task Stealing）
  
- **唤醒时均衡 (Wake-up Balance)：** 任务刚醒来时，内核会快速计算一个“能量/容量”收益，决定它是在原地醒来，还是去另一个 CPU 醒来。
  

---

### 1. 数据结构定义

**文件路径**：`include/linux/sched/topology.h`

`imbalance_pct` 是**调度域 (`struct sched_domain`)** 结构体中的一个重要成员。内核把 CPU 按照物理层级划分为不同的调度域（比如 SMT 域、MC 域、NUMA 域），每个域都有自己的 `imbalance_pct`。

C

```
// include/linux/sched/topology.h
struct sched_domain {
    /* ... 前面有一大堆参数 ... */
    unsigned int min_interval;  /* 最小均衡间隔 */
    unsigned int max_interval;  /* 最大均衡间隔 */
    unsigned int busy_factor;   /* CPU 忙碌时的均衡频率缩放因子 */
    unsigned int imbalance_pct; /* 触发负载均衡的阈值百分比 (核心！) */
    unsigned int cache_nice_tries;
    /* ... */
};
```

---

### 2. 默认阈值赋值

**文件路径**：`kernel/sched/topology.c`

主要两个地方赋值：内核启动/重新划分cgroup；使用时直接读取

内核在启动时，会探测硬件的 CPU 拓扑，并为不同层级的调度域赋予不同的 `imbalance_pct` 默认值。这里定义了到底跨越多远的硬件结构，需要多大的容忍度。

- **SMT 层级 (超线程，Hyper-Threading)**:
  默认值通常是 **110**。因为两个逻辑核共享 L1/L2 Cache，搬迁代价小，只要源 CPU 负载比目标高 10%，就允许迁移。
  
- **MC 层级 (多核，Multi-Core, 同一个物理 CPU 内)**:
  默认值通常是 **117**。因为它们共享 L3 Cache (LLC)，代价适中，需要 17% 的差值。
  
- **NUMA 层级**:
  跨 NUMA 的代价极高，`imbalance_pct` 会更高（根据具体的 NUMA 距离，可能在 **120 到 125** 甚至更高之间动态调整）。
  
  #### 重新划分Cgroup
  
  **调用链：**
  
  1. 用户/Kubelet 修改 `/sys/fs/cgroup/cpuset/xxx/cpuset.cpus` 或 `sched_load_balance`
    
  2. $\rightarrow$ VFS 触发 Cgroup 的写回调 `cpuset_write_resmask()` 或 `cpuset_write_u64()`
    
  3. $\rightarrow$ `update_cpumask()` / `update_flag()`
    
  4. $\rightarrow$ `rebuild_sched_domains_locked()`
    
  5. $\rightarrow$ `partition_sched_domains_locked()`
    
  6. $\rightarrow$ `build_sched_domains()`
    
  7. $\rightarrow$ **`build_sched_domain()`**
    
  8. $\rightarrow$ **`sd_init()`**
    
  
  #### 内核启动
  
  1. **`start_kernel()`** $\rightarrow$ `rest_init()` $\rightarrow$ `kernel_init()` (内核启动主流程)
    
  2. $\rightarrow$ **`sched_init_smp()`** (初始化多核调度器)
    
  3. $\rightarrow$ **`sched_init_domains()`** (开始构建调度域)
    
  4. $\rightarrow$ **`build_sched_domains()`** (遍历架构定义的拓扑层级)
    
  5. $\rightarrow$ **`sd_init()`** (为具体的某个调度域层级初始化 `struct sched_domain` 结构体)
    
  6. #### sd_init()
    
    在 `kernel/sched/topology.c` 中的 `sd_init()` 函数
    
    C
    
    ```
        /*
         * Convert topological properties into behaviour.
         */
        /* Don't attempt to spread across CPUs of different capacities. */
        if ((sd->flags & SD_ASYM_CPUCAPACITY) && sd->child)
            sd->child->flags &= ~SD_PREFER_SIBLING;
    
        if (sd->flags & SD_SHARE_CPUCAPACITY) {
            sd->imbalance_pct = 110;
    
        } else if (sd->flags & SD_SHARE_PKG_RESOURCES) {
            sd->imbalance_pct = 117;
            sd->cache_nice_tries = 1;
    ```
    

---

### 3. 触发迁移的核心逻辑

`kernel/sched/fair.c`->**`find_busiest_group()`**

#### 核心调用上下文

当this_cpu时钟中断到来，或者当前 CPU 变空闲时：

`scheduler_tick()` / `schedule()` $\rightarrow$ `rebalance_domains()` $\rightarrow$ `load_balance()` $\rightarrow$ **`find_busiest_group()`**

rebalance_domains在执行过程中，内核通过 `for_each_domain(cpu, sd)` 宏，沿该 CPU 的 `sched_domain`（调度域）拓扑树自底向上进行严格的层级遍历。定下**imbalance_pct**的值并传递下去

- **第 1 层（SMT 域）**：评估超线程（逻辑核）之间的负载。
  
- **第 2 层（MC 域）**：评估共享 L3 Cache 的物理核之间的负载。
  
- **第 3 层（NUMA 域）**：评估跨 NUMA 节点的 CPU 组之间的负载。
  

find_busiest_group()

    update_sd_lb_stats()遍历该调度域内的所有组。统计负载数值（avg_load）

    calculate_imbalance()计算到底要搬多少

计算负载差异是否超过env->sd->**imbalance_pct**

```C
        /*
         * If the busiest group is more loaded, use imbalance_pct to be
         * conservative.
         */
        if (100 * busiest->avg_load <=
                env->sd->imbalance_pct * local->avg_load)
            goto out_balanced;
```

![](file://C:\Users\86188\AppData\Roaming\marktext\images\2026-03-11-10-35-22-image.png?msec=1773196522280)

**计算到底要搬多少 (`calculate_imbalance`)** 
此时，内核会计算出一个绝对的数值 `env->imbalance`（即需要迁移的负载量）。它力求搬走这部分负载后，`busiest` 和 `local` 的负载比例正好落回到 `imbalance_pct` 允许的安全范围内，而不是强行让两边变成绝对的 1:1。

**参考内核CFS逻辑**：实现imbalance_pct相对不平衡度

scx中实现：

1. 设置一个可配置的阈值，默认10%，只有负载相差过大时才调度

2.使用掩码计算cpu之间的距离，调度时判断目标cpu和当前cpu的相对不平衡度

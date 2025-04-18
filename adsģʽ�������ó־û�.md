## ads模式重启配置持久化

### 概要

kmesh支持在重启过程中加速能力不中断，且自动管理相关配置

### 动机

在K8s集群中使用kmesh进行网格加速，在kmesh重启场景下加速能力不中断，提供无感重启/升级会给kmesh带来很大的竞争力

#### 目标

1. 在kmesh重启场景下将相关配置保存到本地并自动管理，保持加速能力不中断
2. 重启后自动恢复相关配置并更新

### 提议

实现配置持久化管理与服务不中断

配置持久化管理：

- 在kmesh关闭的时候判断是正常关闭还是重启场景，是重启场景则将相关配置持久化保存到指定目录
- 将具体用于服务流量的ebpf程序持久化，在kmesh关闭后依然可以根据配置独立提供流量治理服务，实现服务不中断
- 其他相关功能配置持久化
  - 纳管功能：在每次重启后自动拉取最新配置并刷新
  - 证书订阅：在每次重启后重新获取证书


配置恢复与更新：

- 在kmesh启动的时候判断是新启动还是重启场景，是重启场景则从指定目录恢复配置，与接收到的最新配置做差异比较并更新

### 限制

当前未支持升级场景，后续会支持

kmesh如果进程coredump导致重启，无法实现正常的配置持久化能力

## 设计细节

### 配置持久化管理

#### ebpf程序持久化

- 使用bpf_link将attach过的cgroup的bpf程序固化

- 固化其他ebpf map

- 固化inner_map相关结构信息，需要添加fd信息

  - ```C
    struct inner_map_mng {
        struct inner_map_stat inner_maps[MAX_OUTTER_MAP_ENTRIES];
        int used_cnt;
        int init;
        sem_t fin_tasks;
    };
    ```

以上是功能性的ebpf_map，固化之后可以保证kmesh关闭时，依然依据现有的流量治理规则进行治理

- 将kmesh_version pin到指定目录上

  - ```go
    	mapSpec := &ebpf.MapSpec{
    		Name:       "kmesh_version",
    		Type:       ebpf.Array,
    		KeySize:    4,
    		ValueSize:  4,
    		MaxEntries: 1,
    	}
    ```

该ebpf_map主要用于记录kmesh版本，并作为启动时判断是新启动还是从指定目录中读取ebpf_map的依据

#### 部分配置持久化

将XDS配置树计算出hash并保存于/mnt目录下，用于重启后数据对比

### 配置恢复与更新

1. 重启后加载ebpf程序

   从pin的指定目录恢复bpf_map

   从pin的指定目录恢复inner_map

   启动新的ebpf程序attach后更新替换掉bpf_link中的prog，完成无缝替换

2. 将保存的旧数据和新获取的数据进行对比并刷新

   将/mnt目录下的XDS配置树的hash与新获取到的cache中的XDS配置进行对比，如果不一致则进行Update

   

### 遗留事项

1. 当前XDS树的刷新粒度为顶层一整个config，后续将会细化刷新粒度
1. 其他单点功能与重启功能的配合依然有待考虑
##	环境准备

参考：[Ubuntu下载源码并编译 - liangliangge - 博客园 (cnblogs.com)](https://www.cnblogs.com/liangliangge/p/11358657.html)

[How to Build and Install a Custom Kernel on Ubuntu - Make Tech Easier](https://www.maketecheasier.com/build-custom-kernel-ubuntu/)



```shell
sudo apt-cache search linux-source
sudo apt-get install linux-source-5.15.0
cd /usr/src

tar -xvjf linux-source-5.15.0.tar.bz2
#有对应目录源码
```



```
sudo apt install wget build-essential bison flex libncurses-dev libssl-dev libelf-dev dwarves
```



```shell
#拷贝并打入补丁
cp patches xxxx
patch -p1 < 0001-xxxx
...
patch -p1 < 0008-xxxx
patch -p1 < bpf-support-writable-context-for-bare-tracepoint.patch

#拷贝config文件
cp /boot/config-5.15.0-78-generic .config
#编译新内核
make -jx bindeb-pkg

#如果遇到问题：
debian文件夹拷贝到源码下，解决验证问题

#安装所有编译出来的包：
dpkg -i linux-*.deb
```





## 编译镜像

下载kmesh最新源码，并执行make docker即可获得最新kmesh镜像

```bash
git clone https://github.com/kmesh-net/kmesh.git

make docker TAG=xxx
```

#### 注意：

make docker命令会做以下几件事情：

1、先从远端pull 最新的kmesh-build镜像，该镜像用于准备kmesh编译环境，脱离部分本地依赖

2、使用kmesh-build镜像启动一个容器，将kmesh代码mount到容器内，然后执行build.sh脚本进行编译

3、build.sh脚本会根据当前宿主机环境去控制kmesh的编译宏，决定开启哪些能力，该脚本通过宿主机上部分文件进行判断，且需要编译和当前宿主机匹配的内核模块，所以需要宿主机安装以下软件包：

```
linux-headers和linux-image   --用于编译内核模块
linux-libc-dev -- 用于判断当前内核支持的kmesh能力，需要使用新编译出来的配套包
```

​	如果缺少以上软件包，可能会导致kmesh编译异常

4、build.sh脚本执行完后会将编译产物放在out目录下，然后会使用kmesh.dockerfile文件制作kmesh的运行镜像，将编译产物拷贝进运行镜像

最后可以得到：ghcr.io/kmesh-net/kmesh:xxx的镜像



### 常见问题：

1. 没有编译出七层能力，缺少kmesh.ko，查看编译日志没有编译kmesh.ko和sockops相关日志，bpftool prog没有看到sockops的ebpf程序
   1. 检查/usr/include/linux/bpf.h文件是否存在，该文件隶属于linux-libc-dev包，如果不存在则会影响编译
   2. 检查/lib/modules/build目录是否是指向最新的增强内核
2. 因网络问题导致go download / docker pull失败
   1. 检查网络是否需要代理并配置合适网络

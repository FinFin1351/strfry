# 基于 Ubuntu Jammy 作为构建环境
FROM --platform=linux/amd64 ubuntu:jammy as build

# 设置时区避免交互提示
ENV TZ=Europe/London
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# 工作目录
WORKDIR /build

# 安装必要的工具和依赖
RUN apt update && apt install -y --no-install-recommends \
    build-essential \
    git g++ make pkg-config libtool ca-certificates \
    libssl-dev zlib1g-dev liblmdb-dev libflatbuffers-dev \
    libsecp256k1-dev libzstd-dev debhelper devscripts

# 复制代码到容器
COPY . .

# 更新子模块（如需要）
RUN git submodule update --init

# 编译并生成调试版本
RUN make clean
RUN CFLAGS="-g -fsanitize=address" CXXFLAGS="-g -fsanitize=address" make -j4

# 使用 dpkg-buildpackage 构建 .deb 包
RUN dpkg-buildpackage --build=binary -us -uc

# 单独阶段用于提取 .deb 文件
FROM ubuntu:jammy as package
WORKDIR /packages

# 复制生成的 .deb 文件
COPY --from=build /build/../*.deb ./


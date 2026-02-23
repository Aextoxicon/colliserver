#!/bin/bash

echo "开始构建 Colliserver..."

# 检查是否安装了 Go
if ! command -v go &> /dev/null; then
    echo "错误: 未找到 Go，请先安装 Go"
    exit 1
fi

# 下载依赖
echo "正在下载依赖..."
go mod tidy

# 构建应用
echo "正在构建应用..."
go build -o colliserver .

if [ $? -eq 0 ]; then
    echo "构建成功！"
    echo "运行方法："
    echo "  export JWT_SECRET='your-secret-key'"
    echo "  export DB_PATH='database.db'  # 可选，默认为当前目录下的 database.db"
    echo "  ./colliserver"
else
    echo "构建失败"
    exit 1
fi
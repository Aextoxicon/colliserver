# Colliserver - Golang 版本

这是原始 Node.js 项目的 Golang 版本，使用 Gin 框架和 GORM 实现。

## 功能

- 用户注册/登录/登出
- 评论管理（创建、读取）
- JWT 身份验证
- 黑名单令牌管理

## 依赖

- Go 1.21+
- PostgreSQL 数据库
- Gin 框架
- GORM
- JWT 认证

## 环境变量

需要设置以下环境变量：

```bash
COMMENTS_DATABASE_URL=postgres://username:password@localhost:5432/database_name
JWT_SECRET=your_jwt_secret_key
API_TOKEN=your_api_token
```

## 安装和运行

1. 确保安装了 Go 1.21+

2. 下载依赖：
```bash
go mod tidy
```

3. 设置环境变量：
```bash
export COMMENTS_DATABASE_URL="postgres://username:password@localhost:5432/dbname"
export JWT_SECRET="your-secret-key-here"
export API_TOKEN="your-api-token"
```

4. 运行应用：
```bash
go run main.go
```

或者编译后运行：
```bash
go build -o colliserver .
./colliserver
```

## API 端点

- `POST /api/register` - 用户注册
- `POST /api/login` - 用户登录
- `POST /api/logout` - 用户登出
- `GET /api/comments` - 获取评论列表
- `GET /api/comments/:id` - 获取特定评论
- `GET /api/:username/posts` - 获取特定用户的帖子
- `GET /api/comments/check-auth` - 检查认证状态
- `POST /api/comments` - 创建评论（需要认证）

## 数据库模型

- User: 用户信息
- Comment: 评论信息
- BlacklistedToken: 黑名单令牌（用于登出功能）

## 注意事项

- 确保 PostgreSQL 服务器正在运行
- 确保环境变量正确设置
- 上传目录需要具有适当的写权限
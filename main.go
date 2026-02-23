package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var (
	db       *gorm.DB
	jwtKey   = []byte(os.Getenv("JWT_SECRET"))
	apiToken = os.Getenv("API_TOKEN")
	dbPath   = os.Getenv("DB_PATH")
)

type User struct {
	ID           uint   `json:"id" gorm:"primaryKey"`
	Username     string `json:"username" gorm:"uniqueIndex"`
	PasswordHash string `json:"-"`
}

type Comment struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Title     string    `json:"title"`
	Comment   string    `json:"comment"`
	Timestamp time.Time `json:"timestamp"`
	Username  string    `json:"username"`
}

type BlacklistedToken struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Token     string    `json:"token" gorm:"index"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func init() {
	var err error
	path := dbPath
	if path == "" {
		path = "database.db" // 默认 SQLite 数据库文件
	}
	db, err = gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// 自动迁移
	db.AutoMigrate(&User{}, &Comment{}, &BlacklistedToken{})
}

func main() {
	if _, ok := os.LookupEnv("JWT_SECRET"); !ok {
		log.Fatal("Missing env: JWT_SECRET")
	}
	if _, ok := os.LookupEnv("DB_PATH"); !ok {
		log.Println("Warning: DB_PATH not set, using default: database.db")
	}

	r := gin.Default()

	// CORS 配置
	config := cors.DefaultConfig()
	config.AllowAllOrigins = true
	config.AllowCredentials = true
	config.AllowHeaders = []string{"Origin", "Content-Length", "Content-Type", "Authorization"}
	r.Use(cors.New(config))

	// 用户认证相关路由
	r.POST("/api/register", register)
	r.POST("/api/login", login)
	r.POST("/api/logout", logout)

	// 评论相关路由
	protected := r.Group("/api")
	protected.Use(authMiddleware())
	{
		protected.POST("/comments", createComment)
	}

	// 公开路由
	r.GET("/api/comments", getComments)
	r.GET("/api/comments/:id", getCommentByID)
	r.GET("/api/:username/posts", getUserPosts)
	r.GET("/api/comments/check-auth", checkAuth)

	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}
	log.Printf("Server starting on port %s", port)
	r.Run(":" + port)
}

func register(c *gin.Context) {
	var input struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 检查用户是否已存在
	var existingUser User
	if err := db.Where("username = ?", input.Username).First(&existingUser).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "用户名已存在"})
		return
	}

	// 哈希密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码加密失败"})
		return
	}

	user := User{
		Username:     input.Username,
		PasswordHash: string(hashedPassword),
	}

	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "注册失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":       user.ID,
		"username": user.Username,
	})
}

func login(c *gin.Context) {
	var input struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	if err := db.Where("username = ?", input.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 1)),
		},
	})

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "登录成功",
		"token":   tokenString,
	})
}

func logout(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "未提供 Token"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的 Token 格式"})
		return
	}

	// 解析 Token 以获取过期时间
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "解析 Token 失败"})
		return
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		blacklistedToken := BlacklistedToken{
			Token:     tokenString,
			ExpiresAt: claims.ExpiresAt.Time,
		}

		if err := db.Create(&blacklistedToken).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "登出失败"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "已登出"})
		return
	}

	c.JSON(http.StatusUnauthorized, gin.H{"error": "Token 无效"})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未提供 Token"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的 Token 格式"})
			c.Abort()
			return
		}

		// 检查 Token 是否在黑名单中
		var blacklisted BlacklistedToken
		if err := db.Where("token = ?", tokenString).First(&blacklisted).Error; err == nil {
			if blacklisted.ExpiresAt.After(time.Now()) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token 已失效"})
				c.Abort()
				return
			}
		}

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未认证"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(*Claims); ok && token.Valid {
			c.Set("username", claims.Username)
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未认证"})
			c.Abort()
			return
		}
	}
}

func createComment(c *gin.Context) {
	var input struct {
		Title   string `json:"title" binding:"required"`
		Comment string `json:"comment" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请输入标题和内容"})
		return
	}

	username, _ := c.Get("username")

	comment := Comment{
		Title:    input.Title,
		Comment:  input.Comment,
		Username: username.(string),
	}

	if err := db.Create(&comment).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器内部错误"})
		return
	}

	c.JSON(http.StatusCreated, comment)
}

func getComments(c *gin.Context) {
	pageStr := c.Query("page")
	limitStr := c.Query("limit")

	page := 1
	if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
		page = p
	}

	limit := 4
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
		limit = l
	}

	offset := (page - 1) * limit

	var comments []Comment
	var totalItems int64

	db.Model(&Comment{}).Count(&totalItems)
	db.Offset(offset).Limit(limit).Order("timestamp DESC").Find(&comments)

	totalPages := int(totalItems) / limit
	if int(totalItems)%limit > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, gin.H{
		"rows": comments,
		"pagination": gin.H{
			"currentPage":   page,
			"totalPages":    totalPages,
			"totalItems":    totalItems,
			"itemsPerPage":  limit,
		},
	})
}

func getCommentByID(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效ID"})
		return
	}

	var comment Comment
	if err := db.First(&comment, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "评论不存在"})
		return
	}

	c.JSON(http.StatusOK, comment)
}

func getUserPosts(c *gin.Context) {
	username := c.Param("username")
	pageStr := c.Query("page")
	limitStr := c.Query("limit")

	page := 1
	if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
		page = p
	}

	limit := 4
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
		limit = l
	}

	offset := (page - 1) * limit

	var comments []Comment
	var totalItems int64

	db.Model(&Comment{}).Where("username = ?", username).Count(&totalItems)
	db.Where("username = ?", username).Offset(offset).Limit(limit).Order("timestamp DESC").Find(&comments)

	totalPages := int(totalItems) / limit
	if int(totalItems)%limit > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, gin.H{
		"rows": comments,
		"pagination": gin.H{
			"currentPage":   page,
			"totalPages":    totalPages,
			"totalItems":    totalItems,
			"itemsPerPage":  limit,
		},
	})
}

func checkAuth(c *gin.Context) {
	username, exists := c.Get("username")
	if exists {
		c.JSON(http.StatusOK, gin.H{
			"authenticated": true,
			"user":          username,
		})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{
			"authenticated": false,
			"message":       "未登录",
		})
	}
}
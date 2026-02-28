package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

var (
	db       *sql.DB
	jwtKey   = []byte(os.Getenv("JWT_SECRET"))
	apiToken = os.Getenv("API_TOKEN")
	dbPath   = os.Getenv("DB_PATH")
)

// User 用户表模型
type User struct {
	UID           uint   `json:"uid"`
	Username      string `json:"username"`
	Nickname      string `json:"nickname"`
	PwdHash       string `json:"pwd_hash"`
	LatestMsgTs   int64  `json:"latest_msg_ts"`
	ContactList   string `json:"contact_list"` // JSON格式的联系人列表
	Token         string `json:"token,omitempty"`
	TokenExpireTs int64  `json:"token_expire_ts"`
	CreateTs      int64  `json:"create_ts"`
}

// ChatGroup 群聊表模型
type ChatGroup struct {
	GroupID        uint   `json:"group_id"`
	Name           string `json:"name"`
	OwnerUID       uint   `json:"owner_uid"`
	AdminUids      string `json:"admin_uids"` // JSON格式的管理员ID列表
	MemberUids     string `json:"member_uids"` // JSON格式的成员ID列表
	LastMsgPreview string `json:"last_msg_preview"`
	LastMsgTs      int64  `json:"last_msg_ts"`
	CreateTs       int64  `json:"create_ts"`
}

// PrivateMessage 私聊消息表模型
type PrivateMessage struct {
	MsgID       uint   `json:"msg_id"`
	FromUID     uint   `json:"from_uid"`
	ToUID       uint   `json:"to_uid"`
	ContentJson string `json:"content_json"`
	Ts          int64  `json:"ts"`
}

// GroupMessage 群聊消息表模型
type GroupMessage struct {
	MsgID       uint   `json:"msg_id"`
	GroupID     uint   `json:"group_id"`
	FromUID     uint   `json:"from_uid"`
	ContentJson string `json:"content_json"`
	Ts          int64  `json:"ts"`
}

// PrivateIndex 私聊索引表模型
type PrivateIndex struct {
	ID        uint   `json:"id"`
	UserA     uint   `json:"user_a"`
	UserB     uint   `json:"user_b"`
	MsgIDList string `json:"msg_id_list"` // JSON格式的消息ID列表
}

// GroupIndex 群聊索引表模型
type GroupIndex struct {
	ID        uint   `json:"id"`
	GroupID   uint   `json:"group_id"`
	MsgIDList string `json:"msg_id_list"` // JSON格式的消息ID列表
}

// BlacklistedToken 黑名单令牌表
type BlacklistedToken struct {
	ID        uint      `json:"id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Claims struct {
	UID    uint   `json:"uid"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func init() {
	// 尝试加载 .env 文件
	if err := godotenv.Load(); err != nil {
		log.Printf("没有找到 .env 文件: %v", err)
	} else {
		log.Println(".env 文件加载成功")
	}

	var err error
	path := dbPath
	if path == "" {
		path = "chat_server.db" // 使用更明确的数据库名
	}

	db, err = sql.Open("sqlite3", path)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// 创建表的SQL语句，与你提供的完全一致
	tables := []string{
		`CREATE TABLE IF NOT EXISTS user (
        uid INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        nickname TEXT NOT NULL,
        pwd_hash TEXT NOT NULL,
        latest_msg_ts INTEGER NOT NULL DEFAULT 0,
        contact_list TEXT NOT NULL DEFAULT '[]',
        token TEXT DEFAULT NULL,
        token_expire_ts INTEGER DEFAULT 0,
        create_ts INTEGER NOT NULL
      )`,
		
		`CREATE TABLE IF NOT EXISTS chat_group (
        group_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        owner_uid INTEGER NOT NULL,
        admin_uids TEXT NOT NULL DEFAULT '[]',
        member_uids TEXT NOT NULL DEFAULT '[]',
        last_msg_preview TEXT NOT NULL DEFAULT '',
        last_msg_ts INTEGER NOT NULL DEFAULT 0,
        create_ts INTEGER NOT NULL
      )`,
		
		`CREATE TABLE IF NOT EXISTS msg_private (
        msg_id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_uid INTEGER NOT NULL,
        to_uid INTEGER NOT NULL,
        content_json TEXT NOT NULL,
        ts INTEGER NOT NULL
      )`,
		
		`CREATE INDEX IF NOT EXISTS idx_private_to_ts ON msg_private(to_uid, ts)`,
		
		`CREATE TABLE IF NOT EXISTS msg_group (
        msg_id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER NOT NULL,
        from_uid INTEGER NOT NULL,
        content_json TEXT NOT NULL,
        ts INTEGER NOT NULL
      )`,
		
		`CREATE INDEX IF NOT EXISTS idx_group_gid_ts ON msg_group(group_id, ts)`,
		
		`CREATE TABLE IF NOT EXISTS idx_private (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_a INTEGER NOT NULL,
        user_b INTEGER NOT NULL,
        msg_id_list TEXT NOT NULL DEFAULT '[]',
        UNIQUE(user_a, user_b)
      )`,
		
		`CREATE TABLE IF NOT EXISTS idx_group (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        group_id INTEGER UNIQUE NOT NULL,
        msg_id_list TEXT NOT NULL DEFAULT '[]'
      )`,
		
		`CREATE TABLE IF NOT EXISTS blacklisted_token (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        INDEX(token)
      )`,
	}

	for _, table := range tables {
		_, err = db.Exec(table)
		if err != nil {
			log.Fatal("Failed to create table:", err)
		}
	}
}

func main() {
	if _, ok := os.LookupEnv("JWT_SECRET"); !ok {
		log.Fatal("Missing env: JWT_SECRET")
	}
	if _, ok := os.LookupEnv("DB_PATH"); !ok {
		log.Println("Warning: DB_PATH not set, using default: chat_server.db")
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

	// 聊天相关路由
	protected := r.Group("/api")
	protected.Use(authMiddleware())
	{
		protected.POST("/send-message", sendMessage)
		protected.GET("/fetch-messages", fetchMessages)
		protected.GET("/users/:username", getUser)
		protected.GET("/contacts", getContacts)
	}

	// 群聊相关路由
	protected.POST("/create-group", createGroup)
	protected.GET("/groups", getGroups)
	protected.GET("/groups/:id/messages", getGroupMessages)

	// 公开路由
	r.GET("/health", healthCheck)

	port := os.Getenv("PORT")
	if port == "" {
		port = "5000"
	}
	log.Printf("Chat server starting on port %s", port)
	r.Run(":" + port)
}

func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "healthy"})
}

func register(c *gin.Context) {
	var input struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
		Nickname string `json:"nickname" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 检查用户是否已存在
	var existingUID uint
	err := db.QueryRow("SELECT uid FROM user WHERE username = ?", input.Username).Scan(&existingUID)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "用户名已存在"})
		return
	}

	// 哈希密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码加密失败"})
		return
	}

	currentTime := time.Now().Unix()
	result, err := db.Exec(`
        INSERT INTO user (username, nickname, pwd_hash, latest_msg_ts, contact_list, token, token_expire_ts, create_ts)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		input.Username,
		input.Nickname,
		string(hashedPassword),
		0,
		"[]",
		"",
		0,
		currentTime,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "注册失败"})
		return
	}

	uid, _ := result.LastInsertId()

	c.JSON(http.StatusOK, gin.H{
		"uid":      uint(uid),
		"username": input.Username,
		"nickname": input.Nickname,
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
	err := db.QueryRow("SELECT uid, username, nickname, pwd_hash FROM user WHERE username = ?", input.Username).
		Scan(&user.UID, &user.Username, &user.Nickname, &user.PwdHash)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PwdHash), []byte(input.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		UID:    user.UID,
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)), // 延长到24小时
		},
	})

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成令牌失败"})
		return
	}

	// 更新用户令牌信息
	_, err = db.Exec("UPDATE user SET token = ?, token_expire_ts = ? WHERE uid = ?", 
		tokenString, time.Now().Add(time.Hour * 24).Unix(), user.UID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新令牌失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "登录成功",
		"token":   tokenString,
		"uid":     user.UID,
		"username": user.Username,
		"nickname": user.Nickname,
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

		_, err := db.Exec("INSERT INTO blacklisted_token (token, expires_at) VALUES (?, ?)",
			blacklistedToken.Token, blacklistedToken.ExpiresAt)
		if err != nil {
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
		err := db.QueryRow("SELECT token, expires_at FROM blacklisted_token WHERE token = ?", tokenString).
			Scan(&blacklisted.Token, &blacklisted.ExpiresAt)
			
		if err == nil && blacklisted.ExpiresAt.After(time.Now()) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token 已失效"})
			c.Abort()
			return
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
			c.Set("uid", claims.UID)
			c.Set("username", claims.Username)
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未认证"})
			c.Abort()
			return
		}
	}
}

// 发送消息
func sendMessage(c *gin.Context) {
	var input struct {
		ToUID   uint   `json:"to_uid" binding:"required"`
		Message string `json:"message" binding:"required"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	uid, _ := c.Get("uid")
	fromUID := uid.(uint)

	// 创建私聊消息
	currentTime := time.Now().Unix()
	result, err := db.Exec(`
        INSERT INTO msg_private (from_uid, to_uid, content_json, ts)
        VALUES (?, ?, ?, ?)`,
		fromUID,
		input.ToUID,
		input.Message,
		currentTime,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "发送消息失败"})
		return
	}

	msgID, _ := result.LastInsertId()

	// 更新用户的最新消息时间戳
	_, err = db.Exec("UPDATE user SET latest_msg_ts = ? WHERE uid = ?", currentTime, fromUID)
	if err != nil {
		log.Printf("Error updating user timestamp: %v", err)
	}

	_, err = db.Exec("UPDATE user SET latest_msg_ts = ? WHERE uid = ?", currentTime, input.ToUID)
	if err != nil {
		log.Printf("Error updating recipient timestamp: %v", err)
	}

	// 检查是否已存在私聊索引，否则创建
	minUser := fmt.Sprintf("%d", min(int(fromUID), int(input.ToUID)))
	maxUser := fmt.Sprintf("%d", max(int(fromUID), int(input.ToUID)))

	var idxID uint
	err = db.QueryRow("SELECT id FROM idx_private WHERE user_a = ? AND user_b = ?", minUser, maxUser).
		Scan(&idxID)

	if err != nil {
		// 创建新的私聊索引
		_, err = db.Exec(`
            INSERT INTO idx_private (user_a, user_b, msg_id_list)
            VALUES (?, ?, ?)`,
			minUser, maxUser, fmt.Sprintf("[%d]", msgID))
		if err != nil {
			log.Printf("Error creating private index: %v", err)
		}
	} else {
		// 更新索引中的消息ID列表
		var msgList string
		err = db.QueryRow("SELECT msg_id_list FROM idx_private WHERE user_a = ? AND user_b = ?", minUser, maxUser).
			Scan(&msgList)
		if err != nil {
			log.Printf("Error getting msg list: %v", err)
		} else {
			var list []int
			json.Unmarshal([]byte(msgList), &list)
			list = append(list, int(msgID))
			updatedList, _ := json.Marshal(list)

			_, err = db.Exec("UPDATE idx_private SET msg_id_list = ? WHERE user_a = ? AND user_b = ?",
				string(updatedList), minUser, maxUser)
			if err != nil {
				log.Printf("Error updating msg list: %v", err)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "消息发送成功",
		"msg_id":  msgID,
		"ts":      currentTime,
	})
}

// 获取消息
func fetchMessages(c *gin.Context) {
	pageStr := c.Query("page")
	limitStr := c.Query("limit")
	toUIDStr := c.Query("to_uid") // 与谁的对话

	page := 1
	if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
		page = p
	}

	limit := 20
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
		limit = l
	}

	toUID, err := strconv.Atoi(toUIDStr)
	if err != nil || toUID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "必须提供有效的to_uid参数"})
		return
	}

	uid, _ := c.Get("uid")
	fromUID := uid.(uint)

	offset := (page - 1) * limit

	// 查询双向消息（from -> to 或 to -> from）
	rows, err := db.Query(`
        SELECT msg_id, from_uid, to_uid, content_json, ts
        FROM msg_private
        WHERE (from_uid = ? AND to_uid = ?) OR (from_uid = ? AND to_uid = ?)
        ORDER BY ts DESC
        LIMIT ? OFFSET ?`,
		fromUID, toUID, toUID, fromUID, limit, offset)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取消息失败"})
		return
	}
	defer rows.Close()

	var messages []PrivateMessage
	for rows.Next() {
		var msg PrivateMessage
		err := rows.Scan(&msg.MsgID, &msg.FromUID, &msg.ToUID, &msg.ContentJson, &msg.Ts)
		if err != nil {
			log.Printf("Error scanning message: %v", err)
			continue
		}
		messages = append(messages, msg)
	}

	// 计算总数
	var totalItems int64
	err = db.QueryRow(`
        SELECT COUNT(*)
        FROM msg_private
        WHERE (from_uid = ? AND to_uid = ?) OR (from_uid = ? AND to_uid = ?)`,
		fromUID, toUID, toUID, fromUID).Scan(&totalItems)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "统计消息数量失败"})
		return
	}

	totalPages := int(totalItems) / limit
	if int(totalItems)%limit > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, gin.H{
		"messages": messages,
		"pagination": gin.H{
			"currentPage":  page,
			"totalPages":   totalPages,
			"totalItems":   totalItems,
			"itemsPerPage": limit,
		},
	})
}

// 获取用户信息
func getUser(c *gin.Context) {
	username := c.Param("username")
	
	var user User
	err := db.QueryRow("SELECT uid, username, nickname FROM user WHERE username = ?", username).
		Scan(&user.UID, &user.Username, &user.Nickname)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"uid":      user.UID,
		"username": user.Username,
		"nickname": user.Nickname,
	})
}

// 获取联系人列表
func getContacts(c *gin.Context) {
	uid, _ := c.Get("uid")
	currentUID := uid.(uint)
	
	var contactList string
	err := db.QueryRow("SELECT contact_list FROM user WHERE uid = ?", currentUID).
		Scan(&contactList)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	// 解析联系人列表JSON
	var contacts []map[string]interface{}
	json.Unmarshal([]byte(contactList), &contacts)

	c.JSON(http.StatusOK, gin.H{
		"contacts":         contacts,
		"contact_list_raw": contactList,
	})
}

// 创建群聊
func createGroup(c *gin.Context) {
	uid, _ := c.Get("uid")
	currentUID := uid.(uint)

	var input struct {
		Name string `json:"name" binding:"required"`
		Members []uint `json:"members"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	currentTime := time.Now().Unix()
	
	// 将成员列表转为JSON
	memberBytes, _ := json.Marshal(input.Members)
	memberList := string(memberBytes)

	result, err := db.Exec(`
        INSERT INTO chat_group (name, owner_uid, admin_uids, member_uids, last_msg_preview, last_msg_ts, create_ts)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
		input.Name,
		currentUID,
		fmt.Sprintf("[%d]", currentUID), // 创建者是管理员
		memberList,
		"",
		0,
		currentTime,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建群聊失败"})
		return
	}

	groupID, _ := result.LastInsertId()

	// 为群聊创建索引
	_, err = db.Exec(`INSERT INTO idx_group (group_id, msg_id_list) VALUES (?, ?)`, 
		groupID, "[]")

	if err != nil {
		log.Printf("Error creating group index: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"group_id": groupID,
		"name":     input.Name,
		"message":  "群聊创建成功",
	})
}

// 获取用户群聊列表
func getGroups(c *gin.Context) {
	uid, _ := c.Get("uid")
	currentUID := uid.(uint)

	rows, err := db.Query(`
        SELECT group_id, name, owner_uid, admin_uids, member_uids, last_msg_preview, last_msg_ts, create_ts
        FROM chat_group
        WHERE ? IN (SELECT value FROM json_each(member_uids))
        ORDER BY last_msg_ts DESC`,
		currentUID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取群聊列表失败"})
		return
	}
	defer rows.Close()

	var groups []ChatGroup
	for rows.Next() {
		var group ChatGroup
		var adminList, memberList string
		err := rows.Scan(&group.GroupID, &group.Name, &group.OwnerUID, &adminList, &memberList, 
			&group.LastMsgPreview, &group.LastMsgTs, &group.CreateTs)
		if err != nil {
			log.Printf("Error scanning group: %v", err)
			continue
		}
		group.AdminUids = adminList
		group.MemberUids = memberList
		groups = append(groups, group)
	}

	c.JSON(http.StatusOK, gin.H{
		"groups": groups,
	})
}

// 获取群聊消息
func getGroupMessages(c *gin.Context) {
	groupIDStr := c.Param("id")
	pageStr := c.Query("page")
	limitStr := c.Query("limit")

	groupID, err := strconv.Atoi(groupIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的群聊ID"})
		return
	}

	page := 1
	if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
		page = p
	}

	limit := 20
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
		limit = l
	}

	offset := (page - 1) * limit

	// 查询群聊消息
	rows, err := db.Query(`
        SELECT msg_id, group_id, from_uid, content_json, ts
        FROM msg_group
        WHERE group_id = ?
        ORDER BY ts DESC
        LIMIT ? OFFSET ?`,
		groupID, limit, offset)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取群聊消息失败"})
		return
	}
	defer rows.Close()

	var messages []GroupMessage
	for rows.Next() {
		var msg GroupMessage
		err := rows.Scan(&msg.MsgID, &msg.GroupID, &msg.FromUID, &msg.ContentJson, &msg.Ts)
		if err != nil {
			log.Printf("Error scanning group message: %v", err)
			continue
		}
		messages = append(messages, msg)
	}

	// 计算总数
	var totalItems int64
	err = db.QueryRow("SELECT COUNT(*) FROM msg_group WHERE group_id = ?", groupID).Scan(&totalItems)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "统计消息数量失败"})
		return
	}

	totalPages := int(totalItems) / limit
	if int(totalItems)%limit > 0 {
		totalPages++
	}

	c.JSON(http.StatusOK, gin.H{
		"messages": messages,
		"pagination": gin.H{
			"currentPage":  page,
			"totalPages":   totalPages,
			"totalItems":   totalItems,
			"itemsPerPage": limit,
		},
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
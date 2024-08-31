package main

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func getCurrentTime() string {
	return time.Now().Format("15:04:05 MST")
}

func main() {
	connStr := "host=localhost port=5432 user=postgres password=Gafentiy dbname=postgres sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Error connecting to the database: ", err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatal("Failed to connect to the database: ", err)
	}

	log.Println("Successfully connected to the database")

	router := gin.Default()
	router.LoadHTMLGlob("templates/*")

	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", gin.H{
			"time": getCurrentTime(),
		})
	})

	router.GET("/login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "login.html", gin.H{
			"time": getCurrentTime(),
		})
	})

	router.GET("/admin-login", func(c *gin.Context) {
		c.HTML(http.StatusOK, "admin_login.html", gin.H{
			"time": getCurrentTime(),
		})
	})

	router.POST("/login", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")

		var storedPasswordHash string
		var isAdmin bool
		err := db.QueryRow("SELECT password_hash, is_admin FROM users WHERE username=$1", username).Scan(&storedPasswordHash, &isAdmin)
		if err != nil {
			if err == sql.ErrNoRows {
				c.String(http.StatusUnauthorized, "Invalid username")
				return
			}
			c.String(http.StatusInternalServerError, "Error checking user")
			return
		}

		if err = bcrypt.CompareHashAndPassword([]byte(storedPasswordHash), []byte(password)); err != nil {
			c.String(http.StatusUnauthorized, "Invalid password")
			return
		}

		c.SetCookie("username", username, 3600, "/", "", false, true)
		if isAdmin {
			c.Redirect(http.StatusSeeOther, "/admin")
		} else {
			c.Redirect(http.StatusSeeOther, "/comments")
		}
	})

	router.POST("/admin-login", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")

		var storedPasswordHash string
		var isAdmin bool
		err := db.QueryRow("SELECT password_hash, is_admin FROM users WHERE username=$1", username).Scan(&storedPasswordHash, &isAdmin)
		if err != nil {
			if err == sql.ErrNoRows {
				c.String(http.StatusUnauthorized, "Invalid username or insufficient rights")
				return
			}
			c.String(http.StatusInternalServerError, "Error checking user")
			return
		}

		if err = bcrypt.CompareHashAndPassword([]byte(storedPasswordHash), []byte(password)); err != nil || !isAdmin {
			c.String(http.StatusUnauthorized, "Invalid password or insufficient rights")
			return
		}

		c.SetCookie("username", username, 3600, "/", "", false, true)
		c.Redirect(http.StatusSeeOther, "/admin")
	})

	router.GET("/register", func(c *gin.Context) {
		c.HTML(http.StatusOK, "register.html", gin.H{
			"time": getCurrentTime(),
		})
	})

	router.POST("/register", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Registration error"})
			return
		}

		if _, err = db.Exec("INSERT INTO users (username, password_hash, is_admin) VALUES ($1, $2, FALSE)", username, passwordHash); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving user"})
			return
		}

		c.SetCookie("username", username, 3600, "/", "", false, true)
		c.Redirect(http.StatusSeeOther, "/comments")
	})

	router.GET("/comments", func(c *gin.Context) {
		username, err := c.Cookie("username")
		if err != nil {
			c.Redirect(http.StatusSeeOther, "/login")
			return
		}

		rows, err := db.Query("SELECT id, username, content, created_at FROM comments ORDER BY created_at DESC")
		if err != nil {
			c.String(http.StatusInternalServerError, "Error retrieving comments")
			return
		}
		defer rows.Close()

		var comments []struct {
			ID        int
			Username  string
			Content   string
			CreatedAt string
		}

		for rows.Next() {
			var comment struct {
				ID        int
				Username  string
				Content   string
				CreatedAt string
			}
			if err := rows.Scan(&comment.ID, &comment.Username, &comment.Content, &comment.CreatedAt); err != nil {
				c.String(http.StatusInternalServerError, "Error reading comments")
				return
			}
			comments = append(comments, comment)
		}

		c.HTML(http.StatusOK, "comments.html", gin.H{
			"comments": comments,
			"username": username,
			"time":     getCurrentTime(),
		})
	})

	router.POST("/add-comment", func(c *gin.Context) {
		username, err := c.Cookie("username")
		if err != nil {
			c.Redirect(http.StatusSeeOther, "/login")
			return
		}

		content := c.PostForm("content")
		if _, err = db.Exec("INSERT INTO comments (username, content) VALUES ($1, $2)", username, content); err != nil {
			c.String(http.StatusInternalServerError, "Error adding comment")
			return
		}

		c.Redirect(http.StatusSeeOther, "/comments")
	})

	router.GET("/admin", func(c *gin.Context) {
		username, err := c.Cookie("username")
		if err != nil {
			c.Redirect(http.StatusSeeOther, "/admin-login")
			return
		}

		var isAdmin bool
		if err = db.QueryRow("SELECT is_admin FROM users WHERE username=$1", username).Scan(&isAdmin); err != nil {
			c.String(http.StatusInternalServerError, "Error checking admin rights")
			return
		}

		if !isAdmin {
			c.String(http.StatusForbidden, "Access denied")
			return
		}

		rows, err := db.Query("SELECT id, username, content, created_at FROM comments ORDER BY created_at DESC")
		if err != nil {
			c.String(http.StatusInternalServerError, "Error retrieving comments")
			return
		}
		defer rows.Close()

		var comments []struct {
			ID        int
			Username  string
			Content   string
			CreatedAt string
		}

		for rows.Next() {
			var comment struct {
				ID        int
				Username  string
				Content   string
				CreatedAt string
			}
			if err := rows.Scan(&comment.ID, &comment.Username, &comment.Content, &comment.CreatedAt); err != nil {
				c.String(http.StatusInternalServerError, "Error reading comments")
				return
			}
			comments = append(comments, comment)
		}

		c.HTML(http.StatusOK, "admin.html", gin.H{
			"comments": comments,
			"time":     getCurrentTime(),
		})
	})

	router.POST("/admin-add-comment", func(c *gin.Context) {
		username, err := c.Cookie("username")
		if err != nil {
			c.Redirect(http.StatusSeeOther, "/admin-login")
			return
		}

		var isAdmin bool
		if err = db.QueryRow("SELECT is_admin FROM users WHERE username=$1", username).Scan(&isAdmin); err != nil {
			c.String(http.StatusInternalServerError, "Error checking admin rights")
			return
		}

		if !isAdmin {
			c.String(http.StatusForbidden, "Access denied")
			return
		}

		content := c.PostForm("content")
		if _, err = db.Exec("INSERT INTO comments (username, content) VALUES ($1, $2)", username, content); err != nil {
			c.String(http.StatusInternalServerError, "Error adding comment")
			return
		}

		c.Redirect(http.StatusSeeOther, "/admin")
	})

	router.POST("/delete-comment", func(c *gin.Context) {
		username, err := c.Cookie("username")
		if err != nil {
			c.Redirect(http.StatusSeeOther, "/admin-login")
			return
		}

		var isAdmin bool
		if err = db.QueryRow("SELECT is_admin FROM users WHERE username=$1", username).Scan(&isAdmin); err != nil {
			c.String(http.StatusInternalServerError, "Error checking admin rights")
			return
		}

		if !isAdmin {
			c.String(http.StatusForbidden, "Access denied")
			return
		}

		commentID := c.PostForm("comment_id")
		if _, err = db.Exec("DELETE FROM comments WHERE id=$1", commentID); err != nil {
			c.String(http.StatusInternalServerError, "Error deleting comment")
			return
		}

		c.Redirect(http.StatusSeeOther, "/admin")
	})

	router.GET("/logout", func(c *gin.Context) {
		c.SetCookie("username", "", -1, "/", "", false, true)
		c.Redirect(http.StatusSeeOther, "/")
	})

	router.Run(":8080")
}

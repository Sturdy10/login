package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/smtp"
	"strings"
	"test/database"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type RequestPersonal struct {
	Firstname    string `json:"firstname"`
	Lastname     string `json:"lastname"`
	Jobtitle     string `json:"jobtitle"`
	Mobilenumber string `json:"mobilenumber"`
	Email        string `json:"email"`
	Password     string `json:"password"`
	Oldpassword  string `json:"oldpassword"`
	Newpassword  string `json:"newpassword"`
	Remember     bool   `json:"remember"`
}

var jwtSecret = []byte("not-key") // Replace "your-secret-key" with your actual secret key

func createToken(email string, remember bool) (string, error) {
	// Set expiration time based on the remember parameter
	var expirationTime time.Time
	if remember {
		// Token expires in 30 days
		expirationTime = time.Now().Add(30 * 24 * time.Hour)
	} else {
		// Token expires in 3 days
		expirationTime = time.Now().Add(3 * 24 * time.Hour)
	}

	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["email"] = email
	claims["exp"] = expirationTime.Unix() // Token expiration time

	tokenString, err := token.SignedString(jwtSecret)
	return tokenString, err
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		providedToken := c.Request.Header.Get("Authorization")
		if providedToken == "" {
			c.JSON(401, gin.H{"status": "error", "message": "Missing token"})
			c.Abort()
			return
		}

		// Extract the token from the "Bearer <token>" format
		providedToken = strings.TrimPrefix(providedToken, "Bearer ")

		// Verify the token
		token, err := jwt.Parse(providedToken, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(401, gin.H{"status": "error", "message": "Invalid Token"})
			c.Abort()
			return
		}

		// Set the claims in the context
		c.Set("claims", token.Claims)

		c.Next()
	}
}

func insertData(db *sql.DB, firstname, lastname, jobTitle, mobilenumber, email, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	query := "INSERT INTO personaldetails(per_firstname, per_Lastname, per_jobtitle, per_mobilenumber, per_email, password) VALUES ($1, $2, $3, $4, $5, $6)"
	_, err = db.Exec(query, firstname, lastname, jobTitle, mobilenumber, email, hashedPassword)
	return err
}

func updatePassword(db *sql.DB, email, oldpassword, newpassword string) error {
	// Hash the old password
	var hashedOldPassword string
	query := "SELECT password FROM personaldetails WHERE per_email = $1"
	err := db.QueryRow(query, email).Scan(&hashedOldPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return errors.New("user not found")
		}
		return err
	}

	// Check the old password
	err = bcrypt.CompareHashAndPassword([]byte(hashedOldPassword), []byte(oldpassword))
	if err != nil {
		return errors.New("incorrect old password")
	}

	// Hash the new password
	hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(newpassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Update the password in the database with the new hashed password
	query = "UPDATE personaldetails SET password = $1 WHERE per_email = $2"
	_, err = db.Exec(query, hashedNewPassword, email)
	return err
}

func sendEmail(to, subject, body string) error {
	// กำหนดข้อมูลสำหรับเข้าระบบ SMTP
	smtpServer := "smtp.gmail.com"
	smtpPort := 587
	senderEmail := "report.trac@gmail.com"
	senderPassword := "mcoqvwpabjtdoxvw"

	// กำหนดข้อมูลอีเมล
	from := senderEmail
	recipients := []string{to}
	message := fmt.Sprintf("To: %s\r\n", to) +
		"Subject: " + subject + "\r\n" +
		"\r\n" + body

	// ติดต่อ SMTP เซิร์ฟเวอร์และส่งอีเมล
	auth := smtp.PlainAuth("", senderEmail, senderPassword, smtpServer)
	err := smtp.SendMail(fmt.Sprintf("%s:%d", smtpServer, smtpPort), auth, from, recipients, []byte(message))
	return err
}

func generateRandomPassword(length int) string {
	// สร้างตัวชี้เพื่อใช้ในการสร้างรหัสผ่านแบบสุ่ม
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))

	// สร้างรหัสผ่านแบบสุ่มด้วยความยาวที่กำหนด
	password := make([]byte, length)
	for i := range password {
		password[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(password)
}

func main() {
	db := database.Postgresql()
	defer db.Close()

	err := db.Ping()
	if err != nil {
		log.Fatal("Database connection error: ", err)
	}
	r := gin.Default()

	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"*"}
	config.AllowMethods = []string{"GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "X-Auth-Token", "Authorization"}

	r.Use(cors.New(config))

	r.POST("/api/register", func(c *gin.Context) {
		var reqPersonal RequestPersonal
		if err := c.ShouldBindJSON(&reqPersonal); err != nil {
			c.JSON(400, gin.H{"status": "error", "message": err.Error()})
			return
		}
		firstname := reqPersonal.Firstname
		lastname := reqPersonal.Lastname
		jobTitle := reqPersonal.Jobtitle
		mobilenumber := reqPersonal.Mobilenumber
		email := reqPersonal.Email

		if firstname == "" || lastname == "" || jobTitle == "" || mobilenumber == "" || email == "" {
			c.JSON(400, gin.H{"status": "error", "message": "Missing required fields in JSON"})
			return
		}

		if len(mobilenumber) > 10 {
			c.JSON(400, gin.H{"status": "error", "message": "Mobile number must not exceed 10 characters"})
			return
		}

		generatedPassword := generateRandomPassword(8)

		if err := insertData(db, firstname, lastname, jobTitle, mobilenumber, email, generatedPassword); err != nil {
			c.JSON(500, gin.H{"status": "error", "message": "Failed to register user", "details": err.Error()})
			return
		}

		// ส่งอีเมลแจ้งผู้ใช้
		to := reqPersonal.Email // สมมติว่าคุณมีฟิลด์ "Email" ใน reqPersonal
		subject := "welcome! You have successfully registered."
		body := "Please use the default password porovide below to Login\n"
		body += "Email: " + email + "\n"                // เพิ่มชื่อผู้ใช้
		body += "Password: " + generatedPassword + "\n" // เพิ่มรหัสผ่าน

		if err := sendEmail(to, subject, body); err != nil {
			log.Printf("เกิดข้อผิดพลาดในการส่งอีเมล: %s", err.Error())
			c.JSON(500, gin.H{"status": "error", "message": "Failed to send registration email"})
			return
		}

		c.JSON(200, gin.H{"status": "OK", "message": "User registered successfully"})
	})

	r.POST("/api/login", func(c *gin.Context) {
		var reqPersonal RequestPersonal
		if err := c.ShouldBindJSON(&reqPersonal); err != nil {
			c.JSON(400, gin.H{"status": "error", "message": err.Error()})
			return
		}

		email := reqPersonal.Email
		password := reqPersonal.Password
		remember := reqPersonal.Remember

		
		if email == "" || len(password) < 8 {
			c.JSON(400, gin.H{"status": "error", "message": "Email is missing or the password is too short (min 8 characters)"})
			return
		}

		if len(password) < 8 {
			c.JSON(400, gin.H{"status": "error", "message": "The password must be at least 8 characters long"})
			return
		}

		// Query the user's data from the database
		var hashedPassword string
		query := "SELECT password FROM personaldetails WHERE per_email = $1"
		err := db.QueryRow(query, email).Scan(&hashedPassword)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(401, gin.H{"status": "error", "message": "User not found"})
				return
			}
			c.JSON(500, gin.H{"status": "error", "message": "Database error", "details": err.Error()})
			return
		}

		// Verify the password
		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			c.JSON(401, gin.H{"status": "error", "message": "Incorrect Email or Password"})
			return
		}

		token, err := createToken(email, remember)
		if err != nil {
			c.JSON(500, gin.H{"status": "error", "message": "Failed to create token", "details": err.Error()})
			return
		}

		c.JSON(200, gin.H{"status": "OK", "token": token, "message": "Login successful"})
	})

	r.PATCH("/api/change-password", AuthMiddleware(), func(c *gin.Context) {
		// ดึง email จาก token
		claims := c.MustGet("claims").(jwt.MapClaims)
		email := claims["email"].(string)

		// ตรวจสอบว่า email ใน token ตรงกับ email ในรายละเอียดของคำขอ
		reqPersonal := RequestPersonal{}
		if err := c.ShouldBindJSON(&reqPersonal); err != nil {
			c.JSON(400, gin.H{"status": "error", "message": err.Error()})
			return
		}

		if email != reqPersonal.Email {
			c.JSON(401, gin.H{"status": "error", "message": "invalid token"})
			return
		}

		oldpassword := reqPersonal.Oldpassword
		newpassword := reqPersonal.Newpassword

		if email == "" || oldpassword == "" || newpassword == "" {
			c.JSON(400, gin.H{"status": "error", "message": "Missing email, oldpassword, or newpassword in JSON"})
			return
		}

		if email == "" || len(oldpassword) < 8 || len(newpassword) < 8 {
			c.JSON(400, gin.H{"status": "error", "message": "Email, oldpassword, and newpassword must not be empty and should be at least 8 characters long"})
			return
		}

		// Verify the old password
		query := "SELECT password FROM personaldetails WHERE per_email = $1"
		var hashedPassword string
		err := db.QueryRow(query, email).Scan(&hashedPassword)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(401, gin.H{"status": "error", "message": "User not found"})
				return
			}
			c.JSON(500, gin.H{"status": "error", "message": "Database error", "details": err.Error()})
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(oldpassword))
		if err != nil {
			c.JSON(401, gin.H{"status": "error", "message": "Incorrect Old Password"})
			return
		}

		// Update the password in the database with the new hashed password
		err = updatePassword(db, email, oldpassword, newpassword)
		if err != nil {
			c.JSON(500, gin.H{"status": "error", "message": "Failed to update password", "details": err.Error()})
			return
		}

		c.JSON(200, gin.H{"status": "OK", "message": "Password updated successfully"})
	})

	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}

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
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type RequestPersonal struct {
	ID             uuid.UUID `json:"id"`
	Firstname      string    `json:"firstname"`
	Lastname       string    `json:"lastname"`
	Jobtitle       string    `json:"jobtitle"`
	Mobilenumber   string    `json:"mobilenumber"`
	Email          string    `json:"email"`
	Password       string    `json:"password"`
	Oldpassword    string    `json:"oldpassword"`
	Newpassword    string    `json:"newpassword"`
	Remember       bool      `json:"remember"`
	Requiresaction string    `json:"requires_action"`
}
type UserData struct {
	ID           uuid.UUID `json:"id"`
	Firstname    string    `json:"firstname"`
	Lastname     string    `json:"lastname"`
	Jobtitle     string    `json:"jobtitle"`
	Mobilenumber string    `json:"mobilenumber"`
	Email        string    `json:"email"`
}

var jwtSecret = []byte("not-key") // Replace "your-secret-key" with your actual secret key

func createToken(email string, remember bool, requires_action string) (string, error) {
	// Set expiration time based on the remember parameter
	var expirationTime time.Time
	if remember {
		// Token expires in 30 days
		expirationTime = time.Now().Add(30 * 24 * time.Hour)
	} else {
		// Token expires in 3 days
		expirationTime = time.Now().Add(3 * 24 * time.Hour)
	}

	// Creating the token
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["email"] = email
	claims["requires_action"] = requires_action // fixed the typo and added this field to the token
	claims["exp"] = expirationTime.Unix()       // Token expiration time

	// Signing the token with a secret
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
func createTokenI(email string, remember bool, requires_action string) (string, error) {
	// Set expiration time based on the remember parameter
	var expirationTime time.Time
	if remember {
		// Token expires in 30 days
		expirationTime = time.Now().Add(30 * 24 * time.Hour)
	} else {
		// Token expires in 3 days
		expirationTime = time.Now().Add(3 * 24 * time.Hour)
	}

	// Creating the token
	token := jwt.New(jwt.GetSigningMethod("HS256"))
	claims := token.Claims.(jwt.MapClaims)
	claims["email"] = email
	claims["requires_action"] = requires_action // fixed the typo and added this field to the token
	claims["exp"] = expirationTime.Unix()       // Token expiration time

	// Signing the token with a secret
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
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

func insertData(db *sql.DB, firstname, lastname, jobTitle, mobilenumber, email, password, requiresaction string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	query := "INSERT INTO personaldetails(per_firstname, per_Lastname, per_jobtitle, per_mobilenumber, per_email, password, requires_action) VALUES ($1, $2, $3, $4, $5, $6, $7)"
	_, err = db.Exec(query, firstname, lastname, jobTitle, mobilenumber, email, hashedPassword, requiresaction)
	return err
}

func updatePassword(db *sql.DB, email, oldpassword, newpassword, requires_action string) error {
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

	// Update password and requires_action in the database
	query = "UPDATE personaldetails SET password = $1, requires_action = $2 WHERE per_email = $3"
	_, err = db.Exec(query, string(hashedNewPassword), requires_action, email)

	return err
}
func updatePasswordI(db *sql.DB, email, newpassword, requires_action string) error {
    // Hash the new password
    hashedNewPassword, err := bcrypt.GenerateFromPassword([]byte(newpassword), bcrypt.DefaultCost)
    if err != nil {
        return err
    }

    // Update password and requires_action in the database
    query := "UPDATE personaldetails SET password = $1, requires_action = $2 WHERE per_email = $3"
    _, err = db.Exec(query, string(hashedNewPassword), requires_action, email)

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

	// Create the email content in HTML format
	msg := []byte("To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0;\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\";\r\n" +
		"\r\n" +
		body)

	// ติดต่อ SMTP เซิร์ฟเวอร์และส่งอีเมล
	auth := smtp.PlainAuth("", senderEmail, senderPassword, smtpServer)
	err := smtp.SendMail(fmt.Sprintf("%s:%d", smtpServer, smtpPort), auth, from, recipients, msg)
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
		remember := reqPersonal.Remember
	
		if firstname == "" || lastname == "" || jobTitle == "" || mobilenumber == "" || email == "" {
			c.JSON(400, gin.H{"status": "error", "message": "Missing required fields in JSON"})
			return
		}
	
		if len(mobilenumber) > 10 {
			c.JSON(400, gin.H{"status": "error", "message": "Mobile number must not exceed 10 characters"})
			return
		}
	
		generatedPassword := generateRandomPassword(8)
	
		requires_action := "change_password"
	
		if err := insertData(db, firstname, lastname, jobTitle, mobilenumber, email, generatedPassword, requires_action); err != nil {
			c.JSON(500, gin.H{"status": "error", "message": "Failed to register user", "details": err.Error()})
			return
		}
	
		token, err := createTokenI(email, remember, requires_action)
		if err != nil {
			c.JSON(500, gin.H{"status": "error", "message": "Failed to create token", "details": err.Error()})
			return
		}

			// ส่งอีเมลแจ้งผู้ใช้
			to := reqPersonal.Email
			subject := "welcome! You have successfully registered."
			body := "Please use the default password provided below to Login<br>"
			body += "Email: " + email + "<br>" 
			body += "Password: " + generatedPassword + "<br>"
			body += "<a href='http://localhost:3000/resetpassword/?token=" + token + "'>Confirm Link</a><br>"

			if err := sendEmail(to, subject, body); err != nil {
				log.Printf("เกิดข้อผิดพลาดในการส่งอีเมล: %s", err.Error())
				c.JSON(500, gin.H{"status": "error", "message": "Failed to send registration email"})
				return
			}

			c.JSON(200, gin.H{"status": "OK", "message": "User registered successfully"})
	})

	r.GET("/api/users", func(c *gin.Context) {
		// Query the database to retrieve user data, including ID
		rows, err := db.Query("SELECT per_pk, per_firstname, per_Lastname, per_jobtitle, per_mobilenumber, per_email FROM personaldetails")
		if err != nil {
			c.JSON(500, gin.H{"status": "error", "message": "Failed to retrieve users", "details": err.Error()})
			return
		}
		defer rows.Close()

		users := []UserData{}

		// Iterate through the rows and add them to the users slice
		for rows.Next() {
			var user UserData
			err := rows.Scan(&user.ID, &user.Firstname, &user.Lastname, &user.Jobtitle, &user.Mobilenumber, &user.Email)
			if err != nil {
				c.JSON(500, gin.H{"status": "error", "message": "Failed to scan user data", "details": err.Error()})
				return
			}
			users = append(users, user)
		}

		// Check for errors from iterating over rows
		if err := rows.Err(); err != nil {
			c.JSON(500, gin.H{"status": "error", "message": "Failed to iterate over user data", "details": err.Error()})
			return
		}

		c.JSON(200, gin.H{"status": "OK", "data": users})
	})

	r.DELETE("/api/delete-user/:id", func(c *gin.Context) {
		// Get the user ID from the URL parameter
		userID := c.Param("id")

		// Parse the user ID as a UUID
		id, err := uuid.Parse(userID)
		if err != nil {
			c.JSON(400, gin.H{"status": "error", "message": "Invalid user ID"})
			return
		}

		// Execute the SQL query to delete the user with the given ID
		query := "DELETE FROM personaldetails WHERE per_pk = $1"
		_, err = db.Exec(query, id)
		if err != nil {
			c.JSON(500, gin.H{"status": "error", "message": "Failed to delete user", "details": err.Error()})
			return
		}

		c.JSON(200, gin.H{"status": "OK", "message": "User deleted successfully"})
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
			c.JSON(400, gin.H{"status": "error", "message": "Email is missing or the password is too short (min 8 characters) or remember value is invalid"})
			return
		}

		// Query the user's data from the database, including 'requiresaction'
		var hashedPassword, requires_action string
		query := "SELECT password, requires_action FROM personaldetails WHERE per_email = $1"
		err := db.QueryRow(query, email).Scan(&hashedPassword, &requires_action)
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

	

		
		token, err := createToken(email, remember, requires_action)

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

		// Bind the JSON body to a struct
		reqPersonal := RequestPersonal{}
		if err := c.ShouldBindJSON(&reqPersonal); err != nil {
			c.JSON(400, gin.H{"status": "error", "message": err.Error()})
			return
		}

		// Validate email
		if email != reqPersonal.Email || email == "" {
			c.JSON(401, gin.H{"status": "error", "message": "Invalid token or email"})
			return
		}

		oldpassword := reqPersonal.Oldpassword
		newpassword := reqPersonal.Newpassword
		requires_action := reqPersonal.Requiresaction

		// Validate input
		if oldpassword == "" || newpassword == "" || len(oldpassword) < 8 || len(newpassword) < 8 {
			c.JSON(400, gin.H{"status": "error", "message": "Invalid input"})
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

		err = updatePassword(db, email, oldpassword, newpassword, requires_action)
		if err != nil {
			c.JSON(500, gin.H{"status": "error", "message": "Failed to update password", "details": err.Error()})
			return
		}

		c.JSON(200, gin.H{"status": "OK", "message": "Password updated successfully"})
	})


	r.PATCH("/api/change-password-byconfirm-link", AuthMiddleware(), func(c *gin.Context) {
		// ดึง email จาก token
		claims := c.MustGet("claims").(jwt.MapClaims)
		email := claims["email"].(string)
	
		// Bind the JSON body to a struct
		reqPersonal := RequestPersonal{}
		if err := c.ShouldBindJSON(&reqPersonal); err != nil {
			c.JSON(400, gin.H{"status": "error", "message": err.Error()})
			return
		}
	
		// Validate email
		if email != reqPersonal.Email || email == "" {
			c.JSON(401, gin.H{"status": "error", "message": "Invalid token or email"})
			return
		}
	
		newpassword := reqPersonal.Newpassword
		requires_action := reqPersonal.Requiresaction
	
		// Validate input
		if newpassword == "" || len(newpassword) < 8 {
			c.JSON(400, gin.H{"status": "error", "message": "Invalid input"})
			return
		}
	
		// Update the password and requires_action in the database with the new hashed password
		err := updatePasswordI(db, email, newpassword, requires_action)
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
	
		
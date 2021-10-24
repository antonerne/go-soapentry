package controller

import (
	"go-soapentry/communications"
	"net/http"
	"strconv"
	"time"

	models "github.com/antonerne/go-soap/models"
	"gorm.io/gorm"

	"github.com/gin-gonic/gin"
)

type Controller struct {
	DB        *gorm.DB
	ErrorLog  *models.LogFile
	AccessLog *models.LogFile
}

// This method will be to get the user's entries for a certain number of days.
// this will default to 30 days, but a user can request additional days or
// a period of time.
func (con *Controller) GetEntries(c *gin.Context) {
	// get request from the context
	id := c.Param("id")
	days := 30
	if sdays, ok := c.GetQuery("days"); ok {
		days, _ = strconv.Atoi(sdays)
	}
	if id != "" {
		var answer communications.UserEntries
		// get requested user
		var entries []models.Entry
		var creds models.Credentials

		con.DB.Where("userid = ?", id).Find(&creds)

		now := time.Now()
		lastDate := now.AddDate(0, 0, (-1 * days))
		con.DB.Preload("Reference").Preload("Texts").
			Where("entrydate >= ?", lastDate).Where("entrydate <= ?", now).
			Where("user_id = ?", id).
			Find(&entries)

		for _, entry := range entries {
			key := entry.Key
			for _, text := range entry.Texts {
				text.DecryptText(creds.PrivateKey, key)
			}
			answer.Entries = append(answer.Entries, entry)
		}

		con.DB.Preload("Periods.StudyDays.References").
			Where("startdate <= ?", now).Where("enddate >= ?", now).
			Order("startdate desc").Order("enddate desc").
			First(&answer.UserStudy)

		con.DB.Preload("Periods.StudyDays.References").
			Where("id = ?", answer.UserStudy.BibleStudyID).
			Find(&answer.CurrentStudy)

		con.DB.Order("id asc").Find(&answer.Bible)

		c.JSON(http.StatusOK, gin.H{
			"study": answer,
		})
		return
	}
	c.JSON(http.StatusNotFound, gin.H{
		"error": "User not found",
	})

}

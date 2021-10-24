package controller

import (
	models "github.com/antonerne/go-soap/models"
	"gorm.io/gorm"
)

type StudyController struct {
	DB        *gorm.DB
	ErrorLog  *models.LogFile
	AccessLog *models.LogFile
}

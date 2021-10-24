package communications

import "github.com/antonerne/go-soap/models"

type UserEntries struct {
	Entries      []models.Entry        `json:"entries"`
	UserStudy    models.UserBibleStudy `json:"study"`
	CurrentStudy models.BibleStudy     `json:"current"`
	Bible        []models.BibleBook    `json:"bible"`
}

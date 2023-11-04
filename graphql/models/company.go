package models

import (
	"errors"
	"gorm.io/gorm"
	"strconv"
)

type Conn struct {
	db *gorm.DB
}

func NewService(db *gorm.DB) (*Conn, error) {
	if db == nil {
		return nil, errors.New("please provide a valid connection")
	}

	// We initialize our service with the passed database instance.
	s := &Conn{db: db}
	return s, nil
}

func (s *Conn) CreateCompany(ni NewCompany) (NewCompany, error) {
	cmp := NewCompany{
		CompanyName: ni.CompanyName,
		FoundedYear: ni.FoundedYear,
		Location:    ni.Location,
		//Jobs:        ni.Jobs,
	}
	err := s.db.Create(&cmp).Error
	if err != nil {
		return NewCompany{}, err
	}
	return cmp, nil
}

func (s *Conn) CreateJob(ni NewJob) (NewJob, error) {
	job := NewJob{
		Title:              ni.Title,
		ExperienceRequired: ni.ExperienceRequired,
		CompanyID:          ni.CompanyID,
	}
	err := s.db.Create(&job).Error
	if err != nil {
		return NewJob{}, err
	}
	return job, nil
}

func (s *Conn) ViewAllCompanies() ([]Company, error) {
	var company []Company
	result := s.db.Find(&company)
	err := result.Find(&company).Error
	if err != nil {
		return nil, result.Error
	}
	return company, nil
}

func (s *Conn) ViewAllJobs() ([]Job, error) {
	var job []Job
	result := s.db.Find(&job)
	err := result.Find(&job).Error
	if err != nil {
		return nil, result.Error
	}
	return job, nil
}

func (s *Conn) FindCompanyByID(companyID string) (Company, error) {
	var cmp Company
	//"id = ?", companyID
	cmpID, err := strconv.ParseUint(companyID, 10, 64)
	if err != nil {
		return Company{}, err
	}
	result := s.db.Where("id = ?", cmpID).Find(&cmp)
	if result.Error != nil {
		return Company{}, result.Error
	}
	return cmp, nil
}

func (s *Conn) FindJobByJobID(jobID string) (Job, error) {
	var job Job
	jobid, err := strconv.ParseUint(jobID, 10, 64)
	if err != nil {
		return Job{}, err
	}
	result := s.db.Where("id=?", jobid).Find(&job)
	if result.Error != nil {
		return Job{}, result.Error
	}
	return job, nil
}

func (s *Conn) FindJobByCompanyID(companyID string) ([]Job, error) {
	var job []Job
	cmpID, err := strconv.ParseUint(companyID, 10, 64)
	if err != nil {
		return nil, err
	}
	result := s.db.Where("company_id = ?", cmpID).Find(&job)
	if result.Error != nil {
		return nil, result.Error
	}
	return job, nil
}
func (s *Conn) AutoMigrate() error {

	err := s.db.Migrator().AutoMigrate(&NewUser{}, &NewCompany{}, &NewJob{})
	if err != nil {
		return err
	}

	// AutoMigrate function will ONLY create tables, missing columns and missing indexes, and WON'T change existing column's type or delete unused columns
	err = s.db.Migrator().AutoMigrate(&NewUser{}, &NewCompany{}, &NewJob{})
	if err != nil {
		// If there is an error while migrating, log the error message and stop the program
		return err
	}
	return nil
}

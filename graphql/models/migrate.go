package models

func (s *Conn) AutoMigrate() error {
	//if s.db.Migrator().HasTable(&User{}se
	//	return services
	//}

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

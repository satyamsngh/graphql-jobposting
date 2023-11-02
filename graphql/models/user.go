package models

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"strconv"
	"time"
)

func (s *Conn) Signup(input NewUser) (NewUser, error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return NewUser{}, fmt.Errorf("generating password hash: %w", err)
	}
	u := NewUser{
		Name:     input.Name,
		Email:    input.Email,
		Password: string(hashedPass),
	}
	err = s.db.Create(&u).Error
	if err != nil {
		return NewUser{}, err
	}

	// Successfully created the record, return the user.
	return u, nil

}
func (s *Conn) Find(email, password string) (jwt.RegisteredClaims,
	error) {
	var u NewUser
	tx := s.db.Where("email = ?", email).First(&u)
	if tx.Error != nil {
		return jwt.RegisteredClaims{}, tx.Error
	}

	// We check if the provided password matches the hashed password in the database.
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	if err != nil {
		return jwt.RegisteredClaims{}, err
	}
	c := jwt.RegisteredClaims{
		Issuer:    "gql project",
		Subject:   strconv.FormatUint(uint64(u.ID), 10),
		Audience:  jwt.ClaimStrings{"students"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	return c, nil

}

package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.40

import (
	"context"
	"errors"
	"fmt"
	"graphql/graph/auth"
	"graphql/graph/model"
	"log"
	"net/http"
)

// CreateCompany is the resolver for the createCompany field.
func (r *mutationResolver) CreateCompany(ctx context.Context, input model.NewCompany) (*model.Company, error) {
	return r.S.CreateCompany(input)
}

// CreateJob is the resolver for the createJob field.
func (r *mutationResolver) CreateJob(ctx context.Context, input model.NewJob) (*model.Job, error) {
	return r.S.CreateJob(input)
}

// Signup is the resolver for the signup field.
func (r *mutationResolver) Signup(ctx context.Context, input model.NewUser) (*model.User, error) {
	return r.S.Signup(input)
}

// Login is the resolver for the login field.
func (r *mutationResolver) Login(ctx context.Context, email string, password string) (*model.Token, error) {
	token, err := r.S.Authenticate(email, password)
	if err != nil {
		log.Println("errr")
		return &model.Token{}, err
	}

	tkn := &model.Token{
		Tkn: token,
	}
	return tkn, nil
}

// ViewAllCompanies is the resolver for the viewAllCompanies field.
func (r *queryResolver) ViewAllCompanies(ctx context.Context) ([]*model.Company, error) {
	req := ctx.Value("request").(*http.Request)

	token, err := auth.ExtractTokenFromHeader(req)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, errors.New("Token not found in headers")
	}

	// Validate the token
	err = auth.ValidateToken(token)
	if err != nil {
		return nil, fmt.Errorf("Token validation failed: %w", err)
	}

	return r.S.ViewAllCompanies()
}

// ViewAllJobs is the resolver for the viewAllJobs field.
func (r *queryResolver) ViewAllJobs(ctx context.Context) ([]*model.Job, error) {
	return r.S.ViewAllJobs()
}

// FindCompanyByID is the resolver for the findCompanyById field.
func (r *queryResolver) FindCompanyByID(ctx context.Context, companyID string) (*model.Company, error) {
	return r.S.FindCompanyByID(companyID)
}

// FindJobByJobID is the resolver for the findJobByJobId field.
func (r *queryResolver) FindJobByJobID(ctx context.Context, jobID string) (*model.Job, error) {
	return r.S.FindJobByJobID(jobID)
}

// FindJobByCompanyID is the resolver for the findJobByCompanyId field.
func (r *queryResolver) FindJobByCompanyID(ctx context.Context, companyID string) ([]*model.Job, error) {
	return r.S.FindJobByCompanyID(companyID)
}

// Mutation returns MutationResolver implementation.
func (r *Resolver) Mutation() MutationResolver { return &mutationResolver{r} }

// Query returns QueryResolver implementation.
func (r *Resolver) Query() QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }

package cliauth

import (
	"encoding/json"
	"os"
)

type dbUser struct {
	Login string `json:"login"`
	Hash  string `json:"hash"`
}

type usersStorage interface {
	getAll() ([]*dbUser, error)
	getByLogin(login string) (*dbUser, error)
	save(user *dbUser) error
}

type usersStorageImpl struct {
	dbpath string
}

func (stg *usersStorageImpl) getAll() ([]*dbUser, error) {
	jsonData, err := os.ReadFile(stg.dbpath)
	if err != nil {
		return nil, err
	}
	var users []*dbUser
	if len(jsonData) == 0 {
		return users, nil
	}
	if err := json.Unmarshal(jsonData, &users); err != nil {
		return nil, err
	}
	return users, nil
}

func (stg *usersStorageImpl) getByLogin(login string) (*dbUser, error) {
	users, err := stg.getAll()
	if err != nil {
		return nil, err
	}
	var found *dbUser
	for _, u := range users {
		if login == u.Login {
			found = u
			break
		}
	}
	if found == nil {
		return nil, ErrUserNotFound
	}
	return found, nil
}

func (stg *usersStorageImpl) save(user *dbUser) error {
	users, err := stg.getAll()
	if err != nil {
		return err
	}
	for _, u := range users {
		if user.Login == u.Login {
			return ErrUserAlreadyExists
		}
	}
	users = append(users, user)
	jsonData, err := json.Marshal(users)
	if err != nil {
		return err
	}
	if err := os.WriteFile(stg.dbpath, jsonData, 0600); err != nil {
		return err
	}
	return nil
}

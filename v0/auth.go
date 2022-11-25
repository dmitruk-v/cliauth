package cliauth

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/inancgumus/screen"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

type User struct {
	Login    string
	Password string
}

type registerCredentials struct {
	login       string
	password    string
	passwordRep string
}

type loginCredentials struct {
	login    string
	password string
}

type authenticator struct {
	usersStorage usersStorage
}

func NewAuthenticator() *authenticator {
	return &authenticator{
		usersStorage: NewUsersStorageImpl(),
	}
}

func (au *authenticator) Run() (*User, error) {
	formatError := func(err error) error {
		return fmt.Errorf("[AUTH ERROR]: %v", err)
	}
	au.printMenu()
	for {
		var (
			err  error
			user *User
		)
		key, err := au.askAction()
		if err != nil {
			return nil, formatError(err)
		}
		switch key {
		case "1":
			user, err = au.Login()
		case "2":
			user, err = au.Register()
		case "3":
			os.Exit(0)
		default:
			continue
		}
		if err != nil {
			return nil, formatError(err)
		}
		return user, nil
	}
}

func (au *authenticator) printMenu() {
	au.clearConsole()
	fmt.Printf("\n--- Authenticator menu ---\n\n")
	fmt.Println("1. Login")
	fmt.Println("2. Register")
	fmt.Println("3. Quit")
	fmt.Println()
}

func (au *authenticator) Register() (*User, error) {
	formatError := func(err error) error {
		return fmt.Errorf("register: %v", err)
	}
	creds, err := au.askRegisterCreds()
	if err != nil {
		return nil, formatError(err)
	}
	user, err := au.registerAction(creds)
	if err != nil {
		return nil, formatError(err)
	}
	return user, nil
}

func (au *authenticator) Login() (*User, error) {
	formatError := func(err error) error {
		return fmt.Errorf("login: %v", err)
	}
	creds, err := au.askLoginCreds()
	if err != nil {
		return nil, formatError(err)
	}
	user, err := au.loginAction(creds)
	if err != nil {
		return nil, formatError(err)
	}
	return user, nil
}

func (au *authenticator) Unregister() error {
	panic("not implemented")
}

func (au *authenticator) registerAction(creds registerCredentials) (*User, error) {
	if len(creds.login) == 0 {
		return nil, ErrEmptyLogin
	}
	if creds.password != creds.passwordRep {
		return nil, ErrPasswordsNotEqual
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(creds.password), 12)
	if err != nil {
		return nil, err
	}
	dbuser := &dbUser{
		Login: creds.login,
		Hash:  string(hash),
	}
	if err := au.usersStorage.save(dbuser); err != nil {
		return nil, err
	}
	user := &User{
		Login:    creds.login,
		Password: creds.password,
	}
	return user, nil
}

func (au *authenticator) loginAction(creds loginCredentials) (*User, error) {
	dbuser, err := au.usersStorage.getByLogin(creds.login)
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(dbuser.Hash), []byte(creds.password)); err != nil {
		return nil, ErrBadCredentials
	}
	user := &User{
		Login:    creds.login,
		Password: creds.password,
	}
	return user, nil
}

func (au *authenticator) askAction() (string, error) {
	key := make([]byte, 2)
	fmt.Print("> ")
	_, err := os.Stdin.Read(key)
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(key)), nil
}

func (au *authenticator) askRegisterCreds() (registerCredentials, error) {
	var creds registerCredentials
	r := bufio.NewReader(os.Stdin)
	fmt.Print("Login: ")
	login, err := r.ReadString('\n')
	if err != nil {
		return creds, err
	}
	fmt.Print("Password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return creds, err
	}
	fmt.Println()
	fmt.Print("Repeat password: ")
	passwordRep, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return creds, err
	}
	fmt.Println()
	creds.login = strings.TrimSpace(login)
	creds.password = strings.TrimSpace(string(password))
	creds.passwordRep = strings.TrimSpace(string(passwordRep))
	return creds, nil
}

func (au *authenticator) askLoginCreds() (loginCredentials, error) {
	var creds loginCredentials
	r := bufio.NewReader(os.Stdin)
	fmt.Print("Login: ")
	login, err := r.ReadString('\n')
	if err != nil {
		return creds, err
	}
	fmt.Print("Password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return creds, err
	}
	fmt.Println()
	creds.login = strings.TrimSpace(login)
	creds.password = strings.TrimSpace(string(password))
	return creds, nil
}

func (au *authenticator) clearConsole() {
	screen.Clear()
	screen.MoveTopLeft()
}

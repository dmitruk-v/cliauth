package cliauth

import (
	"bufio"
	"fmt"
	"os"
	"strings"

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
	fmt.Println("---------------------------------")
	fmt.Println("Authenticator menu")
	fmt.Println("---------------------------------")
	fmt.Println("1. Login")
	fmt.Println("2. Register")
	fmt.Println("3. Quit")
	for {
		key, err := au.readKey()
		if err != nil {
			return nil, err
		}
		switch string(key) {
		case "1":
			fmt.Println()
			return au.Login()
		case "2":
			fmt.Println()
			return au.Register()
		case "3":
			fmt.Println()
			os.Exit(0)
		}
	}
}

func (au *authenticator) Register() (*User, error) {
	formatError := func(err error) error {
		return fmt.Errorf("[ERROR]: register: %v", err)
	}
	fmt.Println("---------------------------------")
	fmt.Println("New user registration")
	fmt.Println("---------------------------------")
	creds, err := au.askRegisterCreds()
	if err != nil {
		return nil, formatError(err)
	}
	fmt.Println("--- *** ---")
	user, err := au.registerAction(creds)
	if err != nil {
		return nil, formatError(err)
	}
	fmt.Println("Done!")
	fmt.Println("---------------------------------")
	return user, nil
}

func (au *authenticator) Login() (*User, error) {
	formatError := func(err error) error {
		return fmt.Errorf("[ERROR]: login: %v", err)
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
	fmt.Println("Checking passwords...")
	if creds.password != creds.passwordRep {
		return nil, ErrPasswordsNotEqual
	}
	fmt.Println("Generating hash...")
	hash, err := bcrypt.GenerateFromPassword([]byte(creds.password), 12)
	if err != nil {
		return nil, err
	}
	dbuser := &dbUser{
		Login: creds.login,
		Hash:  string(hash),
	}
	fmt.Println("Saving user...")
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

func (au *authenticator) askRegisterCreds() (registerCredentials, error) {
	var creds registerCredentials
	r := bufio.NewReader(os.Stdin)
	fmt.Print("Login: ")
	login, err := r.ReadString('\n')
	if err != nil {
		return creds, err
	}
	fmt.Print("Password: ")
	password, err := term.ReadPassword(0)
	if err != nil {
		return creds, err
	}
	fmt.Println()
	fmt.Print("Repeat password: ")
	passwordRep, err := term.ReadPassword(0)
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
	password, err := term.ReadPassword(0)
	if err != nil {
		return creds, err
	}
	fmt.Println()
	creds.login = strings.TrimSpace(login)
	creds.password = strings.TrimSpace(string(password))
	return creds, nil
}

func (au *authenticator) readKey() (byte, error) {
	// switch stdin into 'raw' mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return 0, err
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	b := make([]byte, 1)
	_, err = os.Stdin.Read(b)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

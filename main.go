package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
	"strconv"
	"strings"

	_ "github.com/lib/pq"
)

type User struct {
	ID           int    `db:"id"`
	Username     string `db:"username"`
	PasswordHash string `db:"password_hash"`
	Role         string `db:"role"`
}

type Candidate struct {
	ID         int      `db:"id"`
	FullName   string   `db:"full_name"`
	Age        int      `db:"age"`
	Email      string   `db:"email"`
	Experience string   `db:"experience"`
	Skills     []string `db:"skills"`
}

type JobOpening struct {
	ID             int      `db:"id"`
	CompanyID      int      `db:"company_id"`
	Title          string   `db:"title"`
	Experience     string   `db:"experience"`
	Salary         float64  `db:"salary"`
	RequiredSkills []string `db:"required_skills"`
}

type Company struct {
	ID   int    `db:"id"`
	Name string `db:"name"`
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func registerUser(db *sql.DB, username, password string) error {
	if username == "" || password == "" {
		return errors.New("имя пользователя и пароль не могут быть пустыми")
	}

	row := db.QueryRow("SELECT 1 FROM users WHERE username = $1", username)
	var exists int
	err := row.Scan(&exists)
	if err == nil && exists == 1 {
		return errors.New("пользователь с таким именем уже существует")
	} else if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("ошибка проверки существования пользователя: %w", err)
	}

	hashedPassword, err := hashPassword(password)
	if err != nil {
		return fmt.Errorf("ошибка хеширования пароля: %w", err)
	}

	stmt, err := db.Prepare("INSERT INTO users (username, password_hash) VALUES ($1, $2)")
	if err != nil {
		return fmt.Errorf("ошибка подготовки запроса: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(username, hashedPassword)
	if err != nil {
		return fmt.Errorf("ошибка регистрации пользователя: %w", err)
	}
	return nil
}

func loginUser(db *sql.DB, username, password string) (int, string, error) {
	stmt, err := db.Prepare("SELECT id, password_hash, role FROM users WHERE username = $1")
	if err != nil {
		return 0, "", fmt.Errorf("Ошибка подготовки запроса: %w", err)
	}
	defer stmt.Close()

	var user User
	err = stmt.QueryRow(username).Scan(&user.ID, &user.PasswordHash, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, "", errors.New("пользователь не найден")
		}
		return 0, "", fmt.Errorf("ошибка авторизации: %w", err)
	}

	if !checkPasswordHash(password, user.PasswordHash) {
		return 0, "", errors.New("неверный пароль")
	}

	return user.ID, user.Role, nil
}

func getInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func getIntInput(prompt string) (int, error) {
	input := getInput(prompt)
	num, err := strconv.Atoi(input)
	if err != nil {
		return 0, fmt.Errorf("неверный ввод целого числа: %w", err)
	}
	return num, nil
}

func getFloatInput(prompt string) (float64, error) {
	input := getInput(prompt)
	num, err := strconv.ParseFloat(input, 64)
	if err != nil {
		return 0, fmt.Errorf("неверный ввод вещественного числа: %w", err)
	}
	return num, nil
}

func getStringArrayInput(prompt string) ([]string, error) {
	input := getInput(prompt)
	if input == "" {
		return []string{}, nil
	}
	skills := strings.Split(input, ",")
	for i, skill := range skills {
		skills[i] = strings.TrimSpace(skill)
	}
	return skills, nil

}

func addCompany(db *sql.DB, companyName string) error {
	if companyName == "" {
		return errors.New("имя компании не может быть пустым")
	}
	stmt, err := db.Prepare("INSERT INTO companies (name) VALUES ($1)")
	if err != nil {
		return fmt.Errorf("ошибка подготовки запроса: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(companyName)
	if err != nil {
		return fmt.Errorf("ошибка добавления компании: %w", err)
	}
	return nil
}

func addCandidate(db *sql.DB, candidate Candidate) error {
	if candidate.FullName == "" || candidate.Age <= 0 {
		return errors.New("не все обязательные поля заполнены для кандидата")
	}

	skillsJSON, err := json.Marshal(candidate.Skills)
	if err != nil {
		return fmt.Errorf("ошибка сериализации навыков: %w", err)
	}

	stmt, err := db.Prepare("INSERT INTO candidates (full_name, age, email, experience, skills) VALUES ($1, $2, $3, $4, $5)")
	if err != nil {
		return fmt.Errorf("ошибка подготовки запроса: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(candidate.FullName, candidate.Age, candidate.Email, candidate.Experience, skillsJSON)
	if err != nil {
		return fmt.Errorf("ошибка добавления кандидата: %w", err)
	}
	return nil
}

func addJobOpening(db *sql.DB, jobOpening JobOpening) error {
	if jobOpening.Title == "" || jobOpening.CompanyID <= 0 || jobOpening.Salary <= 0 {
		return errors.New("не все обязательные поля заполнены для вакансии")
	}

	requiredSkillsJSON, err := json.Marshal(jobOpening.RequiredSkills)
	if err != nil {
		return fmt.Errorf("ошибка сериализации навыков: %w", err)
	}

	stmt, err := db.Prepare("INSERT INTO job_openings (company_id, title, experience, salary, required_skills) VALUES ($1, $2, $3, $4, $5)")
	if err != nil {
		return fmt.Errorf("ошибка подготовки запроса: %w", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(jobOpening.CompanyID, jobOpening.Title, jobOpening.Experience, jobOpening.Salary, requiredSkillsJSON)
	if err != nil {
		return fmt.Errorf("ошибка добавления вакансии: %w", err)
	}
	return nil
}

func findCandidatesBySkill(db *sql.DB, skill string) ([]Candidate, error) {
	var candidates []Candidate
	rows, err := db.Query("SELECT id, full_name, age, email, experience, skills FROM candidates WHERE skills @> $1::jsonb", `["`+skill+`"]`)
	if err != nil {
		return nil, fmt.Errorf("ошибка запроса к базе данных: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var candidate Candidate
		var skillsJSON []byte
		err := rows.Scan(&candidate.ID, &candidate.FullName, &candidate.Age, &candidate.Email, &candidate.Experience, &skillsJSON)
		if err != nil {
			return nil, fmt.Errorf("ошибка сканирования строки: %w", err)
		}
		json.Unmarshal(skillsJSON, &candidate.Skills)
		candidates = append(candidates, candidate)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка чтения строк: %w", err)
	}

	return candidates, nil
}
func listAllJobOpenings(db *sql.DB) error {
	rows, err := db.Query("SELECT id, company_id, title, experience, salary, required_skills FROM job_openings")
	if err != nil {
		return fmt.Errorf("ошибка запроса к базе данных: %w", err)
	}
	defer rows.Close()

	fmt.Println("Все вакансии:")
	for rows.Next() {
		var jobOpening JobOpening
		var requiredSkillsJSON []byte
		err := rows.Scan(&jobOpening.ID, &jobOpening.CompanyID, &jobOpening.Title, &jobOpening.Experience, &jobOpening.Salary, &requiredSkillsJSON)
		if err != nil {
			return fmt.Errorf("ошибка сканирования строки: %w", err)
		}
		json.Unmarshal(requiredSkillsJSON, &jobOpening.RequiredSkills)
		fmt.Printf("ID: %d\nКомпания ID: %d\nНазвание: %s\nОпыт: %s\nЗарплата: %.2f\nТребуемые навыки: %v\n\n",
			jobOpening.ID, jobOpening.CompanyID, jobOpening.Title, jobOpening.Experience, jobOpening.Salary, jobOpening.RequiredSkills)
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("ошибка чтения строк: %w", err)
	}

	return nil
}

func findJobOpeningsBySkill(db *sql.DB, skill string) ([]JobOpening, error) {
	var jobOpenings []JobOpening
	rows, err := db.Query("SELECT id, company_id, title, experience, salary, required_skills FROM job_openings WHERE required_skills @> $1::jsonb", `["`+skill+`"]`)
	if err != nil {
		return nil, fmt.Errorf("ошибка запроса к базе данных: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var jobOpening JobOpening
		var requiredSkillsJSON []byte
		err := rows.Scan(&jobOpening.ID, &jobOpening.CompanyID, &jobOpening.Title, &jobOpening.Experience, &jobOpening.Salary, &requiredSkillsJSON)
		if err != nil {
			return nil, fmt.Errorf("ошибка сканирования строки: %w", err)
		}
		json.Unmarshal(requiredSkillsJSON, &jobOpening.RequiredSkills)
		jobOpenings = append(jobOpenings, jobOpening)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ошибка чтения строк: %w", err)
	}

	return jobOpenings, nil
}

func createTables(db *sql.DB) error {
	_, err := db.Exec(`
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user'
    );

    CREATE TABLE IF NOT EXISTS companies (
        id SERIAL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL
    );

    CREATE TABLE IF NOT EXISTS candidates (
        id SERIAL PRIMARY KEY,
        full_name TEXT NOT NULL,
        age INTEGER NOT NULL,
        email TEXT NOT NULL,
        experience TEXT,
        skills JSONB
    );

    CREATE TABLE IF NOT EXISTS job_openings (
        id SERIAL PRIMARY KEY,
        company_id INTEGER REFERENCES companies(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        experience TEXT,
        salary NUMERIC(10,2) NOT NULL,
        required_skills JSONB
    );
`)
	if err != nil {
		return fmt.Errorf("ошибка создания таблиц: %w", err)
	}
	return nil
}

func handleError(err error) {
	if err != nil {
		fmt.Println("Произошла ошибка:", err)
	}
}
func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("env не найдено")
	}
	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}
	defer db.Close()

	err = createTables(db)
	handleError(err)
	if err != nil {
		return
	}

	for {
		fmt.Println("\nВыберите действие:")
		fmt.Println("1. Зарегистрироваться")
		fmt.Println("2. Авторизоваться")
		fmt.Println("3. Добавить компанию")
		fmt.Println("4. Добавить кандидата")
		fmt.Println("5. Добавить вакансию")
		fmt.Println("6. Найти кандидатов по навыку")
		fmt.Println("7. Найти вакансии по навыку")
		fmt.Println("8. Показать все вакансии")
		fmt.Println("9. Выйти")

		choice, err := getIntInput("Введите номер действия: ")
		handleError(err)
		if err != nil {
			continue
		}

		switch choice {
		case 1:
			username := getInput("Введите имя пользователя: ")
			password := getInput("Введите пароль: ")
			err := registerUser(db, username, password)
			handleError(err)
			if err == nil {
				fmt.Println("Регистрация успешна!")
			}
		case 2:
			username := getInput("Введите имя пользователя: ")
			password := getInput("Введите пароль: ")
			userID, role, err := loginUser(db, username, password)
			handleError(err)
			if err == nil {
				fmt.Printf("Авторизация успешна! ID пользователя: %d, Роль: %s\n", userID, role)
			}
		case 3:
			companyName := getInput("Введите название компании: ")
			err := addCompany(db, companyName)
			handleError(err)
			if err == nil {
				fmt.Println("Компания успешно добавлена!")
			}
		case 4:
			candidate := Candidate{}
			candidate.FullName = getInput("Введите ФИО кандидата: ")
			candidate.Age, err = getIntInput("Введите возраст кандидата: ")
			handleError(err)
			if err != nil {
				continue
			}
			candidate.Email = getInput("Введите email кандидата: ")
			candidate.Experience = getInput("Введите опыт работы кандидата: ")
			candidate.Skills, err = getStringArrayInput("Введите навыки кандидата (через запятую): ")
			handleError(err)
			if err != nil {
				continue
			}
			err = addCandidate(db, candidate)
			handleError(err)
			if err == nil {
				fmt.Println("Кандидат успешно добавлен!")
			}
		case 5:
			jobOpening := JobOpening{}
			jobOpening.Title = getInput("Введите название вакансии: ")
			jobOpening.CompanyID, err = getIntInput("Введите ID компании: ")
			handleError(err)
			if err != nil {
				continue
			}
			jobOpening.Experience = getInput("Введите требуемый опыт работы: ")
			jobOpening.Salary, err = getFloatInput("Введите зарплату: ")
			handleError(err)
			if err != nil {
				continue
			}
			jobOpening.RequiredSkills, err = getStringArrayInput("Введите требуемые навыки (через запятую): ")
			handleError(err)
			if err != nil {
				continue
			}
			err = addJobOpening(db, jobOpening)
			handleError(err)
			if err == nil {
				fmt.Println("Вакансия успешно добавлена!")
			}
		case 6:
			skill := getInput("Введите навык для поиска кандидатов: ")
			candidates, err := findCandidatesBySkill(db, skill)
			handleError(err)
			if err == nil {
				fmt.Println("Найденные кандидаты:")
				for _, c := range candidates {
					fmt.Printf("ID: %d, ФИО: %s, Навыки: %v\n", c.ID, c.FullName, c.Skills)
				}
			}
		case 7:
			skill := getInput("Введите навык для поиска вакансий: ")
			jobOpenings, err := findJobOpeningsBySkill(db, skill)
			handleError(err)
			if err == nil {
				fmt.Println("Найденные вакансии:")
				for _, j := range jobOpenings {
					fmt.Printf("ID: %d, Название: %s, Требуемые навыки: %v\n", j.ID, j.Title, j.RequiredSkills)
				}
			}
		case 8:
			err := listAllJobOpenings(db)
			handleError(err)
			if err != nil {
				fmt.Println("Ошибка при выводе вакансий:", err)
			}
		case 9:
			fmt.Println("Выход из программы.")
			return
		default:
			fmt.Println("Неверный выбор действия. Попробуйте снова.")
		}
	}
}

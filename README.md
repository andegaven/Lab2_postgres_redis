## Лабораторная работа: FastAPI с PostgreSQL и Redis

### Описание проекта

Этот проект демонстрирует реализацию REST API с использованием FastAPI с двумя разными backend-хранилищами:
- Версия с PostgreSQL (реляционная СУБД)
- Версия с Redis (хранилище ключ-значение)

Обе версии предоставляют одинаковый функционал:
- Регистрация пользователей
- Аутентификация (JWT токены)
- Получение списка пользователей

### Структура проекта

```
lab2/
├── lab2_postgres.py # Реализация с PostgreSQL
├── ostapenko_users.py # Реализация с Redis
├── requirements.txt # Зависимости
├── README.md # Инструкция (этот файл)
└── answer.md # Ответы на вопросы
```
### Технологии

- Python 3.10+
- FastAPI
- PostgreSQL (через SQLAlchemy)
- Redis (через redis-py)
- JWT для аутентификации
- Pydantic для валидации данных

### Установка и запуск

1. Клонируйте репозиторий:
```bash
git clone <ваш-репозиторий>
cd lab2
```
2. Установите зависимости:

```bash
pip install -r requirements.txt
```
3. Настройте подключения к БД (при необходимости измените параметры в файлах):
Для PostgreSQL: lab2_postgres.py 
Для Redis: lab2_redis.py

4. Запустите нужную версию:
PostgreSQL версия:
```bash
uvicorn lab2_postgres:app --reload
```
Redis версия:
```bash
uvicorn lab2_redis:app --reload
```

# TOTPly Backend

REST API сервер для управления TOTP-токенами (Time-based One-Time Password).

**Автор:** Matvei Khavankin

**Деплой:** https://totply-backend.onrender.com/

## Доменная область

Приложение позволяет пользователям безопасно хранить и генерировать TOTP-коды для двухфакторной аутентификации. Секреты шифруются с использованием AES-256-GCM и envelope encryption.

## Сущности

- **User** — пользователь системы, хранит учётные данные и статус верификации email
- **Session** — активная сессия пользователя, привязана к JWT-токену
- **TotpEntry** — запись TOTP-токена с зашифрованным секретом, параметрами алгоритма (SHA1/SHA256/SHA512, digits, period)

## ER-диаграмма

![ER-диаграмма](erd.svg)

## Стек

NestJS, Prisma, PostgreSQL, JWT, bcrypt, otplib

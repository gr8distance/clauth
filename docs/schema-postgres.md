# clauth schema — PostgreSQL

Back to [schema overview](./schema.md).

This page contains the PostgreSQL DDL clauth expects, and shows how
to apply it with [`dbmate`](https://github.com/amacneil/dbmate),
[`golang-migrate`](https://github.com/golang-migrate/migrate), and
[`goose`](https://github.com/pressly/goose).

---

## DDL

The minimum clauth needs — copy verbatim, or use as the body of a
migration:

```sql
-- users
CREATE TABLE users (
  id                  BIGSERIAL PRIMARY KEY,
  email               VARCHAR(254) NOT NULL,
  password_hash       VARCHAR(255) NOT NULL,
  confirmed_at        TIMESTAMP,
  failed_login_count  INTEGER,                  -- optional: only if you use authenticate-with-lockout
  locked_until        TIMESTAMP,                -- optional: same as above
  role                VARCHAR(40),              -- optional: only if you use require-role
  inserted_at         TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
  updated_at          TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);

CREATE UNIQUE INDEX users_email_idx ON users (lower(email));

-- auth_tokens
CREATE TABLE auth_tokens (
  id                BIGSERIAL PRIMARY KEY,
  user_id           BIGINT       NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash        VARCHAR(64)  NOT NULL,
  context           VARCHAR(40)  NOT NULL,
  authenticated_at  TIMESTAMP    NOT NULL,
  expires_at        TIMESTAMP,
  inserted_at       TIMESTAMP    NOT NULL DEFAULT (now() AT TIME ZONE 'utc'),
  updated_at        TIMESTAMP    NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
);

CREATE UNIQUE INDEX auth_tokens_token_hash_idx     ON auth_tokens (token_hash);
CREATE        INDEX auth_tokens_user_id_idx        ON auth_tokens (user_id);
CREATE        INDEX auth_tokens_user_id_context_idx ON auth_tokens (user_id, context);
```

### Notes specific to PostgreSQL

- `BIGSERIAL` is used so `id` columns are 64-bit. If you prefer the
  newer `GENERATED ALWAYS AS IDENTITY` syntax (Postgres 10+), the
  switch is mechanical and clauth doesn't care which one you pick.
- The unique index on `users` is `lower(email)` — this makes the
  uniqueness case-insensitive even though clauth already lowercases
  email at cast time. Belt-and-braces.
- `:naive-datetime` clecto values are stored as plain `TIMESTAMP`
  (without time zone). UTC is enforced at the application layer by
  `clecto:now-utc-datetime`.
- `ON DELETE CASCADE` on `auth_tokens.user_id` is always honored —
  no per-connection toggle needed (unlike SQLite).

---

## Applying with a migration tool

### dbmate

```sh
# install
brew install dbmate            # or: go install github.com/amacneil/dbmate@latest

# create migration file
dbmate -d db/migrations new create_clauth_tables
# → db/migrations/20260524123045_create_clauth_tables.sql

# paste the DDL above between -- migrate:up and -- migrate:down

# apply
dbmate -e "postgres://user:pass@localhost/myapp?sslmode=disable" up
```

### golang-migrate

```sh
# install
brew install golang-migrate    # or: go install github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# create migration files (creates both up + down)
migrate create -ext sql -dir db/migrations -seq create_clauth_tables
# → 000001_create_clauth_tables.up.sql
# → 000001_create_clauth_tables.down.sql

# paste the DDL above into the .up.sql
# write reverse DDL (DROP TABLE …) into the .down.sql

# apply
migrate -path db/migrations -database "postgres://user:pass@localhost/myapp?sslmode=disable" up
```

### goose

```sh
# install
go install github.com/pressly/goose/v3/cmd/goose@latest

# create migration file
goose -dir db/migrations create create_clauth_tables sql
# → 20260524123045_create_clauth_tables.sql

# paste the DDL above between -- +goose Up and -- +goose Down

# apply
goose -dir db/migrations postgres "postgres://user:pass@localhost/myapp?sslmode=disable" up
```

---

## Without a tool

The DDL above is plain SQL — pipe it into `psql` if you don't need
a migration runner:

```sh
psql -d myapp -f schema.sql
```

For production, you probably want a real migration tool — schema
changes ordered, versioned, and reversible. The three tools above
each cost ~5 minutes to set up.

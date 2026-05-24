# clauth schema — SQLite

Back to [schema overview](./schema.md).

This page contains the SQLite DDL clauth expects, and shows how to
apply it with [`dbmate`](https://github.com/amacneil/dbmate),
[`golang-migrate`](https://github.com/golang-migrate/migrate), and
[`goose`](https://github.com/pressly/goose).

---

## DDL

The minimum clauth needs — copy verbatim, or use as the body of a
migration:

```sql
-- users
CREATE TABLE users (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  email               TEXT    NOT NULL,
  password_hash       TEXT    NOT NULL,
  confirmed_at        TEXT,
  failed_login_count  INTEGER,        -- optional: only if you use authenticate-with-lockout
  locked_until        TEXT,           -- optional: same as above
  role                TEXT,           -- optional: only if you use require-role
  inserted_at         TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at          TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX users_email_idx ON users(email);

-- auth_tokens
CREATE TABLE auth_tokens (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash        TEXT    NOT NULL,
  context           TEXT    NOT NULL,
  authenticated_at  TEXT    NOT NULL,
  expires_at        TEXT,
  inserted_at       TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX auth_tokens_token_hash_idx ON auth_tokens(token_hash);
CREATE INDEX auth_tokens_user_id_idx           ON auth_tokens(user_id);
CREATE INDEX auth_tokens_user_id_context_idx   ON auth_tokens(user_id, context);
```

### Notes specific to SQLite

- `INTEGER PRIMARY KEY AUTOINCREMENT` is the canonical SQLite rowid
  pattern. clauth's helpers don't care what `id`'s actual type is —
  they just round-trip it.
- Timestamps are stored as ISO-8601 `TEXT` (the `:naive-datetime` clecto
  type writes/reads strings like `"2026-05-24 10:30:00"`).
- SQLite's `ALTER TABLE` is restricted. Dropping a column requires
  SQLite 3.35+ (`ALTER TABLE ... DROP COLUMN`). For older versions,
  the rename-and-rebuild dance is the official escape hatch.
- The `ON DELETE CASCADE` on `auth_tokens.user_id` only fires when
  foreign keys are enabled at runtime: `PRAGMA foreign_keys = ON;`.
  Add this to your connection setup if you depend on it.

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
dbmate -e "sqlite:./app.db" up
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
migrate -path db/migrations -database "sqlite3://./app.db" up
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
goose -dir db/migrations sqlite3 ./app.db up
```

---

## Without a tool

The DDL above is plain SQL — pipe it into the SQLite shell if you
don't need a migration runner:

```sh
sqlite3 app.db < schema.sql
```

This is what `onogoro` does for its REPL demo: the bootstrap is a
one-off `CREATE TABLE` pass, no migration history needed.

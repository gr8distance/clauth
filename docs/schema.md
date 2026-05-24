# clauth schema

clauth expects two tables in your database: **`users`** and
**`auth_tokens`**. It does not ship a migration runner — the DDL is
documented here, and you apply it with whichever migration tool you
already use.

The DDL differs slightly between databases. Pick your dialect:

- [SQLite](./schema-sqlite.md)
- [PostgreSQL](./schema-postgres.md)

---

## Common invariants (both dialects)

Whichever DDL you write, these have to hold:

| Constraint | Why |
| ---------- | --- |
| `users.email` UNIQUE                | `register-changeset` relies on this for `unique_constraint` to fire. Without it duplicate accounts slip through. |
| `auth_tokens.token_hash` UNIQUE     | `find-and-validate-token` hits this index on every authenticated request. Without it both performance and the "no duplicate token" invariant collapse. |
| `auth_tokens.user_id` references `users.id` | Recommended foreign key. Not strictly required by clauth, but useful for cleanup-on-delete. |
| `auth_tokens.context` indexed       | Optional but recommended — token lookup combines hash-equality (uses unique index) with context match. |

## Optional columns

These columns are only needed if you use the corresponding feature.
Omit them otherwise.

| Column on `users`        | Feature | Touched by |
| ------------------------ | ------- | ---------- |
| `role` (text)            | Role-based authorization | `require-role` |
| `failed_login_count` (integer) | Account lockout | `authenticate-with-lockout` |
| `locked_until` (timestamp)     | Account lockout | `authenticate-with-lockout` |

## Defining the clecto schemas in your app

The migration creates the physical table. You still need to declare a
clecto schema so clauth's helpers know which columns to read and write.
Define this in **your app**, not in clauth — the schema name is yours
and you may want extra columns alongside the required ones.

`clauth` ships two helpers that return the canonical field lists, so
you don't have to hand-write them:

```lisp
(clecto:defschema user "users"
  (:id :integer :primary-key t)
  ,@(clauth:auth-fields)
  (:role :string)                          ; optional extension
  (:timestamps))

(clecto:defschema auth-token "auth_tokens"
  (:id :integer :primary-key t)
  ,@(clauth:auth-token-fields)
  (:timestamps))
```

If you'd rather see the field list verbatim instead of splicing, see
the "Schema fields" section of the main README — `auth-fields`
returns exactly what's documented there.

**Keep the migration and the defschema in sync.** Adding a column on
one side without the other is the most common foot-gun. The
recommended practice:

1. Write the migration first (`<timestamp>_add_two_factor_columns.up.sql`)
2. Apply it
3. Update the defschema to declare the new columns
4. Use them in your handlers

---

## Migrations

clauth doesn't ship a migration runner. The dialect pages
([SQLite](./schema-sqlite.md), [PostgreSQL](./schema-postgres.md))
show how to apply the DDL with three common Go-based migration tools:

- **[dbmate](https://github.com/amacneil/dbmate)** — single binary, plain SQL files, Docker-friendly
- **[golang-migrate](https://github.com/golang-migrate/migrate)** — the most popular option, supports many backends
- **[goose](https://github.com/pressly/goose)** — plain SQL or annotated SQL, lightweight

Pick whichever you already have in your stack. The SQL itself is
identical regardless of tool; only the runner command and the
filename convention differ.

If you already have your own migration tooling (sqitch, Flyway,
Liquibase, a shell script, …), the dialect pages also include the raw
SQL you can drop into your existing pipeline.

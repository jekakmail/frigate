"""Peewee migrations -- 031_add_two_factor_auth.py.

This migration adds the necessary fields to the User model to support two-factor authentication:
- two_factor_enabled: Boolean field to indicate if 2FA is enabled for the user
- two_factor_secret: Char field to store the TOTP secret
- recovery_codes: JSON field to store recovery codes
- used_totp_codes: JSON field to store used TOTP codes (to prevent replay attacks)
- device_tokens: JSON field to store device tokens for trusted devices

Some examples (model - class or model name):::

    > Model = migrator.orm['model_name']            # Return model in the current state by name

    > migrator.sql(sql)                             # Run custom SQL
    > migrator.python(func, *args, **kwargs)        # Run python code
    > migrator.create_model(Model)                  # Create a model (could be used as decorator)
    > migrator.remove_model(model, cascade=True)    # Remove a model
    > migrator.add_fields(model, **fields)          # Add fields to a model
    > migrator.change_fields(model, **fields)       # Change fields
    > migrator.remove_fields(model, *field_names, cascade=True)
    > migrator.rename_field(model, old_field_name, new_field_name)
    > migrator.rename_table(model, new_table_name)
    > migrator.add_index(model, *col_names, unique=False)
    > migrator.drop_index(model, *col_names)
    > migrator.add_not_null(model, *field_names)
    > migrator.drop_not_null(model, *field_names)
    > migrator.add_default(model, field_name, default)

"""

import peewee as pw

SQL = pw.SQL


def migrate(migrator, database, fake=False, **kwargs):
    # Add two_factor_enabled column (boolean, default false)
    migrator.sql(
        'ALTER TABLE "user" ADD COLUMN "two_factor_enabled" BOOLEAN NOT NULL DEFAULT 0'
    )

    # Add two_factor_secret column (varchar, nullable)
    migrator.sql(
        'ALTER TABLE "user" ADD COLUMN "two_factor_secret" VARCHAR(64) NULL'
    )

    # Add recovery_codes column (json, nullable)
    migrator.sql(
        'ALTER TABLE "user" ADD COLUMN "recovery_codes" JSON NULL'
    )

    # Add the used_totp_codes column (json, nullable)
    migrator.sql(
        'ALTER TABLE "user" ADD COLUMN "used_totp_codes" JSON NULL'
    )

    # Add device_tokens column (json, nullable)
    migrator.sql(
        'ALTER TABLE "user" ADD COLUMN "device_tokens" JSON NULL'
    )


def rollback(migrator, database, fake=False, **kwargs):
    # Remove the columns in reverse order
    migrator.sql('ALTER TABLE "user" DROP COLUMN "device_tokens"')
    migrator.sql('ALTER TABLE "user" DROP COLUMN "used_totp_codes"')
    migrator.sql('ALTER TABLE "user" DROP COLUMN "recovery_codes"')
    migrator.sql('ALTER TABLE "user" DROP COLUMN "two_factor_secret"')
    migrator.sql('ALTER TABLE "user" DROP COLUMN "two_factor_enabled"')


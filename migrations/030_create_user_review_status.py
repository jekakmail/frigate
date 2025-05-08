"""Peewee migrations -- 030_create_user_review_status.py.

This migration creates the UserReviewStatus table to track per-user review states,
migrates existing has_been_reviewed data from ReviewSegment to all users in the user table,
and drops the has_been_reviewed column. Rollback drops UserReviewStatus and restores the column.

Some examples (model - class or model_name)::

    > Model = migrator.orm['model_name']            # Return model in current state by name
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

from frigate.models import UserReviewStatus

SQL = pw.SQL


def migrate(migrator, database, fake=False, **kwargs):
    # Set the database for UserReviewStatus
    UserReviewStatus._meta.database = database

    migrator.sql(
        """
        CREATE TABLE IF NOT EXISTS "userreviewstatus" (
            "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
            "user_id" VARCHAR(30) NOT NULL,
            "review_segment_id" VARCHAR(30) NOT NULL,
            "has_been_reviewed" INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY ("review_segment_id") REFERENCES "reviewsegment" ("id") ON DELETE CASCADE
        )
        """
    )

    # Add unique index on (user_id, review_segment_id)
    migrator.sql(
        'CREATE UNIQUE INDEX IF NOT EXISTS "userreviewstatus_user_segment" ON "userreviewstatus" ("user_id", "review_segment_id")'
    )

    # Migrate existing has_been_reviewed data to UserReviewStatus for all users
    def migrate_data():
        try:
            # Get usernames directly with SQL to avoid loading the User model which might have fields not yet in DB
            cursor = database.execute_sql('SELECT "username" FROM "user"')
            usernames = [row[0] for row in cursor.fetchall()] + ["anonymous"]
            if not usernames:
                return

            cursor = database.execute_sql(
                'SELECT "id" FROM "reviewsegment" WHERE "has_been_reviewed" = 1'
            )
            reviewed_segment_ids = [row[0] for row in cursor.fetchall()]

            # Use direct SQL to insert records instead of using the model
            for segment_id in reviewed_segment_ids:
                for username in usernames:
                    database.execute_sql(
                        'INSERT INTO "userreviewstatus" ("user_id", "review_segment_id", "has_been_reviewed") VALUES (?, ?, ?)',
                        (username, segment_id, 1)
                    )
        except Exception as e:
            # Log the error but continue with migration
            print(f"Error during data migration: {e}")
            # If we can't migrate the data, we'll just continue without it

    if not fake:  # Only run data migration if not faking
        migrator.python(migrate_data)

    migrator.sql('ALTER TABLE "reviewsegment" DROP COLUMN "has_been_reviewed"')


def rollback(migrator, database, fake=False, **kwargs):
    migrator.sql('DROP TABLE IF EXISTS "userreviewstatus"')
    # Restore has_been_reviewed column to reviewsegment (no data restoration)
    migrator.sql(
        'ALTER TABLE "reviewsegment" ADD COLUMN "has_been_reviewed" INTEGER NOT NULL DEFAULT 0'
    )

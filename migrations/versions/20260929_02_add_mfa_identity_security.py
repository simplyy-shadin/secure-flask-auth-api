"""add MFA identity-security schema

Revision ID: 20260929_02
Revises: 20260929_01
Create Date: 2026-09-29
"""

from alembic import op
import sqlalchemy as sa


revision = "20260929_02"
down_revision = "20260929_01"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column(
                "mfa_enabled",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch_op.add_column(
            sa.Column("mfa_secret_encrypted", sa.Text(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("mfa_last_used_step", sa.BigInteger(), nullable=True)
        )
        batch_op.alter_column("mfa_enabled", server_default=None)

    with op.batch_alter_table("auth_sessions") as batch_op:
        batch_op.add_column(
            sa.Column(
                "mfa_authenticated",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch_op.alter_column("mfa_authenticated", server_default=None)

    op.create_table(
        "mfa_recovery_codes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("code_hash", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_mfa_recovery_codes_user_id",
        "mfa_recovery_codes",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_mfa_recovery_codes_used_at",
        "mfa_recovery_codes",
        ["used_at"],
        unique=False,
    )

    op.create_table(
        "mfa_challenges",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_mfa_challenges_user_id",
        "mfa_challenges",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_mfa_challenges_expires_at",
        "mfa_challenges",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_mfa_challenges_consumed_at",
        "mfa_challenges",
        ["consumed_at"],
        unique=False,
    )


def downgrade():
    op.drop_index("ix_mfa_challenges_consumed_at", table_name="mfa_challenges")
    op.drop_index("ix_mfa_challenges_expires_at", table_name="mfa_challenges")
    op.drop_index("ix_mfa_challenges_user_id", table_name="mfa_challenges")
    op.drop_table("mfa_challenges")

    op.drop_index("ix_mfa_recovery_codes_used_at", table_name="mfa_recovery_codes")
    op.drop_index("ix_mfa_recovery_codes_user_id", table_name="mfa_recovery_codes")
    op.drop_table("mfa_recovery_codes")

    with op.batch_alter_table("auth_sessions") as batch_op:
        batch_op.drop_column("mfa_authenticated")

    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_column("mfa_last_used_step")
        batch_op.drop_column("mfa_secret_encrypted")
        batch_op.drop_column("mfa_enabled")

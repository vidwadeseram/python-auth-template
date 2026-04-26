"""add extended auth and rbac schema

Revision ID: 202604260900
Revises: 202604260850
Create Date: 2026-04-26 09:00:00.000000
"""

import uuid
from collections.abc import Sequence
from datetime import datetime

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "202604260900"
down_revision: str | None = "202604260850"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


permission_table = sa.table(
    "permissions",
    sa.column("id", postgresql.UUID(as_uuid=True)),
    sa.column("name", sa.String(length=100)),
    sa.column("description", sa.String(length=255)),
    sa.column("created_at", sa.DateTime(timezone=True)),
)


role_permission_table = sa.table(
    "role_permissions",
    sa.column("role_id", postgresql.UUID(as_uuid=True)),
    sa.column("permission_id", postgresql.UUID(as_uuid=True)),
)


def upgrade() -> None:
    op.add_column("users", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "password_reset_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index(op.f("ix_password_reset_tokens_token_hash"), "password_reset_tokens", ["token_hash"], unique=False)

    op.create_table(
        "email_verification_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False, server_default=sa.text("gen_random_uuid()")),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index(op.f("ix_email_verification_tokens_token_hash"), "email_verification_tokens", ["token_hash"], unique=False)

    op.create_table(
        "permissions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index(op.f("ix_permissions_name"), "permissions", ["name"], unique=True)

    op.create_table(
        "role_permissions",
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("permission_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(["permission_id"], ["permissions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("role_id", "permission_id"),
    )

    op.create_table(
        "user_roles",
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "role_id"),
    )

    created_at = datetime.utcnow()
    permissions = [
        (uuid.UUID("44444444-4444-4444-4444-444444444441"), "users:read", "Read users"),
        (uuid.UUID("44444444-4444-4444-4444-444444444442"), "users:write", "Create or update users"),
        (uuid.UUID("44444444-4444-4444-4444-444444444443"), "users:delete", "Delete users"),
        (uuid.UUID("44444444-4444-4444-4444-444444444444"), "roles:read", "Read roles"),
        (uuid.UUID("44444444-4444-4444-4444-444444444445"), "roles:write", "Create or update roles"),
        (uuid.UUID("44444444-4444-4444-4444-444444444446"), "roles:delete", "Delete roles"),
        (uuid.UUID("44444444-4444-4444-4444-444444444447"), "permissions:read", "Read permissions"),
        (uuid.UUID("44444444-4444-4444-4444-444444444448"), "permissions:write", "Create permissions"),
    ]
    op.bulk_insert(
        permission_table,
        [{"id": permission_id, "name": name, "description": description, "created_at": created_at} for permission_id, name, description in permissions],
    )

    super_admin_role_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    admin_role_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
    role_permission_rows = [{"role_id": super_admin_role_id, "permission_id": permission_id} for permission_id, _, _ in permissions]
    role_permission_rows.extend([
        {"role_id": admin_role_id, "permission_id": uuid.UUID("44444444-4444-4444-4444-444444444441")},
        {"role_id": admin_role_id, "permission_id": uuid.UUID("44444444-4444-4444-4444-444444444442")},
        {"role_id": admin_role_id, "permission_id": uuid.UUID("44444444-4444-4444-4444-444444444444")},
        {"role_id": admin_role_id, "permission_id": uuid.UUID("44444444-4444-4444-4444-444444444445")},
        {"role_id": admin_role_id, "permission_id": uuid.UUID("44444444-4444-4444-4444-444444444447")},
        {"role_id": admin_role_id, "permission_id": uuid.UUID("44444444-4444-4444-4444-444444444448")},
    ])
    op.bulk_insert(role_permission_table, role_permission_rows)


def downgrade() -> None:
    op.drop_table("user_roles")
    op.drop_table("role_permissions")
    op.drop_index(op.f("ix_permissions_name"), table_name="permissions")
    op.drop_table("permissions")
    op.drop_index(op.f("ix_email_verification_tokens_token_hash"), table_name="email_verification_tokens")
    op.drop_table("email_verification_tokens")
    op.drop_index(op.f("ix_password_reset_tokens_token_hash"), table_name="password_reset_tokens")
    op.drop_table("password_reset_tokens")
    op.drop_column("users", "deleted_at")

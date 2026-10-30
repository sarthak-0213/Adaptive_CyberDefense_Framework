"""Add gateway request logs

Revision ID: b7e2311f4d9a
Revises: a4f0333d24e6
Create Date: 2026-10-30 11:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b7e2311f4d9a'
down_revision: Union[str, None] = 'a4f0333d24e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'gateway_request_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ip_address', sa.String(), nullable=False),
        sa.Column('method', sa.String(length=10), nullable=False),
        sa.Column('endpoint', sa.String(), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=False),
        sa.Column('response_time_ms', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('classification', sa.String(length=32), nullable=False, server_default='legitimate'),
        sa.Column('detection_result', sa.String(length=64), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True, server_default='0.0'),
        sa.Column('mitigation_action', sa.String(length=64), nullable=True, server_default='none'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_gateway_request_logs_id'), 'gateway_request_logs', ['id'], unique=False)
    op.create_index(op.f('ix_gateway_request_logs_timestamp'), 'gateway_request_logs', ['timestamp'], unique=False)
    op.create_index(op.f('ix_gateway_request_logs_ip_address'), 'gateway_request_logs', ['ip_address'], unique=False)
    op.create_index(op.f('ix_gateway_request_logs_endpoint'), 'gateway_request_logs', ['endpoint'], unique=False)
    op.create_index(op.f('ix_gateway_request_logs_status_code'), 'gateway_request_logs', ['status_code'], unique=False)
    op.create_index(op.f('ix_gateway_request_logs_classification'), 'gateway_request_logs', ['classification'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_gateway_request_logs_classification'), table_name='gateway_request_logs')
    op.drop_index(op.f('ix_gateway_request_logs_status_code'), table_name='gateway_request_logs')
    op.drop_index(op.f('ix_gateway_request_logs_endpoint'), table_name='gateway_request_logs')
    op.drop_index(op.f('ix_gateway_request_logs_ip_address'), table_name='gateway_request_logs')
    op.drop_index(op.f('ix_gateway_request_logs_timestamp'), table_name='gateway_request_logs')
    op.drop_index(op.f('ix_gateway_request_logs_id'), table_name='gateway_request_logs')
    op.drop_table('gateway_request_logs')

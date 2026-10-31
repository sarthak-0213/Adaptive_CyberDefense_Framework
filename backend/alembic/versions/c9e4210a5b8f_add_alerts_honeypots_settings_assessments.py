"""Add alerts, honeypots, settings, and assessments tables

Revision ID: c9e4210a5b8f
Revises: b7e2311f4d9a
Create Date: 2026-10-31 19:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c9e4210a5b8f'
down_revision: Union[str, None] = 'b7e2311f4d9a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = inspector.get_table_names()

    # 1. alerts
    if 'alerts' not in existing_tables:
        op.create_table(
            'alerts',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('title', sa.String(), nullable=False),
            sa.Column('violation_type', sa.String(), nullable=False),
            sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
            sa.Column('severity', sa.String(), nullable=False, server_default='medium'),
            sa.Column('status', sa.String(), nullable=False, server_default='active'),
            sa.Column('description', sa.String(), nullable=True),
            sa.Column('evidence_path', sa.String(), nullable=True),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_alerts_id'), 'alerts', ['id'], unique=False)

    # 2. honeypot_logs
    if 'honeypot_logs' not in existing_tables:
        op.create_table(
            'honeypot_logs',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('decoy_path_triggered', sa.String(), nullable=False),
            sa.Column('ip_address', sa.String(), nullable=False),
            sa.Column('user_agent', sa.String(), nullable=True),
            sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
            sa.Column('headers_logged', sa.JSON(), nullable=True),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_honeypot_logs_id'), 'honeypot_logs', ['id'], unique=False)
        op.create_index(op.f('ix_honeypot_logs_ip_address'), 'honeypot_logs', ['ip_address'], unique=False)

    # 3. system_settings
    if 'system_settings' not in existing_tables:
        op.create_table(
            'system_settings',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('category', sa.String(), nullable=False),
            sa.Column('key', sa.String(), nullable=False),
            sa.Column('value', sa.Text(), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_by', sa.String(), nullable=True),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_system_settings_id'), 'system_settings', ['id'], unique=False)
        op.create_index(op.f('ix_system_settings_category'), 'system_settings', ['category'], unique=False)
        op.create_index(op.f('ix_system_settings_key'), 'system_settings', ['key'], unique=True)

    # 4. security_assessments
    if 'security_assessments' not in existing_tables:
        op.create_table(
            'security_assessments',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('target', sa.String(), nullable=False),
            sa.Column('user_id', sa.Integer(), nullable=True),
            sa.Column('status', sa.String(), nullable=False, server_default='completed'),
            sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('summary_json', sa.Text(), nullable=True),
            sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_security_assessments_id'), 'security_assessments', ['id'], unique=False)
        op.create_index(op.f('ix_security_assessments_target'), 'security_assessments', ['target'], unique=False)

    # 5. assessment_results
    if 'assessment_results' not in existing_tables:
        op.create_table(
            'assessment_results',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('assessment_id', sa.Integer(), nullable=False),
            sa.Column('section', sa.String(), nullable=False),
            sa.Column('status', sa.String(), nullable=False, server_default='PASS'),
            sa.Column('details_json', sa.Text(), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(['assessment_id'], ['security_assessments.id'], ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_assessment_results_id'), 'assessment_results', ['id'], unique=False)
        op.create_index(op.f('ix_assessment_results_assessment_id'), 'assessment_results', ['assessment_id'], unique=False)
        op.create_index(op.f('ix_assessment_results_section'), 'assessment_results', ['section'], unique=False)

    # 6. security_findings
    if 'security_findings' not in existing_tables:
        op.create_table(
            'security_findings',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('assessment_id', sa.Integer(), nullable=False),
            sa.Column('section', sa.String(), nullable=False),
            sa.Column('title', sa.String(), nullable=False),
            sa.Column('severity', sa.String(), nullable=False, server_default='LOW'),
            sa.Column('status', sa.String(), nullable=False, server_default='WARNING'),
            sa.Column('finding', sa.Text(), nullable=False),
            sa.Column('recommendation', sa.Text(), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(['assessment_id'], ['security_assessments.id'], ondelete='CASCADE'),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_security_findings_id'), 'security_findings', ['id'], unique=False)
        op.create_index(op.f('ix_security_findings_assessment_id'), 'security_findings', ['assessment_id'], unique=False)
        op.create_index(op.f('ix_security_findings_section'), 'security_findings', ['section'], unique=False)


def downgrade() -> None:
    op.drop_table('security_findings')
    op.drop_table('assessment_results')
    op.drop_table('security_assessments')
    op.drop_table('system_settings')
    op.drop_table('honeypot_logs')
    op.drop_table('alerts')

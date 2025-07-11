"""Initial schema with approval fields

Revision ID: bc7cf00f76a0
Revises: 
Create Date: 2025-06-18 04:22:15.122018

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'bc7cf00f76a0'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('credit_applications', schema=None) as batch_op:
        batch_op.add_column(sa.Column('status', sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column('approved_by', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('approved_at', sa.DateTime(), nullable=True))
        batch_op.create_foreign_key('fk_credit_approved_by', 'users', ['approved_by'], ['id'])

    with op.batch_alter_table('shariah_applications', schema=None) as batch_op:
        batch_op.add_column(sa.Column('status', sa.String(length=20), nullable=True))
        batch_op.add_column(sa.Column('approved_by', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('approved_at', sa.DateTime(), nullable=True))
        batch_op.create_foreign_key('fk_shariah_approved_by', 'users', ['approved_by'], ['id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('shariah_applications', schema=None) as batch_op:
        batch_op.drop_constraint('fk_shariah_approved_by', type_='foreignkey')
        batch_op.drop_column('approved_at')
        batch_op.drop_column('approved_by')
        batch_op.drop_column('status')

    with op.batch_alter_table('credit_applications', schema=None) as batch_op:
        batch_op.drop_constraint('fk_credit_approved_by', type_='foreignkey')
        batch_op.drop_column('approved_at')
        batch_op.drop_column('approved_by')
        batch_op.drop_column('status')

    # ### end Alembic commands ###

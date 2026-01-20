
# mkdir -p alembic-migrate/versions
now=$(date +"%Y%m%d%H%M%S")

python3 -m alembic revision --autogenerate -m "$now"
python3 -m alembic upgrade head

# python3 -m alembic revision --autogenerate -m "$now"
# python3 -m alembic upgrade head
# 修复迁移历史 python3 -m alembic stamp head
cd /workspace && \
poetry install && \
poetry run python manage.py migrate && \
poetry run python manage.py createsuperuser --noinput && \
bash /workspace/.devcontainer/scripts/install-pre-commit.sh

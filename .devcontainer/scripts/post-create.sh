cd /workspace

CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}Installing Poetry${NC}"
poetry install

echo -e "${CYAN}Making Migrations${NC}"
poetry run python manage.py migrate

echo -e "${CYAN}Creating Superuser${NC}"
poetry run python manage.py createsuperuser --noinput

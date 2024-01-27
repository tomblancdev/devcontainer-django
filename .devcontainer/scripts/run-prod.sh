cd /workspace

CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}Installing Poetry${NC}"
poetry install

echo -e "${CYAN}Making Migrations${NC}"
poetry run python manage.py migrate

echo -e "${CYAN}Creating Superuser${NC}"
poetry run python manage.py createsuperuser --noinput

echo -e "${CYAN}Copying Nginx Configuration${NC}"
cp /workspace/.devcontainer/nginx.conf /etc/nginx/nginx.conf

echo -e "${CYAN}Starting Nginx${NC}"
service nginx stop
service nginx start

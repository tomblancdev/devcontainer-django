cd /workspace

git pull

echo -e "${CYAN}Installing dependencies${NC}"

poetry install

echo -e "${CYAN}Making Migrations${NC}"
poetry run python manage.py migrate

echo -e "${CYAN}Creating Superuser${NC}"
poetry run python manage.py createsuperuser --noinput

echo -e """${CYAN}
                       ____________________
                     //|           |        |
                   //  |           |          |
      ___________//____|___________|__________()\__________________
    /__________________|_=_________|_=___________|_________________{}
    [           ______ |           | .           | ==  ______      { }
  __[__        /##  ##\|           |             |    /##  ##\    _{# }_
 {_____)______|##    ##|___________|_____________|___|##    ##|__(______}
             /  ##__##                              /  ##__##        |
----------------------------------------------------------------------------

██     ██ ███████ ██       ██████  ██████  ███    ███ ███████     ██ ██ ██
██     ██ ██      ██      ██      ██    ██ ████  ████ ██          ██ ██ ██
██  █  ██ █████   ██      ██      ██    ██ ██ ████ ██ █████       ██ ██ ██
██ ███ ██ ██      ██      ██      ██    ██ ██  ██  ██ ██
 ███ ███  ███████ ███████  ██████  ██████  ██      ██ ███████     ██ ██ ██

----------------------------------------------------------------------------

${NC}
"""

echo -e "${CYAN}Welcome to the container !${NC}"

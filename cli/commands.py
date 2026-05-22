from cli.app import app
from core.menu import menu


def run():
       menu()

app.command()(run)
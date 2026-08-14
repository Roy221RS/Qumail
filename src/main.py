"""
main.py

Entry point for QuMail. Run this from inside src/:
    cd qumail/src
    python main.py

(Must be run from src/ so the flat imports in gui_app.py / email_engine.py
resolve correctly - see the note in gui_app.py's docstring.)
"""

from guiApp import QuMailApp

if __name__ == "__main__":
    app = QuMailApp()
    app.mainloop()

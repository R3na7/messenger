"""Entry point for the PyQt GUI client."""
from .gui.windows import ChatApplication


def main() -> None:
    app = ChatApplication()
    app.run()


if __name__ == "__main__":
    main()

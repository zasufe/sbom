from src.db import engine
from src.db.models import DbModel


def main():
    DbModel.metadata.create_all(bind=engine)
    print('DB tables created')


if __name__ == '__main__':
    main()

import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from indralab_auth_tools.conf import get_indra_conf

logger = logging.getLogger(__name__)

try:
    db_config = get_indra_conf("INDRALAB_USERS_DB", missing_ok=False)
    # This is for handling empty strings set as the environmental variable
    if not db_config:
        raise KeyError()
    # See
    # https://docs.sqlalchemy.org/en/14/core/pooling.html#disconnect-handling-pessimistic
    # and
    # https://docs.sqlalchemy.org/en/14/core/engines.html#sqlalchemy.create_engine
    engine = create_engine(
        db_config,
        convert_unicode=True,
        pool_pre_ping=True,
        pool_size=30,
        max_overflow=20,
        pool_recycle=300,  # 5 minutes
    )
    # Use a session factory and create a session object from the factory as needed.
    # See:
    # https://docs.sqlalchemy.org/en/14/orm/session_basics.html#using-a-sessionmaker
    db_session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base = declarative_base()
except KeyError:
    engine = None

    class Base(object):
        pass

    logger.warning("Missing INDRLAB_USERS_DB var, cannot use database.")


def init_db():
    # import all modules here that might define models so that
    # they will be registered properly on the metadata.  Otherwise
    # you will have to import them first before calling init_user_db()
    import indralab_auth_tools.src.models as models

    Base.metadata.create_all(bind=engine)

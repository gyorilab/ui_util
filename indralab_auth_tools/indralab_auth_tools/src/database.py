import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from indralab_auth_tools.conf import get_indra_conf

logger = logging.getLogger(__name__)


engine_config = {
    "convert_unicode": True,
    "pool_pre_ping": True,
    "pool_size": 30,
    "max_overflow": 20,
    "pool_recycle": 300,  # 5 minutes
}
sessionmaker_config = {
    "autocommit": False,
    "autoflush": False,
    # https://docs.sqlalchemy.org/en/14/orm/session_api.html#sqlalchemy.orm.Session.params.expire_on_commit
    "expire_on_commit": False
}

try:
    db_config = get_indra_conf("INDRALAB_USERS_DB", missing_ok=False)
    # This is for handling empty strings set as the environmental variable
    if not db_config:
        raise KeyError()
    # See
    # https://docs.sqlalchemy.org/en/14/core/pooling.html#disconnect-handling-pessimistic
    # and
    # https://docs.sqlalchemy.org/en/14/core/engines.html#sqlalchemy.create_engine
    engine = create_engine(db_config, **engine_config)
    # Use a session factory and create a session object from the factory as needed.
    # See:
    # https://docs.sqlalchemy.org/en/14/orm/session_basics.html#using-a-sessionmaker
    db_session = sessionmaker(bind=engine, **sessionmaker_config)
    Base = declarative_base()
except KeyError:
    engine = None

    class Base(object):
        pass

    logger.warning("Missing INDRLAB_USERS_DB var, cannot use database.")


def reset_database_connection():
    """Reset the database connection."""
    global engine, db_session
    logger.info("Attempting to reset database connection.")
    try:
        if engine is None:
            return
        engine.dispose()  # Close all connections
        engine = create_engine(db_config, **engine_config)
        db_session.configure(bind=engine)
        logger.info("Database connection reset.")
    except Exception as e:
        logger.error(f"Error resetting database connection: {e}")
        raise e


def monitor_database_connection(interval=60):
    """Monitor the database connection

    This function will check the database connection and reset it if it is lost.

    Example:
    ```
    import threading
    import time
    from indralab_auth_tools.src.database import monitor_database_connection

    threading.Thread(target=monitor_database_connection, args=(60,)).start()
    """
    import time
    global engine
    while True:
        time.sleep(interval)
        try:
            if engine is None:
            with engine.connect() as conn:
                conn.execute("SELECT 1")
                raise RuntimeError("Database engine is None.")
        except Exception as e:
            logger.error(f"Database connection lost: {e}")
            reset_database_connection()


def init_db():
    # import all modules here that might define models so that
    # they will be registered properly on the metadata.  Otherwise
    # you will have to import them first before calling init_user_db()
    import indralab_auth_tools.src.models as models

    Base.metadata.create_all(bind=engine)

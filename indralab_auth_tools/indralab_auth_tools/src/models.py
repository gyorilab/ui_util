import os
import scrypt
import logging
from base64 import b64encode
from datetime import datetime
from time import sleep

from sqlalchemy.orm import relationship, backref, Session
from sqlalchemy import Boolean, DateTime, Column, Integer, \
                       String, ForeignKey, LargeBinary
from sqlalchemy.dialects.postgresql import JSON, JSONB
from indralab_auth_tools.src.database import Base, db_session

logger = logging.getLogger(__name__)



class UserDatabaseError(Exception):
    pass


class BadIdentity(UserDatabaseError):
    pass



class _AuthMixin(object):
    _label = NotImplemented

    def save(self, session: Session = None):
        """Save the object to the database."""
        # Pass the session to the save method to avoid creating a new
        # session and transaction inside the save method when it's run from inside an
        # already started session context block.
        if session is None:
            with db_session() as session:
                self._save(session)
        else:
            self._save(session)

    def _save(self, session: Session):
            if not self.id:
                session.add(self)
            try:
                session.commit()
            except Exception as e:
                session.rollback()
                raise e

    def __str__(self):
        if isinstance(self._label, list) or isinstance(self._label, set) \
                or isinstance(self._label, tuple):
            label = ' '.join(getattr(self, label) for label in self._label)
        else:
            label = getattr(self, self._label)
        return "< %s: %s - %s >" % (self.__class__.__name__, self.id, label)

    def __repr__(self):
        return str(self)


class RolesUsers(Base):
    __tablename__ = 'roles_users'
    user_id = Column(Integer, ForeignKey('user.id'), primary_key=True)
    role_id = Column(Integer, ForeignKey('role.id'), primary_key=True)


class Role(Base, _AuthMixin):
    __tablename__ = 'role'
    id = Column(Integer(), primary_key=True)
    name = Column(String(80), unique=True)
    api_key = Column(String(40), unique=True)
    api_access_count = Column(Integer, default=0)
    description = Column(String(255))
    permissions = Column(JSON)

    _label = 'name'

    @classmethod
    def get_by_name(cls, name, *args):
        """Look for a role by a given name."""
        with db_session() as session:

            if len(args) > 1:
                raise ValueError("Expected at most 1 extra argument.")

            role = session.query(cls).filter_by(name=name).first()
            if not role:
                if not args:
                    raise UserDatabaseError(f"Role {name} does not exist.")
                return args[0]

            # Load the attributes before returning out of the session.
            session.refresh(role)
            return role

    @classmethod
    def get_by_api_key(cls, api_key):
        """Get a role from its API Key."""
        with db_session() as session:
            # Look for the role.
            role = session.query(cls).filter(cls.api_key == api_key).first()
            if not role:
                raise UserDatabaseError("Api Key {api_key} is not valid."
                                        .format(api_key=api_key))

            # Count the number of times this role has been accessed by API key.
            role.api_access_count = role.api_access_count + 1
            role.save(session=session)

            # Now fully load the role before returning it.
            # See:
            # https://docs.sqlalchemy.org/en/14/orm/session_state_management.html#refreshing-expiring
            # and
            # https://docs.sqlalchemy.org/en/14/orm/session_api.html#sqlalchemy.orm.Session.refresh
            # Note, this does not load
            # any relationships, e.g. 'users'. For that, see:
            # https://docs.sqlalchemy.org/en/14/orm/loading_relationships.html
            session.refresh(role)

            return role


class User(Base, _AuthMixin):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True)
    password = Column(LargeBinary)
    last_login_at = Column(DateTime())
    current_login_at = Column(DateTime())
    last_login_ip = Column(String(100))
    current_login_ip = Column(String(100))
    login_count = Column(Integer, default=0)
    active = Column(Boolean())
    confirmed_at = Column(DateTime())
    roles = relationship('Role',
                         secondary='roles_users',
                         backref=backref('users', lazy='joined'),
                         lazy='joined')

    _label = 'email'
    _identity_cols = {'id', 'email'}

    @classmethod
    def new_user(cls, email, password, **kwargs):
        return cls(email=email.lower(), password=hash_password(password),
                   **kwargs)

    @classmethod
    def get_by_email(cls, email, verify=None):
        """Get a user by email."""
        with db_session() as session:
            user = session.query(cls).filter(cls.email == email.lower()).first()
            if user is None:
                print("User %s not found." % email.lower())
                return None

            if verify:
                if verify_password(user.password, verify):
                    user.last_login_at = datetime.now()
                    user.login_count += 1
                    user.save(session=session)
                    # Load the attributes before returning out of the session.
                    session.refresh(user)
                    return user
                else:
                    print("User password failed.")
                    return None
            # Load the attributes before returning out of the session.
            session.refresh(user)
            return user

    @classmethod
    def get_by_identity(cls, identity):
        """Get a user from the identity JSON."""
        if not isinstance(identity, dict) or set(identity.keys()) != cls._identity_cols:
            raise BadIdentity("'{identity}' is not an identity."
                              .format(identity=identity))

        with db_session() as session:
            user = session.query(cls).get(identity['id'])
            if not user:
                raise BadIdentity("User {} does not exist.".format(identity['id']))
            if user.email.lower() != identity['email'].lower():
                raise BadIdentity("Invalid identity, email on database does "
                                  "not match email given.")
            # Load the attributes before returning out of the session.
            session.refresh(user)
            return user

    def reset_password(self, new_password):
        self.password = hash_password(new_password)
        self.save()

    def bestow_role(self, role_name):
        """Give this user a role."""
        role = Role.get_by_name(role_name)
        new_link = RolesUsers(user_id=self.id, role_id=role.id)
        with db_session() as session:
            session.add(new_link)
            session.commit()
        return

    def identity(self):
        """Get the user's identity"""
        return {col: getattr(self, col) for col in self._identity_cols}


class AuthLog(Base, _AuthMixin):
    __tablename__ = 'auth_log'
    id = Column(Integer, primary_key=True)
    date = Column(DateTime, nullable=False)
    success = Column(Boolean, nullable=False)
    attempt_ip = Column(String(64), nullable=False)
    action = Column(String(20), nullable=False)
    response = Column(JSON)
    code = Column(Integer)
    input_identity_token = Column(JSON)
    details = Column(JSON)

    _label = ['action', 'date']


class QueryLog(Base, _AuthMixin):
    __tablename__ = 'query_log'
    id = Column(Integer, primary_key=True)
    service_name = Column(String)
    start_date = Column(DateTime)
    end_date = Column(DateTime)
    result_status = Column(Integer)
    user_id = Column(Integer, ForeignKey("user.id"))
    api_key_role_id = Column(Integer, ForeignKey("role.id"))
    user = relationship(User, lazy='joined')
    user_ip = Column(String(64))
    user_agent = Column(String)
    url = Column(String)
    annotations = Column(JSONB)

    _label = ['service_name', 'start_date', 'user_ip']


def hash_password(password, maxtime=0.5, datalength=64):
    hp = scrypt.encrypt(b64encode(os.urandom(datalength)), password,
                        maxtime=maxtime)
    return hp


def verify_password(hashed_password, guessed_password, maxtime=0.5):
    try:
        scrypt.decrypt(hashed_password, guessed_password, maxtime)
        return True
    except scrypt.error:
        sleep(1)
        return False


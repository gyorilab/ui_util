from setuptools import setup, find_packages


def main():
    setup(
        name="indralab_auth_tools",
        description="Authentication tools for indralab UIs.",
        author="Patrick Greene",
        author_email="patrick_greene@hms.harvard.edu",
        url="http://github.com/indralab/ui_util",
        packages=find_packages(),
        install_requires=["flask-jwt-extended", "flask", "sqlalchemy<2", "scrypt==0.8.24"],
        include_package_data=True,
        version="1.0.0",
    )


if __name__ == "__main__":
    main()

from setuptools import setup, find_packages

setup(
    name="saga",
    version="1.0.0",
    author="Georgios Syros, Anshuman Suri",
    author_email="syros.g@northeastern",
    description="A project for secure user registration and authentication.",
    packages=find_packages(),
    install_requires=[
        "cryptography",
        "requests",
        "flask",
        "flask_sqlalchemy",
        "flask_pymongo",
        "flask_bcrypt",
        "flask_jwt_extended",
        "authlib",
        "smolagents"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
)

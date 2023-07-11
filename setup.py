#!/usr/bin/env python
from setuptools import setup, find_packages

with open("README.md", "r", encoding='utf-8') as fh:
    long_description = fh.read()


setup(
    name="nginx-ldap-auth-service",
    version="2.0.2",
    description="A FastAPI app that authenticates users via LDAP and sets a cookie for nginx",
    author="Caltech IMSS ADS",
    author_email="imss-ads-staff@caltech.edu",
    url="https://github.com/caltechads/nginx-ldap-auth-service",
    packages=find_packages(exclude=["bin"]),
    install_requires=[
        "aiodogstatsd==0.16.0.post0",
        "fastapi>=0.95.0",
        "uvicorn[standard]==0.21.1",
        "bonsai==1.5.1",
        "pydantic-settings",
        "pydantic>=1.9.0",
        "structlog==23.1.0",
        "tabulate>=0.8.9",
        "click>=8.0",
        "sentry-sdk>=1.1.0",
        "jinja2>=3.0.1",
        "starsessions[redis]>=2.1.1",
        "python-multipart>=0.0.6",
        "watchfiles",
        "python-dotenv",
    ],
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords=['nginx', 'ldap', 'auth', 'fastapi', 'devops'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Development Status :: 3 - Alpha",
        "Framework :: FastAPI",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP",
    ],
    include_package_data=True,
    entry_points={
        'console_scripts': ['nginx-ldap-auth = nginx_ldap_auth.main:main']
    }
)

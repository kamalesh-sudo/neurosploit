from pathlib import Path

from setuptools import find_packages, setup

README = Path("README.md").read_text(encoding="utf-8")

setup(
    name="neurosploit",
    version="3.0.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "requests",
        "dnspython",
        "urllib3",
        "textual>=0.58.0",
        "rich>=13.7.0",
    ],
    entry_points={
        "console_scripts": [
            "neurosploit = neurosploit.cli:main",
        ],
    },
    package_data={
        "neurosploit": ["data/*.txt", "prompts/*.txt", "*.tcss"],
    },
    author="Kamalesh",
    author_email="ragavhrxh@gmail.com",
    description="Interactive TUI-powered AI reconnaissance framework",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/iharishragav/neurosploit",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
)

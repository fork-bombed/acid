from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name         = "acid",
    version      = "0.1.0",
    author       = "Ryan Murphy",
    author_email = "ryan@unpacked.io",
    description  = "Acid memory management",
    long_description = long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fork-bombed/acid",
    packages = ['acid'],
    entry_points = {
        'console_scripts': [
            'acid = acid.__main__:main'
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: Windows",
    ],
    python_requires='>=3.7'
)


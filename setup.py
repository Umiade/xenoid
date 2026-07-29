from setuptools import setup, find_packages

setup(
    name="xenoid",
    version="0.1.0",
    description="Xenoid Android runtime orchestration for Apple Silicon macOS and Linux ARM",
    package_dir={"": "src"},
    packages=find_packages("src"),
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "xenoid=xenoid.cli:main",
            "xenoid-mcp=xenoid.mcp_server:main",
        ]
    },
)

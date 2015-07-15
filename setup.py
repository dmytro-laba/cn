from setuptools import setup, find_packages
import cn

setup(
    name='cn',
    version=cn.__version__,
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'tornado==4.2',
        'pycrypto==2.6.1',
    ],
)

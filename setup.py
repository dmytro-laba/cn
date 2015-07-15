from setuptools import setup, find_packages
import cn

setup(
    name='cn',
    version=cn.__version__,
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'tornado==4.2',
        'motor==0.4.1',
        'jmespath==0.7.1',
        'mock==1.0.1',
        'pycrypto==2.6.1',
    ],
)

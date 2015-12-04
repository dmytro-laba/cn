from setuptools import setup, find_packages
import cn

setup(
    name='cn',
    version="0.2.4",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'tornado==4.2',
        'pycrypto==2.6.1',
        'chu==0.2.0',
        'pika==0.10.0',
        'boto==2.38.0',
        'logentries',
        'tornado_aws',
        'requests-aws'
    ],
)

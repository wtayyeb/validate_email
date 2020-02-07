from setuptools import setup

setup(
    name='validate-email-wt',
    version='1.4.6',
    py_modules=('validate_email',),
    author='w.Tayyeb',
    author_email='w.tayyeb@gmail.com',
    description='validate_email verifies if an email address is valid and really exists.',
    long_description=open('README.rst').read(),
    keywords='email validation verification mx verify',
    url='https://github.com/wtayyeb/validate_email',
    license='LGPL',
    install_requires=[
        'disposable-email-domains',
    ]
)

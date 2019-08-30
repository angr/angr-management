# This script installs the unicorn engine on MacOS.
rm -rf ../unicorn
cd ../
git clone https://github.com/unicorn-engine/unicorn.git
cd unicorn/bindings/python
python setup.py install

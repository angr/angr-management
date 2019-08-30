# This script installs the unicorn engine on MacOS.
# Check if the OS is MacOS
if [ "$(uname)" == "Darwin" ]; then

    # Clone everything
    rm -rf ../unicorn
    cd ../
    git clone https://github.com/unicorn-engine/unicorn.git

    # Install unicorn
    cd unicorn/bindings/python
    python setup.py install

    # Cleanup
    cd ../../../
    rm -rf unicorn
    
else
    echo "This script is for MacOS only!"
fi

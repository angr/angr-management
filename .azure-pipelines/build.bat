call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars64.bat"

@echo on

pip install pyinstaller
pip install git+https://github.com/angr/archinfo.git#egg=archinfo
pip install git+https://github.com/angr/pyvex.git#egg=pyvex
pip install git+https://github.com/angr/cle.git#egg=cle
pip install git+https://github.com/angr/claripy.git#egg=claripy
pip install git+https://github.com/angr/ailment.git#egg=ailment
pip install git+https://github.com/angr/angr.git#egg=angr
pip install -e .

python .azure-pipelines\bundle.py --onefile
python .azure-pipelines\bundle.py --onedir

mkdir upload
move onefile\angr-management.exe upload\angr-management-onefile-win64.exe
7z a upload\angr-management-win64.zip .\dist\*

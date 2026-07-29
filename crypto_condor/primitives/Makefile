.PHONY: all clean binaries
all: libs

# Installs libs through the installation function of their module.
libs:
# Force recompilation of AES C code
	zip -j _aes/AES.zip _aes/aes.c _aes/aes.h
	python AES.py
	python TestU01.py
	python MLDSA.py
	python MLKEM.py


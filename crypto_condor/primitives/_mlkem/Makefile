all: mlkem.zip

kyber:
	git clone https://github.com/pq-crystals/kyber.git && git -C kyber checkout 10b478fc3cc4ff6215eb0b6a11bd758bf0929cbd

mlkem.zip: kyber
	git -C kyber apply ../cc-mlkem.patch
	zip $@ kyber/ref/*.c kyber/ref/*.h kyber/ref/Makefile

cc-mlkem.patch:
	git -C kyber diff >$@

ZIP = sqlite-amalgamation-3071700.zip
URL = http://www.sqlite.org/2013/$(ZIP)

all: sqlite3.c

sqlite3.c: $(ZIP) 
	@unzip -j $(ZIP)
	@touch $@
	
$(ZIP):
	@wget $(URL)

clean:
	@rm -f *.c *.h

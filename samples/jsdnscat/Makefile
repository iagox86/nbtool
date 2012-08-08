js/skullsecurity.all.min.js : js/skullsecurity.keylogger.js js/skullsecurity.jsdnscat.js
	@cat js/skullsecurity.keylogger.js js/skullsecurity.jsdnscat.js | ruby bin/compiler.rb > js/skullsecurity.all.min.js
	@echo js/skullsecurity.all.min.js

clean:
	@rm -f js/skullsecurity.all.min.js

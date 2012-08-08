#!/usr/bin/env ruby 
require 'cgi' 
#this takes up less room then including the closure compiler
doc     = CGI.escape(STDIN.read) 
options = "'output_format=text&output_info=compiled_code&&compilation_level=SIMPLE_OPTIMIZATIONS&js_code=#{doc}'" 
cmd     = "curl -s -X POST -d #{options} closure-compiler.appspot.com/compile"

print system(cmd)

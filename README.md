# IDA Scripts

Some useful IDA scripts.

## vtable_to_struct.idc

Intended for use on Mac/Linux binaries with symbols.

First, find the location of the vtable for a function. This is usually pretty easily found by pressing 'x'
on a function name to get the xrefs to it, then looking for an entry like `dd offset mangled_func_name` in
the list.

Once you've found the vtable, scroll up to the top of the offset listing and select the identifier that IDA
has given it. 

![IDA Screenshot](http://puu.sh/1ysn9)

Then, File -> Script File... and select `vtable_to_struct.idc` and follow the prompts.
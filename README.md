# Fr0mars-gdb

Implementation of a debugging suite




## Features 

- A nm like utilities that behaves more like readelf

- A custom strace

- A gdb like utility with multiple functions explained with the help command


https://i.imgflip.com/7gembr.jpg

## Usage

Just make in the corresponding directory


Notes for strace :

The syscall filtering is done via command line :
If you only provide a binary to trace then strace behaves normally
otherwise, all arguments after -e are treated as syscall filters.

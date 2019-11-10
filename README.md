# LibMatch: context-based library matching w/ angr

LibMatch is a proof-of-concept tool for matching object files to binary executables.  The key idea here is *context* -- in firmware, many functions look very similar, which will confuse other tools like FLIRT.  Sometimes, the functions will be entirely identical, but we'll want to care what their name is for the purposes of re-hosting with High Level Emulation. Other benefits include using imports to indirectly name functions we don't have the code for, or whose code was changed due to compiler flags for version mismatches.

This tool is meant to go with, and was developed along-side HALucinator(https://github.)

## Installing

*Note: This is a proof-of-concept, it uses tons of RAM and isn't the world's most efficient tool.  It does get the job done, and we've used it on real firmware successfully, it just needs a little refactoring before I'd say it's ready for prime-time.*

First, get angr(https://angr.horse/ )
I suggest using the angr-dev package to do so (https://github.com/angr/angr-dev/ )

You'll also probably want autoblob, a Loader that I wrote which helps with some binary blob loading (https://github.com/subwire/autoblob/ ) 

## Usage

Once you have an angr environment, you can use the ./utils/unblob tool to build some databases.  Put all your objects in a folder structure like:
```
./objects/my_hal/library1/obj1.o
./objects/my_hal/library1/obj2.o
./objects/my_hal/library2/foo/obj3.o
```

Objects can live in any depth of subfolders you like.  You can even just copy in the build tree of the SDK or library into a folder.

Then, do the following:

```
./utils/unblob -B ./objects/my_hal ./objects/my_hal.lmdb
```

...and go get a coffee.

Once that's done, grab your blob or ELF, and do:

```
./utils/unblob -U -L ./objects/my_hal.lmdb -Y ./bins/my_firmware.bin ./bins/my_firmware.yml
```

...and go get a much smaller coffee. This will produce a YML file of symbols, immediately ready to be ingested by HALucinator or hal-fuzz.


Curious how well it's doing? Debugging problems? Got an ELF with symbols? Try this:

```
./utils/unblob -U --scoring -L ./objects/my_hal.lmdb -Y ./bins/my_firmware.elf ./my_firmware.yml
```

This will produce nice colorful debug output with accuracy and collision information.


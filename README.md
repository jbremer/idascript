IDAScript
=========

Ability to easily run ida python scripts.

Usage:

```
idascript [-B] <idb-file> <script-file> [script arguments]
-B flag tells IDA Pro to go into Batch Mode
```

`Batch mode` means that IDA Pro will *not* show a GUI.

Installing
==========

Currently the scripts paths are hardcoded (which wasn't the case for
Craig Heffner's version..)
However, assuming you want the temporary file in `$TEMP/idaout.txt`, you'll
only have to adjust the IDA Pro absolute path in `idascript`.

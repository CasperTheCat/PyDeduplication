Python Deduplication
===

Tested on Windows and Linux

Terms
---

Term | Meaning
--- | ---
Short Hash | Hash of the first and last 4Ki of the file
Long Hash | Hash of the entirity of the file


File Containers
---

Some files are wrapped in containers, such as `.mkv` or `.png` files. These files can show false negatives if the container metadata is changed, such as when EXIF data is removed from an image. Opening the underlying content of the file and hashing that solves this issue, but at the cost of performance. 

This mode of scanning is enabled using the `--raw` flag. 

Currently, only images are supported.

Skip Directories
---

To skip a directory, place a `.skipfolder` file at the level you wish to ignore.
The `.skipfolder` file instructs this program to ignore that folder, including all subfiles and subfolders.

Directories named `.git` are automatically ignored, as are `.gitignore` files.
*Please note that `.gitmodules` is not currently ignored as intended.* 




GenerateHashList.py
---

Usage: python3 GenerateHashList.py [OPTIONS] \<directory\>

Flags | Short Flag | Purpose
--- | --- | ---
--fast | -f | Only use short hashes for comparing files
--short-hash | -sh | Only generate short hashes when adding files (Implies --fast)
--raw | -r | Hash the file as it appears on disk. Do not open the file container.
--silient | None | Don't print as much
--hashtable | -t | Specify the hashtable name. Defaults to `.!HashList`
--allow-quarantine | None | Enable moving files to `../.!Quarantine/`


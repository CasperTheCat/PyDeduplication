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


Extensions
---

Extensions are supplied via the constructor of CHashList. They are set in the HashList at creation, and cannot current be changed. The reason for this limitation is that changing extensions would at best behave unexpected and at worst invalidate all current entries.

*NOTE: Larger block sizes take priority over smaller sizes if multiple are specified.*

Extension | Meaning
--- | ---
PerceptualHash | Enable the perceptual hash of images
SHA512 | Switch from SHA3_256 to SHA512_256
16MiBShortHashBlock | Expand the 4Ki block to 16Mi.
1MiBShortHashBlock | Expand the 4Ki block to 1Mi
IncludeFileMiddleInShortHash | Include the middle `BlockSize` in the hash



GenerateHashList.py
---

Usage: python3 GenerateHashList.py [OPTIONS] \<directory\>

Flags | Short Flag | Purpose
--- | --- | ---
--fast | -f | Only use short hashes for comparing files
--short-hash | -sh | Only generate short hashes when adding files (Implies --fast)
--raw | -r | Hash the file as it appears on disk. Do not open the file container.
--silent | None | Don't print as much
--hashtable | -t | Specify the hashtable name. Defaults to `.!HashList`
--allow-quarantine | None | Enable moving files to `../.!Quarantine/`


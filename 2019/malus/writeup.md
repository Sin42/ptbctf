## Contest commentary
So the approach used by both solving teams, as well as other people working on the task, was to establish that file6301.png 
had been altered (modified or overwritten somehow) and then tinker with the 4 blocks of 4096 bytes each that comprised the 
flag picture. Either permute them until the full flag is shown, or use the upper part of the characters, which rendered 
correctly, to determine what character was in each position.

There were also a lot of participants that looked for various forms of steganography:
* file timestamps
* file sizes
* file names
* pixel stuff
* the hex strings inside the pictures

These were all added noise. My goal was to create a forensic challenge with the relatively new APFS, one that there wasn't
a forensics tool already out there that would solve with a few clicks/keystrokes. The 10000 random files were intended to 
simulate a normal working disk, where you have lots of files and you would like to see prior versions of one file.
The mid-competition clarification which ended with "Look deeper" and the task description phrase "Time is of the essence"
were intended to guide the CTF player towards understanding the nature of the task. In hindsight, I was naive to hope that
everybody would get the [spec](https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf) and start reading it with an eye kept open for useful features that could hide a file.
So I'll outline my intended (and most likely) overcomplicated solution. Please keep the specification at hand since I will 
not copy structure definitions and pictures from it here, for the sake of brevity. The short version is to look for all
versions of all files and look for the ones that are not found in the 10000 files visible when mounting the disk image,
using something like SHA256.

## APFS 101
Everything in APFS is an object, having a type, a subtype, an object identifier, a transaction identifier, and a checksum.
I was intrigued with the transaction identifier, because it didn't seem like you really need it to just store files, so
what was its purpose? Turns out APFS saved the state of the filesystem periodically as checkpoints, such that in case of
something like power failure you can have your data in a known good state available. Checkpoints are also the building
blocks for features like snapshots and Time Machine. This seemed like a good idea to use to place the flag since many people
seem to forget to backup and then wish they could get their data back.

Back to objects, there are 3 kinds of them:
* ephemeral - only exist on disk in checkpoints, made to be copied to memory and updated frequently; not relevant for our purposes
* physical - their object identifier is the offset from the start of the partition where the data is found
* virtual - their data is retrieved by combinind the object identifier and a transaction identifier to form a key used to lookup the offset in an object map

This might seem a lot to take in at once so you can just remember that there is a type of object you don't really need when
working with disk images, a type for which you can retrieve the data directly, and a third for which you can retrieve the
data using an auxiliary object and a transaction identifier.

An APFS partition usually holds an APFS container, which in turn holds one or more APFS volumes, and a volume holds one
filesystem. In approximate LVM terms, an APFS container is a LVM Volume Group and an APFS volume is a LVM Logical Volume.
The process of getting from partition to filesystem data is outlined better in the subsection "Mounting an Apple File 
System Partition" on page 24 of the specification.

Up to a certain point the structures and fields can be parsed and dumped with something like apfs-dump from the [apfs-fuse](https://github.com/sgan81/apfs-fuse)
project. However, I needed a bit more verbose output when doing the research for this task and so I've written an incomplete
template using [Kaitai Struct](https://kaitai.io/) for my purposes.
Funny enough, both tools seem to reach their limits when facing the task of parsing one particular APFS structure: the B-Tree.
So I just wrote a separate B-tree dumper. Up to this point, I could use something like apfs-dump to get filenames,
object identifiers and transaction identifiers. I could put together the file, the past version of it, but not the data and
the way its chunks are ordered.

## APFS B-Trees
There are some unpleasant aspects to deal with when writing a parser for this structure (please read the chapter on them at
page 107 in the spec at this point):
1. Each B-tree object represents a B-tree level. Useful data is only at the leaf level so we have to jump around the image
file from offset to offset until we get to the leafs.
2. We have to take into account both fixed and variable size keys and values.
3. Table of contents, key area, free space area and value area have neither fixed offsets, nor fixed size. We only know the
start of the table of contents and that the there areas come one after the other.
4. There are free lists for the keys and values areas, marking entries we should ignore.
5. For nodes which are neither root, nor leaf, the "values" are not any of the `j_*_val_t` types, but an object identifier
used to locate the child node.

Of the numerous value types that are available, you only need to parse inodes and file extent records, so that you can pair
file names and file data offsets. The trouble is that inodes have the file name in an extended field to there are a few more
other structures to parse.

Putting it all together, the interesting block is 26299, for which I will include a truncated dump here, relevant to our
flag file:
```
image_offset: 107741184
Checksum: 76 48 a8 60 e7 ca 30 9b 
OID: 1448
XID: 51
Type: B-tree node
Type Flags:  0
Storage type: virtual
Subtype: tree containing file-system records
B-tree Node Flags: leaf node |  0
Number of child levels below: 0
Number of keys stored: 48
Table of Contents: off=0 (107741240) len=384
Free Space: off=512 (107742136) len=52
Free Key Space: off=65535 len=0
Free Value Space: off=65535 len=12
Table of Contents:
[...]
        k.off=128 k.len=8 v.off=912 v.len=160 |                 OID: 5038 |     Type: inode
                        PID: 2 |        ID: 5038 |      ctime: 1565705228298889776 |    mtime: 1565705228299000566 |    chtime: 1565705228299059764 |   atime: 1565705228298889776
                        Flags: INODE_NO_RSRC_FORK | 0
                        Number of children/links: 1 |   Default protection class: DIR_NONE  |   Write Gen Counter: 2 |  BSD Flags: 0
                        UID: 99 |       GID: 99 |       Mode: 81a4
                        Number of extents: 2 |  Used space: 56
                                Type: name |    Flags: XF_DO_NOT_COPY | 0
                                        Size: 13 | Name:  file6301.png
                                Type: data stream |     Flags: XF_SYSTEM_FIELD | 0
                                        Size: 40 | Data size: 0x0000003c62000000 | Alloced size: 0x0000004000000000 | Default Crypto ID: 0x0000000000000000 | Bytes W: 0x0000003c62000000 | Bytes R: 0x0000000000000000
        k.off=136 k.len=8 v.off=916 v.len=4 |           OID: 5038 |     Type: data stream
        k.off=144 k.len=16 v.off=940 v.len=24 |                 OID: 5038 |     Type: physical extent record for a file
                        OID: 5038 Offset in data: 0 |   Block: 26087 |  Length: 4096 |  Flags: 0x0000000000000000 |     Crypto ID: 0x0000000000000000
        k.off=160 k.len=16 v.off=3092 v.len=24 |                OID: 5038 |     Type: physical extent record for a file
                        OID: 5038 Offset in data: 4096 |        Block: 26089 |  Length: 4096 |  Flags: 0x0000000000000000 |     Crypto ID: 0x0000000000000000
        k.off=176 k.len=16 v.off=3068 v.len=24 |                OID: 5038 |     Type: physical extent record for a file
                        OID: 5038 Offset in data: 8192 |        Block: 26088 |  Length: 4096 |  Flags: 0x0000000000000000 |     Crypto ID: 0x0000000000000000
        k.off=192 k.len=16 v.off=3044 v.len=24 |                OID: 5038 |     Type: physical extent record for a file
                        OID: 5038 Offset in data: 12288 |       Block: 26086 |  Length: 4096 |  Flags: 0x0000000000000000 |     Crypto ID: 0x0000000000000000
        k.off=208 k.len=8 v.off=0 v.len=0 |             OID: 5038 |     Type: invalid
        k.off=208 k.len=8 v.off=0 v.len=0 |             OID: 5038 |     Type: invalid
        k.off=216 k.len=8 v.off=0 v.len=0 |             OID: 5038 |     Type: invalid
[...]
```
So here we see that a file named file6301.png has OID 5038 from the inode record and that the four parts for OID 5038 are
placed on disk in the order part 4, part 1, part 3, part 2 from the physical extent record. There are also some invalid
entries at the end pertaining to OID 5038. This is because, like the other files, APFS recorded one single physical extent
record of 16384 bytes which meant that the flag could be obtained with something like binwalk or foremost. That was clearly
unacceptable to I used a hex editor to jumble up the pieces. But that meant that I partially had to overwrite another file's
entries and then use the invalid records as padding, in order to not trip up errors with some tool I haven't tested or if
someone mounted the filesystem. After I updated the checksum for this block, the task was ready for people to attempt
solving it. As far as my tests went, MacOS will refuse to mount an image if an checksum fails. No warning, no error, just 
does not mount. Since I wanted it to behave as much as possible as a normal disk, I had to update the checksum.

## Conclusion
So that is what I had in mind for this task. I was even thinking that there might be another route to solve the task, maybe
using the reaper structures that handle unused blocks, but I didn't look into that avenue. I was curious if some team would
find a solution using that.
However, because I focused so hard on a filesystem level approach, I didn't consider things like fseventsd logs at all. When
people started asking about it I was initially worried that maybe it had a trivial solution. But luckily, those logs didn't
store enough information, so it was still a difficult task.
All in all, I hope people enjoyed the task and maybe even this writeup.
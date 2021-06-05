chymera Core
=============

Setup
---------------------
chymera Core is the original chymera client and it builds the backbone of the network. It downloads and, by default, stores the entire history of chymera transactions, which requires a few hundred gigabytes of disk space. Depending on the speed of your computer and network connection, the synchronization process can take anywhere from a few hours to a day or more.

To download chymera Core, visit [chymeracore.org](https://chymeracore.org/en/download/).

Running
---------------------
The following are some helpful notes on how to run chymera Core on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/chymera-qt` (GUI) or
- `bin/chymerad` (headless)

### Windows

Unpack the files into a directory, and then run chymera-qt.exe.

### macOS

Drag chymera Core to your applications folder, and then run chymera Core.

### Need Help?

* See the documentation at the [chymera Wiki](https://en.chymera.it/wiki/Main_Page)
for help and more information.
* Ask for help on the [chymera StackExchange](https://chymera.stackexchange.com)
* Ask for help on [#chymera](https://webchat.freenode.net/#chymera) on Freenode. If you don't have an IRC client, use [webchat here](https://webchat.freenode.net/#chymera).
* Ask for help on the [chymeraTalk](https://chymeratalk.org/) forums, in the [Technical Support board](https://chymeratalk.org/index.php?board=4.0).

Building
---------------------
The following are developer notes on how to build chymera Core on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)
- [FreeBSD Build Notes](build-freebsd.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [NetBSD Build Notes](build-netbsd.md)
- [Android Build Notes](build-android.md)
- [Gitian Building Guide (External Link)](https://github.com/chymera-core/docs/blob/master/gitian-building.md)

Development
---------------------
The chymera repo's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Productivity Notes](productivity.md)
- [Release Notes](release-notes.md)
- [Release Process](release-process.md)
- [Source Code Documentation (External Link)](https://doxygen.chymeracore.org/)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Shared Libraries](shared-libraries.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)

### Resources
* Discuss on the [chymeraTalk](https://chymeratalk.org/) forums, in the [Development & Technical Discussion board](https://chymeratalk.org/index.php?board=6.0).
* Discuss project-specific development on #chymera-core-dev on Libera Chat. If you don't have an IRC client, use [webchat here](https://web.libera.chat/#chymera-core-dev).
* Discuss general chymera development on #chymera-dev on Freenode. If you don't have an IRC client, use [webchat here](https://webchat.freenode.net/#chymera-dev).

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [chymera.conf Configuration File](chymera-conf.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [Reduce Memory](reduce-memory.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [ZMQ](zmq.md)
- [PSBT support](psbt.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).

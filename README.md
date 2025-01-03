# Disassembly of Atari TOS 1.00 (French) with Ghidra
This software is Copyright © 1985 Atari Corp. & Digital Research, Inc.\
It is now considered as abandonware.

[TOS (The Operating System)](https://en.wikipedia.org/wiki/Atari_TOS) was the operating system of the Atari ST range of computers since 1985.
Early Atari ST used a bootstrap ROM and loaded TOS from a floppy disk.
Then the system was updated and the whole TOS was included into a 192 KB ROM.
This is the version disassembled here, localized in French. That ROM dump is commonly referred as `tos100fr.img`.
Subsequently, there was a few updates to support new hardware and fix bugs.

[Ghidra](https://ghidra-sre.org/) is a Free software reverse engineering tool developed by the NSA. It requires a computer with a Java Development Kit (JDK) installed.

The goals of this disassembly are:
- To deeply understand and document the operating system internals.
- To find bugs and possible workarounds.
- To provide precise information for writing better user software.

# Browse the disassembly with Ghidra
Ghidra projects can't be visualized online, and can't easily be shared between users (unless using a Ghidra Server). You need to install Ghidra on your computer, download the `TOS100FR.gar` archive and import it (using the *Restore Project* feature) to your local Ghidra workspace.

## Install Ghidra
There are 2 steps:
1. Install the Java Development Kit (JDK) version 21 or above, if not already present.
2. Install Ghidra itself.

### Install Ghidra on Windows

#### Install Java

The simplest way is to use the *Eclipse Temurin* build, provided by the *Adoptium Working Group*.
- Go to the [Adoptium homepage](https://adoptium.net/).
- Scroll down, and click on the big *Latest LTS Release* button. It will download a file with a name like *OpenJDK...jdk_x64_windows_hotspot_....msi*.
- Double-click to the OpenJDK MSI file to start the installation, and follow the instructions.

#### Install Ghidra
  - Go to the [Ghidra homepage](https://ghidra-sre.org/).
  - Click on the big red button *Download from GitHub*.
  - In the *Assets* section, click on *ghidra_..._PUBLIC_....zip* to download it.
  - Unzip that file somewhere on your hard disk. There is no installer.

## Download the TOS disassembly archive
Ghidra projects can't be shared directly. You must download the Ghidra project archive (*.gar) then import it to your local workspace.
There are several ways to download the project archive.

First, create a local directory to store your local GitHub projects. It will be referred as your *local workspace*.
If you plan to use `git` command to download the archive, `cd` to that directory now.\
Then use one of the methods below:

1. If you already have a GitHub account and set up your [SSH keys](https://github.com/settings/keys):

Clone the repository using the Git protocol:\
`git clone git@github.com:disastos/tos100fr.git`

2. If you don't have SSH keys, but still prefer to download using Git:

Clone the repository using the https protocol:\
`git clone https://github.com/disastos/tos100fr.git`

3. If you don't want to mess with Git stuff:

Just download the [TOS100FR.gar](https://github.com/disastos/tos100fr/raw/refs/heads/main/TOS100FR.gar) file and go on.

## Run Ghidra

1. Double-click on the `ghidraRun.bat` program. A console window will appear, and disappear quickly. Then be patient: it could take about 20 seconds for something to happen. Then the Ghidra spash screen will appear, followed by the Ghidra project manager.

<img width="325" alt="image" src="https://github.com/user-attachments/assets/36eb8a2d-e58e-45cf-8d3e-0ef7020982d0" />

3. Be sure that `NO ACTIVE PROJECT` is displayed. If not, select *File > Close Project*.

4. Import the project archive.

To do that, select *File > Restore Project...*\
In *Archive File*, click on *...* to select the file `TOS100FR.gar`.\
Ensure that the *Restore Directory* is correct, then click *OK*.

You have now a local copy of the TOS disassembly.

4. Run the *CodeBrowser* tool

In the Ghidra project manager, simply double-click on `tos100fr.img`. And wait a few seconds for the tool to load. It will look like this:

<img width="960" alt="image" src="https://github.com/user-attachments/assets/1e6b8ec2-b4d8-41b2-96d2-7a100e2eb275" />

## Browse the disassembly

There are 2 main windows:
- On the middle: the *Listing* window. Actually, it is the disassembly.
- On the right: the *Decompile* window. It is an automatic interpretation of the disassembly, using C language.

Even if Ghidra can be used using the menus, it is best to use a combination of mouse and keyboard shortcuts. Note that most keyboard shortcuts are a **single key** (not Ctrl+key) and that shortcuts **may be different between Listing and Decompile windows**. Some of them act on current selection, so beware of what is selected.

### A few useful commands
- Double-click a function or variable to see its definition.
- Press `Alt+Left` to go back.
- Type `G` to go to an adress or label.
- Type `Ctrl+Shift+F` to find the references to a label.
- Type `L` to rename a variable, function or label.
- In the Listing window : type `F` to create a function (then `Delete` to remove it)
- In the Decompile window : click in the function name, then type `L` to rename it.
- In the Decompile window : right-click in the function name, then select *Edit Function Signature* to change the parameters.
- In the Decompile window : type `Ctrl+L` to change the type of a variable.
- In the Listing window : type `T` to change the type of a variable.
- In the Listing window : type `D` to disassemble the selected bytes (if not already).
- In the Listing window : type `C` to cancel disassembly or data interpretation of selected bytes.
- In the Listing window : type `Ctrl+Alt+R` to convert a constant to a reference.
- In the Listing window : type `Delete` to remove a reference and convert it back to an integer constant.
- In the Listing window : type `R` to add or edit a reference with options.

## Detailed information about TOS internals

A few pointers are listed on the [internals.md](internals.md) page.

An essential resource to understand TOS internals is [Thorsten Otto's tos1x repository](https://github.com/th-otto/tos1x). He managed to reconstruct TOS source code using various parts glued together. This information is necessarily reliable, because those sources can be compiled with original tools to produce byte-exact binary ROM images. The only drawback is that such reconstructed sources are only available for TOS 1.04 and higher. Most of the time, the code is similar, but sometimes there are variations. So the newer source code is the primary information to understand the whole point. Then the disassembly must be checked for possible differences.

## Ghidra caveats

Ghidra is a very powerful tool:
- It can disassemble a binary into an assembly source.
- Code and data fragments are automatically detected, and can be manually adjusted.
- Functions are dynamically decompiled into a C source for easy understanding of algorithms.
- The disassembly can be annotated in various ways, including : labels, equates, references, types, structs, variable names...
- It supports the Motorola 68000.
- C decompilation works rather well for code initially written in C, provided that the structs have been defined and the variables are correctly typed. This is the case for GEMDOS.

However, there are a few caveats.
- The C decompilation doesn't work well with 16-bit ints. When shorts are used as function arguments, the function signature must be manually edited. Even after that, the short variables arent always decompiled as expected.
- Leading underscore for functions and global variables isn't supported. If used, they also become visible on the C side. So I chose to avoid them for a clean decompilation.
- Most of time, C decompilation works poorly for manually written assembly. This doesn't matter, because in that case the disassembly is already readable enough. Annotations help a lot, as well as source code of other versions.
- Stack parameters for traps aren't recognized as such.
- The Line-F hack to shorten function calls in AES/Desktop isn't properly decompiled. So references between functions can't be automatically detected. And sadly, the Line-F opcodes are different between TOS 1.0 and TOS 1.04 versions, so @th-otto's source code can't be used to match functions.

But there is hope. Because Ghidra is a Free project. So contributions could be added for better support.\
Moreover, Ghidra supports usage of scripts written with Java or Python. This could be used to automate a few things.

## Contribute to the disassembly

In current state, this disassembly is *very far* from complete. But it is already useful, as most entry points have been recovered. BIOS/XBIOS/BDOS/VDI functions adresses have been found, and tagged with appropriate labels. For AES and desktop, the task is much more difficult due to obfuscation of function calls through Line-F instructions.

The TOS 1.0 ROM has a size of only 192 KB. But this represents a huge number of functions and assembler instructions. It would take a colossal amount of time to understand and clean everything. On the other hand, we don't need to understand the whole ROM. When someone needs to work on some area, he can enhance the disassembly, and share his progress. So this will necessarily be a cooperative task.

There is still a technical problem. Ghidra projects can't easily be shared on GitHub. Ghidra supports multi-user access to a shared project, but this requires a Ghidra Server. And currently, we don't have one. Ghidra local files can't be directly shared among users. The alternative is to archive the local project into a GAR file, and share it. Then other people need to unarchive it prior to use it. Even if this is very unconvenient, this is the solution I propose to you.

So here are the rules.
- If you are experienced with both Ghidra and TOS internals, your contributions will be welcome. This is a cooperative project.
- First you need to get the current TOS disassembly, and familiarize yourself to it.
- If you have something significant to contribute (structures, labels, equates, types, local variable names, comments...) then go ahead.
- Note that, as much as possible, labels and function names must be taken from [th-otto/tos1x](https://github.com/th-otto/tos1x) to ease comparison between TOS versions. Only exception is the leading underscore for global variables and functions: it mustn't be used in the disassembly, because Ghidra doesn't handle it correctly (it would also appear on the C side).
- As this GitHub project contains a Ghidra project archive, it can't be edited concurrently. You need to be alone when working on the project. So you need somehow to "lock" the archive into exclusive mode before working on it with the intention of pushing your changes. I simply propose you to open a new [discussion](https://github.com/disastos/tos100fr/discussions) on the project and tell something like "Hey, I'm starting working on the project, please don't update it until I finish".
- To get write access to the repository, be sure to have a GitHub account, then ask for it in a new [discussion](https://github.com/disastos/tos100fr/discussions).

Of course this is only the beginning. Best practices will evolve.

---
This disassembly project has been initiated by [Vincent Rivière](https://github.com/vinriviere/) on 02/01/2025.

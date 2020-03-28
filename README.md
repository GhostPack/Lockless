# LockLess

----

LockLess is a C# tool that allows for the enumeration of open file handles and the copying of locked files.

It was inspired by [@fuzzysec](https://twitter.com/fuzzysec)'s [Get-Handles.ps1](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Get-Handles.ps1) and draws on [code from Stackoverflow](https://stackoverflow.com/questions/860656/using-c-how-does-one-figure-out-what-process-locked-a-file) as well.

Handles are enumerated with NtQuerySystemInformation:SystemHandleInformation.

To copy out a locked file, the code:
* Opens the process that has a lock on the file with `DuplicateHandle` permissions.
* Uses `DuplicateHandle()` to duplicate the specific file handle associated with the file we're wanting to copy.
* Uses `CreateFileMapping()` to create a mapping of the duplicated file handle.
* Uses `MapViewOfFile()` to map the entire file into memory.
* Uses `WriteFile()` to write out the mapped contents to the temporary file specified.


LockLess is licensed under the BSD 3-Clause license.

## Usage

    C:\Temp\LockLess.exe

        LockLess.exe <file.ext | all> [/process:NAME1,NAME2,...] [/copy | /copy:C:\Temp\file.ext]


File out which process has a handled to the locked "WebCacheV01.dat" file:

    C:\Temp>LockLess.exe WebCacheV01.dat

    [*] Searching processes for an open handle to "WebCacheV01.dat"
    [+] Process "taskhostw" (5332) has a file handle (ID 880) to "C:\Users\harmj0y\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat"


Copy the locked "WebCacheV01.dat" file to a temporary file:

    C:\Temp>LockLess.exe WebCacheV01.dat /copy

    [*] Searching processes for an open handle to "WebCacheV01.dat"
    [+] Process "taskhostw" (5332) has a file handle (ID 880) to "C:\Users\harmj0y\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat"
    [*] Copying to: C:\Users\harmj0y\AppData\Local\Temp\tmp18BE.tmp
    [*] Copied 23068672 bytes from "C:\Users\harmj0y\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat" to "C:\Users\harmj0y\AppData\Local\Temp\tmp18BE.tmp"


Copy the file "WebCacheV01.dat" locked by "taskhostw" to a specific location:

    C:\Temp>LockLess.exe WebCacheV01.dat /process:taskhostw /copy:C:\Temp\out.tmp

    [*] Searching processes for an open handle to "WebCacheV01.dat"
    [+] Process "taskhostw" (9668) has a file handle (ID 892) to "C:\Users\harmj0y\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat"
    [*] Copying to: C:\Temp\out.tmp
    [*] Copied 23068672 bytes from "C:\Users\harmj0y\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat" to "C:\Temp\out.tmp"


Enumerate all open handles, outputting as a CSV:

    C:\Temp>LockLess.exe all

    ProcessName,ProcessID,FileHandleID,FileName
    Code,4740,64,C:\Users\harmj0y\AppData\Local\Programs\Microsoft VS Code
    ...(snip)...


## Compile Instructions

We are not planning on releasing binaries for LockLess, so you will have to compile yourself :)

LockLess has been built against .NET 3.5 and is compatible with [Visual Studio 2019 Community Edition](https://visualstudio.microsoft.com/downloads/). Simply open up the project .sln, choose "release", and build.

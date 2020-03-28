using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace LockLess
{
    class Program
    {
        public static Dictionary<string, string> BuildDeviceMap()
        {
            // adapted from https://stackoverflow.com/questions/860656/using-c-how-does-one-figure-out-what-process-locked-a-file

            string networkDevicePrefix = "\\Device\\LanmanRedirector\\";

            string[] logicalDrives = Environment.GetLogicalDrives();
            Dictionary<string, string> localDeviceMap = new Dictionary<string, string>(logicalDrives.Length);
            StringBuilder lpTargetPath = new StringBuilder(260);
            foreach (string drive in logicalDrives)
            {
                string lpDeviceName = drive.Substring(0, 2);
                Kernel32.QueryDosDevice(lpDeviceName, lpTargetPath, 260);
                localDeviceMap.Add(NormalizeDeviceName(lpTargetPath.ToString()), lpDeviceName);
            }
            localDeviceMap.Add(networkDevicePrefix.Substring(0, networkDevicePrefix.Length - 1), "\\");
            return localDeviceMap;
        }

        public static string NormalizeDeviceName(string deviceName)
        {
            // adapted from https://stackoverflow.com/questions/860656/using-c-how-does-one-figure-out-what-process-locked-a-file

            string networkDevicePrefix = "\\Device\\LanmanRedirector\\";

            if (string.Compare(deviceName, 0, networkDevicePrefix, 0, networkDevicePrefix.Length, StringComparison.InvariantCulture) == 0)
            {
                string shareName = deviceName.Substring(deviceName.IndexOf('\\', networkDevicePrefix.Length) + 1);
                return string.Concat(networkDevicePrefix, shareName);
            }
            return deviceName;
        }

        public static Dictionary<int, string> ConvertDevicePathsToDosPaths(Dictionary<int, string> devicePaths)
        {
            Dictionary<int, string> dosPaths = new Dictionary<int, string>();

            foreach (var devicePath in devicePaths)
            {
                Dictionary<string, string> deviceMap = BuildDeviceMap();
                int i = devicePath.Value.Length;
                while (i > 0 && (i = devicePath.Value.LastIndexOf('\\', i - 1)) != -1)
                {
                    string drive;
                    if (deviceMap.TryGetValue(devicePath.Value.Substring(0, i), out drive))
                    {
                        dosPaths.Add(devicePath.Key, string.Concat(drive, devicePath.Value.Substring(i)));
                    }
                }
            }

            return dosPaths;
        }

        public static Dictionary<int, string> GetHandleNames(int targetPid)
        {
            Dictionary<int, string> fileHandles = new Dictionary<int, string>();

            int length = 0x10000;
            IntPtr ptr = IntPtr.Zero;

            try
            {
                while (true)
                {
                    ptr = Marshal.AllocHGlobal(length);
                    int wantedLength;

                    // query for system handles we can read
                    var result = Ntdll.NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemHandleInformation, ptr, length, out wantedLength);
                    if (result == NT_STATUS.STATUS_INFO_LENGTH_MISMATCH)
                    {
                        length = Math.Max(length, wantedLength);
                        Marshal.FreeHGlobal(ptr);
                        ptr = IntPtr.Zero;
                    }
                    else if (result == NT_STATUS.STATUS_SUCCESS)
                        break;
                    else
                        throw new Exception("Failed to retrieve system handle information.");
                }

                var offset = ptr.ToInt64();
                offset += IntPtr.Size;
                int size = Marshal.SizeOf(typeof(SYSTEM_HANDLE_INFORMATION));

                int handleCount = IntPtr.Size == 4 ? Marshal.ReadInt32(ptr) : (int)Marshal.ReadInt64(ptr);

                // open the target process for handle duplication
                IntPtr processHandle = Kernel32.OpenProcess(ProcessAccessFlags.DuplicateHandle, true, (uint)targetPid);
                IntPtr currentProcessHandle = Kernel32.GetCurrentProcess();

                for (int i = 0; i < handleCount; i++)
                {
                    if (Marshal.ReadInt32((IntPtr)offset) == targetPid)
                    {
                        SYSTEM_HANDLE_INFORMATION info = (SYSTEM_HANDLE_INFORMATION)Marshal.PtrToStructure(new IntPtr(offset), typeof(SYSTEM_HANDLE_INFORMATION));

                        // actually duplicate the handle so we can get its name
                        int dummy = 0;
                        IntPtr duplicatedHandle = new IntPtr();
                        bool success = Kernel32.DuplicateHandle(processHandle, new IntPtr(info.HandleValue), currentProcessHandle, out duplicatedHandle, 0, false, DuplicateOptions.DUPLICATE_SAME_ACCESS);

                        // check if this handle is on disk (a file) so things don't hang
                        if (Kernel32.GetFileType(duplicatedHandle) == FileType.Disk)
                        {
                            if (success)
                            {
                                int length2 = 0x200;
                                IntPtr buffer = Marshal.AllocHGlobal(length2);

                                // use NtQueryObject so we can get this object's name 
                                NT_STATUS status = Ntdll.NtQueryObject(duplicatedHandle, OBJECT_INFORMATION_CLASS.ObjectNameInformation, buffer, length2, out dummy);

                                if (status == NT_STATUS.STATUS_SUCCESS)
                                {
                                    OBJECT_NAME_INFORMATION temp = (OBJECT_NAME_INFORMATION)Marshal.PtrToStructure(buffer, typeof(OBJECT_NAME_INFORMATION));
                                    if (!String.IsNullOrEmpty(temp.Name.ToString()) && !String.IsNullOrEmpty(temp.Name.ToString().Trim()))
                                    {
                                        // only add the file/object to the results if it ends with our target file search pattern
                                        fileHandles.Add(info.HandleValue, temp.Name.ToString().Trim());
                                    }
                                }
                                else
                                {
                                    // Console.WriteLine("[X] NtQueryObject status: {0}", status);
                                }

                                Marshal.FreeHGlobal(buffer);
                            }
                        }
                        Kernel32.CloseHandle(duplicatedHandle);
                    }

                    offset += size;
                }

                Kernel32.CloseHandle(processHandle);
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                    Marshal.FreeHGlobal(ptr);
            }

            // convert all the paths to readable formats
            return ConvertDevicePathsToDosPaths(fileHandles);
        }

        public static List<ProcessFileHandle> GetAllFileHandles()
        {
            // return a list of ALL file handles currently open

            List<ProcessFileHandle> handles = new List<ProcessFileHandle>();
            Process[] processes = Process.GetProcesses();

            // if we have specified process IDs to search for
            foreach (var process in processes)
            {
                var processHandle = GetHandleNames(process.Id);

                foreach (var handle in processHandle)
                {
                    handles.Add(new ProcessFileHandle(process.ProcessName, process.Id, handle.Value, handle.Key));
                }
            }

            return handles;
        }

        public static ProcessFileHandle FindFileHandle(string targetFile, string[] candidateProcesses = null)
        {
            // find a specific file that's open/locked by a process

            Dictionary<int, string> handleNames = new Dictionary<int, string>();
            List<Process> processes = new List<Process>();

            if (candidateProcesses == null)
            {
                // no candidate processes -> search all processes we can
                foreach (Process p in Process.GetProcesses())
                {
                    if(p.HandleCount != 0)
                    {
                        processes.Add(p);
                    }
                }
            }
            else
            {
                // otherwise let's add all of the candidate processes we're looking for
                foreach(string candidateProcess in candidateProcesses)
                {
                    processes.AddRange(Process.GetProcessesByName(candidateProcess));
                }
            }

            // if we have specified process IDs to search for
            foreach (var process in processes)
            {
                var processHandle = GetHandleNames(process.Id);

                foreach (var handle in processHandle)
                {
                    if (handle.Value.EndsWith(targetFile, StringComparison.CurrentCultureIgnoreCase))
                    {
                        return new ProcessFileHandle(process.ProcessName, process.Id, handle.Value, handle.Key);
                    }
                }
            }

            return new ProcessFileHandle();
        }

        public static void CopyLockedFile(ProcessFileHandle fileHandle, string copyTo = "")
        {
            // Copies a locked file to a random temp file or the location specified
            //  -Opens the process with DuplicateHandle permissions
            //  -Duplicates the file handle supplied
            //  -Uses CreateFileMapping() on the duplicated handle
            //  -Uses MapViewOfFile() to map the entire file into memory
            //  -Writes the mapped data to the new temp file

            // open the target process with "duplicate handle" permissions
            IntPtr processHandle = Kernel32.OpenProcess(ProcessAccessFlags.DuplicateHandle, true, (uint)fileHandle.ProcessID);
            IntPtr currentProcessHandle = Kernel32.GetCurrentProcess();

            IntPtr duplicatedHandle = new IntPtr();

            // duplicate the specific file handle opened by the process locking it
            bool success = Kernel32.DuplicateHandle(processHandle, new IntPtr(fileHandle.FileHandleID), currentProcessHandle, out duplicatedHandle, 0, false, DuplicateOptions.DUPLICATE_SAME_ACCESS);

            if (success)
            {
                long fileSize = 0; // size of the file we're copying out
                Kernel32.GetFileSizeEx(duplicatedHandle, out fileSize);

                // create a file mapping with the duplicated handle
                IntPtr mappedPtr = Kernel32.CreateFileMapping(duplicatedHandle, IntPtr.Zero, FileMapProtection.PageReadonly, 0, 0, null);

                // map the entire file into memory
                IntPtr mappedViewPtr = Kernel32.MapViewOfFile(mappedPtr, FileMapAccess.FileMapRead, 0, 0, 0);

                // generate a temporary file name if a target isn't specified
                if(String.IsNullOrEmpty(copyTo))
                {
                    copyTo = Path.GetTempFileName();
                }
                Console.WriteLine($"[*] Copying to: {copyTo}");

                // create the temporary file to copy to
                //  GENERIC_READ = 0x80000000
                //  GENERIC_WRITE = 0x40000000
                //  FILE_SHARE_READ = 0x00000001
                //  FILE_SHARE_WRITE = 0x00000002
                //  CREATE_ALWAYS = 0x00000002
                IntPtr tempFilePtr = Kernel32.CreateFile(copyTo, 0x80000000 | 0x40000000, 0x00000001 | 0x00000002, (IntPtr)null, 0x00000002, 0, (IntPtr)null);
                // write out the memory mapped file to the new temp file
                uint written = 0;
                Kernel32.WriteFile(tempFilePtr, mappedViewPtr, (uint)fileSize, out written, (IntPtr)null);

                Console.WriteLine($"[*] Copied {written} bytes from \"{fileHandle.FileName}\" to \"{copyTo}\"");

                // cleanup
                Kernel32.UnmapViewOfFile(mappedViewPtr);
                Kernel32.CloseHandle(tempFilePtr);
                Kernel32.CloseHandle(duplicatedHandle);
            }

            Kernel32.CloseHandle(processHandle);
        }

        public static void Usage()
        {
            Console.WriteLine("\r\n  LockLess.exe <file.ext | all> [/process:NAME1,NAME2,...] [/copy | /copy:C:\\Temp\\file.ext]\r\n");
        }

        static void Main(string[] args)
        {

            var parsed = ArgumentParser.Parse(args);
            string[] candidateProcesses = null;
            bool copyFile = false;
            string copyDestination = "";

            if (parsed.ParsedOk == false)
            {
                Usage();
                return;
            }

            if (
                parsed.Arguments.ContainsKey("/h") ||
                parsed.Arguments.ContainsKey("/H") ||
                parsed.Arguments.ContainsKey("/?") ||
                parsed.Arguments.ContainsKey("/help") ||
                parsed.Arguments.ContainsKey("/HELP") ||
                parsed.Arguments.ContainsKey("-h") ||
                parsed.Arguments.ContainsKey("-H") ||
                parsed.Arguments.ContainsKey("-?") ||
                parsed.Arguments.ContainsKey("-help") ||
                parsed.Arguments.ContainsKey("-HELP"))
            {
                Usage();
                return;
            }

            var targetFile = args.Length != 0 ? args[0] : "";

            if (String.IsNullOrEmpty(targetFile))
            {
                Usage();
                return;
            }

            if (parsed.Arguments.ContainsKey("/process"))
            {
                candidateProcesses = parsed.Arguments["/process"].Split(',');
            }

            if (parsed.Arguments.ContainsKey("/copy"))
            {
                copyFile = true;
                copyDestination = parsed.Arguments["/copy"];
            }

            if (targetFile == "all")
            {
                Console.WriteLine($"ProcessName,ProcessID,FileHandleID,FileName");

                List<ProcessFileHandle> handles = GetAllFileHandles();

                foreach (ProcessFileHandle handle in handles)
                {
                    Console.WriteLine($"{handle.ProcessName},{handle.ProcessID},{handle.FileHandleID},{handle.FileName}");
                }
            }
            else
            {
                Console.WriteLine($"\r\n[*] Searching processes for an open handle to \"{targetFile}\"");

                ProcessFileHandle foundHandle = FindFileHandle(targetFile, candidateProcesses);

                if (foundHandle.ProcessID != 0)
                {
                    Console.WriteLine($"[+] Process \"{foundHandle.ProcessName}\" ({foundHandle.ProcessID}) has a file handle (ID {foundHandle.FileHandleID}) to \"{foundHandle.FileName}\"");

                    if (copyFile)
                    {
                        CopyLockedFile(foundHandle, copyDestination);
                    }
                }
                else
                {
                    Console.WriteLine($"[X] Handle not found for \"{targetFile}\"");
                }
            }
        }
    }   
}

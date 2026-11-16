#requires -Version 5.1
<#
.SYNOPSIS
    Phase 4 (Rev 4.0) User-Mode C# / PowerShell IOCTL Client for ProcmonSecDrv.sys.
.DESCRIPTION
    Provides PowerShell cmdlets talking to \\.\ProcmonSecDrv via DeviceIoControl:
      - Test-ProcmonSecDrvConnection      (IOCTL_PROCMONSEC_PING)
      - Get-KernelObjectSecurityDescriptor(IOCTL_PROCMONSEC_QUERY_OBJECT_SD — Module 1)
      - Get-KernelDriverLiveDevices       (IOCTL_PROCMONSEC_QUERY_DRIVER_DEVICES — Module 2)
      - Read-PplProcessMemory             (IOCTL_PROCMONSEC_READ_PPL_MEM — Module 3)
      - Receive-KernelHandleEvents        (IOCTL_PROCMONSEC_DRAIN_HANDLE_EVENTS — Module 4)
#>

$csharpDriverClient = @"
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Collections.Generic;

namespace ProcmonPhase4Driver {
    public static class NativeDriverClient {
        private const uint GENERIC_READ  = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_READ  = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;

        public const uint IOCTL_PROCMONSEC_PING                 = 0x00222000;
        public const uint IOCTL_PROCMONSEC_QUERY_OBJECT_SD      = 0x00222004;
        public const uint IOCTL_PROCMONSEC_QUERY_DRIVER_DEVICES = 0x00222008;
        public const uint IOCTL_PROCMONSEC_READ_PPL_MEM         = 0x0022200C;
        public const uint IOCTL_PROCMONSEC_DRAIN_HANDLE_EVENTS  = 0x00222010;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            byte[] lpInBuffer,
            int nInBufferSize,
            byte[] lpOutBuffer,
            int nOutBufferSize,
            out int lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private static IntPtr OpenDriverDevice() {
            IntPtr h = CreateFileW("\\\\.\\ProcmonSecDrv", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (h == new IntPtr(-1)) return IntPtr.Zero;
            return h;
        }

        public class PingResult {
            public bool Connected;
            public uint VersionMajor;
            public uint VersionMinor;
            public bool ObCallbacksActive;
            public uint BufferedHandleEvents;
        }

        public static PingResult Ping() {
            PingResult res = new PingResult();
            IntPtr h = OpenDriverDevice();
            if (h == IntPtr.Zero) return res;
            try {
                byte[] outBuf = new byte[16];
                int ret = 0;
                if (DeviceIoControl(h, IOCTL_PROCMONSEC_PING, null, 0, outBuf, outBuf.Length, out ret, IntPtr.Zero) && ret >= 16) {
                    res.Connected            = true;
                    res.VersionMajor         = BitConverter.ToUInt32(outBuf, 0);
                    res.VersionMinor         = BitConverter.ToUInt32(outBuf, 4);
                    res.ObCallbacksActive    = BitConverter.ToUInt32(outBuf, 8) != 0;
                    res.BufferedHandleEvents = BitConverter.ToUInt32(outBuf, 12);
                }
            } finally {
                CloseHandle(h);
            }
            return res;
        }

        public static byte[] QueryObjectSecurityDescriptor(uint objectKind, uint targetPid, string ntObjectPath, out uint ntStatus) {
            ntStatus = 0xC0000001;
            IntPtr h = OpenDriverDevice();
            if (h == IntPtr.Zero) return null;
            try {
                // PROCMONSEC_SD_REQUEST: uint ObjectKind (4) + uint TargetPid (4) + WCHAR ObjectPath[512] (1024) = 1032 bytes
                byte[] inBuf = new byte[1032];
                Buffer.BlockCopy(BitConverter.GetBytes(objectKind), 0, inBuf, 0, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(targetPid), 0, inBuf, 4, 4);
                if (!string.IsNullOrEmpty(ntObjectPath)) {
                    byte[] strBytes = Encoding.Unicode.GetBytes(ntObjectPath);
                    int copyLen = Math.Min(strBytes.Length, 1022);
                    Buffer.BlockCopy(strBytes, 0, inBuf, 8, copyLen);
                }

                // PROCMONSEC_SD_RESPONSE: uint Status (4) + uint SdLength (4) + UCHAR SdBytes[4096] = 4104 bytes
                byte[] outBuf = new byte[4104];
                int ret = 0;
                if (DeviceIoControl(h, IOCTL_PROCMONSEC_QUERY_OBJECT_SD, inBuf, inBuf.Length, outBuf, outBuf.Length, out ret, IntPtr.Zero) && ret >= 8) {
                    ntStatus = BitConverter.ToUInt32(outBuf, 0);
                    uint sdLen = BitConverter.ToUInt32(outBuf, 4);
                    if (ntStatus == 0 && sdLen > 0 && sdLen <= 4096) {
                        byte[] sd = new byte[sdLen];
                        Buffer.BlockCopy(outBuf, 8, sd, 0, (int)sdLen);
                        return sd;
                    }
                }
                return null;
            } finally {
                CloseHandle(h);
            }
        }

        public class LiveKernelDeviceInfo {
            public string DeviceName;
            public uint DeviceType;
            public uint Characteristics;
            public bool HasSecureOpen;
            public ulong IrpMjCreateAddr;
            public ulong IrpMjCloseAddr;
            public ulong IrpMjDeviceControlAddr;
            public ulong IrpMjInternalDeviceControlAddr;
            public byte[] SdBytes;
            public string Sddl;
        }

        public static List<LiveKernelDeviceInfo> QueryDriverDevices(string driverObjectPath, out uint ntStatus) {
            ntStatus = 0xC0000001;
            List<LiveKernelDeviceInfo> list = new List<LiveKernelDeviceInfo>();
            IntPtr h = OpenDriverDevice();
            if (h == IntPtr.Zero) return list;
            try {
                // PROCMONSEC_DRIVER_QUERY_REQUEST: WCHAR DriverObjectPath[256] = 512 bytes
                byte[] inBuf = new byte[512];
                if (!string.IsNullOrEmpty(driverObjectPath)) {
                    byte[] strBytes = Encoding.Unicode.GetBytes(driverObjectPath);
                    int copyLen = Math.Min(strBytes.Length, 510);
                    Buffer.BlockCopy(strBytes, 0, inBuf, 0, copyLen);
                }

                // PROCMONSEC_DEVICE_ENTRY size = 256 (DeviceName) + 4 (DeviceType) + 4 (Characteristics) + 4 (HasSecureOpen+Reserved) + 32 (4x ULONG64) + 4 (SdLength) + 512 (SdBytes) = 816 bytes
                // PROCMONSEC_DRIVER_QUERY_RESPONSE = 8 + (16 * 816) = 13064 bytes
                const int entrySize = 816;
                byte[] outBuf = new byte[8 + (16 * entrySize)];
                int ret = 0;
                if (DeviceIoControl(h, IOCTL_PROCMONSEC_QUERY_DRIVER_DEVICES, inBuf, inBuf.Length, outBuf, outBuf.Length, out ret, IntPtr.Zero) && ret >= 8) {
                    ntStatus = BitConverter.ToUInt32(outBuf, 0);
                    uint count = BitConverter.ToUInt32(outBuf, 4);
                    if (ntStatus == 0 && count > 0) {
                        for (int i = 0; i < count && i < 16; i++) {
                            int baseOff = 8 + (i * entrySize);
                            LiveKernelDeviceInfo info = new LiveKernelDeviceInfo();
                            int strEnd = 0;
                            while (strEnd < 254 && (outBuf[baseOff + strEnd] != 0 || outBuf[baseOff + strEnd + 1] != 0)) {
                                strEnd += 2;
                            }
                            info.DeviceName                     = (strEnd > 0) ? Encoding.Unicode.GetString(outBuf, baseOff, strEnd) : "";
                            info.DeviceType                     = BitConverter.ToUInt32(outBuf, baseOff + 256);
                            info.Characteristics                = BitConverter.ToUInt32(outBuf, baseOff + 260);
                            info.HasSecureOpen                  = outBuf[baseOff + 264] != 0;
                            info.IrpMjCreateAddr                = BitConverter.ToUInt64(outBuf, baseOff + 268);
                            info.IrpMjCloseAddr                 = BitConverter.ToUInt64(outBuf, baseOff + 276);
                            info.IrpMjDeviceControlAddr         = BitConverter.ToUInt64(outBuf, baseOff + 284);
                            info.IrpMjInternalDeviceControlAddr = BitConverter.ToUInt64(outBuf, baseOff + 292);
                            uint sdLen                          = BitConverter.ToUInt32(outBuf, baseOff + 300);
                            if (sdLen >= 20 && sdLen <= 512) {
                                info.SdBytes = new byte[sdLen];
                                Buffer.BlockCopy(outBuf, baseOff + 304, info.SdBytes, 0, (int)sdLen);
                                try {
                                    RawSecurityDescriptor rsd = new RawSecurityDescriptor(info.SdBytes, 0);
                                    info.Sddl = rsd.GetSddlForm(AccessControlSections.All);
                                } catch {
                                    info.Sddl = "";
                                }
                            } else {
                                info.Sddl = "";
                            }
                            list.Add(info);
                        }
                    }
                }
            } finally {
                CloseHandle(h);
            }
            return list;
        }

        public static byte[] ReadPplMemory(uint targetPid, ulong virtualAddress, uint size, out uint ntStatus) {
            ntStatus = 0xC0000001;
            if (size == 0 || size > 65536) return null;
            IntPtr h = OpenDriverDevice();
            if (h == IntPtr.Zero) return null;
            try {
                // PROCMONSEC_READ_MEM_REQUEST: uint TargetPid (4) + uint Size (4) + ulong VirtualAddress (8) = 16 bytes
                byte[] inBuf = new byte[16];
                Buffer.BlockCopy(BitConverter.GetBytes(targetPid), 0, inBuf, 0, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(size), 0, inBuf, 4, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(virtualAddress), 0, inBuf, 8, 8);

                byte[] outBuf = new byte[8 + size];
                int ret = 0;
                if (DeviceIoControl(h, IOCTL_PROCMONSEC_READ_PPL_MEM, inBuf, inBuf.Length, outBuf, outBuf.Length, out ret, IntPtr.Zero) && ret >= 8) {
                    ntStatus = BitConverter.ToUInt32(outBuf, 0);
                    uint bytesRead = BitConverter.ToUInt32(outBuf, 4);
                    if (ntStatus == 0 && bytesRead > 0 && bytesRead <= size) {
                        byte[] data = new byte[bytesRead];
                        Buffer.BlockCopy(outBuf, 8, data, 0, (int)bytesRead);
                        return data;
                    }
                }
                return null;
            } finally {
                CloseHandle(h);
            }
        }

        public class KernelHandleEvent {
            public uint CallerPid;
            public uint CallerTid;
            public uint TargetPid;
            public uint Operation;
            public uint DesiredAccess;
            public bool IsKernelHandle;
            public long TimestampFileTime;
        }

        public static List<KernelHandleEvent> DrainHandleEvents() {
            List<KernelHandleEvent> list = new List<KernelHandleEvent>();
            IntPtr h = OpenDriverDevice();
            if (h == IntPtr.Zero) return list;
            try {
                // PROCMONSEC_HANDLE_EVENT = 32 bytes; PROCMONSEC_DRAIN_EVENTS_RESPONSE = 4 + (64 * 32) = 2052 bytes
                const int evSize = 32;
                byte[] outBuf = new byte[4 + (64 * evSize)];
                int ret = 0;
                if (DeviceIoControl(h, IOCTL_PROCMONSEC_DRAIN_HANDLE_EVENTS, null, 0, outBuf, outBuf.Length, out ret, IntPtr.Zero) && ret >= 4) {
                    uint count = BitConverter.ToUInt32(outBuf, 0);
                    for (int i = 0; i < count && i < 64; i++) {
                        int off = 4 + (i * evSize);
                        KernelHandleEvent ev = new KernelHandleEvent();
                        ev.CallerPid         = BitConverter.ToUInt32(outBuf, off);
                        ev.CallerTid         = BitConverter.ToUInt32(outBuf, off + 4);
                        ev.TargetPid         = BitConverter.ToUInt32(outBuf, off + 8);
                        ev.Operation         = BitConverter.ToUInt32(outBuf, off + 12);
                        ev.DesiredAccess     = BitConverter.ToUInt32(outBuf, off + 16);
                        ev.IsKernelHandle    = outBuf[off + 20] != 0;
                        ev.TimestampFileTime = BitConverter.ToInt64(outBuf, off + 24);
                        list.Add(ev);
                    }
                }
            } finally {
                CloseHandle(h);
            }
            return list;
        }
    }
}
"@

try {
    Add-Type -TypeDefinition $csharpDriverClient -Language CSharp -ErrorAction Stop
} catch {
    if (-not $_.Exception.Message.Contains("already exists")) {
        Write-Warning "Failed to compile NativeDriverClient: $($_.Exception.Message)"
    }
}

function Test-ProcmonSecDrvConnection {
    try {
        return [ProcmonPhase4Driver.NativeDriverClient]::Ping()
    } catch {
        return [PSCustomObject]@{ Connected = $false; VersionMajor = 0; VersionMinor = 0; ObCallbacksActive = $false; BufferedHandleEvents = 0 }
    }
}

function Get-KernelObjectSecurityDescriptor {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('FileOrDevice','RegistryKey','ProcessPid')]
        [string]$ObjectKind,

        [uint32]$TargetPid = 0,

        [string]$NtObjectPath = ""
    )
    $kindMap = @{ 'FileOrDevice' = 0; 'RegistryKey' = 1; 'ProcessPid' = 2 }
    $ntStatus = [uint32]0
    $sdBytes = [ProcmonPhase4Driver.NativeDriverClient]::QueryObjectSecurityDescriptor([uint32]$kindMap[$ObjectKind], $TargetPid, $NtObjectPath, [ref]$ntStatus)
    $sddl = ""
    if ($null -ne $sdBytes -and $sdBytes.Length -ge 20) {
        try {
            $rsd = New-Object System.Security.AccessControl.RawSecurityDescriptor($sdBytes, 0)
            $sddl = $rsd.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
        } catch {}
    }
    return [PSCustomObject]@{
        Success  = ($null -ne $sdBytes -and $ntStatus -eq 0)
        NtStatus = ("0x{0:X8}" -f $ntStatus)
        SdBytes  = $sdBytes
        Sddl     = $sddl
    }
}

function Get-KernelDriverLiveDevices {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DriverName
    )
    $drvPath = if ($DriverName.StartsWith("\")) { $DriverName } else { "\Driver\$DriverName" }
    $ntStatus = [uint32]0
    $devs = [ProcmonPhase4Driver.NativeDriverClient]::QueryDriverDevices($drvPath, [ref]$ntStatus)
    return [PSCustomObject]@{
        DriverPath = $drvPath
        Success    = ($ntStatus -eq 0)
        NtStatus   = ("0x{0:X8}" -f $ntStatus)
        Devices    = @($devs)
    }
}

function Read-PplProcessMemory {
    param(
        [Parameter(Mandatory=$true)]
        [uint32]$TargetPid,

        [Parameter(Mandatory=$true)]
        [uint64]$VirtualAddress,

        [Parameter(Mandatory=$true)]
        [ValidateRange(1, 65536)]
        [uint32]$Size
    )
    $ntStatus = [uint32]0
    $bytes = [ProcmonPhase4Driver.NativeDriverClient]::ReadPplMemory($TargetPid, $VirtualAddress, $Size, [ref]$ntStatus)
    return [PSCustomObject]@{
        Success   = ($null -ne $bytes -and $ntStatus -eq 0)
        NtStatus  = ("0x{0:X8}" -f $ntStatus)
        BytesRead = if ($null -ne $bytes) { $bytes.Length } else { 0 }
        Data      = $bytes
    }
}

function Receive-KernelHandleEvents {
    return @([ProcmonPhase4Driver.NativeDriverClient]::DrainHandleEvents())
}

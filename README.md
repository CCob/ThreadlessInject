# Threadless Process Injection

From my Bsides Cymru 2023 talk: **[Needles Without the Thread](https://pretalx.com/bsides-cymru-2023-2022/talk/BNC8W3/)**.

> As red teamers, we always find ourselves in a cat and mouse game with the blue team. Many Anti-virus and EDR solutions over the past 10 years have become significantly more advanced at detecting fileless malware activity in a generic way.
>
> Process injection, a technique used for executing code from within the address space of another process is a common method within the offensive operator’s toolbox. Commonly used to mask activity within legitimate processes such as browsers and instant messaging clients already running on the target workstation.
>
> Within the last 2 years, tools such as Sysmon have added new detections and events for process injection along with big improvements in detections within commercial EDR space.
> With this in mind, a new method of injection was researched that would not fall foul to the traditional methods that are often detected today.

# Usage

```powershell
# inject calc-loader-shellcode into Chrome's kernelbase.dll!CreateEventW
.\ThreadlessInject.exe -p (Get-Process "Chrome").id -d kernelbase.dll -e CreateEventW
```

```powershell
# inject ret-0-shellcode into Notepads's kernelbase.dll!MapViewOfFileEx
.\ThreadlessInject.exe -p (Get-Process "Notepad").id -d kernelbase.dll -e MapViewOfFileEx -x "SDHAww=="
```

```powershell
# inject calc-loader-shellcode into Notepads's kernelbase.dll!MapViewOfFileEx searching for a code cave in a random remote DLL
.\ThreadlessInject.exe -p (Get-Process "Notepad").id -d kernelbase.dll -e MapViewOfFileEx -c -r
```

## Possible Improvements

- [x] Use more covert allocation and write primitives.
- [ ] Use patchless hooking via debugger attachment and hardware breakpoints [(https://www.pentestpartners.com/security-blog/patchless-amsi-bypass-using-sharpblock)](https://www.pentestpartners.com/security-blog/patchless-amsi-bypass-using-sharpblock/).
- [x] Avoid RWX on hooked function.  Hook assembly will need to handle VirtualProtect calls.
- [x] Support any DLL via remote module enumeration.

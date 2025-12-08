# Add-Type
By specifying `Add-Type` in PowerShell, it will **compile and create** an object. This can be used to define classes, enums, structs, and even `P/Invoke` signatures.

``` powershell
Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class CustomMethods
{
    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentProcessId();
}
"@

# Call it:
[CustomMethods]::GetCurrentProcessId()
```
> Defining `@` keywords allows multi-line text in PowerShell

## OPSEC
When using `Add-Type` to compile `C#` code in PowerShell, it is to note that files are being **written** to disk. It will generate the following events
- `CreateFile`
- `WriteFile`
- `CloseFile`
Hence, this may be used to **trigger EDRs  or antivirus solutions** on the system.

> The files being created during compilation are randomly generated.

# AppDomain Class
## What is AppDomain?
`AppDomain` class represents an **application domain** which is a logical isolation inside a single process where `.NET` code runs. One of the reason `AppDomain` was introduced  was to separate **loaded assemblies**.

> Think of it as a lightweight sandbox inside a process.

You can enumerate the assemblies loaded in the current PowerShell session with:
``` powershell
[AppDomain]::CurrentDomain.GetAssemblies()
# or
[System.AppDomain]::CurrentDomain.GetAssemblies()
```

Because PowerShell runs on `.NET`, any of these loaded assemblies can be inspected and consumed directly from PowerShell without compiling additional code which resolves the OPSEC issues faced when using `Add-Type`.
## Dynamic Lookups
To mitigate the OPSEC concerns associated with `Add-Type`, PowerShell can rely on `AppDomain` to discover precompiled assemblies that are already loaded in the process, and use those existing types to achieve the required functionality without compiling new code.
### Background: Required Native Functions

Before we can dynamically lookup addresses of functions useful to us, we have to locate the pre-loaded assemblies that export these functions: 
- `GetModuleHandle`: Retrieves a module handle for the specified module. The module must have been loaded by the calling process.
	``` c++
	HMODULE GetModuleHandleA(
		[in, optional] LPCSTR lpModuleName
	);
	```
- `GetProcAddress`: Retrieves the address of an exported function (also known as a procedure) or variable from the specified dynamic-link library (DLL).
	``` c++
	FARPROC GetProcAddress(
		[in] HMODULE hModule,
		[in] LPCSTR  lpProcName
	);
	```

Since these functions are exposed via Win32 APIs, they’re often wrapped in internal .NET classes with names like `NativeMethods`, `SafeNativeMethods`, or `UnsafeNativeMethods`. We should review these classes, especially `UnsafeNativeMethods`, to find the P/Invoke signatures we can reuse.

> UnsafeNativeMethods is a naming convention used for classes that wraps **unmanaged** APIs such as Win32 APIs. 

### Finding .NET Wrappers for `GetModuleHandle` and `GetProcAddress`

As mentioned above, the `GetModuleHandle` and `GetProcAddress` can be found in assembly with the `UnsafeNativeMethods`. This can be performed using the following PowerShell script:
``` powershell
# Get all assemblies loaded into the current AppDomain
$assemblies = [AppDomain]::CurrentDomain.GetAssemblies()

foreach ($assembly in $assemblies) {

    # Try to resolve the UnsafeNativeMethods type from this assembly
    try {
        $unsafeType = $assembly.GetType('Microsoft.Win32.UnsafeNativeMethods', $false)
    } catch {
        $unsafeType = $null
    }

    if (-not $unsafeType) { continue }

    # If we’re here, this assembly defines Microsoft.Win32.UnsafeNativeMethods
    $assemblyName = $assembly.GetName().Name
    $assemblyPath = $assembly.Location

    Write-Host "Found Microsoft.Win32.UnsafeNativeMethods in:"
    Write-Host "  Assembly Name : $assemblyName"
    Write-Host "  Assembly Path : $assemblyPath"
    Write-Host

    # Get all static methods on this type
    $methods = $unsafeType.GetMethods([System.Reflection.BindingFlags] "Public,NonPublic,Static")

    # Filter for GetModuleHandle and GetProcAddress
    $targetMethods = $methods | Where-Object {
        $_.Name -in 'GetModuleHandle', 'GetProcAddress'
    }

    foreach ($m in $targetMethods) {
        $paramStrings = $m.GetParameters() |
            ForEach-Object { "$($_.ParameterType.Name) $($_.Name)" }

        $paramsJoined = $paramStrings -join ', '

        Write-Host "  Method : $($m.Name)"
        Write-Host "    Return Type : $($m.ReturnType.FullName)"
        Write-Host "    Signature   : $($m.Name)($paramsJoined)"
        Write-Host
    }
}
```

The desired methods can be found in `System.dll` (note there may be others):
``` powershell
Found Microsoft.Win32.UnsafeNativeMethods in:
  Assembly Name : System
  Assembly Path : C:\Windows\Microsoft.Net\assembly\GAC_MSIL\System\v4.0_4.0.0.0__b77a5c561934e089\System.dll

  Method : GetModuleHandle
    Return Type : System.IntPtr
    Signature   : GetModuleHandle(String modName)

  Method : GetProcAddress
    Return Type : System.IntPtr
    Signature   : GetProcAddress(IntPtr hModule, String methodName)

  Method : GetProcAddress
    Return Type : System.IntPtr
    Signature   : GetProcAddress(HandleRef hModule, String lpProcName)
```

**However**, we are not able call these methods which was intended for internal use by `.NET` code. This can be seen by using `dnSpy` and loading the `System.dll`: 
``` c#
namespace Microsoft.Win32
{
	[SuppressUnmanagedCodeSecurity]
	[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
	internal static class UnsafeNativeMethods {
		[DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto)]  
		public static extern IntPtr GetModuleHandle(string modName);
		
		[DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]  
		public static extern IntPtr GetProcAddress(IntPtr hModule, string methodName);
		
		[DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Ansi)]  
		public static extern IntPtr GetProcAddress(HandleRef hModule, string lpProcName);
		
		...
	}
```
### Getting reference with reflection
#### Understanding Reflection API
Because `Microsoft.Win32.UnsafeNativeMethods` is an internal type, its methods are not directly accessible from external code. However, we can still obtain the type and invoke its methods by using `.NET` reflection APIs.

> Reflection APIs can be treated as a "master" key which unlocks locked door for us.

There are three reflection APIs that will be used `GetType`, `GetMethod`, and `Invoke`.
#### Using Reflection API
``` powershell
$systemdll = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('Syst' + 'em.dll') })

$systemdll.GetType().FullName
> System.Reflection.RuntimeAssembly
```
`$systemdll` right now is an **Assembly** object which represents the loaded `System.dll` file. 

Afterwards, the following command is ran
``` Powershell
$unsafeObj = $systemdll.GetType('Microsoft.Win32.UnsafeNativeMethods')
```
This looks inside the metadata of the assembly and returns the `Type` object. The `Type` object provides us another useful reflection API `GetMethod`.

``` powershell
$GetModuleHandle = $unsafeObj.GetMethod("GetModuleHandle")
$GetProcAddress = $unsafeObj.GetMethod("GetProcAddress", [Type[]]@([System.IntPtr], [string]))
```

> From previous section, we found that `System.dll` overloads `GetProcAddress`. `GetMethod` allows us to define which overload we want to use.

Now, we can utilize `Invoke` from the `MethodInfo` class to run the execute the functions.
``` Powershell
$modulePtr = $GetModuleHandle.Invoke($null, @("user32.dll"))

$funcPtr = $GetProcAddress.Invoke($null, @($modulePtr, "MessageBoxA"))
```
#### Creating a Powershell function utilizing reflection
To provide reusability, we will define a function in PowerShell
``` powershell
function LookupFunc {
    param(
        [string]$ModuleName,
        [string]$FunctionName
    )

    # Get System.dll assembly
    $systemdll = [AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object {
            $_.GlobalAssemblyCache -and
            [IO.Path]::GetFileName($_.Location) -eq 'Syst' + 'em.dll'
        } |
        Select-Object -First 1

    # Get the internal UnsafeNativeMethods type
    $unsafeObj = $systemdll.GetType('Microsoft.Win32.UnsafeNativeMethods')

    # Get the methods we want
    $GetModuleHandle = $unsafeObj.GetMethod('GetModuleHandle', [Type[]]@([string]))
    $GetProcAddress  = $unsafeObj.GetMethod('GetProcAddress', [Type[]]@([System.IntPtr], [string]))

    # Call GetModuleHandle(moduleName)
    $modulePtr = $GetModuleHandle.Invoke($null, @($ModuleName))

    # Call GetProcAddress(hModule, functionName) and return the function pointer
    $GetProcAddress.Invoke($null, @($modulePtr, $FunctionName))
}
```

# Delegates Type
With the ability to reference Win32 APIs with the `LookupFunc` created, we are left with defining the arguments and it's type. This can be achieved through the use of `Delegates` type. According the the [documentation](https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/delegates/):

>When you instantiate a delegate, you can associate the delegate instance with any method that has a compatible signature and return type.

The intended purpose of `Delegates` is to reduce duplication of code. For [example](https://stackoverflow.com/questions/2019402/when-why-to-use-delegates), the delegate defined represents a method which returns a `bool` and takes a `Person` type as its argument:
``` c#
public delegate bool FilterDelegate(Person p);
```

Other methods with the same signature is also defined:
``` csharp
static bool IsChild(Person p) {
  return p.Age < 18;
}

static bool IsAdult(Person p) {
  return p.Age >= 18;
}

static bool IsSenior(Person p) {
  return p.Age >= 65;
}
```

And they are all called through the `filter(p)`:
``` csharp
if (filter(p)) { // ...
```

In our context, delegates define the structure and calling convention for how a function pointer should be interpreted and invoked. However, because PowerShell does not expose the delegate keyword, we must **define a delegate type ourselves** by creating a small .NET class (in an in-memory assembly) and loading it into the PowerShell runtime.

After defining the delegate type, we can then use `GetDelegateForFunctionPointer` to convert an **unmanaged** pointer to a delegate:
``` c++
public static Delegate GetDelegateForFunctionPointer(IntPtr ptr, Type t);
// t: The type of the delegate to be returned.
```

``` powershell
$func = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($funcPtr, $customDelegateType)
$func.Invoke($funcArgument)
```
## Utilizing `GetDelegateForFunctionPointer`
### Initializing a custom delegate type
We can initialize a delegate type either by using `Add-Type` (which compiles C# and writes an assembly to disk) or by creating a dynamic in-memory assembly with `AssemblyName`/`Reflection.Emit` and defining the delegate type inside it.

``` powershell
$customAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
```

**1. Create assembly in memory**
In order to make it not save on disk and executable, we utilize the `DefineDynamicAssembly` method:
``` csharp
public static System.Reflection.Emit.AssemblyBuilder 
	DefineDynamicAssembly(System.Reflection.AssemblyName name, System.Reflection.Emit.AssemblyBuilderAccess access);
```

``` powershell
$domain = [AppDomain]::CurrentDomain
$myAsmBuilder = $domain.DefineDynamicAssembly($customAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
```

|Name|Value|Description|
|---|---|---|
|Run|1|The dynamic assembly can be executed, but not saved.|
**2. Defining a module for assembly**
A module can now be defined in the created assembly using `DefineDynamicModule`
``` csharp
public System.Reflection.Emit.ModuleBuilder DefineDynamicModule(string name, bool emitSymbolInfo);
```

We will set `emitSymbolInfo` to false as this will generate debugging symbol information that debuggers can use.
``` powershell
# System.Reflection.Emit.ModuleBuilder
$myModuleBuilder = $myAsmBuilder.DefineDynamicModule('ReflectedModule', $false);
```

**3. Construct the Delegate type**
After the module is defined, we can define the **delegate type** through the `DefineType` method:
``` csharp
public System.Reflection.Emit.TypeBuilder DefineType(string name, System.Reflection.TypeAttributes attr, Type parent);
```

The **crucial** argument here is `[System.MulticastDelegate]` as it is practically saying that "*this type is a delegate*".
``` powershell
# $myTypeBuilder is a TypeBuilder that represents a delegate type under construction
$myTypeBuilder = $myModuleBuilder.DefineType(
    'DelegateType',
    'Class, Public, Sealed, AnsiClass, AutoClass',
    [System.MulticastDelegate]
)
```

**4. Define the constructor**
`DefineConstructor` can be used to add a constructor to the `DelegateType`.

``` csharp
public System.Reflection.Emit.ConstructorBuilder DefineConstructor(
	System.Reflection.MethodAttributes attributes, 
	System.Reflection.CallingConventions callingConvention, 
	Type[]? parameterTypes
);
```

> A constructor is a special method within a class that is automatically called when an object is created to initialize it.

Suppose we want the delegate type for `VirtualAllocA`
``` c++
LPVOID VirtualAlloc(
	[in, optional] LPVOID lpAddress,
	[in]           SIZE_T dwSize,
	[in]           DWORD  flAllocationType,
	[in]           DWORD  flProtect
);
```

Then the constructor should be defined as follow (in Powershell):
``` PowerShell
$myConstructorBuilder = $myTypeBuilder.DefineConstructor(
	'RTSpecialName, HideBySig, Public',
    [System.Reflection.CallingConventions]::Standard,
    @([IntPtr, [UInt32], [UInt32], [UInt32]]
)
$myConstructorBuilder.SetImplementationFlags('Runtime, Managed')
```

**5. Define the Invoke method**
The `Invoke` method defines the delegate's signature which helps in marshalling arguments and calling the unmanaged function
``` powershell
$myMethodBuilder = $myTypeBuilder.DefineMethod(
	'Invoke',
	'Public, HideBySig, NewSlot, Virtual',
	[int],
	@([IntPtr, [int], [String], [String]]
)
$myMethodBuilder.SetImplementationFlags('Runtime, Managed')
```

**6. Instantiate delegate type**
The custom constructor can be called through the `CreateType`:
``` powershell
$myDelegateType = $myTypeBuilder.CreateType()
```
### Utilizing custom delegate type
After instantiating the delegate type, we can utilize the delegate type through `GetDelegateFunctionPointer`:
``` powershell
$virtualAllocAddr = LookupFunc kernel32.dll VirtualAlloc

# instantiate delegate type
$myVirtualAllocDelegate = $myTypeBuilder.CreateType()

$virtualAlloc = $System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($virtualAllocAddr, $myVirtualAllocDelegate)

$virtualAlloc.Invoke([IntPtr]::Zero, 0x1, 0x3000, 0x40)
```

### Modularizing delegate type instantiation
The code for instantiating a delegate type can be modularized:
``` powershell
function CustomDelegateType {
    param(
        [Parameter(Mandatory = $true)]
        [string] $DelegateName,

        [Parameter(Mandatory = $true)]
        [Type]   $ReturnType,

        [Parameter(Mandatory = $true)]
        [Type[]] $ParameterTypes
    )

    # 1. Create a dynamic in-memory assembly & module
    $asmName        = New-Object System.Reflection.AssemblyName 'ReflectedDelegates'
    $domain         = [AppDomain]::CurrentDomain
    $asmBuilder     = $domain.DefineDynamicAssembly(
        $asmName,
        [System.Reflection.Emit.AssemblyBuilderAccess]::Run  # execute only, do not save
    )
    $modBuilder     = $asmBuilder.DefineDynamicModule('ReflectedModule', $false)  # no symbol info

    # 2. Define the delegate type: public sealed class <DelegateName> : MulticastDelegate
    $typeAttrs      = [System.Reflection.TypeAttributes] 'Class, Public, Sealed, AnsiClass, AutoClass'
    $typeBuilder    = $modBuilder.DefineType(
        $DelegateName,
        $typeAttrs,
        [System.MulticastDelegate]
    )

    # 3. Define the standard delegate constructor: .ctor(object target, IntPtr method)
    $ctorAttrs      = [System.Reflection.MethodAttributes] 'Public, HideBySig, SpecialName, RTSpecialName'
    $ctorParamTypes = [Type[]]@([object], [IntPtr])

    $ctorBuilder = $typeBuilder.DefineConstructor(
        $ctorAttrs,
        [System.Reflection.CallingConventions]::Standard,
        $ctorParamTypes
    )

    $ctorBuilder.SetImplementationFlags(
        [System.Reflection.MethodImplAttributes] 'Runtime, Managed'
    )

    # 4. Define Invoke(...) with your desired signature
    #    This is the actual delegate signature used for marshalling and calling.
    $invokeAttrs = [System.Reflection.MethodAttributes] 'Public, HideBySig, NewSlot, Virtual'

    $invokeBuilder = $typeBuilder.DefineMethod(
        'Invoke',
        $invokeAttrs,
        $ReturnType,
        $ParameterTypes
    )

    $invokeBuilder.SetImplementationFlags(
        [System.Reflection.MethodImplAttributes] 'Runtime, Managed'
    )

    # 5. Finalize and return the delegate Type
    return $typeBuilder.CreateType()
}
```

# References
- Offensive Security: Evasion Techniques and Breaching Defenses
- Microsoft Documentation
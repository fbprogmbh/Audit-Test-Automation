# Loading the module

When loading the module, make sure that the manifest is loaded as well. Do not include the file extension of the module file.

```Powershell
Import-Module -Name .\IIS10Audit -Verbose
```

This is important because the manifest tells Powershell about the assemblies and modules that the module requires.
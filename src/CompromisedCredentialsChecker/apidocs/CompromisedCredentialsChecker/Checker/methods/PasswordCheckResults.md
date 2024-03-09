﻿<!--  
  <auto-generated>   
    The contents of this file were generated by a tool.  
    Changes to this file may be list if the file is regenerated  
  </auto-generated>   
-->

# Checker.PasswordCheckResults Method

**Declaring Type:** [Checker](../index.md)  
**Namespace:** [CompromisedCredentialsChecker](../../index.md)  
**Assembly:** CompromisedCredentialsChecker  
**Assembly Version:** 1.1.0+a9a21def0e2af4af3a7b63addf16a5ea0ec3c567

Determine if the password has been found in a hack, returns API results as a string

```csharp
public static string PasswordCheckResults(string ApiKey, string UserAgent, string PlainPassword);
```

## Parameters

`ApiKey`  string

API Key from https:\/\/haveibeenpwned.com\/API\/Key

`UserAgent`  string

String to indicate what application is using the API

`PlainPassword`  string

The password to be checked

## Returns

string

Raw result from the API

___

*Documentation generated by [MdDocs](https://github.com/ap0llo/mddocs)*
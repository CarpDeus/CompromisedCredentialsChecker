﻿<!--  
  <auto-generated>   
    The contents of this file were generated by a tool.  
    Changes to this file may be list if the file is regenerated  
  </auto-generated>   
-->

# Checker.CheckPastesResult Method

**Declaring Type:** [Checker](../index.md)  
**Namespace:** [CompromisedCredentialsChecker](../../index.md)  
**Assembly:** CompromisedCredentialsChecker  
**Assembly Version:** 1.1.0+22dbbdca84054ddb046fb45a459f0b9fcca949b8

Check for pastes that have been found that include this email address. Returns API results as a string

```csharp
public static string CheckPastesResult(string ApiKey, string UserAgent, string emailAddress);
```

## Parameters

`ApiKey`  string

API Key from https:\/\/haveibeenpwned.com\/API\/Key

`UserAgent`  string

String to indicate what application is using the API

`emailAddress`  string

Email address to be searched for

## Returns

string

Raw result from the API

___

*Documentation generated by [MdDocs](https://github.com/ap0llo/mddocs)*

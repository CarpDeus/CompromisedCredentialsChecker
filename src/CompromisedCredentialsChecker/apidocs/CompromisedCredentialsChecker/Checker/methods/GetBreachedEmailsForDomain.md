﻿<!--  
  <auto-generated>   
    The contents of this file were generated by a tool.  
    Changes to this file may be list if the file is regenerated  
  </auto-generated>   
-->

# Checker.GetBreachedEmailsForDomain Method

**Declaring Type:** [Checker](../index.md)  
**Namespace:** [CompromisedCredentialsChecker](../../index.md)  
**Assembly:** CompromisedCredentialsChecker  
**Assembly Version:** 1.0.0\-alpha+23c76aa59eca04a3d453c27db8bebfed2cebeb6d

Determine all the breaches for email addresses for a specific domain.

```csharp
public static object GetBreachedEmailsForDomain(string ApiKey, string UserAgent, string Domain);
```

## Parameters

`ApiKey`  string

API Key from https:\/\/haveibeenpwned.com\/API\/Key

`UserAgent`  string

String to indicate what application is using the API

`Domain`  string

Email address to be searched for

## Returns

object

All email addresses on a given domain and the breaches they've appeared in can be returned via the domain search API. Only domains that have been successfully added to the domain search dashboard after verifying control can be searched. 

___

*Documentation generated by [MdDocs](https://github.com/ap0llo/mddocs)*
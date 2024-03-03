﻿<!--  
  <auto-generated>   
    The contents of this file were generated by a tool.  
    Changes to this file may be list if the file is regenerated  
  </auto-generated>   
-->

# HIBPSubscriptionStatus Class

**Namespace:** [CompromisedCredentialsChecker](../index.md)  
**Assembly:** CompromisedCredentialsChecker  
**Assembly Version:** 1.0.0\-alpha+23c76aa59eca04a3d453c27db8bebfed2cebeb6d

SubscriptionStatus from the HaveIBeenPwned API

```csharp
public class HIBPSubscriptionStatus
```

**Inheritance:** object → HIBPSubscriptionStatus

## Constructors

| Name                                              | Description |
| ------------------------------------------------- | ----------- |
| [HIBPSubscriptionStatus()](constructors/index.md) |             |

## Properties

| Name                                                                             | Description                                                                                                                                                                            |
| -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Description](properties/Description.md)                                         | A human readable sentence explaining the scope of the subscription.                                                                                                                    |
| [DomainSearchMaxBreachedAccounts](properties/DomainSearchMaxBreachedAccounts.md) | The size of the largest domain the subscription can search. This is expressed in the total number of breached accounts on the domain, excluding those that appear solely in spam list. |
| [Rpm](properties/Rpm.md)                                                         | The rate limit in requests per minute. This applies to the rate the breach search by email address API can be requested.                                                               |
| [SubscribedUntil](properties/SubscribedUntil.md)                                 | The date and time the current subscription ends in ISO 8601 format.                                                                                                                    |
| [SubscriptionName](properties/SubscriptionName.md)                               | The name representing the subscription being either "Pwned 1", "Pwned 2", "Pwned 3" or "Pwned 4".                                                                                      |

___

*Documentation generated by [MdDocs](https://github.com/ap0llo/mddocs)*
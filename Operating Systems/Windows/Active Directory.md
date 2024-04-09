# Content
- [Organizational unit](#organizational-unit)
- [Group Policy Objects](#group-policy-objects)
  - [GPO types](#gpo-types)   
- [Objects](#objects)
  - [Groups](#groups)


## Organizational unit
- An Organizational Unit (OU) in Active Directory is a logical container object used to organize and manage users, groups, computers, and other Active Directory objects within a domain. 
- can apply policy using `Group Policy`

![Screenshot_3](https://github.com/kiro6/penetration-testing-notes/assets/57776872/59e4ee58-42c3-4aba-8f7f-30347151ee22)



## Group Policy Objects 
Group Policy Objects (GPOs) can be linked to OUs to apply specific configurations, settings, and policies to the objects within those OUs. This allows administrators to apply different policies based on the requirements of different departments or organizational units.

![Screenshot_1](https://github.com/kiro6/penetration-testing-notes/assets/57776872/a0c7ec7a-de08-405b-b48c-43e0ec1b45a3)


![Screenshot_2](https://github.com/kiro6/penetration-testing-notes/assets/57776872/6fadfe24-f2e4-4e40-b5e3-d213dfbc96ac)



#### for example : 
- Password Policy: Enforce password complexity requirements, minimum password length, and password expiration policies to enhance security.

- Account Lockout Policy: Configure settings to lock out user accounts after a certain number of incorrect login attempts, helping to prevent unauthorized access.

- Software Installation: Automatically install software applications on users' computers upon startup or user login, ensuring consistent software deployment across the organization.


### GPO types

| Level                           | Description                                                                                                                                                                                                                                                                                                                               |
|---------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Local Group Policy              | The policies are defined directly to the host locally outside the domain. Any setting here will be overwritten if a similar setting is defined at a higher level.                                                                                                                                                                       |
| Site Policy                     | Any policies specific to the Enterprise Site that the host resides in. Remember that enterprise environments can span large campuses and even across countries. So it stands to reason that a site might have its own policies to follow that could differentiate it from the rest of the organization. Access Control policies are a great example of this. Say a specific building or site performs secret or restricted research and requires a higher level of authentication for access to resources. You could specify those settings at the site level and ensure they are linked so as not to be overwritten by domain policy. This is also a great way to perform actions like printer and share mapping for users in specific sites. |
| Domain-wide Policy             | Any settings you wish to have applied across the domain as a whole. For example, setting the password policy complexity level, configuring a Desktop background for all users, and setting a Notice of Use and Consent to Monitor banner at the login screen.                                                                                                                                |
| Organizational Unit (OU)       | These settings would affect users and computers who belong to specific OUs. You would want to place any unique settings here that are role-specific. For example, the mapping of a particular share drive that can only be accessed by HR, access to specific resources like printers, or the ability for IT admins to utilize PowerShell and command-prompt.                                                              |
| Any OU Policies nested within other OUs | Settings at this level would reflect special permissions for objects within nested OUs. For example, providing Security Analysts a specific set of Applocker policy settings that differ from the standard IT Applocker settings.                                                                                                                                                                      |


![Screenshot_4](https://github.com/kiro6/penetration-testing-notes/assets/57776872/d2eadbff-043d-49c0-aae5-bba627ae372a)


## Objects 

### Groups
**there are 2 types of groups** 
1) **security Group:**
used to manage access permissions to resources such as files, folders, printers, and other objects within the network. Security groups allow you to grant or deny access to these resources based on the membership of users or other groups.

2) **Distribution Groups:**
These are used primarily for email distribution purposes. Distribution groups allow you to send emails to multiple recipients by simply addressing the email to the group rather than individual email addresses.


**there 3 types of scope:** 

1) **Domain Local Groups**
2) **Global Groups**
3) **Universal Groups**


| Group Scope        | Can Contain                                             | Cannot Contain                                     |
|--------------------|---------------------------------------------------------|-----------------------------------------------------|
| Global Groups      | Users from the same domain, global groups from the same domain | Users from other domains or forests, local groups |
| Domain Local Groups| Users, global groups from the same domain, universal groups from any domain within the forest, users or groups from any trusted forest | Users or groups from other forests |
| Universal Groups   | Users from any domain within the forest, global groups from any domain within the forest, other universal groups | Users or groups from trusted external forests |




In a small environment, there's really no difference in practicebut in an environment with multiple domains and/or forests, a common approach to managing permissions involves using domain local groups to attach permissions to resources. Then, access is granted via universal groups, which can span across domains within the forest. Finally, global groups containing users are added to the universal groups.

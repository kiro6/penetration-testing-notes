## Organizational unit
- An Organizational Unit (OU) in Active Directory is a logical container object used to organize and manage users, groups, computers, and other Active Directory objects within a domain. 
- can apply policy using `Group Policy`

![Screenshot_3](https://github.com/kiro6/penetration-testing-notes/assets/57776872/59e4ee58-42c3-4aba-8f7f-30347151ee22)



## Group Policy Objects 
Group Policy Objects (GPOs) can be linked to OUs to apply specific configurations, settings, and policies to the objects within those OUs. This allows administrators to apply different policies based on the requirements of different departments or organizational units.


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

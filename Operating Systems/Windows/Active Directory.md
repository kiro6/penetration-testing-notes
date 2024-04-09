# Content
- [Organizational unit](#organizational-unit)
- [Group Policy Objects](#group-policy-objects)
  - [GPO types](#gpo-types)   
- [Active Directory Objects](#active-directory-objects)
  - [Users](#users)
  - [Groups](#groups)
  - [Contacts](#contacts)
- [Distinguished Name & Relative Distinguished Name](#distinguished-name--relative-distinguished-name)
- [Flexible Single Master Operations(FSMO) Roles](#flexible-single-master-operationsfsmo-roles)


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


## Active Directory Objects 

### Users
- Users are considered leaf objects, which means that they cannot contain any other objects within them
- A user object is considered a security principal and has a security identifier (SID) and a global unique identifier (GUID).
- User objects have many possible attributes, such as their display name, last login time, date of last password change, email address, account description, manager, address, and more.
- [all active directory user object attributes](https://www.easy365manager.com/how-to-get-all-active-directory-user-object-attributes/)

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


### Contacts 
- In Active Directory, "Contacts" refer to objects used to represent external entities, such as people or resources, who are not part of the Active Directory domain.
- They are leaf objects and are NOT security principals (securable objects), so they don't have a SID, only a GUID. 
- Contacts are typically created for entities outside of the organization, such as partners, clients, vendors, or individuals in other domains.
- Administrators can define permissions for Contacts, specifying who can view, modify, or delete them. This allows for controlled access to contact information within the organization.


![Screenshot_6](https://github.com/kiro6/penetration-testing-notes/assets/57776872/7b6c6d9f-6c52-47dc-96ed-60270d6b042e)


## Distinguished Name & Relative Distinguished Name
- A Distinguished Name (DN) describes the full path to an object in AD `(such as cn=bjones, ou=IT, ou=Employees, dc=inlanefreight, dc=local)`
- A Relative Distinguished Name (RDN) is a single component of the Distinguished Name that identifies the object as unique from other objects at the current level in the naming hierarchy. In our example `The Common Name (CN), bjones`

![Screenshot_5](https://github.com/kiro6/penetration-testing-notes/assets/57776872/39be0a60-df9f-495b-a8d3-626e3d66edd2)



## Flexible Single Master Operations(FSMO) Roles

### Per Forest
**Schema Master:**
- Manages the read/write copy of the Active Directory schema.
- Controls the structure and attributes of objects stored in Active Directory.
- Responsible for making changes to the schema, such as adding or modifying attributes.

**Domain Naming Master:**
- Manages domain names within the forest.
- Ensures the uniqueness of domain names across the entire forest.
- Controls the addition or removal of domains from the forest.

### Per Domain
**Relative Identifier (RID) Master:**
- Allocates unique Relative Identifiers (RIDs) to objects within a domain.
- Ensures that each object in the domain has a unique security identifier (SID).
- Prevents SID conflicts by managing RID pools.

**Primary Domain Controller (PDC) Emulator:**
- Provides backward compatibility for older Windows clients.
- Handles authentication requests, password changes, and time synchronization.
- Acts as the primary source for Group Policy updates within the domain.

**Infrastructure Master:**
- Updates references to objects in other domains within the same forest.
- This role translates GUIDs, SIDs, and DNs between domains
- Ensures that cross-domain object references are properly maintained.
- Only relevant in domains where not all domain controllers are also Global Catalog servers.
- If this role is not functioning properly, Access Control Lists (ACLs) will show SIDs instead of fully resolved names.

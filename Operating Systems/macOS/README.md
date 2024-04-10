## OS & Architecture Info
- [xnu](https://github.com/apple-oss-distributions/xnu)
- [darwin-xnu ](https://github.com/apple/darwin-xnu)

#### **Kernel:** XNU
The Mach kernel is the basis (along with portions from BSD) of the macOS and iOS XNU Kernel architecture, which handles our memory, processors, drivers, and other low-level processes.

#### **OS Base:** Darwin, a FreeBSD Derivative open-sourced by Apple.
Darwin is the base of the macOS operating system. Apple has released Darwin for open-source use. Darwin, combined with several other components such as Aqua, Finder, and other custom components, make up the macOS as we know it.


## Core Components

- **GUI:**
[Aqua](https://en.wikipedia.org/wiki/Aqua_(user_interface)#References) is the basis for the Graphical interface and visual theme for macOS.

- **File Manager:**
[Finder](https://support.apple.com/en-us/HT201732) is the component of macOS that provides the Desktop experience and File management functions within the OS.
Aqua is also responsible for the launching of other applications.

- **Application Sandbox:**
By default, macOS and any apps within it utilize the concept of sandboxing, which restricts the application's access outside of the resources necessary for it to run. This security feature would limit the risk of a vulnerability to the application itself and prevent harm to the macOS system or other files/applications within it.

- **Cocoa:**
[Cocoa](https://developer.apple.com/library/archive/documentation/macOSX/Conceptual/OSX_Technology_Overview/CocoaApplicationLayer/CocoaApplicationLayer.html) is the application management layer and API used with macOS. It is responsible for the behavior of many built-in applications within macOS. Cocoa is also a development framework made for bringing applications into the Apple ecosystem. Things like notifications, Siri, and more, function because of Cocoa.

## Graphical User Interface

| Component      | Description                                                                                              |
|----------------|----------------------------------------------------------------------------------------------------------|
| Apple Menu     | This is our main point of reference for critical host operations such as System Settings, locking our screen, shutting down the host, etc. |
| Finder         | Finder is the component of macOS that provides the Desktop experience and File management functions within the OS. |
| Spotlight      | Spotlight serves as a helper of sorts on your system. It can search the filesystem and your iCloud, perform mathematical conversions, and more. |
| Dock           | The Dock at the bottom of your screen, by default, acts as the holder for any apps you frequently use and where your currently open apps will appear. |
| Launchpad      | This is the application menu where you can search for and launch applications.                            |
| Control Center | Control Center is where we can manage our network settings, sound and display options, notification, and more at a glance. |


## System Hierarchy

### MacOS Domains
In macOS, a file system is divided into multiple domains that separate files and resources depending on their intended usage. Domains apply access privilege to the files and resources in that domain, preventing unauthorized users from changing files.

![Screenshot 2024-04-10 at 14-13-23 MacOS Fundamentals](https://github.com/kiro6/penetration-testing-notes/assets/57776872/f7263c21-88ea-42b5-937b-bc3e3ba6cb4a)

| Domain         | Description                                                                                                        |
|----------------|--------------------------------------------------------------------------------------------------------------------|
| Local Domain   | Contains resources such as apps that are local to the current computer and shared among all computer users.       |
| System Domain  | Contains the system software installed by Apple.                                                                   |
| User Domain    | Contains resources specific to the users who log in to the system. This domain reflects the home directory of the current user at runtime. |
| Network Domain | Contains resources such as apps and documents that are shared among users of a local area network.               |


### macOS File System Structure

![Screenshot 2024-04-10 at 14-15-00 MacOS Fundamentals](https://github.com/kiro6/penetration-testing-notes/assets/57776872/85d05846-6bc1-40f1-b170-7a89247defec)

#### /Applications
The Applications directory contains applications that users would commonly use. There are multiple /Applications folders, each belonging to a different domain.

| Domain         | Description                                                                                                  |
|----------------|--------------------------------------------------------------------------------------------------------------|
| User Domain    | Applications that are installed and related to a particular user are saved under `/Users/username/Applications`. |
| Local Domain   | Applications which are installed by a user, installed by Apple, and which can be used by all users present in a computer are saved under `/Applications`. |
| System Domain  | Applications which are related to the system or installed by Apple are saved under `/System/Applications`.     |

#### /Users
- The Users directory belongs to the User Domain. It contains user-related applications, files, and resources. 
- Each user account has its own user folder, located under /Users/username. Each user has access only to their user directory and cannot access items on another user's directory.

#### /Library
- The Library directory stores custom data files for applications, caches, configurations, resources, preferences, and user data. 
- The Local and system domain Library directories are Global in scope, while the user Library directory is specific to that user.

| Domain         | Description                                                                                                    |
|----------------|----------------------------------------------------------------------------------------------------------------|
| User Domain    | Information about the applications related to the current user is stored in `/Users/username/Library`.         |
| Local Domain   | Information related to an application that is shared by all the users who are using that application is stored in `/Library` directory. |
| System Domain  | Information about system applications is stored in `/System/Library`.                                          |


**The Library directory contains some key subdirectories:**

    Library/Application Support: Contains app-specific support files, data files & configuration files
    Library/Caches: Contains app-specific support files that the app can re-create easily
    Library/Frameworks: Stores libraries that are used, or needed, to create an application
    Library/Preferences: contains the application preferences (PowerManagement, SoftwareUpdate, Logging, Calendar, etc.)


#### /Network
The Network directory contains files that belong to the network domain. This directory contains the list of computers in the local area network.

#### /System
The System directory contains the system resources required by macOS to run. These files are installed by Apple and shouldn't be modified.

### Unix-Specific Directories

![Screenshot 2024-04-10 at 14-21-56 MacOS Fundamentals](https://github.com/kiro6/penetration-testing-notes/assets/57776872/5f332767-c4dc-4455-8fce-c7d199f9d084)

| Directory  | Description                                                                                           |
|------------|-------------------------------------------------------------------------------------------------------|
| /          | Is the root filesystem and contains everything the operating system needs to complete the boot cycle. |
| /bin       | Is our main storage point for binaries.                                                               |
| /dev       | Maintains our device-id files that enable the use of hardware devices attached to the system.         |
| /etc       | /etc contains our system and application configuration files.                                          |
| /sbin      | Contains all the essential and common administrative binaries we need to keep our systems running smoothly. |
| /tmp       | The /tmp directory is used by the operating system to store temporary files that do not need to be persistent. |
| /usr       | This is one of the largest directories on our host. It contains all of the libraries we may need, applications such as FTP, SSH, and even vim. |
| /var       | This is where we store our system log files, sources for our web servers, backups, and more.           |
| /private   | Stores critical system files and caches required to operate. They are hidden in the /Private directory to ensure the standard user does not modify them. |
| /opt       | This is our storage point for any third-party applications or packages we install.                     |
| /cores     | Contains Core Dumps stored by macOS that are intended for developers to troubleshoot any issues that arise. |
| /home      | Each user on the system has a subdirectory here for storage. Our user Desktop, Downloads, and Documents folders can be found here. |

### File and Directory Permissions
same as linux 

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

# Content

# Directories

| Directory        | Purpose                                                                                           |
|------------------|---------------------------------------------------------------------------------------------------|
| `/system`        | Contains the core Android OS files, including system apps, libraries, and binaries.               |
| `/data`          | Stores user and app-specific data. Apps store private files and databases here.                   |
| `/cache`         | Holds temporary and frequently accessed data, such as cached app data.                            |
| `/sdcard`        | Provides access to the external storage for user media files like pictures, videos, and downloads.|
| `/vendor`        | Contains hardware-specific drivers, libraries, and binaries from the device manufacturer.         |
| `/odm`           | Holds device-specific code, firmware, and configuration files from the original design manufacturer (ODM). |
| `/proc`          | A virtual filesystem providing information about running processes and system states.             |
| `/sys`           | A virtual filesystem exposing kernel objects and attributes for hardware interaction.             |
| `/dev`           | Contains device nodes that represent the system's hardware components, like disks and input devices. |
| `/mnt`           | Mount point for external storage volumes like SD cards and USB drives.                            |
| `/apex`          | Used for Android’s APEX system, allowing core components to be updated as modular packages.        |
| `/oem`           | Contains proprietary apps, configuration files, and system customizations from the OEM.           |
| `/init`          | Stores initialization scripts and configuration files used during the Android boot process.       |
| `/acct`          | Virtual filesystem providing process accounting and resource usage information.                   |
| `/odm_dlkm`      | Stores Device Kernel Loadable Modules (DKLMs) specific to hardware, allowing kernel modularization.|
| `/vendor_dlkm`   | Similar to `/odm_dlkm`, stores kernel modules specific to vendor hardware.                        |
| `/storage`       | Mount point for all external storage volumes, organizing various external storage locations.       |

# Important Files
- The `/system/etc/permissions/platform.xml` file defines system-wide permissions, policies, and mappings for granting access to components and features in Android. EX: [android src code](https://android.googlesource.com/platform/frameworks/base/+/master/data/etc/platform.xml)

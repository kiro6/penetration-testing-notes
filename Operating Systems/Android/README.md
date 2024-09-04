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

## android_filesystem_config.h
- this file defines users and groups in the android system
- EX: [android_filesystem_config in googlesource](https://android.googlesource.com/platform/system/core/+/master/libcutils/include/private/android_filesystem_config.h) 



## platform.xml

- The `/etc/permissions/platform.xml`  file in Android is to **manage** and **define** system-level permissions for different components and apps on the device. so it defines the permssions , and maps it to user's uid to access it at the andorid system level. 
- outlines permissions required by the Android platform to control access to sensitive system features like cameras, sensors, network interfaces, and system settings.
- It acts as a centralized configuration file that specifies which system services, apps, or user groups can access particular system resources or perform certain privileged operations. 
- EX: [android src code](https://android.googlesource.com/platform/frameworks/base/+/master/data/etc/platform.xml)





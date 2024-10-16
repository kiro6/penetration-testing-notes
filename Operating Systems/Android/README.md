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


# Android App Components


## BroadcastReceiver

A **BroadcastReceiver** listens for broadcast messages (or intents) from the system or other apps.

#### Example of BroadcastReceiver:

**Manifest Declaration:**
```xml
<receiver android:name=".BatteryReceiver">
    <intent-filter>
        <action android:name="android.intent.action.BATTERY_CHANGED" />
    </intent-filter>
</receiver>
```

**BroadcastReceiver Implementation:**
```java
public class BatteryReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        int level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
        int scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1);

        float batteryPct = level / (float) scale * 100;

        Toast.makeText(context, "Battery Level: " + batteryPct + "%", Toast.LENGTH_SHORT).show();
    }
}
```

---

## ContentProvider

A **ContentProvider** manages access to a structured set of data and allows other applications to query or modify that data.

#### Example of ContentProvider:

**ContentProvider Implementation:**
```java
public class MyContentProvider extends ContentProvider {
    @Override
    public boolean onCreate() {
        // Initialize database or data structures
        return true;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        // Implement query to retrieve data from database
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        // Insert new data into database
        return null;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // Update data in the database
        return 0;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // Delete data from the database
        return 0;
    }

    @Override
    public String getType(Uri uri) {
        // Return the MIME type of data for the URI
        return null;
    }
}
```

---

## FileProvider

A **FileProvider** facilitates secure sharing of files between apps by generating a content URI for the files.

#### Example of FileProvider:

**Manifest Declaration:**
```xml
<provider
    android:name="androidx.core.content.FileProvider"
    android:authorities="${applicationId}.provider"
    android:exported="false"
    android:grantUriPermissions="true">
    <meta-data
        android:name="android.support.FILE_PROVIDER_PATHS"
        android:resource="@xml/file_paths" />
</provider>
```

**File Provider Paths XML (`res/xml/file_paths.xml`):**
```xml
<paths xmlns:android="http://schemas.android.com/apk/res/android">
    <external-files-path name="images" path="Pictures/" />
</paths>
```

**Usage in Code (Sharing a File):**
```java
File file = new File(context.getExternalFilesDir(Environment.DIRECTORY_PICTURES), "my_image.jpg");
Uri fileUri = FileProvider.getUriForFile(context, context.getApplicationContext().getPackageName() + ".provider", file);

Intent shareIntent = new Intent(Intent.ACTION_SEND);
shareIntent.setType("image/jpeg");
shareIntent.putExtra(Intent.EXTRA_STREAM, fileUri);
shareIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

context.startActivity(Intent.createChooser(shareIntent, "Share Image"));
```





## Add Exclusion on Windows Defender
```powershell
# need to be admin or system auth priv 
powershell -ep bypass
Add-MpPreference -ExclusionPath c:\temp
```

## 

# Obfuscator
Simple, basic obfuscator that was intended for commercial use but is no longer used. 

The obfuscator was originally intended to be a private, experimental obfuscator for testing & learning purposes. 

The codebase of this software is very poor, and I no longer maintain this code as I have made a rewrite. 

I would strongly advise you **do not** use this obfuscator to obfuscate your code as it is very basic. Every feature can be easily removed with methods such as static analysis. 

# Usage
`gradlew build`

You will find your built jar in `build/libs`. 

To run the obfuscator: `java -jar file.jar settings.json input.jar output.jar`


## Configuration

```json 
{
  "ignoreJarEntries": [],
  "modId": "MinecraftModID",
  "validObfPackages": [
    "club.cpacket.client"
  ],
  "excludeObfClasses": [
    "^club\\.cpacket\\.client\\.MainModClass$"
  ],
  "excludeObfAnnotations": [],
  "obfPackage": "club.cpacket.client",
  "obfPackageMapping": [],
  "enableClassObf": true,
  "enableFieldObf": true,
  "enableMethodObf": true,
  "enableLocalObf": true,
  "obfNameFormat": "RANDOM",
  "removeKotlinMetadata": true,
  "removeSignatures": true,
  "removeSourceInfo": true,
  "hideClassMembers": true,
  "eventAnnotations": [],
  "numbersAsExpressions": true,
  "removeLineNumbers": true,
  "stringMangling": true,
  "stringEncryption": false,
  "fieldValueOverrides": {},
  "storeEncryptedClasses": false,
  "excludeEncryptionClasses": [],
  "mixinPackage": "club.cpacket.client.mixin",
  "numbersAsExpressionsWithSeed": true,
  "addFunctionIndirections": true,
  "useInvokeDynamic": false,
  "criticalPerformanceClasses": []
}
```

**Some of these options do not work due to bugs or are depreciated as they are commented out in the code.** 

You are advised to run this obfuscator on java 11 as this was the main version of java this software was developed with, however it supports java 8 through to 13. (Newer versions have not been tested.)

**No support will be provided, and this project will not be maintained. Feel free to fork it and maintain your own versions. I have just released it so others can learn a thing or two if they want to get into java obfuscation.** (You shouldn't though. :P) 

#### Licensing

This project is licensed under the GNU General Public License v3.0.

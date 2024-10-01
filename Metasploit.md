# Introduction to Metasploit
The Metasploit Framework includes a suite of tools that you can use to test security vulnerabilities, enumerate networks, execute attacks, and evade detection. 
Metasploit is not a jack of all trades but a swiss army knife with just enough tools to get us through the most common unpatched vulnerabilities.

The Metasploit Pro version is different from the Metasploit Framework one with some additional features:

Task Chains, Social Engineering, Vulnerability Validations, GUI, Quick Start Wizards, Nexpose Integration.

## Archietecture
__Data, Documentation, Lib__ These are the base files for the Framework. The Data and Lib are the functioning parts of the msfconsole interface, while the Documentation folder contains all the technical details about the project.
__Modules__ The Modules detailed above are split into separate categories in this folder. 
```
ls /usr/share/metasploit-framework/modules
```
__Plugins__
Plugins offer the pentester more flexibility when using the msfconsole since they can easily be manually or automatically loaded as needed to provide extra functionality and automation during our assessment.
```
ls /usr/share/metasploit-framework/plugins/
```
__Scripts__ Meterpreter functionality and other useful scripts.
```
ls /usr/share/metasploit-framework/scripts/
```
__Tools__ Command-line utilities that can be called directly from the msfconsole menu.
```
ls /usr/share/metasploit-framework/tools/
```
# Introddction to MSFconsole

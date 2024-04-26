# Update API FGT BNP

The program is for upgrading automatically Fortigates via a Fortimanager. It runs first pre-checks on the Fortigates to verify their health. If one is not responding well, then the upgrade won't happen on it.
The upgrade task is done in a single task including all the Fortigates targeted. It follows an upgrade path predifined by the Fortimanager. Once it is done, the program post-cheks the Fortigates to catch the upgrade errors and if there are some a retry is proposed on the Fortigates concerned.

## PREREQUISITES

Install the following python libraries:

```bash
pip install pyfmg
pip install pysnmp
```

The Fortigates must be able to ping the FortiManager.
The computer from where you launch the program has to request via SNMP the fortigates. It gets the ips registered on the Fortimanager. You must be able to connect to Fortigates via these ips.

## INITIALIZATION

All the inputs are the .ini file:

### GENERAL

- All the logs are saved in a file (log_file) and the verbosity of the console and the file can be changed.
- nb_thread gives details about the max number of parallel upgrades you authorize. The more it is big the more CPU will be consumed on the Fortimanager.
- target_version is the final version of the fortigate.
- automatic is a boolean. If False, if an upgrade fails or a connection error happens, then the user will be able to retry the upgrade or reconnect. If it is to True, on a failed upgrade the program won't retry the upgrade on the Fortigate. On a connection error it will try infinitely to reconnect.

### ADOM

- Place the list of adoms you want to upgrade

### FORTIANALYZER

- User, and password needs to be API user.
- event_severity is the level of unacceptable events for an upgrade. These events are not the logs but manually configured events on the FAZ triggered when the action targeted is logged from the FGT.

### OID

- We get the session count, rate, the cpu and memery usage and the interfaces Status. All these checks are made on the global system execpt "ifOperStatus" made at the interface level.

### OID_LIMIT

- Treshold to validate the snmp checks. For session count and rate, this treshold is a minimum to validate the goo health of the Fortigate.
- Limits for CPU and MEMORY usage are maximum usage we can accept.

# Lazarus Sigma Rules

The Sigma rules in this repository were created by the F-Secure Countercept Detection and Response Team to provide detection coverage for the Tools, Techniques and Procedures recently used by the Lazarus Group.

The blog posts discussing the creation of these Sigma rules can be found here: 

- https://labs.f-secure.com/blog/catching-lazarus-threat-intelligence-to-real-detection-logic
- https://labs.f-secure.com/blog/catching-lazarus-threat-intelligence-to-real-detection-logic-part-two

## Detection Rules

 - **win_word_create_lnk** - Detects the creation of anomalous shortcut file by Word document
 - **win_word_launch_explorer** - Detects explorer being launched by Microsoft Word document
 - **win_mshta_load_vbscript** - Detects suspicious execution of VBScript by Mshta.exe
 - **win_nonbrowser_susp_url** - Detects suspicious non-browser attempts to access suspicious URL
 - **win_powershell_disable_windefender** - Detects PowerShell command used to disable Windows Defender
 - **win_powershell_ip_args** - Detects Powershell execution with arguments containing external IP addresses
 - **win_anom_schtasks_creation.yml** - Detects the creation of scheduled tasks to run anomalous programs
 - **win_disable_credential_guard.yml** - Detects attempt to disable Windows Defender Credential Guard
 - **win_reg_enable_wdigest.yml** - Detects the enumeration or modification of WDigest plaintext credential caching registry entry
 - **win_remote_schtasks_creation.yml** - Detects the creation of scheduled task on remote endpoints as part of lateral movement
 - **win_susp_exec_programdata.yml** - Detects a suspicious execution from the unusual folder ProgramData
 - **win_susp_schtasks_execution.yml** - Detects the execution of suspicious process from schedule task
 - **win_wevtutil_clear_export_logs.yml** - Detects the use of wevtutil to clear or export Windows Security logs

## Detection Notes
As every network is different, we recommend studying the provided Sigma rules before implementing them in your environment. The process of introducing new rules to a network is often an iterative process of development and whitelisting in order to get the rules to a suitable level of fidelity, and to ensure that the volume of log data being collected can be queried and stored.

The rules provided in this repository were tested against a sysmon deployment using the [SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) configuration with a few minor changes:

### ImageLoad Events (Event ID 7)
To configure Sysmon to collect ImageLoad events, the Event ID 7 RuleGroup was set to:

	<RuleGroup name="" groupRelation="or">
		<ImageLoad onmatch="exclude">
			<Image condition="image">chrome.exe</Image>
			<Image condition="image">vmtoolsd.exe</Image>
		</ImageLoad>
	</RuleGroup>
Reference: [Cyb3rWard0g](https://gist.github.com/Cyb3rWard0g/136481552d8845e52962534d1a4b8664)

### FileCreate Events (EventID 11)
To enable the **win_word_create_lnk.yml** rule to operate correctly, the following line was added to the Event ID 11 rule group so that FileCreate events relating to .lnk were logged:

	<TargetFilename condition="end with">.lnk</TargetFilename>
	
### Registry Events

If you are using the SwiftOnSecurity Sysmon Config there appears to be an error in the config which results in registry events for the "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\" path to not be logged. There is an existing [Pull Request](https://github.com/SwiftOnSecurity/sysmon-config/pull/102) to fix this issue, but you will need to manually fix the config error in the meantime.  

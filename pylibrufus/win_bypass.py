from typing import List, Tuple, Dict
import enum

class BypassOption(enum.Flag):
    NONE = 0
    SECUREBOOT_TPM_MINRAM = 1
    NO_ONLINE_ACCOUNT = 2
    NO_DATA_COLLECTION = 4
    DUPLICATE_LOCALE = 8
    SET_USER = 16
    DISABLE_BITLOCKER = 32
    WINPE_SETUP_MASK = 1 # In Rufus this overlaps with SECUREBOOT_TPM_MINRAM for the WINPE pass

    # Defaults in Rufus often include TPM/SecureBoot bypass
    DEFAULT = SECUREBOOT_TPM_MINRAM | NO_ONLINE_ACCOUNT | NO_DATA_COLLECTION

def get_bypass_registry_keys() -> List[Tuple[str, str, str, int]]:
    """
    Returns the registry keys Rufus normally injects into the Windows offline hive.
    Format: (Key, ValueName, Type, Value)
    Type is "REG_DWORD" (represented as string here for simplicity, or we could use enum).
    """
    # From src/wue.c:
    # const char* bypass_name[] = { "BypassTPMCheck", "BypassSecureBootCheck", "BypassRAMCheck" };
    # HKLM\SYSTEM\Setup\LabConfig

    keys = []
    base_key = r"HKLM\SYSTEM\Setup\LabConfig"
    bypass_names = ["BypassTPMCheck", "BypassSecureBootCheck", "BypassRAMCheck"]

    for name in bypass_names:
        keys.append((base_key, name, "REG_DWORD", 1))

    return keys

def generate_bypass_xml(flags: BypassOption = BypassOption.DEFAULT,
                        username: str = "User",
                        arch: str = "amd64") -> str:
    """
    Returns the content of the autounattend.xml file Rufus normally generates to bypass checks.

    Args:
        flags: Bitmask of options (BypassOption).
        username: Username to create if SET_USER is set.
        arch: Architecture string (x86, amd64, arm, arm64).
    """

    # Based on CreateUnattendXml in src/wue.c

    xml_parts = []
    xml_parts.append('<?xml version="1.0" encoding="utf-8"?>')
    xml_parts.append('<unattend xmlns="urn:schemas-microsoft-com:unattend">')

    # windowsPE pass
    # Used for TPM/SecureBoot/RAM bypass if registry injection is not possible (or as fallback)
    # Rufus seems to use RunSynchronous commands here.

    # In Rufus src/wue.c:
    # if (flags & UNATTEND_WINPE_SETUP_MASK) { ... }
    # UNATTEND_WINPE_SETUP_MASK seems to be 1 (same as UNATTEND_SECUREBOOT_TPM_MINRAM???)
    # Looking at rufus.h or wue.c logic.
    # In src/wue.c: "const char* bypass_name[] = { "BypassTPMCheck", "BypassSecureBootCheck", "BypassRAMCheck" };"

    if flags & BypassOption.SECUREBOOT_TPM_MINRAM:
        xml_parts.append('  <settings pass="windowsPE">')
        xml_parts.append(f'    <component name="Microsoft-Windows-Setup" processorArchitecture="{arch}" language="neutral" '
                         'xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                         'publicKeyToken="31bf3856ad364e35" versionScope="nonSxS">')
        xml_parts.append('      <UserData>')
        xml_parts.append('        <ProductKey>')
        xml_parts.append('          <Key />')
        xml_parts.append('        </ProductKey>')
        xml_parts.append('      </UserData>')

        xml_parts.append('      <RunSynchronous>')
        order = 1
        bypass_names = ["BypassTPMCheck", "BypassSecureBootCheck", "BypassRAMCheck"]
        for name in bypass_names:
            xml_parts.append('        <RunSynchronousCommand wcm:action="add">')
            xml_parts.append(f'          <Order>{order}</Order>')
            xml_parts.append(f'          <Path>reg add HKLM\\SYSTEM\\Setup\\LabConfig /v {name} /t REG_DWORD /d 1 /f</Path>')
            xml_parts.append('        </RunSynchronousCommand>')
            order += 1
        xml_parts.append('      </RunSynchronous>')
        xml_parts.append('    </component>')
        xml_parts.append('  </settings>')

    # pass="specialize"
    # Used for NO_ONLINE_ACCOUNT
    if flags & BypassOption.NO_ONLINE_ACCOUNT:
        xml_parts.append('  <settings pass="specialize">')
        xml_parts.append(f'    <component name="Microsoft-Windows-Deployment" processorArchitecture="{arch}" language="neutral" '
                         'xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                         'publicKeyToken="31bf3856ad364e35" versionScope="nonSxS">')
        xml_parts.append('      <RunSynchronous>')

        # BypassNRO
        xml_parts.append('        <RunSynchronousCommand wcm:action="add">')
        xml_parts.append('          <Order>1</Order>')
        xml_parts.append('          <Path>reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OOBE /v BypassNRO /t REG_DWORD /d 1 /f</Path>')
        xml_parts.append('        </RunSynchronousCommand>')

        xml_parts.append('      </RunSynchronous>')
        xml_parts.append('    </component>')
        xml_parts.append('  </settings>')

    # pass="oobeSystem"
    # Used for NO_DATA_COLLECTION, SET_USER, DUPLICATE_LOCALE, DISABLE_BITLOCKER
    oobe_needed = flags & (BypassOption.NO_DATA_COLLECTION | BypassOption.SET_USER | BypassOption.DUPLICATE_LOCALE | BypassOption.DISABLE_BITLOCKER)

    if oobe_needed:
        xml_parts.append('  <settings pass="oobeSystem">')

        # Shell-Setup component
        shell_setup_needed = flags & (BypassOption.NO_DATA_COLLECTION | BypassOption.SET_USER | BypassOption.DUPLICATE_LOCALE)
        if shell_setup_needed:
            xml_parts.append(f'    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="{arch}" language="neutral" '
                             'xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                             'publicKeyToken="31bf3856ad364e35" versionScope="nonSxS">')

            if flags & BypassOption.NO_DATA_COLLECTION:
                xml_parts.append('      <OOBE>')
                xml_parts.append('        <ProtectYourPC>3</ProtectYourPC>')
                xml_parts.append('      </OOBE>')

            # Skipping DUPLICATE_LOCALE as it requires host system info which we might not want to hardcode or assume.

            if (flags & BypassOption.SET_USER) and username:
                xml_parts.append('      <UserAccounts>')
                xml_parts.append('        <LocalAccounts>')
                xml_parts.append('          <LocalAccount wcm:action="add">')
                xml_parts.append(f'            <Name>{username}</Name>')
                xml_parts.append(f'            <DisplayName>{username}</DisplayName>')
                xml_parts.append('            <Group>Administrators;Power Users</Group>')
                xml_parts.append('            <Password>')
                xml_parts.append('              <Value>UABhAHMAcwB3AG8AcgBkAA==</Value>')
                xml_parts.append('              <PlainText>false</PlainText>')
                xml_parts.append('            </Password>')
                xml_parts.append('          </LocalAccount>')
                xml_parts.append('        </LocalAccounts>')
                xml_parts.append('      </UserAccounts>')

                xml_parts.append('      <FirstLogonCommands>')
                order = 1
                xml_parts.append('        <SynchronousCommand wcm:action="add">')
                xml_parts.append(f'          <Order>{order}</Order>')
                xml_parts.append(f'          <CommandLine>net user &quot;{username}&quot; /logonpasswordchg:yes</CommandLine>')
                xml_parts.append('        </SynchronousCommand>')
                order += 1
                xml_parts.append('        <SynchronousCommand wcm:action="add">')
                xml_parts.append(f'          <Order>{order}</Order>')
                xml_parts.append('          <CommandLine>net accounts /maxpwage:unlimited</CommandLine>')
                xml_parts.append('        </SynchronousCommand>')
                xml_parts.append('      </FirstLogonCommands>')

            xml_parts.append('    </component>')

        if flags & BypassOption.DISABLE_BITLOCKER:
            xml_parts.append(f'    <component name="Microsoft-Windows-SecureStartup-FilterDriver" processorArchitecture="{arch}" language="neutral" '
                             'xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                             'publicKeyToken="31bf3856ad364e35" versionScope="nonSxS">')
            xml_parts.append('      <PreventDeviceEncryption>true</PreventDeviceEncryption>')
            xml_parts.append('    </component>')
            xml_parts.append(f'    <component name="Microsoft-Windows-EnhancedStorage-Adm" processorArchitecture="{arch}" language="neutral" '
                             'xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                             'publicKeyToken="31bf3856ad364e35" versionScope="nonSxS">')
            xml_parts.append('      <TCGSecurityActivationDisabled>1</TCGSecurityActivationDisabled>')
            xml_parts.append('    </component>')

        xml_parts.append('  </settings>')

    xml_parts.append('</unattend>')

    return '\n'.join(xml_parts) + '\n'

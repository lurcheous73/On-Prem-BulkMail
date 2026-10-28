#!/usr/bin/env python3
"""Build only the service against the unchanged deployed Core assembly."""
import pathlib
import shutil
import xml.etree.ElementTree as ET
import hashlib
import json
import subprocess

source = pathlib.Path('/tmp/onlyoffice-imapsync-hotfix-source')
target = pathlib.Path('/tmp/onlyoffice-imapsync-service-build-v3')
manifest = json.loads(pathlib.Path(__file__).with_name('manifest.json').read_text())
def digest(data):
    return hashlib.sha256(data).hexdigest()
head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=source, capture_output=True, text=True, check=True).stdout.strip()
assert head == manifest['upstream_commit'], 'Unsupported upstream commit'
source_name = 'Services/ASC.Mail.ImapSync.Service/MailImapClient.cs'
original = subprocess.run(['git', 'show', head + ':' + source_name], cwd=source, capture_output=True, check=True).stdout
assert digest(original) == manifest['original_source_sha256'], 'Original source does not match production'
assert digest((source / source_name).read_bytes()) == manifest['patched_source_sha256'], 'Apply the reviewed source patch first'
# Preserve the exact isolated source path used by the reviewed v3 build.
staged_source = pathlib.Path('/tmp/onlyoffice-imapsync-hotfix-v3/MailImapClient.cs')
staged_source.parent.mkdir(exist_ok=True)
shutil.copyfile(source / source_name, staged_source)
assert digest(pathlib.Path('/tmp/onlyoffice-mail-core.dll').read_bytes()) == manifest['unchanged_core_sha256'], 'Unsupported Core assembly'
target.mkdir(exist_ok=True)
project = ET.parse(source / 'Services/ASC.Mail.ImapSync.Service/ASC.Mail.ImapSync.Service.csproj')
root = project.getroot()
for group in list(root.findall('ItemGroup')):
    if group.find('ProjectReference') is not None or group.find('Content') is not None:
        root.remove(group)
for frameworks in root.iter('TargetFrameworks'):
    frameworks.tag = 'TargetFramework'
    frameworks.text = 'net8.0'
props = root.find('PropertyGroup')
ET.SubElement(props, 'EnableDefaultCompileItems').text = 'false'
ET.SubElement(props, 'AssemblyName').text = 'ASC.Mail.ImapSync.Service'
ET.SubElement(props, 'DebugType').text = 'portable'
for reference in root.iter('Reference'):
    reference.find('HintPath').text = str(source / 'redistributable' / (reference.attrib['Include'] + '.dll'))
group = ET.SubElement(root, 'ItemGroup')
ET.SubElement(group, 'Compile', {
    'Include': str(source / 'Services/ASC.Mail.ImapSync.Service/**/*.cs'),
    'Exclude': str(source / 'Services/ASC.Mail.ImapSync.Service/obj/**/*.cs') + ';' + str(source / 'Services/ASC.Mail.ImapSync.Service/bin/**/*.cs') + ';' + str(source / 'Services/ASC.Mail.ImapSync.Service/MailEnginesFactoryExtentions.cs') + ';' + str(source / source_name)
})
# This service file has an unused OpenStack import. Strip only that import from
# a build copy; its compiled methods do not reference OpenStack at all.
compatibility = target / 'build-inputs'
compatibility.mkdir(exist_ok=True)
extension_source = (source / 'Services/ASC.Mail.ImapSync.Service/MailEnginesFactoryExtentions.cs').read_text(encoding='utf-8-sig')
unused_import = 'using net.openstack.Providers.Rackspace.Objects.Databases;\n'
assert extension_source.count(unused_import) == 1
(compatibility / 'MailEnginesFactoryExtentions.cs').write_text(extension_source.replace(unused_import, ''), encoding='utf-8')
ET.SubElement(group, 'Compile', {'Include': str(compatibility / 'MailEnginesFactoryExtentions.cs')})
ET.SubElement(group, 'FrameworkReference', {'Include': 'Microsoft.AspNetCore.App'})
ref = ET.SubElement(group, 'Reference', {'Include': 'ASC.Mail.Core'})
ET.SubElement(ref, 'HintPath').text = str(target / 'refs/ASC.Mail.Core.dll')
ET.SubElement(ref, 'Private').text = 'true'
# These are inherited via Core in the original project; keep the exact versions.
for name, version in [
    ('Microsoft.EntityFrameworkCore.Relational', '8.0.26'),
    ('Microsoft.Extensions.Hosting.Systemd', '7.0.0'),
    ('Microsoft.Extensions.Hosting.WindowsServices', '7.0.0'),
    ('AutoMapper', '12.0.1'),
]:
    ET.SubElement(group, 'PackageReference', {'Include': name, 'Version': version})
ET.SubElement(group, 'Compile', {'Include': str(staged_source)})
ET.indent(project, space='  ')
project.write(target / 'ASC.Mail.ImapSync.Service.csproj', encoding='utf-8', xml_declaration=True)
refs = target / 'refs'
refs.mkdir(exist_ok=True)
core = pathlib.Path('/tmp/onlyoffice-mail-core.dll')
if core.exists():
    shutil.copyfile(core, refs / 'ASC.Mail.Core.dll')
    print('Build project prepared with the deployed Core assembly')
else:
    print('Build project prepared; awaiting the deployed Core assembly')

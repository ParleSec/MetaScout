"""
Executable metadata analysis
"""

from typing import Dict, List, Any

from ..core.models import MetadataFinding
from .base import BaseAnalyzer


class ExecutableAnalyzer(BaseAnalyzer):
    """Analyzer for executable metadata."""
    
    @classmethod
    def can_handle(cls, file_type: str) -> bool:
        """Check if this analyzer can handle the specified file type."""
        return file_type.lower() == 'executable'
    
    def analyze(self, metadata: Dict[str, Any]) -> List[MetadataFinding]:
        """Analyze executable metadata for security concerns."""
        findings = []
        
        # Check file type
        if 'file_headers' in metadata and 'type' in metadata['file_headers']:
            file_type = metadata['file_headers']['type']
            findings.append(MetadataFinding(
                type="information",
                description=f"Executable type: {file_type}",
                severity="low",
                data={"executable_type": file_type}
            ))
        
        # Check for high entropy sections (possible encryption/packing)
        high_entropy_sections = []
        if 'sections' in metadata:
            for section in metadata['sections']:
                if isinstance(section, dict) and 'entropy' in section and section['entropy'] > 7.0:
                    high_entropy_sections.append(section['name'])
        elif 'file_headers' in metadata and 'sections' in metadata['file_headers']:
            for section in metadata['file_headers']['sections']:
                if isinstance(section, dict) and 'entropy' in section and section['entropy'] > 7.0:
                    high_entropy_sections.append(section['name'])
        
        if high_entropy_sections:
            findings.append(MetadataFinding(
                type="security",
                description="High entropy sections detected (possible packing/encryption)",
                severity="high",
                data={"sections": high_entropy_sections}
            ))
        
        # Check for suspicious libraries or imports
        suspicious_libs = []
        suspicious_terms = ['inject', 'hook', 'crypt', 'keylog', 'screen', 'exploit', 
                           'hide', 'stealth', 'spy', 'capture', 'password']
        
        # Check libraries field
        if 'libraries' in metadata:
            for lib in metadata['libraries']:
                if isinstance(lib, dict) and 'name' in lib:
                    lib_name = lib['name'].lower()
                    if any(sus in lib_name for sus in suspicious_terms):
                        suspicious_libs.append(lib['name'])
        
        # Check imports field (PE specific)
        if 'imports' in metadata:
            for imp in metadata['imports']:
                if isinstance(imp, dict) and 'name' in imp:
                    imp_name = imp['name'].lower()
                    if any(sus in imp_name for sus in suspicious_terms):
                        suspicious_libs.append(imp['name'])
                    
                    # Check for specific functions that might be suspicious
                    if 'imports' in imp and isinstance(imp['imports'], list):
                        for func in imp['imports']:
                            if any(sus in func.lower() for sus in suspicious_terms):
                                suspicious_libs.append(f"{imp['name']}:{func}")
        
        if suspicious_libs:
            findings.append(MetadataFinding(
                type="security",
                description="Potentially suspicious libraries or imports detected",
                severity="high",
                data={"suspicious_items": suspicious_libs}
            ))
        
        # Check digital signature status
        if 'signatures' in metadata:
            if metadata['signatures'].get('signed', False):
                verified = metadata['signatures'].get('verified', False)
                if verified:
                    findings.append(MetadataFinding(
                        type="security",
                        description="Executable is digitally signed and verified",
                        severity="low",
                        data={"signature": "verified"}
                    ))
                else:
                    findings.append(MetadataFinding(
                        type="security",
                        description="Executable is signed but not verified",
                        severity="medium",
                        data={"signature": "unverified"}
                    ))
            else:
                findings.append(MetadataFinding(
                    type="security",
                    description="Executable is not digitally signed",
                    severity="medium",
                    data={"signature": "unsigned"}
                ))
        
        # Check compilation timestamp
        compile_time = None
        if 'file_headers' in metadata and 'compile_time' in metadata['file_headers']:
            compile_time = metadata['file_headers']['compile_time']
        elif 'pe_info' in metadata and 'compile_time' in metadata['pe_info']:
            compile_time = metadata['pe_info']['compile_time']
        
        if compile_time:
            findings.append(MetadataFinding(
                type="information",
                description=f"Compilation timestamp: {compile_time}",
                severity="low",
                data={"compile_time": compile_time}
            ))
        
        # Check for uncommon or suspicious section names (PE files)
        suspicious_sections = []
        standard_sections = {'.text', '.data', '.rdata', '.bss', '.rsrc', '.reloc', '.idata', '.edata', 
                           '.pdata', '.debug', '.tls', '.crt', '.sxdata', '.gfids'}
        
        if 'sections' in metadata:
            for section in metadata['sections']:
                if isinstance(section, dict) and 'name' in section:
                    section_name = section['name']
                    if section_name not in standard_sections and not section_name.startswith('.'):
                        suspicious_sections.append(section_name)
        elif 'file_headers' in metadata and 'sections' in metadata['file_headers']:
            for section in metadata['file_headers']['sections']:
                if isinstance(section, dict) and 'name' in section:
                    section_name = section['name']
                    if section_name not in standard_sections and not section_name.startswith('.'):
                        suspicious_sections.append(section_name)
        
        if suspicious_sections:
            findings.append(MetadataFinding(
                type="security",
                description="Non-standard section names detected",
                severity="medium",
                data={"sections": suspicious_sections}
            ))
        
        # Check for .NET assemblies
        is_dotnet = False
        if 'pe_info' in metadata and 'is_dotnet' in metadata['pe_info']:
            is_dotnet = metadata['pe_info']['is_dotnet']
        
        if is_dotnet:
            findings.append(MetadataFinding(
                type="information",
                description=".NET assembly detected",
                severity="low",
                data={"dotnet": True}
            ))
        
        # Check for specific resources that might be suspicious
        suspicious_resources = []
        if 'resources' in metadata:
            suspicious_resource_types = ['BINARY', 'HTML', 'RCDATA', 'UNKNOWN']
            for res in metadata['resources']:
                if res in suspicious_resource_types:
                    suspicious_resources.append(res)
        
        if suspicious_resources:
            findings.append(MetadataFinding(
                type="security",
                description="Potentially suspicious resources embedded in executable",
                severity="medium",
                data={"resources": suspicious_resources}
            ))
        
        # Check for dynamic libraries (ELF specific)
        if 'dynamic' in metadata:
            # Just report shared libraries as information
            shared_libs = [lib['name'] for lib in metadata['dynamic'] 
                          if isinstance(lib, dict) and lib.get('type') == 'shared_library']
            
            if shared_libs:
                findings.append(MetadataFinding(
                    type="information",
                    description=f"Executable dynamically links to {len(shared_libs)} libraries",
                    severity="low",
                    data={"libraries": shared_libs[:10]}  # Limit to first 10
                ))
            
            # Check for RPATH or RUNPATH (might indicate non-standard library locations)
            rpath_entries = [lib['value'] for lib in metadata['dynamic'] 
                            if isinstance(lib, dict) and lib.get('type') in ('DT_RPATH', 'DT_RUNPATH')]
            
            if rpath_entries:
                findings.append(MetadataFinding(
                    type="security",
                    description="Executable uses custom library search paths (RPATH/RUNPATH)",
                    severity="medium",
                    data={"paths": rpath_entries}
                ))
        
        # Mach-O specific checks
        if 'macho_info' in metadata and 'headers' in metadata['macho_info']:
            # Check if it's a universal/fat binary
            if len(metadata['macho_info']['headers']) > 1:
                architectures = [header.get('cpu_type', 'unknown') for header in metadata['macho_info']['headers']]
                findings.append(MetadataFinding(
                    type="information",
                    description=f"Universal binary with {len(architectures)} architectures",
                    severity="low",
                    data={"architectures": architectures}
                ))
        
        return findings
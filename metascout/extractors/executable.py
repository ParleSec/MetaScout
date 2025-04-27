"""
Executable file metadata extraction
"""

import os
import sys
import logging
import datetime
from typing import Dict, Any, Optional

from ..config.constants import SUPPORTED_EXTENSIONS
from ..config.dependencies import OPTIONAL_DEPENDENCIES
from .base import BaseExtractor


class ExecutableExtractor(BaseExtractor):
    """Extract metadata from executable files."""
    
    @classmethod
    def can_handle(cls, file_path: str, mime_type: Optional[str] = None) -> bool:
        """Check if this extractor can handle the specified file."""
        ext = os.path.splitext(file_path)[1].lower()
        if ext in SUPPORTED_EXTENSIONS['executables']:
            return True
        
        if mime_type and any(mime in mime_type for mime in 
                           ['application/x-executable', 'application/x-msdos-program', 
                            'application/x-msdownload', 'application/x-sharedlib',
                            'application/x-mach-binary']):
            return True
            
        return False
    
    def extract(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from executable files."""
        metadata = {
            'file_headers': {},
            'libraries': [],
            'signatures': {},
        }
        
        try:
            # Basic file signature analysis
            with open(file_path, 'rb') as f:
                header = f.read(16)  # Read first 16 bytes
                
                # Check for PE files (Windows executables)
                if header[0:2] == b'MZ':
                    metadata['file_headers']['type'] = 'Windows PE'
                    if OPTIONAL_DEPENDENCIES['pefile']:
                        metadata.update(self._extract_pe_metadata(file_path))
                    else:
                        metadata['note'] = "Install pefile package for detailed PE analysis"
                
                # Check for ELF files (Linux executables)
                elif header[0:4] == b'\x7fELF':
                    metadata['file_headers']['type'] = 'Linux ELF'
                    if OPTIONAL_DEPENDENCIES['pyelftools']:
                        metadata.update(self._extract_elf_metadata(file_path))
                    else:
                        metadata['note'] = "Install pyelftools package for detailed ELF analysis"
                
                # Check for Mach-O files (macOS executables)
                elif header[0:4] in (b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe'):
                    metadata['file_headers']['type'] = 'macOS Mach-O'
                    if OPTIONAL_DEPENDENCIES['macholib']:
                        metadata.update(self._extract_macho_metadata(file_path))
                    else:
                        metadata['note'] = "Install macholib package for detailed Mach-O analysis"
                else:
                    metadata['file_headers']['type'] = 'Unknown executable format'
                    # Extract magic bytes for identification
                    metadata['file_headers']['magic_bytes'] = header.hex()
            
            # Check for digital signatures
            self._check_signature(file_path, metadata)
            
            return metadata
        except Exception as e:
            logging.error(f"Error extracting executable metadata from {file_path}: {e}")
            return {'error': str(e)}
    
    def _extract_pe_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from PE (Windows) executable files."""
        metadata = {
            'pe_info': {},
            'sections': [],
            'imports': [],
            'exports': [],
            'resources': []
        }
        
        try:
            import pefile
            pe = pefile.PE(file_path)
            
            # Get timestamp
            timestamp = pe.FILE_HEADER.TimeDateStamp
            metadata['pe_info']['compile_time'] = datetime.datetime.fromtimestamp(timestamp).isoformat()
            
            # Get machine type
            machine_types = {
                0x014c: 'x86 (32-bit)',
                0x0200: 'IA64',
                0x8664: 'x64 (AMD64)'
            }
            metadata['pe_info']['machine'] = machine_types.get(pe.FILE_HEADER.Machine, f'Unknown ({pe.FILE_HEADER.Machine:04X})')
            
            # Get subsystem
            subsystems = {
                1: 'Native',
                2: 'Windows GUI',
                3: 'Windows Console',
                5: 'OS/2 Console',
                7: 'POSIX Console',
                9: 'Windows CE GUI'
            }
            metadata['pe_info']['subsystem'] = subsystems.get(pe.OPTIONAL_HEADER.Subsystem, f'Unknown ({pe.OPTIONAL_HEADER.Subsystem})')
            
            # Get other headers info
            metadata['pe_info']['image_base'] = f"0x{pe.OPTIONAL_HEADER.ImageBase:08X}"
            metadata['pe_info']['entry_point'] = f"0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}"
            metadata['pe_info']['file_alignment'] = pe.OPTIONAL_HEADER.FileAlignment
            metadata['pe_info']['section_alignment'] = pe.OPTIONAL_HEADER.SectionAlignment
            metadata['pe_info']['characteristics'] = pe.FILE_HEADER.Characteristics
            
            # Get imported DLLs
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', 'ignore') if entry.dll else 'Unknown'
                    imports = []
                    
                    if hasattr(entry, 'imports'):
                        for imp in entry.imports:
                            if imp.name:
                                imports.append(imp.name.decode('utf-8', 'ignore'))
                    
                    metadata['imports'].append({
                        'name': dll_name,
                        'imports': imports[:10]  # Limit to first 10 for brevity
                    })
            
            # Get exported functions
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                exports = []
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append(exp.name.decode('utf-8', 'ignore'))
                metadata['exports'] = exports[:20]  # Limit to first 20 for brevity
            
            # Get sections
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', 'ignore').strip('\x00')
                section_info = {
                    'name': section_name,
                    'virtual_address': f"0x{section.VirtualAddress:08X}",
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': section.get_entropy()
                }
                metadata['sections'].append(section_info)
            
            # Get resources if available
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    try:
                        resource_type_name = pefile.RESOURCE_TYPE.get(resource_type.id, str(resource_type.id))
                        metadata['resources'].append(resource_type_name)
                    except Exception as e:
                        logging.debug(f"Error parsing resource: {e}")
            
            # Detect if it's a .NET assembly
            metadata['pe_info']['is_dotnet'] = hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR')
            
            pe.close()
            
        except Exception as e:
            logging.error(f"Error parsing PE file: {e}")
            metadata['error'] = str(e)
        
        return metadata
    
    def _extract_elf_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from ELF (Linux) executable files."""
        metadata = {
            'elf_info': {},
            'sections': [],
            'symbols': [],
            'dynamic': []
        }
        
        try:
            from elftools.elf.elffile import ELFFile
            from elftools.elf.dynamic import DynamicSection
            from elftools.elf.sections import SymbolTableSection
            
            with open(file_path, 'rb') as f:
                elf = ELFFile(f)
                
                # Get basic header info
                metadata['elf_info']['class'] = elf.elfclass
                metadata['elf_info']['data_encoding'] = elf.elfdata
                metadata['elf_info']['machine_type'] = elf.header['e_machine']
                metadata['elf_info']['entry_point'] = f"0x{elf.header['e_entry']:X}"
                metadata['elf_info']['file_type'] = elf.header['e_type']
                
                # Get OS/ABI information
                metadata['elf_info']['os_abi'] = elf.header['e_ident']['EI_OSABI']
                
                # Get sections
                for section in elf.iter_sections():
                    metadata['sections'].append({
                        'name': section.name,
                        'type': section['sh_type'],
                        'size': section['sh_size'],
                        'address': f"0x{section['sh_addr']:X}" if section['sh_addr'] else 'N/A',
                        'flags': section['sh_flags']
                    })
                
                # Get symbols (if available)
                for section in elf.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        symbols = list(section.iter_symbols())
                        limit = min(20, len(symbols))  # Limit to 20 symbols
                        
                        for i in range(limit):
                            symbol = symbols[i]
                            if symbol.name:
                                metadata['symbols'].append({
                                    'name': symbol.name,
                                    'type': symbol['st_info']['type'],
                                    'binding': symbol['st_info']['bind'],
                                    'value': f"0x{symbol['st_value']:X}" if symbol['st_value'] else 'N/A'
                                })
                
                # Get dynamic sections (shared libraries, etc.)
                for section in elf.iter_sections():
                    if isinstance(section, DynamicSection):
                        for tag in section.iter_tags():
                            if tag.entry.d_tag == 'DT_NEEDED':
                                metadata['dynamic'].append({
                                    'type': 'shared_library',
                                    'name': tag.needed
                                })
                            elif tag.entry.d_tag == 'DT_RPATH' or tag.entry.d_tag == 'DT_RUNPATH':
                                metadata['dynamic'].append({
                                    'type': tag.entry.d_tag,
                                    'value': tag.rpath
                                })
        
        except Exception as e:
            logging.error(f"Error parsing ELF file: {e}")
            metadata['error'] = str(e)
        
        return metadata
    
    def _extract_macho_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extract metadata from Mach-O (macOS) executable files."""
        metadata = {
            'macho_info': {},
            'load_commands': [],
            'libraries': []
        }
        
        try:
            from macholib.MachO import MachO
            
            macho = MachO(file_path)
            metadata['macho_info']['headers'] = []
            
            for header in macho.headers:
                header_info = {
                    'magic': f"0x{header.MH_MAGIC:08X}",
                    'cpu_type': header.header.cputype,
                    'cpu_subtype': header.header.cpusubtype,
                    'file_type': header.header.filetype
                }
                metadata['macho_info']['headers'].append(header_info)
                
                # Get file type as string
                file_types = {
                    0x1: 'OBJECT',
                    0x2: 'EXECUTE',
                    0x3: 'FVMLIB',
                    0x4: 'CORE',
                    0x5: 'PRELOAD',
                    0x6: 'DYLIB',
                    0x7: 'DYLINKER',
                    0x8: 'BUNDLE',
                    0x9: 'DYLIB_STUB',
                    0xA: 'DSYM',
                    0xB: 'KEXT_BUNDLE'
                }
                header_info['file_type_name'] = file_types.get(header.header.filetype, 'UNKNOWN')
            
            # Get load commands
            for header in macho.headers:
                for cmd in header.commands:
                    cmd_info = {
                        'cmd': cmd[0].cmd,
                        'cmd_name': cmd[0].get_cmd_name()
                    }
                    metadata['load_commands'].append(cmd_info)
                    
                    # Extract libraries
                    if cmd[0].cmd == 0x0C:  # LC_LOAD_DYLIB
                        if hasattr(cmd[1], 'name'):
                            lib_name = cmd[1].name.decode('utf-8', 'ignore') if isinstance(cmd[1].name, bytes) else cmd[1].name
                            metadata['libraries'].append({'name': lib_name})
                    
                    # Get version information if available
                    if cmd[0].cmd == 0x24:  # LC_VERSION_MIN_MACOSX
                        if hasattr(cmd[1], 'version'):
                            version = cmd[1].version
                            metadata['macho_info']['min_os_version'] = f"{version >> 16}.{(version >> 8) & 0xff}.{version & 0xff}"
        
        except Exception as e:
            logging.error(f"Error parsing Mach-O file: {e}")
            metadata['error'] = str(e)
        
        return metadata
    
    def _check_signature(self, file_path: str, metadata: Dict[str, Any]) -> None:
        """Check for digital signatures in executable files."""
        try:
            # For Windows executables on Windows platform
            if sys.platform == 'win32' and os.path.splitext(file_path)[1].lower() in ('.exe', '.dll'):
                try:
                    import win32api
                    import win32security
                    
                    # Get file version info
                    try:
                        info = win32api.GetFileVersionInfo(file_path, '\\')
                        ms = info['FileVersionMS']
                        ls = info['FileVersionLS']
                        metadata['version'] = f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
                    except:
                        pass
                    
                    # Check for Authenticode signature
                    try:
                        cert_store = win32security.CryptQueryObject(
                            win32security.CERT_QUERY_OBJECT_FILE,
                            file_path,
                            win32security.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                            win32security.CERT_QUERY_FORMAT_FLAG_BINARY,
                            0,
                            0, 0, 0, None, None
                        )
                        metadata['signatures']['signed'] = True
                        metadata['signatures']['verified'] = True  # This is simplified - in practice would need more checks
                    except:
                        metadata['signatures']['signed'] = False
                except ImportError:
                    metadata['signatures']['note'] = "PyWin32 required for signature verification on Windows"
            
            # For Linux and macOS, could use OpenSSL command line for signature verification
            # but that's more complex and requires external tools
        
        except Exception as e:
            logging.warning(f"Error checking executable signature: {e}")
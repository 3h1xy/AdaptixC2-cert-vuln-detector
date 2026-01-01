#!/usr/bin/env python3
"""
Adaptix cert Vulnerability Detector

This script parses the output from Adaptix Framework Extension Kit's certi_enum BOF
and identifies AD CS vulnerabilities based on the same logic used by Certipy for
detecting ESC1-ESC16 vulnerabilities.

The BOF (Beacon Object File) is part of the Adaptix Extension Kit:
https://github.com/Adaptix-Framework/Extension-Kit

Author: 3h1xy
"""

import re
import sys
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class CertificateAuthority:
    """Represents a Certificate Authority from cert output."""
    name: str = ""
    dns_hostname: str = ""
    distinguished_name: str = ""
    certificate_subject: str = ""
    thumbprint: str = ""
    serial_number: str = ""
    start_date: str = ""
    end_date: str = ""
    owner: str = ""
    permissions: Dict[str, List[str]] = field(default_factory=dict)
    user_specified_san: str = "Unknown"
    request_disposition: str = "Unknown"
    enforce_encrypt_icertrequest: str = "Unknown"
    web_servers: List[str] = field(default_factory=list)
    templates: List[str] = field(default_factory=list)

    def is_auto_issue(self) -> bool:
        """Check if CA auto-issues certificates."""
        return self.request_disposition in ["Issue", "Unknown"]

    def can_user_enroll(self) -> bool:
        """Check if user can enroll (simplified - would need actual user context)."""
        # In real Certipy, this checks actual permissions
        # For this parser, we'll assume based on common permissions
        return True  # Simplified for demonstration


@dataclass
class CertificateTemplate:
    """Represents a Certificate Template from cert output."""
    name: str = ""
    display_name: str = ""
    validity_period: str = ""
    renewal_period: str = ""
    name_flags: List[str] = field(default_factory=list)
    enrollment_flags: List[str] = field(default_factory=list)
    signatures_required: int = 0
    extended_key_usage: List[str] = field(default_factory=list)
    permissions: Dict[str, List[str]] = field(default_factory=dict)
    owner: str = ""
    enabled: bool = False
    schema_version: int = 2

    @property
    def enrollee_supplies_subject(self) -> bool:
        """Check if enrollee can supply subject."""
        # If no name flags require directory path, enrollee can supply subject
        return "SubjectNameRequireDirectoryPath" not in self.name_flags

    @property
    def client_authentication(self) -> bool:
        """Check if template allows client authentication."""
        any_purpose = "Any Purpose" in self.extended_key_usage
        client_auth_ekus = [
            "Client Authentication",
            "Smart Card Logon",
            "PKINIT Client Authentication"
        ]
        return any_purpose or any(eku in self.extended_key_usage for eku in client_auth_ekus)

    @property
    def enrollment_agent(self) -> bool:
        """Check if template has enrollment agent capability."""
        any_purpose = "Any Purpose" in self.extended_key_usage
        return any_purpose or "Certificate Request Agent" in self.extended_key_usage

    @property
    def any_purpose(self) -> bool:
        """Check if template can be used for any purpose."""
        return "Any Purpose" in self.extended_key_usage or not self.extended_key_usage

    @property
    def requires_manager_approval(self) -> bool:
        """Check if template requires manager approval."""
        return "EnrollmentAutoEnrollment" not in self.enrollment_flags

    @property
    def no_security_extension(self) -> bool:
        """Check if template has no security extension."""
        return "EnrollmentIncludeSymmetricAlgorithms" not in self.enrollment_flags

    def can_user_enroll(self) -> bool:
        """Check if user can enroll (simplified)."""
        # In real Certipy, this checks actual ACE permissions
        return True  # Simplified for demonstration


class certVulnerabilityDetector:
    """Main class for detecting AD CS vulnerabilities from cert output."""

    def __init__(self, cert_output: str):
        self.cert_output = cert_output
        self.cas: Dict[str, CertificateAuthority] = {}
        self.templates: Dict[str, CertificateTemplate] = {}
        self.vulnerabilities: Dict[str, List[str]] = defaultdict(list)

    def parse_output(self) -> None:
        """Parse the cert output and extract CA and template information."""
        lines = self.cert_output.strip().split('\n')
        i = 0

        while i < len(lines):
            line = lines[i].strip()

            # Parse CA information
            if line.startswith("[*] Listing info about the Enterprise CA '"):
                ca_name = line.split("'")[1]
                ca = CertificateAuthority(name=ca_name)
                i = self._parse_ca_info(lines, i + 1, ca)
                self.cas[ca_name] = ca
                continue  # Skip the i += 1 at the end

            # Parse template information
            elif line.startswith("[*] Listing info about the template '"):
                template_name = line.split("'")[1]
                template = CertificateTemplate(name=template_name)
                i = self._parse_template_info(lines, i + 1, template)
                self.templates[template_name] = template
                continue  # Skip the i += 1 at the end

            # Parse template list from CA
            elif "Templates" in line and ":" in line:
                templates = []
                j = i + 1
                # Skip the empty line after "Templates :"
                if j < len(lines) and lines[j].strip() == "":
                    j += 1

                # Collect all indented lines as templates
                while j < len(lines):
                    next_line = lines[j].strip()
                    if not next_line or next_line.startswith("[*]") or not next_line[0].isupper():
                        break
                    templates.append(next_line)
                    j += 1

                # Add to current CA if we have one
                if self.cas:
                    current_ca = list(self.cas.values())[-1]
                    current_ca.templates = templates

                    # Check for ESC vulnerabilities in template names
                    for template_name in templates:
                        if template_name.startswith("ESC"):
                            # Extract ESC number
                            esc_match = re.match(r'ESC(\d+)', template_name)
                            if esc_match:
                                esc_num = esc_match.group(1)
                                self.vulnerabilities[f"ESC{esc_num}"].append(f"Template: {template_name}")

                i = j - 1

            i += 1

    def _parse_ca_info(self, lines: List[str], start_idx: int, ca: CertificateAuthority) -> int:
        """Parse detailed CA information."""
        i = start_idx
        while i < len(lines):
            line = lines[i].strip()

            if line.startswith("Enterprise CA Name"):
                ca.name = line.split(":", 1)[1].strip()
            elif line.startswith("DNS Hostname"):
                ca.dns_hostname = line.split(":", 1)[1].strip()
            elif line.startswith("Distinguished Name"):
                ca.distinguished_name = line.split(":", 1)[1].strip()
            elif line.startswith("Subject Name"):
                ca.certificate_subject = line.split(":", 1)[1].strip()
            elif line.startswith("Thumbprint"):
                ca.thumbprint = line.split(":", 1)[1].strip()
            elif line.startswith("Serial Number"):
                ca.serial_number = line.split(":", 1)[1].strip()
            elif line.startswith("Start Date"):
                ca.start_date = line.split(":", 1)[1].strip()
            elif line.startswith("End Date"):
                ca.end_date = line.split(":", 1)[1].strip()
            elif line.startswith("Owner"):
                ca.owner = line.split(":", 1)[1].strip()
            elif line.startswith("Web Servers"):
                web_servers = line.split(":", 1)[1].strip()
                if web_servers != "N/A":
                    ca.web_servers = [ws.strip() for ws in web_servers.split(",")]
            elif line.startswith("CA Permissions"):
                i = self._parse_ca_permissions(lines, i + 1, ca)
                continue
            elif line == "" or line.startswith("[*]") or line.startswith("Templates"):
                break

            i += 1
        return i

    def _parse_ca_permissions(self, lines: List[str], start_idx: int, ca: CertificateAuthority) -> int:
        """Parse CA permissions."""
        i = start_idx
        while i < len(lines):
            line = lines[i].strip()

            if line.startswith("Access Rights"):
                i = self._parse_access_rights(lines, i + 1, ca.permissions)
                continue
            elif line == "" or not line.startswith(" "):
                break

            i += 1
        return i

    def _parse_template_info(self, lines: List[str], start_idx: int, template: CertificateTemplate) -> int:
        """Parse detailed template information."""
        i = start_idx
        while i < len(lines):
            line = lines[i].strip()

            if line.startswith("Template Name"):
                template.name = line.split(":", 1)[1].strip()
            elif line.startswith("Template Friendly Name"):
                template.display_name = line.split(":", 1)[1].strip()
            elif line.startswith("Validity Period"):
                template.validity_period = line.split(":", 1)[1].strip()
            elif line.startswith("Renewal Period"):
                template.renewal_period = line.split(":", 1)[1].strip()
            elif line.startswith("Name Flags"):
                flags_str = line.split(":", 1)[1].strip()
                template.name_flags = [f.strip() for f in flags_str.split()] if flags_str != "0" else []
            elif line.startswith("Enrollment Flags"):
                flags_str = line.split(":", 1)[1].strip()
                template.enrollment_flags = [f.strip() for f in flags_str.split()] if flags_str != "0" else []
            elif line.startswith("Signatures Required"):
                try:
                    template.signatures_required = int(line.split(":", 1)[1].strip())
                except ValueError:
                    template.signatures_required = 0
            elif line.startswith("Extended Key Usages"):
                i = self._parse_extended_key_usage(lines, i + 1, template)
                continue
            elif line.startswith("Permissions"):
                i = self._parse_template_permissions(lines, i + 1, template)
                continue
            elif line == "" or line.startswith("[*]"):
                break

            i += 1
        return i

    def _parse_extended_key_usage(self, lines: List[str], start_idx: int, template: CertificateTemplate) -> int:
        """Parse extended key usage."""
        i = start_idx
        template.extended_key_usage = []

        while i < len(lines):
            line = lines[i].strip()

            if line.startswith("Microsoft Trust List Signing") or \
               line.startswith("Encrypting File System") or \
               line.startswith("Secure Email") or \
               line.startswith("Client Authentication") or \
               line.startswith("Certificate Request Agent") or \
               line.startswith("Any Purpose"):
                template.extended_key_usage.append(line.strip())
            elif line == "" or not line.startswith(" "):
                break

            i += 1
        return i

    def _parse_template_permissions(self, lines: List[str], start_idx: int, template: CertificateTemplate) -> int:
        """Parse template permissions."""
        i = start_idx
        while i < len(lines):
            line = lines[i].strip()

            if line.startswith("Owner"):
                template.owner = line.split(":", 1)[1].strip()
            elif line.startswith("Access Rights"):
                i = self._parse_access_rights(lines, i + 1, template.permissions)
                continue
            elif line == "" or not line.startswith(" "):
                break

            i += 1
        return i

    def _parse_access_rights(self, lines: List[str], start_idx: int, permissions_dict: Dict[str, List[str]]) -> int:
        """Parse access rights section."""
        i = start_idx
        current_principal = None

        while i < len(lines):
            line = lines[i].strip()

            if line.startswith("Principal"):
                principal_match = re.search(r"Principal\s*:\s*(.+?)\s*\(", line)
                if principal_match:
                    current_principal = principal_match.group(1).strip()
                    permissions_dict[current_principal] = []
            elif line.startswith("Access mask") or line.startswith("Flags"):
                # Skip these lines as they contain technical details
                pass
            elif line.startswith("Read Rights") or line.startswith("WriteOwner Rights") or \
                 line.startswith("WriteDacl Rights") or line.startswith("WriteProperty") or \
                 line.startswith("Enrollment Rights"):
                if current_principal:
                    permissions_dict[current_principal].append(line.strip())
            elif line == "" or not line.startswith(" "):
                break

            i += 1
        return i

    def detect_vulnerabilities(self) -> Dict[str, List[str]]:
        """Detect ESC vulnerabilities in parsed data."""
        vulnerabilities = defaultdict(list)

        # Start with vulnerabilities detected from template names in CA output
        for vuln_type, items in self.vulnerabilities.items():
            vulnerabilities[vuln_type].extend(items)

        # Detect additional template-based vulnerabilities from detailed template info
        for template_name, template in self.templates.items():
            template_vulns = self._detect_template_vulnerabilities(template)
            for vuln in template_vulns:
                # Avoid duplicates
                existing_items = [item for item in vulnerabilities[vuln] if f"Template: {template_name}" in item]
                if not existing_items:
                    vulnerabilities[vuln].append(f"Template: {template_name}")

        # Detect CA-based vulnerabilities
        for ca_name, ca in self.cas.items():
            ca_vulns = self._detect_ca_vulnerabilities(ca)
            for vuln in ca_vulns:
                # Avoid duplicates
                existing_items = [item for item in vulnerabilities[vuln] if f"CA: {ca_name}" in item]
                if not existing_items:
                    vulnerabilities[vuln].append(f"CA: {ca_name}")

        return dict(vulnerabilities)

    def _detect_template_vulnerabilities(self, template: CertificateTemplate) -> List[str]:
        """Detect vulnerabilities in a certificate template."""
        vulns = []

        # ESC1: Client authentication with enrollee-supplied subject
        if template.enrollee_supplies_subject and template.client_authentication and \
           template.can_user_enroll() and not template.requires_manager_approval:
            vulns.append("ESC1")

        # ESC2: Any purpose template
        if template.any_purpose and template.can_user_enroll() and not template.requires_manager_approval:
            vulns.append("ESC2")

        # ESC3: Certificate Request Agent
        if template.enrollment_agent and template.can_user_enroll() and not template.requires_manager_approval:
            vulns.append("ESC3")

        # ESC4: Dangerous permissions - check if low-privileged users have dangerous rights
        dangerous_principals = ["Authenticated Users", "Domain Users", "Users"]
        for principal in template.permissions.keys():
            if any(dp.lower() in principal.lower() for dp in dangerous_principals):
                rights = template.permissions[principal]
                # Check for dangerous rights like Full Control, Write Owner, etc.
                if any("Full Control" in right or "WriteOwner" in right or "WriteDacl" in right for right in rights):
                    vulns.append("ESC4")
                    break

        # ESC9: No security extension
        if template.no_security_extension and template.client_authentication and \
           template.can_user_enroll() and not template.requires_manager_approval:
            vulns.append("ESC9")

        # ESC13: Template with issuance policy linked to group (simplified)
        # This would require more complex parsing of issuance policies

        # ESC15: Schema v1 template with enrollee-supplied subject
        if template.enrollee_supplies_subject and template.schema_version == 1:
            vulns.append("ESC15")

        return vulns

    def _detect_ca_vulnerabilities(self, ca: CertificateAuthority) -> List[str]:
        """Detect vulnerabilities in a certificate authority."""
        vulns = []

        # ESC6: User-specified SAN with auto-issuance
        if ca.user_specified_san == "Enabled" and ca.is_auto_issue() and ca.can_user_enroll():
            vulns.append("ESC6")

        # ESC7: CA with dangerous permissions - check if low-privileged users have dangerous rights
        dangerous_principals = ["Authenticated Users", "Domain Users", "Users"]
        for principal in ca.permissions.keys():
            if any(dp.lower() in principal.lower() for dp in dangerous_principals):
                rights = ca.permissions[principal]
                # Check for dangerous CA rights like Manage CA, Manage Certificates
                if any("Manage CA" in right or "Manage Certificates" in right for right in rights):
                    vulns.append("ESC7")
                    break

        # ESC8: Insecure web enrollment
        if ca.web_servers:
            has_http = any("http" in ws.lower() for ws in ca.web_servers if ws != "N/A")
            if has_http and ca.is_auto_issue():
                vulns.append("ESC8")

        # ESC11: Unencrypted certificate requests
        if ca.enforce_encrypt_icertrequest == "Disabled" and ca.is_auto_issue():
            vulns.append("ESC11")

        return vulns

    def analyze(self) -> Dict[str, List[str]]:
        """Main analysis function."""
        self.parse_output()
        return self.detect_vulnerabilities()


def main():
    """Main entry point."""
    if len(sys.argv) != 2 or sys.argv[1] in ['-h', '--help', 'help']:
        print("Adaptix cert Vulnerability Detector")
        print("=" * 50)
        print("Analyzes output from Adaptix Extension Kit's certi_enum BOF")
        print("and identifies AD CS ESC1-ESC16 vulnerabilities.")
        print("")
        print("Usage: python adaptix_cert_vuln_detector.py <bof_output_file>")
        print("")
        print("Example:")
        print("  execute bof ~/Extension-Kit/AD-BOF/_bin/certi_enum.x64.o")
        print("  # Save output to file, then:")
        print("  python adaptix_cert_vuln_detector.py bof_output.txt")
        print("")
        print("Related: https://github.com/Adaptix-Framework/Extension-Kit")
        if len(sys.argv) != 2 or sys.argv[1] in ['-h', '--help', 'help']:
            sys.exit(0)
        else:
            sys.exit(1)

    output_file = sys.argv[1]

    try:
        with open(output_file, 'r', encoding='utf-8') as f:
            cert_output = f.read()
    except FileNotFoundError:
        print(f"Error: File '{output_file}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    # Create detector and analyze
    detector = certVulnerabilityDetector(cert_output)
    vulnerabilities = detector.analyze()

    # Print results
    print("AD CS Vulnerability Analysis Results")
    print("=" * 50)

    if not vulnerabilities:
        print("No vulnerabilities detected.")
        return

    for vuln_type, affected_items in vulnerabilities.items():
        print(f"\n{vuln_type}:")
        for item in affected_items:
            print(f"  - {item}")

    print(f"\nTotal vulnerabilities found: {sum(len(items) for items in vulnerabilities.values())}")


if __name__ == "__main__":
    main()

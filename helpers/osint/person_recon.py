"""
OSINPY — Person Recon (Identity OSINT Aggregator)
Combines Username, Email, Phone, and Leak search for a target individual.
"""

from __future__ import annotations
from dataclasses import dataclass, field

from helpers.osint.username_osint import UsernameOSINT, UsernameResult
from helpers.osint.email_osint import EmailOSINT, EmailOSINTResult
from helpers.osint.phone_osint import PhoneOSINT, PhoneResult
from helpers.osint.leak_search import LeakSearch, LeakSearchResult


@dataclass
class PersonReconResult:
    name: str = ""
    username: str = ""
    email: str = ""
    phone: str = ""
    
    username_data: UsernameResult | None = None
    email_data: EmailOSINTResult | None = None
    phone_data: PhoneResult | None = None
    
    leaks_email: LeakSearchResult | None = None
    leaks_username: LeakSearchResult | None = None
    leaks_phone: LeakSearchResult | None = None


class PersonRecon:
    """Aggregates human-focused OSINT modules."""
    
    def __init__(self, name: str = "", username: str = "", email: str = "", phone: str = "",
                 config=None, timeout: int = 10):
        self.name = name.strip()
        self.username = username.strip()
        self.email = email.strip()
        self.phone = phone.strip()
        self.config = config
        self.timeout = timeout

    def run(self) -> PersonReconResult:
        result = PersonReconResult(
            name=self.name, username=self.username, email=self.email, phone=self.phone
        )
        
        # 1. Phone
        if self.phone:
            key = self.config.NUMVERIFY_API_KEY if self.config else None
            p_osint = PhoneOSINT(self.phone, numverify_api_key=key, timeout=self.timeout)
            result.phone_data = p_osint.run()
            
            # Leak check for phone
            l_osint = LeakSearch(
                self.phone, "phone", 
                self.config.DEHASHED_EMAIL if self.config else None,
                self.config.DEHASHED_API_KEY if self.config else None,
                self.config.INTELX_API_KEY if self.config else None,
                self.timeout
            )
            result.leaks_phone = l_osint.run()
            
        # 2. Email
        if self.email:
            e_osint = EmailOSINT(
                self.email,
                self.config.HIBP_API_KEY if self.config else None,
                self.config.HUNTER_API_KEY if self.config else None,
                self.timeout
            )
            result.email_data = e_osint.run()
            
            # Leak check for email
            l_osint = LeakSearch(
                self.email, "email", 
                self.config.DEHASHED_EMAIL if self.config else None,
                self.config.DEHASHED_API_KEY if self.config else None,
                self.config.INTELX_API_KEY if self.config else None,
                self.timeout
            )
            result.leaks_email = l_osint.run()
            
        # 3. Username
        if self.username:
            u_osint = UsernameOSINT(self.username, timeout=self.timeout)
            result.username_data = u_osint.run()
            
            # Leak check for username
            l_osint = LeakSearch(
                self.username, "username", 
                self.config.DEHASHED_EMAIL if self.config else None,
                self.config.DEHASHED_API_KEY if self.config else None,
                self.config.INTELX_API_KEY if self.config else None,
                self.timeout
            )
            result.leaks_username = l_osint.run()

        return result

    @staticmethod
    def print_result(result: PersonReconResult) -> None:
        try:
            from rich.console import Console
            console = Console()
            console.print(f"\n[bold magenta]═══ Identity OSINT Dossier ═══[/bold magenta]")
            if result.name:
                console.print(f"Name: [bold]{result.name}[/bold]")
            console.print()
            
            if result.phone_data:
                PhoneOSINT.print_result(result.phone_data)
            if result.leaks_phone and result.leaks_phone.total_found > 0:
                LeakSearch.print_result(result.leaks_phone)
                
            if result.email_data:
                EmailOSINT.print_result(result.email_data)
            if result.leaks_email and result.leaks_email.total_found > 0:
                LeakSearch.print_result(result.leaks_email)
                
            if result.username_data:
                UsernameOSINT.print_result(result.username_data)
            if result.leaks_username and result.leaks_username.total_found > 0:
                LeakSearch.print_result(result.leaks_username)
                
        except ImportError:
            pass

    @staticmethod
    def to_dict(result: PersonReconResult) -> dict:
        return {
            "target": {
                "name": result.name,
                "username": result.username,
                "email": result.email,
                "phone": result.phone,
            },
            "phone_data": PhoneOSINT.to_dict(result.phone_data) if result.phone_data else None,
            "email_data": EmailOSINT.to_dict(result.email_data) if result.email_data else None,
            "username_data": UsernameOSINT.to_dict(result.username_data) if result.username_data else None,
            "leaks_phone": LeakSearch.to_dict(result.leaks_phone) if result.leaks_phone else None,
            "leaks_email": LeakSearch.to_dict(result.leaks_email) if result.leaks_email else None,
            "leaks_username": LeakSearch.to_dict(result.leaks_username) if result.leaks_username else None,
        }

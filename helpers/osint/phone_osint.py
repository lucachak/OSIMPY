"""
OSINPY — Phone OSINT Module
Validates and extracts data from phone numbers using 'phonenumbers' lib,
plus optional external lookups (e.g. Numverify).
"""

from __future__ import annotations
import phonenumbers
from phonenumbers import geocoder, carrier, timezone
from dataclasses import dataclass, field

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class PhoneResult:
    target: str
    is_valid: bool = False
    international_format: str = ""
    country_code: str = ""
    national_number: str = ""
    location: str = ""
    carrier: str = ""
    timezones: list[str] = field(default_factory=list)
    line_type: str = "Unknown"  # Mobile, Fixed-line, Toll-free, etc.
    # External API data
    numverify_data: dict = field(default_factory=dict)


class PhoneOSINT:
    def __init__(self, phone: str, numverify_api_key: str | None = None, timeout: int = 10):
        # Make sure the phone number has a leading + if the user forgot but provided country code
        if not phone.startswith("+") and len(phone) >= 10:
            self.phone = "+" + phone.strip()
        else:
            self.phone = phone.strip()
            
        self.numverify_api_key = numverify_api_key
        self.timeout = timeout

    def run(self) -> PhoneResult:
        result = PhoneResult(target=self.phone)
        print(f"\n[phone] 🔍 Analyzing phone number: {self.phone}...")

        try:
            # Parse number
            parsed = phonenumbers.parse(self.phone, None)
            
            result.is_valid = phonenumbers.is_valid_number(parsed)
            if not result.is_valid:
                print(f"[phone] ❌ Number '{self.phone}' is not a valid phone number.")
                return result

            # Formats
            result.international_format = phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            )
            result.country_code = str(parsed.country_code)
            result.national_number = str(parsed.national_number)
            
            # Geo & Carrier
            result.location = geocoder.description_for_number(parsed, "en")
            result.carrier = carrier.name_for_number(parsed, "en")
            result.timezones = list(timezone.time_zones_for_number(parsed))

            # Line type
            ntype = phonenumbers.number_type(parsed)
            types = {
                phonenumbers.PhoneNumberType.MOBILE: "Mobile",
                phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed-line",
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed-line or Mobile",
                phonenumbers.PhoneNumberType.TOLL_FREE: "Toll-free",
                phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium-rate",
                phonenumbers.PhoneNumberType.VOIP: "VOIP",
                phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal",
                phonenumbers.PhoneNumberType.PAGER: "Pager",
            }
            result.line_type = types.get(ntype, "Unknown")
            
        except phonenumbers.NumberParseException as e:
            print(f"[phone] ❌ Parsing Error: {e}")
            return result

        # Optional: Numverify check
        if self.numverify_api_key and HAS_REQUESTS:
            self._numverify_check(result)

        print(f"[phone] ✅ Analysis complete. Valid: {result.is_valid}")
        return result

    def _numverify_check(self, result: PhoneResult) -> None:
        try:
            # Numverify expects number without the +
            clean_number = result.international_format.replace("+", "").replace(" ", "").replace("-", "")
            url = "http://apilayer.net/api/validate"
            params = {
                "access_key": self.numverify_api_key,
                "number": clean_number
            }
            resp = _requests.get(url, params=params, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("valid"):
                    result.numverify_data = data
                    print("[phone] ✅ Numverify data fetched.")
                else:
                    print(f"[phone] Numverify error or invalid: {data.get('error', data)}")
        except Exception as e:
            print(f"[phone] Numverify error: {e}")

    @staticmethod
    def print_result(result: PhoneResult) -> None:
        try:
            from rich.console import Console
            console = Console()
            console.print(f"\n[bold cyan]═══ Phone OSINT — {result.target} ═══[/bold cyan]\n")
            
            if not result.is_valid:
                console.print("[bold red]❌ Invalid Phone Number[/bold red]")
                return

            console.print(f"[bold green]✅ Valid Number:[/bold green] {result.international_format}")
            console.print(f"  • [bold]Country Code:[/bold] +{result.country_code}")
            console.print(f"  • [bold]Location:[/bold]     {result.location or 'Unknown'}")
            console.print(f"  • [bold]Carrier:[/bold]      {result.carrier or 'Unknown'}")
            console.print(f"  • [bold]Line Type:[/bold]    {result.line_type}")
            console.print(f"  • [bold]Timezone(s):[/bold]  {', '.join(result.timezones)}")

            if result.numverify_data:
                d = result.numverify_data
                console.print("\n[bold]☁️  Numverify Data:[/bold]")
                console.print(f"  • Line type: {d.get('line_type')}")
                console.print(f"  • Carrier:   {d.get('carrier')}")
                
        except ImportError:
            print(f"\nPhone: {result.international_format} (Valid: {result.is_valid})")
            print(f"Location: {result.location}")
            print(f"Carrier: {result.carrier}")

    @staticmethod
    def to_dict(result: PhoneResult) -> dict:
        return {
            "target": result.target,
            "is_valid": result.is_valid,
            "international_format": result.international_format,
            "country_code": result.country_code,
            "location": result.location,
            "carrier": result.carrier,
            "line_type": result.line_type,
            "timezones": result.timezones,
            "numverify_data": result.numverify_data,
        }

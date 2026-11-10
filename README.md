# iPhone Activation Diagnostics

A small, read-only Windows 11 diagnostic utility for collecting local host and
Apple USB driver/service information while troubleshooting an iPhone connection.

## Important limitation

This project **does not bypass, disable, or remove Activation Lock**. It does not
contact Apple's activation servers, generate activation tickets, modify firmware,
enter recovery/DFU mode, or change anything on the iPhone. A local USB report
cannot prove that an iPhone can be activated or that cellular service will work.

Activation Lock is an ownership protection enforced during Apple activation.
Only valid account/device-owner recovery or an Apple-authorized release can
change that server-side state.

## Requirements

- Windows 10 or Windows 11
- Python 3.10+
- PowerShell (included with Windows)
- Apple Devices or Apple Mobile Device Support installed for Apple USB service data

No third-party Python packages are required. Administrator privileges are not
normally needed.

## Run

Open PowerShell in this repository:

```powershell
python .\diagnostics.py
```

Choose a report path:

```powershell
python .\diagnostics.py --output .\reports\iphone-diagnostics.json
```

The report includes Windows/Python/Git versions and present Apple/iPhone
Plug-and-Play devices plus Apple/Bonjour services. Hardware instance IDs,
serial numbers, IMEI values, Apple Account details, and personal files are
intentionally excluded.

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Safety

- Do not use this tool to run Restore, Flash, Erase, Jailbreak, or activation
  modification operations.
- Review the JSON report before sharing it; host details may still be sensitive.
- This utility is diagnostic only and makes no claim that a bypass exists.

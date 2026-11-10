# iPhone Activation Diagnostics

A read-only Windows utility for inspecting local Apple USB connectivity while
troubleshooting an iPhone connection.

## Important limitation

This project **does not bypass, disable, or remove Activation Lock**. It does not
contact Apple's activation servers, generate activation tickets, modify firmware,
or change anything on the iPhone. A local USB report cannot prove that an iPhone
can be activated or that cellular service will work.

Activation Lock is enforced during Apple activation. Only valid account recovery
or an Apple-authorized release can change that server-side state.

## Requirements

- Windows 10 or Windows 11
- Python 3.10+
- PowerShell (included with Windows)
- Apple Devices or Apple Mobile Device Support for Apple USB driver information

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

## Report contents

The JSON report includes:

- Windows, Python, and Git version information.
- Present Apple-related Plug-and-Play devices.
- Device status, class, driver service, and problem code.
- Sanitized USB vendor/product IDs (VID/PID only).
- A heuristic mode classification: DFU, Recovery, NormalLikely,
  AppleUSBTransport, or Unknown.
- Availability of optional `ideviceinfo`, `idevice_id`, and `irecovery`
  command-line tools.
- Apple/Bonjour Windows services when present.

The mode classification is intentionally conservative. A Windows device name
such as **Apple iPhone** is reported as `NormalLikely`, not as proof that the
phone is fully accessible. USB product IDs can vary by device and software.
The tool does not collect USB instance IDs, serial numbers, IMEI values, Apple
Account details, or personal files.

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Safety

- The utility performs local read-only inspection only.
- It does not run Restore, Flash, Erase, Jailbreak, or activation modification
  operations.
- Review the JSON report before sharing it; host details may still be sensitive.
- This utility is diagnostic only and makes no claim that an Activation Lock
  bypass exists.

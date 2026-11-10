import unittest

from activation_preflight import evaluate_preflight


def matching_snapshot():
    return {
        "properties": {
            "ProductType": {"available": True, "value": "iPhone17,3"},
            "ProductVersion": {"available": True, "value": "18.3.2"},
            "BuildVersion": {"available": True, "value": "22D82"},
            "ActivationState": {"available": True, "value": "Unactivated"},
        },
        "privacy": {
            "udid_included": False,
            "serial_number_included": False,
            "ecid_included": False,
        },
        "safety": {"read_only": True},
    }


def matching_ipsw_report():
    return {
        "expected_target": {
            "product_type": "iPhone17,3",
            "product_version": "18.3.2",
            "product_build_version": "22D82",
        },
        "checks": {"inspection_passed": True},
    }


class ActivationPreflightTests(unittest.TestCase):
    def test_matching_evidence_passes_non_invasive_preflight(self):
        report = evaluate_preflight(matching_snapshot(), matching_ipsw_report())
        self.assertTrue(report["preflight_passed"])
        self.assertEqual(report["assessment"], "ready_for_non_invasive_inspection")
        self.assertEqual(report["allowed_next_scope"], "read_only_observation_only")
        self.assertFalse(report["safety"]["device_accessed"])

    def test_wrong_device_build_blocks_preflight(self):
        snapshot = matching_snapshot()
        snapshot["properties"]["BuildVersion"]["value"] = "22D72"
        report = evaluate_preflight(snapshot, matching_ipsw_report())
        self.assertFalse(report["preflight_passed"])
        self.assertFalse(report["checks"]["device_identity_matches_expected_target"])

    def test_unknown_activation_state_blocks_preflight(self):
        snapshot = matching_snapshot()
        snapshot["properties"]["ActivationState"]["available"] = False
        report = evaluate_preflight(snapshot, matching_ipsw_report())
        self.assertFalse(report["checks"]["activation_state_is_unactivated"])

    def test_unverified_ipsw_checksum_blocks_preflight(self):
        report_data = matching_ipsw_report()
        report_data["checks"]["inspection_passed"] = False
        report = evaluate_preflight(matching_snapshot(), report_data)
        self.assertFalse(report["checks"]["ipsw_manifest_and_checksum_checks_passed"])

    def test_identifier_inclusion_blocks_preflight(self):
        snapshot = matching_snapshot()
        snapshot["privacy"]["serial_number_included"] = True
        report = evaluate_preflight(snapshot, matching_ipsw_report())
        self.assertFalse(report["checks"]["snapshot_excludes_device_identifiers"])


if __name__ == "__main__":
    unittest.main()

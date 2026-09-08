"""Coverage for the default-profile deterministic PII recognizers.

Each fires when a labeled-field anchor (`First Name:`, `Address:`, `DOB:`,
`Account Number:`, etc.) is followed by an explicit `[:#=]` delimiter and
a value matching the per-entity shape constraint. Mirrors the discipline
of `regex.national_id_anchored`: anchor + delimiter gate keeps benign-FP
load at zero while the per-entity value class trims FP risk further
(capitalized first letter for PERSON, digit-density for BANK_ACCOUNT,
date-shape for DATE_OF_BIRTH).
"""

from __future__ import annotations

import unittest

from lsdf.scanners.regex import RegexScanner, default_recognizers
from lsdf.surfaces import Surface


class DefaultPIIRecognizerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scanner = RegexScanner(default_recognizers())

    def _findings_of(self, text: str, detector_id: str):
        surface = Surface(name="output.content", pointer=("content",), value=text)
        return [f for f in self.scanner.scan(surface) if f.detector_id == detector_id]

    # -- PERSON recognizer ----------------------------------------------

    def test_person_first_name_label_captures_value(self):
        text = "- First Name: Melissa\n- Last Name: Nealon\n"
        ids = self._findings_of(text, "regex.person_anchored")
        self.assertGreaterEqual(len(ids), 1, ids)
        self.assertIn("Melissa", [f.value for f in ids])
        for f in ids:
            self.assertEqual(f.entity, "PERSON")

    def test_person_markdown_bold_anchor(self):
        text = "**First Name**: Jemima"
        ids = self._findings_of(text, "regex.person_anchored")
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "Jemima")

    def test_person_multi_word_value_captured_whole(self):
        # Greedy value class must capture "Long Wong" not just "Long".
        text = "Patient Name: Long Wong\n\n**Date**"
        ids = self._findings_of(text, "regex.person_anchored")
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "Long Wong")

    def test_person_dutch_voornaam_numbered_label(self):
        text = "- Voornaam 1: Arjen\n- Voornaam 2: Zomerhaven"
        ids = self._findings_of(text, "regex.person_anchored")
        captured = sorted(f.value for f in ids)
        self.assertEqual(captured, ["Arjen", "Zomerhaven"], ids)

    def test_person_snake_case_json_given_name(self):
        text = '"given_name": "Ylli", "passport_number": "JJ"'
        ids = self._findings_of(text, "regex.person_anchored")
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "Ylli")

    def test_person_title_anchor_captures_honorific(self):
        text = "- Title: Professor\n- Email: foo"
        ids = self._findings_of(text, "regex.person_anchored")
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "Professor")

    def test_portuguese_name_context_captures_chat_names(self):
        text = "Claro, meu nome é Cauã Rocha. De nada, Sr. Otávio Peixoto!"
        ids = self._findings_of(text, "regex.person_portuguese_context")
        self.assertEqual([f.value for f in ids], ["Cauã Rocha", "Sr. Otávio Peixoto"])
        for f in ids:
            self.assertEqual(f.entity, "PERSON")

    def test_person_lowercase_value_does_not_match(self):
        # Value class requires capitalized first letter; lowercase values
        # like "report.pdf" prevent benign "File Name: report.pdf" FP.
        text = "File Name: report.pdf"
        ids = self._findings_of(text, "regex.person_anchored")
        self.assertEqual(ids, [])

    # -- ADDRESS recognizer ---------------------------------------------

    def test_address_street_address_anchor(self):
        text = "Street Address: 123 Main Street\nCity: Springfield"
        ids = self._findings_of(text, "regex.address_anchored")
        self.assertGreaterEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].entity, "ADDRESS")
        self.assertIn("123 Main Street", ids[0].value)

    def test_address_dutch_adres_label(self):
        text = "- Adres: Voorbeeldlaan 461\n- Land: CH"
        ids = self._findings_of(text, "regex.address_anchored")
        self.assertGreaterEqual(len(ids), 1, ids)
        self.assertIn("Voorbeeldlaan", ids[0].value)

    def test_address_does_not_fire_on_ip_address_label(self):
        # `IP Address:` and `IP-adres:` must NOT match address regex.
        text = "IP Address: 192.168.1.1\nIP-adres: 10.0.0.1\nMAC address: 3C:22"
        ids = self._findings_of(text, "regex.address_anchored")
        self.assertEqual(ids, [])

    def test_distinctive_postcode_shapes_fire_as_address(self):
        cases = [
            ("UK postcode SW1A 1AA appears in the reply.", "SW1A 1AA"),
            ("Dutch postcode 1234 AB appears in the reply.", "1234 AB"),
            ("Canadian postcode K1A 0B1 appears in the reply.", "K1A 0B1"),
        ]
        for text, expected in cases:
            with self.subTest(expected=expected):
                ids = self._findings_of(text, "regex.address_postcode_shape")
                self.assertEqual(len(ids), 1, ids)
                self.assertEqual(ids[0].entity, "ADDRESS")
                self.assertEqual(ids[0].value, expected)

    def test_brazil_address_shape_with_state_and_cep(self):
        expected = "Conjunto Hellena Peixoto, 2359, Santa Sofia, Pastor - SP, 92610-902"
        ids = self._findings_of(f"O novo endereço é {expected}.", "regex.brazil_address")
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].entity, "ADDRESS")
        self.assertEqual(ids[0].value, expected)

    # -- Brazilian national ID and phone recognizers ---------------------

    def test_cpf_shape_uses_check_digit_validator(self):
        ids = self._findings_of("cpf: 275 860 391 86", "regex.cpf")
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].entity, "BR_CPF")
        self.assertEqual(ids[0].value, "275 860 391 86")

    def test_invalid_cpf_shape_is_rejected(self):
        cases = [
            "cpf: 111.111.111-11",
            "cpf: 275 860 391 87",
        ]
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(self._findings_of(text, "regex.cpf"), [])

    def test_brazil_phone_shape_does_not_match_nanp(self):
        ids = self._findings_of("Telefone: (11) 90116-2128", "regex.brazil_phone")
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].entity, "PHONE")
        self.assertEqual(ids[0].value, "(11) 90116-2128")
        self.assertEqual(
            self._findings_of("US phone: (212) 555-0199", "regex.brazil_phone"),
            [],
        )

    # -- DATE_OF_BIRTH recognizer ---------------------------------------

    def test_dob_iso_date_value(self):
        text = "DOB: 1985-03-22\n\nNotes:"
        ids = self._findings_of(text, "regex.date_of_birth_anchored")
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "1985-03-22")
        self.assertEqual(ids[0].entity, "DATE_OF_BIRTH")

    def test_dob_dutch_geboortedatum_freeform_value(self):
        text = "- Geboortedatum: 12e juni 2041\n- Naam"
        ids = self._findings_of(text, "regex.date_of_birth_anchored")
        self.assertEqual(len(ids), 1, ids)
        self.assertIn("12e", ids[0].value)
        self.assertIn("juni", ids[0].value)

    def test_dob_date_of_birth_iso_long_form(self):
        text = "Date of Birth: 1977-08-15\nSocial"
        ids = self._findings_of(text, "regex.date_of_birth_anchored")
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "1977-08-15")

    # -- BANK_ACCOUNT recognizer ----------------------------------------

    def test_bank_account_number_anchor_with_dashed_value(self):
        text = "Account Number: 152634-93721548\nPIN:"
        ids = self._findings_of(text, "regex.bank_account_anchored")
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].entity, "BANK_ACCOUNT")
        self.assertEqual(ids[0].value, "152634-93721548")

    def test_bank_routing_number_anchor(self):
        text = "Bank Routing Number: 091000022 - Date"
        ids = self._findings_of(text, "regex.bank_account_anchored")
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "091000022")

    def test_bank_account_low_digit_value_rejected(self):
        # Lookahead requires ≥6 digits in capture — "Account: open" must
        # NOT fire (no digits at all in the value).
        text = "Account Number: open\nAnother"
        ids = self._findings_of(text, "regex.bank_account_anchored")
        self.assertEqual(ids, [])

    # -- Detector family + entity contracts ----------------------------

    def test_detector_ids_and_entities_pinned(self):
        text = (
            "Name: Alice\n"
            "Street Address: 1 Privet Drive\n"
            "DOB: 2000-01-01\n"
            "Account Number: 12345678\n"
        )
        findings = self.scanner.scan(
            Surface(name="output.content", pointer=("content",), value=text)
        )
        by_detector = {f.detector_id: f.entity for f in findings}
        self.assertEqual(by_detector.get("regex.person_anchored"), "PERSON")
        self.assertEqual(by_detector.get("regex.address_anchored"), "ADDRESS")
        self.assertEqual(by_detector.get("regex.date_of_birth_anchored"), "DATE_OF_BIRTH")
        self.assertEqual(by_detector.get("regex.bank_account_anchored"), "BANK_ACCOUNT")

    # -- Negative: no anchors / no delimiter ----------------------------

    def test_no_anchor_no_match(self):
        text = "Just some narrative text mentioning Alice and Springfield."
        for det_id in [
            "regex.person_anchored",
            "regex.address_anchored",
            "regex.date_of_birth_anchored",
            "regex.bank_account_anchored",
        ]:
            self.assertEqual(self._findings_of(text, det_id), [])

    def test_anchor_present_but_no_delimiter_does_not_match(self):
        # Narrative "First Name Alice was born in Toronto." has no `[:#=]`
        # delimiter — the recognizer must not fire.
        text = "First Name Alice was born in Toronto."
        ids = self._findings_of(text, "regex.person_anchored")
        self.assertEqual(ids, [])

    def test_person_single_letter_value_rejected(self):
        # "Speaker: I think the answer..." must not capture `I` as a person.
        # The trailing `[A-Za-zÀ-ÿŽž]` in the value class requires ≥2 chars.
        text = "Speaker: I think the answer is yes."
        ids = self._findings_of(text, "regex.person_anchored")
        # If anything fires, it must NOT be a single-letter capture.
        for f in ids:
            self.assertGreater(len(f.value), 1, f"single-letter PERSON: {f}")

    def test_known_fp_proper_noun_capitalized_value_does_match(self):
        # Documents a known-FP class: bare `Title:` / `Name:` anchors
        # combined with capitalized values fire on benign content like
        # "Movie Title: Wonder Woman" / "Project Name: Apollo". The
        # capitalized-first-letter value-class guard rejects lowercase
        # benign values (handled by test_person_lowercase_value_does_not_match)
        # but cannot distinguish proper nouns. Pinning the current behavior
        # so a future regex tightening that would change this is visible.
        text = "Movie Title: Wonder Woman\n"
        ids = self._findings_of(text, "regex.person_anchored")
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "Wonder Woman")

    def test_pinned_confidences_per_recognizer(self):
        # Pin confidence values so silent drift surfaces.
        text = (
            "First Name: Alice\n"
            "Street Address: 1 Privet Drive\n"
            "DOB: 2000-01-01\n"
            "Account Number: 12345678\n"
        )
        findings = self.scanner.scan(
            Surface(name="output.content", pointer=("content",), value=text)
        )
        confidences = {f.detector_id: f.confidence for f in findings}
        self.assertAlmostEqual(confidences.get("regex.person_anchored", -1), 0.78, places=2)
        self.assertAlmostEqual(confidences.get("regex.address_anchored", -1), 0.78, places=2)
        self.assertAlmostEqual(confidences.get("regex.date_of_birth_anchored", -1), 0.84, places=2)
        self.assertAlmostEqual(confidences.get("regex.bank_account_anchored", -1), 0.86, places=2)

    def test_nfd_accented_anchor_normalizes_without_losing_original_span(self):
        text = "Nume\u0301ro_Social: 9-11-22-33333-444-55"
        ids = self._findings_of(text, "regex.national_id_anchored")
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "9-11-22-33333-444-55")


if __name__ == "__main__":
    unittest.main()

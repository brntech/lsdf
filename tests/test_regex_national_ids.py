"""Coverage for the international national-ID anchored recognizer.

The `regex.national_id_anchored` recognizer fires when a labeled national-
identifier anchor (BSN, codice fiscale, NIR, Steuer-ID, DNI/NIE, NINO,
Social Number, etc.) is followed by an explicit `[:#=]` delimiter and a
6-30 char alphanumeric value. These tests pin per-locale coverage,
JSON / camelCase / underscore variant tolerance, and the negative cases
(narrative-style without delimiter, benign English prose containing
acronyms like `cf` or `nir` outside an anchor context).
"""

from __future__ import annotations

import unittest

from lsdf.scanners.regex import RegexScanner, default_recognizers
from lsdf.surfaces import Surface


class NationalIdAnchoredTests(unittest.TestCase):
    """One detector_id, many anchor families. Each test pins one anchor."""

    @classmethod
    def setUpClass(cls):
        # Use the production recognizer set so tests catch any drift in the
        # default_recognizers() ordering or shape.
        cls.scanner = RegexScanner(default_recognizers())

    def _findings(self, text: str):
        surface = Surface(name="output.content", pointer=("content",), value=text)
        return self.scanner.scan(surface)

    def _national_ids(self, text: str):
        return [
            f for f in self._findings(text)
            if f.detector_id == "regex.national_id_anchored"
        ]

    # -- Dutch BSN --------------------------------------------------------

    def test_dutch_bsn_nummer_label_with_dashed_value(self):
        text = "BSN-nummer: 11-22-33-44-A55-6 - Identiteitskaart: foo"
        ids = self._national_ids(text)
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "11-22-33-44-A55-6")
        self.assertEqual(ids[0].entity, "NATIONAL_ID")

    def test_dutch_burgerservicenummer_label_with_dotted_value(self):
        text = "Burgerservicenummer: 111.2222.3333.44 - Identiteitskaart: X0000000"
        ids = self._national_ids(text)
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "111.2222.3333.44")

    def test_dutch_sociaal_nummer_label_with_pure_digits(self):
        text = "Sociaal nummer: 900000001 Identiteitskaart: FRG"
        ids = self._national_ids(text)
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "900000001")

    # -- French NIR / sécurité sociale -----------------------------------

    def test_french_camelcase_socialsecuritynumber_json(self):
        text = '"SocialSecurityNumber":"900000000000001",'
        ids = self._national_ids(text)
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "900000000000001")

    def test_french_numero_social_underscore_json(self):
        text = '"Numéro_Social": "9-11-22-33333-444-55",'
        ids = self._national_ids(text)
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "9-11-22-33333-444-55")

    # -- Italian codice fiscale + sicurezza sociale ----------------------

    def test_italian_numero_di_sicurezza_sociale(self):
        text = "- Numero di Sicurezza Sociale: 90000000A001 - Carta"
        ids = self._national_ids(text)
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "90000000A001")

    def test_italian_numero_di_previdenza_sociale(self):
        text = "Numero di previdenza sociale: 9000000001 - Password:"
        ids = self._national_ids(text)
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "9000000001")

    # -- German Steuer-ID + Sozialversicherungsnummer --------------------

    def test_german_sozialversicherungsnummer(self):
        text = "**Sozialversicherungsnummer:** 11 22 33 44 A55 6 - Adresse"
        ids = self._national_ids(text)
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "11 22 33 44 A55 6")

    def test_german_sozialnummer(self):
        text = "Spieler A: - Sozialnummer: 90000000B002 - IP-Adresse:"
        ids = self._national_ids(text)
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "90000000B002")

    # -- Spanish DNI / seguridad social ---------------------------------

    def test_spanish_numero_de_seguridad_social_underscore_json(self):
        text = 'Numero_de_seguridad_social: "900000000001"'
        ids = self._national_ids(text)
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "900000000001")

    # -- Markdown-asterisk anchor tolerance ------------------------------

    def test_markdown_asterisk_wrapped_anchor(self):
        text = "*Social Number:* 55-44-33-22-B11-0 - *Driver License:*"
        ids = self._national_ids(text)
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "55-44-33-22-B11-0")

    # -- Generic Social Number / Social Security Number -----------------

    def test_english_social_security_number_label(self):
        text = "Social Security Number: 262-98-7007\n\n**Contact**"
        ids = self._national_ids(text)
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "262-98-7007")

    def test_english_social_number_label_with_dashed_value(self):
        text = "Social Number: 900-000-0001\n - Driver"
        ids = self._national_ids(text)
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "900-000-0001")

    # -- Negative: narrative without delimiter ---------------------------

    def test_narrative_social_security_number_is_value_does_not_match_anchored(self):
        # The shipped US-shape `regex.ssn` recognizer catches the SSN, but
        # this anchored recognizer must NOT span over English prepositions
        # ("is", "of") between anchor and value — otherwise it would glom
        # the value with surrounding prose.
        text = "My Social Security Number is 212-92-7506. I have"
        ids = self._national_ids(text)
        self.assertEqual(ids, [])

    # -- Negative: benign acronyms outside anchor context ----------------

    def test_benign_cf_acronym_does_not_match_without_value_delimiter(self):
        # `\bcf\b` requires immediate `[:#=]` or `\s+[A-Z0-9]` lookahead;
        # this prose-style usage of "cf." (Latin abbreviation) must not fire.
        text = "See the appendix; cf. section 4 for the methodology."
        ids = self._national_ids(text)
        self.assertEqual(ids, [])

    def test_benign_nir_acronym_in_prose_does_not_match(self):
        # Bare `NIR` standalone is in the anchor list; without a `[:#=]`
        # delimiter it must not fire.
        text = "The NIR study group reported the findings last quarter."
        ids = self._national_ids(text)
        self.assertEqual(ids, [])

    def test_benign_dni_acronym_without_delimiter_does_not_match(self):
        # `\bDNI\b` standalone needs `:#=` to claim a value.
        text = "The DNI Spanish identity system uses 8 digits plus a letter."
        ids = self._national_ids(text)
        self.assertEqual(ids, [])

    # -- Negative: value class refuses newlines --------------------------

    def test_value_does_not_absorb_newlines_into_next_field(self):
        # The value class is `[A-Za-z0-9.\- ]` (literal space, no `\s`);
        # a newline must terminate the captured value before the next label.
        text = (
            "- Social Number: 900 000 0001\n"
            "- Passport Number: 900000002\n"
        )
        ids = self._national_ids(text)
        # Should match the Social Number value cleanly, not glom in
        # "\n- Passport Number:".
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "900 000 0001")

    # -- Detector id and entity contract ---------------------------------

    def test_detector_id_and_entity(self):
        text = "BSN-nummer: 900000003 ..."
        ids = self._national_ids(text)
        self.assertEqual(len(ids), 1)
        self.assertEqual(ids[0].entity, "NATIONAL_ID")
        self.assertEqual(ids[0].detector_family, "regex")
        self.assertEqual(ids[0].detector_id, "regex.national_id_anchored")
        # Confidence baked at 0.86; pin so silent drift surfaces.
        self.assertAlmostEqual(ids[0].confidence, 0.86, places=2)

    # -- Anchor list survives wrapping in JSON quotes --------------------

    def test_quoted_anchor_in_json_object_with_quoted_value(self):
        text = '"Social Number":"900000004","ID Card":"YHH",'
        ids = self._national_ids(text)
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "900000004")

    # -- Multiple anchors in one document (per-anchor independence) ------

    def test_two_anchors_in_one_document_both_match_independently(self):
        text = (
            "Profile A: BSN-nummer: 900000003\n"
            "Profile B: Codice fiscale: RSSMRA80A01H501Z\n"
        )
        ids = self._national_ids(text)
        captured = sorted(f.value for f in ids)
        self.assertEqual(captured, ["900000003", "RSSMRA80A01H501Z"], ids)

    # -- Field-separator negative lookahead pin --------------------------

    def test_field_separator_space_dash_space_terminates_value(self):
        # Without the inner ` - ` lookahead in the value class, this would
        # absorb " - Adresse: foo" into the captured value because dash and
        # space are both in the value-class character set.
        text = "Sozialversicherungsnummer: 11 22 33 44 A55 6 - Adresse: foo"
        ids = self._national_ids(text)
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "11 22 33 44 A55 6")

    def test_value_with_internal_dashes_no_spaces_is_kept_intact(self):
        # `TST-AAA-42-B-07-C-ZZZ`-shape values (codice-fiscale-ish) use dashes
        # without surrounding whitespace; the field-separator lookahead must
        # NOT terminate these prematurely.
        text = "Social Number: TST-AAA-42-B-07-C-ZZZ - Password: secret"
        ids = self._national_ids(text)
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "TST-AAA-42-B-07-C-ZZZ")

    # -- Length boundary: value class is anchored at 6-30 chars ----------

    def test_value_under_six_chars_does_not_match(self):
        # Anchored value must be at least 6 chars (1 anchor char + 4-28
        # interior + 1 anchor char). A 5-char value fails the regex shape.
        text = "BSN: 12345"
        ids = self._national_ids(text)
        self.assertEqual(ids, [])

    def test_value_at_exactly_six_chars_does_match(self):
        text = "BSN: 123456"
        ids = self._national_ids(text)
        self.assertEqual(len(ids), 1, ids)
        self.assertEqual(ids[0].value, "123456")

    # -- IBAN-shape under an ID anchor (collision with regex.iban) -------

    def test_iban_shaped_value_under_bsn_anchor_fires_both_recognizers(self):
        # Documents that the anchored recognizer and the IBAN recognizer
        # are both allowed to fire on the same span — overlap resolution
        # is owned by DetectorRegistry, not by the recognizers themselves.
        # A future change that suppresses one detector would update this
        # test rather than silently change the behavior.
        text = "BSN-nummer: NL91ABNA0417164300"
        findings = self._findings(text)
        national_id = [f for f in findings if f.detector_id == "regex.national_id_anchored"]
        ibans = [f for f in findings if f.detector_id == "regex.iban"]
        self.assertEqual(len(national_id), 1, findings)
        self.assertEqual(len(ibans), 1, findings)
        self.assertEqual(national_id[0].value, "NL91ABNA0417164300")
        self.assertEqual(ibans[0].value, "NL91ABNA0417164300")


if __name__ == "__main__":
    unittest.main()

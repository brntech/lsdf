import unittest
from pathlib import Path

import yaml


class DeploymentConfigurationTests(unittest.TestCase):
    def test_documented_detector_settings_reach_source_and_release_gateways(self):
        settings = ("LSDF_PERSON_DENY_LIST_EXTRA", "LSDF_ENTROPY_DENY_SUBSTRINGS",
                    "LSDF_EMAIL_DENY_LOCAL_PARTS")
        for filename, names in (("docker-compose.yml", ("gateway", "runtime", "gateway-ml")),
                                ("compose.release.yaml", ("gateway",))):
            services = yaml.safe_load(Path(filename).read_text())["services"]
            for name in names:
                with self.subTest(filename=filename, service=name):
                    for setting in settings:
                        self.assertEqual(services[name]["environment"][setting], "${" + setting + ":-}")

    def test_ml_worker_deadlines_reach_model_services(self):
        for filename, names in (("docker-compose.yml", ("optional-cli", "gateway-ml", "optional-test")),
                                ("compose.release.yaml", ("gateway",))):
            services = yaml.safe_load(Path(filename).read_text())["services"]
            for name in names:
                with self.subTest(filename=filename, service=name):
                    env = services[name]["environment"]
                    for setting, default in (("LSDF_OPENAI_PRIVACY_FILTER_STARTUP_TIMEOUT_SECONDS", 300),
                                             ("LSDF_OPENAI_PRIVACY_FILTER_INFERENCE_TIMEOUT_SECONDS", 60)):
                        self.assertEqual(env[setting], "${" + setting + ":-" + str(default) + "}")


if __name__ == "__main__":
    unittest.main()

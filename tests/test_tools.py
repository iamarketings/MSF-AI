
import sys
import os
import unittest
import time
from unittest.mock import MagicMock, patch

# Ajouter le répertoire racine au chemin
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from msf_aiv4.tools import network, os_tools, web

class TestToolsv4(unittest.TestCase):

    def test_check_port_open(self):
        # On teste juste que ça retourne un booléen (vrai ou faux selon l'environnement)
        res = network.check_port_open("127.0.0.1", 22)
        self.assertIsInstance(res, bool)

    def test_safe_mode_blocking(self):
        # Configuration simulée du mode safe
        os_tools.set_config({
            "security_mode": "safe",
            "forbidden_commands": ["rm -rf", "del /f"]
        })

        # Test d'une commande autorisée
        res_ok = os_tools.execute_linux_command("whoami")
        # Sur l'environnement de test jules, on s'attend à "jules"
        self.assertNotIn("Blocage de sécurité", res_ok)

        # Test d'une commande non autorisée en mode safe
        res_block = os_tools.execute_linux_command("apt-get install nmap")
        self.assertIn("Blocage de sécurité", res_block)

        # Test d'une commande interdite (critique)
        res_forbidden = os_tools.execute_linux_command("rm -rf /")
        self.assertIn("Blocage de sécurité critique", res_forbidden)

    def test_web_rate_limiting(self):
        # On définit un petit rate limit pour le test
        @web.rate_limit(calls_per_minute=2)
        def test_func():
            return "ok"

        self.assertEqual(test_func(), "ok")
        self.assertEqual(test_func(), "ok")
        # Le 3ème appel doit échouer
        res = test_func()
        self.assertIn("Rate limit dépassé", res)

if __name__ == '__main__':
    unittest.main()

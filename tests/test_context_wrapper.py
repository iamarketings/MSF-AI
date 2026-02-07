import sys
import os
import unittest
from unittest.mock import MagicMock

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mocking parts of the system to avoid importing everything
class MockConversation:
    def __init__(self):
        self.dynamic_context = {}

class MockOrchestrator:
    def __init__(self):
        self.context = {}

class MockController:
    def __init__(self):
        self.conversation = MockConversation()
        self.orchestrator = MockOrchestrator()

    # Copying the method logic directly or importing it?
    # Importing it is better but it's a member method.
    # I will rely on the fact that I just implemented it in msf_controller.py
    # But to test it properly, I should instantiate MSFAIController or copy the logic.
    # Since MSFAIController has many dependencies (MSFModel, etc.), it's hard to instantiate.
    # I'll manually bind the method I wrote to this MockController or just copy the logic for unit testing the *logic*.
    # Ideally, I'd import MSFAIController, but its __init__ does heavy lifting (dotenv, connection).
    # I'll try to import the class but patch __init__.

    def _wrap_tool_with_context(self, func_name: str, func):
        # This is the exact code I injected.
        # For the test to be valid, I should rely on the actual file content,
        # but since I cannot easily partial-import, I will verify the logic by "re-implementing"
        # or better: I will create a small script that imports `msf_controller` but mocks `__init__`.
        pass

from msf_controller import MSFAIController

class TestContextWrapper(unittest.TestCase):
    def setUp(self):
        # Monkey patch __init__ to avoid side effects
        self.original_init = MSFAIController.__init__
        MSFAIController.__init__ = lambda x: None

        self.controller = MSFAIController()
        # Restore manually what we need
        self.controller.conversation = MockConversation()
        self.controller.orchestrator = MockOrchestrator()

    def tearDown(self):
        MSFAIController.__init__ = self.original_init

    def test_wrap_nmap_scan(self):
        # Setup context
        self.controller.conversation.dynamic_context['TARGET'] = "192.168.1.10"

        # Dummy tool
        mock_tool = MagicMock(return_value="Scan result")

        # Wrap it
        wrapped = self.controller._wrap_tool_with_context("nmap_scan", mock_tool)

        # Call without args
        wrapped()

        # Check if target was injected
        mock_tool.assert_called_with(target="192.168.1.10")
        print("[OK] nmap_scan injected target from dynamic_context")

    def test_wrap_run_exploit(self):
        # Setup context in orchestrator this time
        self.controller.conversation.dynamic_context = {}
        self.controller.orchestrator.context['RHOSTS'] = "10.0.0.5"

        # Dummy tool
        mock_tool = MagicMock(return_value="Exploit launched")

        # Wrap it
        wrapped = self.controller._wrap_tool_with_context("run_exploit", mock_tool)

        # Call without args
        wrapped()

        # Check if options['RHOSTS'] was injected
        mock_tool.assert_called_with(options={'RHOSTS': "10.0.0.5"})
        print("[OK] run_exploit injected RHOSTS from orchestrator context")

    def test_wrap_web_tool(self):
        self.controller.conversation.dynamic_context['TARGET'] = "example.com"

        mock_tool = MagicMock(return_value="WAF result")
        wrapped = self.controller._wrap_tool_with_context("check_waf", mock_tool)

        wrapped()

        # Should add http://
        mock_tool.assert_called_with(url="http://example.com")
        print("[OK] check_waf injected url with http prefix")

    def test_no_override_if_provided(self):
        self.controller.conversation.dynamic_context['TARGET'] = "192.168.1.10"

        mock_tool = MagicMock(return_value="Scan result")
        wrapped = self.controller._wrap_tool_with_context("nmap_scan", mock_tool)

        # Call WITH args
        wrapped(target="8.8.8.8")

        # Should NOT use context
        mock_tool.assert_called_with(target="8.8.8.8")
        print("[OK] User argument overrides context injection")

if __name__ == '__main__':
    unittest.main()

"""Focused assertion probe for the four independently specified mutations."""
import json
import unittest
import test_model

if __name__ == '__main__':
    suite = unittest.TestSuite([
        test_model.Contract('test_frozen_reports'),
        test_model.Contract('test_roundup_boundary_helpers')])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps({'tests': result.testsRun, 'failures': len(result.failures),
                      'errors': len(result.errors),
                      'assertion_only': all('AssertionError:' in text for _, text in result.failures)}))
    raise SystemExit(0 if result.wasSuccessful() else 1)

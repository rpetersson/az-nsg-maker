import unittest
from main import LoadDataFromExcel, NSGRule, main
import os
import json

class TestLoadDataFromExcel(unittest.TestCase):
    def test_load_excel(self):
        loader = LoadDataFromExcel('test_input.xls')
        loader.loadExcel()
        data = loader.getData()
        self.assertIsNotNone(data)
        self.assertIsInstance(data, list)

class TestNSGRule(unittest.TestCase):
    def test_to_dict(self):
        rule = NSGRule(
            priority=1000,
            direction='Inbound',
            source_asg='sourceAsg',
            destination_asg='destinationAsg',
            destination_port='8080',
            source_ip='192.168.1.1',
            destination_ip='192.168.2.1'
        )
        rule_dict = rule.to_dict()
        self.assertEqual(rule_dict['priority'], 1000)
        self.assertEqual(rule_dict['direction'], 'Inbound')
        self.assertEqual(rule_dict['access'], 'Allow')
        self.assertEqual(rule_dict['protocol'], 'Tcp')

class TestMainFunction(unittest.TestCase):
    def test_main(self):
        input_file = 'test_input.xls'
        output_dir = 'test_output'
        main(input_file, output_dir)
        self.assertTrue(os.path.exists(output_dir))
        self.assertTrue(len(os.listdir(output_dir)) > 0)
        for file_name in os.listdir(output_dir):
            with open(os.path.join(output_dir, file_name), 'r') as f:
                data = json.load(f)
                self.assertIsInstance(data, list)

if __name__ == '__main__':
    unittest.main()

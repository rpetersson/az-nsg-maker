from python_excel2json import parse_excel_to_json
import json
import os
import argparse  # Import argparse for command-line arguments
from schema import EXCEL_SHEET_SCHEMA  # Import the schema

class LoadDataFromExcel:
    """
    Class to load data from an Excel file and convert it to JSON format.
    """
    def __init__(self, path: str) -> None:
        """
        Initialize the LoadDataFromExcel class with the path to the Excel file.

        :param path: Path to the Excel file.
        """
        self.path = path
        self.data = None  # Initialize data as None
        
    def loadExcel(self) -> None:
        """
        Load the Excel file and convert it to JSON format using the provided schema.
        """
        self.data = parse_excel_to_json(EXCEL_SHEET_SCHEMA, self.path)  # Use the imported schema
        
    def getData(self) -> list:
        """
        Get the loaded data.

        :return: List of data loaded from the Excel file.
        """
        return self.data

class NSGRule:
    """
    Class to represent a Network Security Group (NSG) rule.
    """
    def __init__(self, priority: int, direction: str, source_asg: str, destination_asg: str, destination_port: str, source_ip: str = None, destination_ip: str = None) -> None:
        """
        Initialize the NSGRule class with the given parameters.

        :param priority: Priority of the rule.
        :param direction: Direction of the rule (Inbound/Outbound).
        :param source_asg: Source Application Security Group.
        :param destination_asg: Destination Application Security Group.
        :param destination_port: Destination port.
        :param source_ip: Source IP address (optional).
        :param destination_ip: Destination IP address (optional).
        """
        self.priority = priority
        self.direction = direction
        self.source_asg = source_asg
        self.destination_asg = destination_asg
        self.destination_port = destination_port
        self.source_ip = source_ip
        self.destination_ip = destination_ip

    def to_dict(self) -> dict:
        """
        Convert the NSG rule to a dictionary format.

        :return: Dictionary representation of the NSG rule.
        """
        rule = {
            'name': 'Allow-{}-{}-to-{}-{}'.format(
                self.direction,
                self.source_asg or self.source_ip,
                self.destination_asg or self.destination_ip,
                self.destination_port
            ),
            'priority': self.priority,
            'direction': self.direction,
            'access': 'Allow',
            'protocol': 'Tcp',
            'sourcePortRanges': ['*'],
            'destinationPortRanges': [self.destination_port]
        }

        # Add sourceApplicationSecurityGroups or sourceAddressPrefixes
        if self.source_asg:
            rule['sourceApplicationSecurityGroups'] = [{'id': self.source_asg}]
        elif self.source_ip:
            rule['sourceAddressPrefixes'] = [self.source_ip]

        # Add destinationApplicationSecurityGroups or destinationAddressPrefixes
        if self.destination_asg:
            rule['destinationApplicationSecurityGroups'] = [{'id': self.destination_asg}]
        elif self.destination_ip:
            rule['destinationAddressPrefixes'] = [self.destination_ip]

        return rule

class NSGRuleManager:
    def __init__(self, input_file: str, output_dir: str) -> None:
        self.input_file = input_file
        self.output_dir = output_dir
        self.loader = LoadDataFromExcel(input_file)
        self.rules_by_destination_asg = {}
        self.rules_by_source_asg = {}

    def process_data(self) -> None:
        self.loader.loadExcel()
        data = self.loader.getData()
        sheet_data = data[0].get("results")
        sorted_sheet_data = sorted(sheet_data, key=lambda x: x['sourceAsg'])

        c = 0
        for i in sorted_sheet_data:
            source_asg = i.get("sourceAsg") or i.get("Source IP")
            destination_asg = i.get("destinationAsg") or i.get("Destination IP")
            source_ip = i.get("Source IP")
            destination_ip = i.get("Destination IP")

            inbound_nsg_rule = NSGRule(
                priority=1000 + c,
                direction='Inbound',
                source_asg=source_asg if source_asg != source_ip else None,
                destination_asg=destination_asg if destination_asg != destination_ip else None,
                destination_port=i.get("Destination port"),
                source_ip=source_ip if source_asg == source_ip else None,
                destination_ip=destination_ip if destination_asg == destination_ip else None
            ).to_dict()

            outbound_nsg_rule = NSGRule(
                priority=1000 + c,
                direction='Outbound',
                source_asg=source_asg if source_asg != source_ip else None,
                destination_asg=destination_asg if destination_asg != destination_ip else None,
                destination_port=i.get("Destination port"),
                source_ip=source_ip if source_asg == source_ip else None,
                destination_ip=destination_ip if destination_asg == destination_ip else None
            ).to_dict()
            outbound_nsg_rule['name'] = 'Allow-Outbound-{}-to-{}-{}'.format(
                outbound_nsg_rule.get('sourceApplicationSecurityGroups', [{'id': source_ip}])[0].get('id', source_ip) if 'sourceApplicationSecurityGroups' in outbound_nsg_rule else outbound_nsg_rule.get('sourceAddressPrefixes', [source_ip])[0],
                outbound_nsg_rule.get('destinationApplicationSecurityGroups', [{'id': destination_ip}])[0].get('id', destination_ip) if 'destinationApplicationSecurityGroups' in outbound_nsg_rule else outbound_nsg_rule.get('destinationAddressPrefixes', [destination_ip])[0],
                outbound_nsg_rule['destinationPortRanges'][0]
            )

            if destination_asg not in self.rules_by_destination_asg:
                self.rules_by_destination_asg[destination_asg] = []
            self.rules_by_destination_asg[destination_asg].append(inbound_nsg_rule)

            if source_asg not in self.rules_by_source_asg:
                self.rules_by_source_asg[source_asg] = []
            self.rules_by_source_asg[source_asg].append(outbound_nsg_rule)

            c += 1

    def write_rules_to_files(self) -> None:
        os.makedirs(self.output_dir, exist_ok=True)

        for destination_asg, rules in self.rules_by_destination_asg.items():
            file_path = os.path.join(self.output_dir, f'{destination_asg}_inbound_subnet.json')
            with open(file_path, 'w') as f:
                json.dump(rules, f, indent=4)

        for source_asg, rules in self.rules_by_source_asg.items():
            file_path = os.path.join(self.output_dir, f'{source_asg}_outbound_subnet.json')
            with open(file_path, 'w') as f:
                json.dump(rules, f, indent=4)


def main(input_file: str, output_dir: str) -> None:
    nsg_rule_manager = NSGRuleManager(input_file, output_dir)
    nsg_rule_manager.process_data()
    nsg_rule_manager.write_rules_to_files()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process Excel file to generate NSG rules.')
    parser.add_argument('input_file', type=str, nargs='?', default='input_2.xls', help='Path to the input Excel file')
    parser.add_argument('output_dir', type=str, nargs='?', default='output', help='Directory to store the output JSON files')
    args = parser.parse_args()
    main(args.input_file, args.output_dir)
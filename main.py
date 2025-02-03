from python_excel2json import parse_excel_to_json
import json
import os

class NetworkSecurityGroupRule:
    """
    Represents a Network Security Group (NSG) rule.
    """
    def __init__(self, name: str, priority: int, direction: str, source_asg: str, destination_asg: str, destination_port: str) -> None:
        """
        Initializes a NetworkSecurityGroupRule instance.

        :param name: The name of the NSG rule.
        :param priority: The priority of the NSG rule.
        :param direction: The direction of the NSG rule (Inbound/Outbound).
        :param source_asg: The source Application Security Group (ASG).
        :param destination_asg: The destination Application Security Group (ASG).
        :param destination_port: The destination port for the NSG rule.
        """
        self.name = name
        self.priority = priority
        self.direction = direction
        self.source_asg = source_asg
        self.destination_asg = destination_asg
        self.destination_port = destination_port

    def to_dict(self) -> dict:
        """
        Converts the NetworkSecurityGroupRule instance to a dictionary.

        :return: A dictionary representation of the NSG rule.
        """
        return {
            'name': self.name,
            'priority': self.priority,
            'direction': self.direction,
            'access': 'Allow',
            'protocol': 'Tcp',
            'sourcePortRanges': ['*'],
            'destinationPortRanges': [self.destination_port],
            'sourceApplicationSecurityGroups': [{'id': self.source_asg}],
            'destinationApplicationSecurityGroups': [{'id': self.destination_asg}]
        }

class NSGJsonGenerator:
    """
    Generates NSG rules in JSON format from provided data.
    """
    def __init__(self, data: list) -> None:
        """
        Initializes an NSGJsonGenerator instance.

        :param data: A list of data from which NSG rules will be generated.
        """
        self.data = data
        self.nsg_rules = []

    def create_nsg_rule(self, item: dict, direction: str, count: int) -> NetworkSecurityGroupRule:
        """
        Creates a NetworkSecurityGroupRule instance from provided item data.

        :param item: A dictionary containing item data.
        :param direction: The direction of the NSG rule (Inbound/Outbound).
        :param count: The count used to set the priority of the NSG rule.
        :return: A NetworkSecurityGroupRule instance.
        """
        name = f"Allow-ASG-{direction}-{item.get('Destination port')}"
        source_asg = item.get('sourceAsg') or item.get('Source IP')
        return NetworkSecurityGroupRule(
            name=name,
            priority=100 + count,
            direction=direction,
            source_asg=source_asg,
            destination_asg=item.get('destinationAsg'),
            destination_port=item.get('Destination port')
        )

    def generate_nsg_rules(self) -> dict:
        """
        Generates a dictionary of NSG rules grouped by server.

        :return: A dictionary where keys are server names and values are lists of NSG rules.
        """
        server_rules = {}
        for sheet in self.data:
            results = sheet.get('results', [])
            for count, item in enumerate(results, start=1):
                server_name = item.get('Destination server name')
                if server_name not in server_rules:
                    server_rules[server_name] = []
                for direction in ['Outbound', 'Inbound']:
                    rule = self.create_nsg_rule(item, direction, count)
                    server_rules[server_name].append(rule.to_dict())
        return server_rules

    def save_to_files(self, output_dir: str) -> None:
        """
        Saves the generated NSG rules to separate files, one per server.

        :param output_dir: The directory where the JSON files will be saved.
        """
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        server_rules = self.generate_nsg_rules()
        for server_name, rules in server_rules.items():
            filename = os.path.join(output_dir, f"{server_name}_nsg_rules.json")
            with open(filename, 'w') as f:
                json.dump(rules, f, indent=2)

class ExcelDataLoader:
    """
    Loads data from an Excel file and converts it to JSON format.
    """
    def __init__(self, path: str) -> None:
        """
        Initializes an ExcelDataLoader instance.

        :param path: The path to the Excel file.
        """
        self.path = path
        self.data = None

    def load_data(self) -> list:
        """
        Loads data from the Excel file.

        :return: A list of data loaded from the Excel file.
        """
        excel_sheets_format = {
            'start_row_sheet_parsing': 1,
            'start_column_sheet_parsing': 0,
            'sheet_formats': [
                {
                    'sheet_index': 1,
                    'column_names': [
                        {'name': 'Source server name', 'type': 'str'},
                        {'name': 'sourceAsg', 'type': 'str'},
                        {'name': 'Source IP', 'type': 'str'},
                        {'name': 'Destination server name', 'type': 'str'},
                        {'name': 'Destination IP', 'type': 'str'},
                        {'name': 'Destination port', 'type': 'str'},
                        {'name': 'Comment', 'type': 'str'},
                        {'name': 'Environment', 'type': 'str'},
                        {'name': 'destinationAsg', 'type': 'str'},
                        {'name': 'Az snet', 'type': 'str'}
                    ],
                    'is_ordered': True
                }
            ]
        }
        self.data = parse_excel_to_json(excel_sheets_format, self.path)
        return self.data

# Create an instance of ExcelDataLoader
loader = ExcelDataLoader('/Users/robban/Downloads/azmigratefiltered.xls')
data = loader.load_data()

print(json.dumps(data, indent=3))

# Create an instance of NSGJsonGenerator
nsg_generator = NSGJsonGenerator(data)

# Save the NSG rules to separate files, one per server
output_directory = 'nsg_rules_per_server'
nsg_generator.save_to_files(output_directory)
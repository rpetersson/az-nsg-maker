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

def main(input_file: str, output_dir: str) -> None:
    """
    Main function to process the Excel file and generate NSG rules.

    :param input_file: Path to the input Excel file.
    :param output_dir: Directory to store the output JSON files.
    """
    # Create an instance of LoadDataFromExcel
    loader = LoadDataFromExcel(input_file)
    loader.loadExcel()
    data = loader.getData()  # Access the data variable

    sheet_data = data[0].get("results")
    #sort sheet data by sourceAsg
    sortedSheetData = sorted(sheet_data, key=lambda x: x['sourceAsg'])

    c = 0
    previousSourceAsg = ""
    rules_by_destination_asg = {}
    rules_by_source_asg = {}

    for i in sortedSheetData:
        sourceAsg = i.get("sourceAsg")
        destinationAsg = i.get("destinationAsg")
        sourceIp = i.get("Source IP")
        destinationIp = i.get("Destination IP")

        # Handle empty cells that show up as "42" or empty strings
        if sourceAsg == "42" or sourceAsg == "":
            sourceAsg = None
        if destinationAsg == "42" or destinationAsg == "":
            destinationAsg = None
        if sourceIp == "42" or sourceIp == "":
            sourceIp = None
        if destinationIp == "42" or destinationIp == "":
            destinationIp = None

        # Use IP addresses if ASG values are None
        if sourceAsg is None:
            sourceAsg = sourceIp
        if destinationAsg is None:
            destinationAsg = destinationIp

        inboundNsgRule = NSGRule(
            priority=1000 + c,
            direction='Inbound',
            source_asg=sourceAsg if sourceAsg != sourceIp else None,
            destination_asg=destinationAsg if destinationAsg != destinationIp else None,
            destination_port=i.get("Destination port"),
            source_ip=sourceIp if sourceAsg == sourceIp else None,
            destination_ip=destinationIp if destinationAsg == destinationIp else None
        ).to_dict()

        outboundNsgRule = NSGRule(
            priority=1000 + c,
            direction='Outbound',
            source_asg=sourceAsg if sourceAsg != sourceIp else None,
            destination_asg=destinationAsg if destinationAsg != destinationIp else None,
            destination_port=i.get("Destination port"),
            source_ip=sourceIp if sourceAsg == sourceIp else None,
            destination_ip=destinationIp if destinationAsg == destinationIp else None
        ).to_dict()
        outboundNsgRule['name'] = 'Allow-Outbound-{}-to-{}-{}'.format(
            outboundNsgRule.get('sourceApplicationSecurityGroups', [{'id': sourceIp}])[0].get('id', sourceIp) if 'sourceApplicationSecurityGroups' in outboundNsgRule else outboundNsgRule.get('sourceAddressPrefixes', [sourceIp])[0],
            outboundNsgRule.get('destinationApplicationSecurityGroups', [{'id': destinationIp}])[0].get('id', destinationIp) if 'destinationApplicationSecurityGroups' in outboundNsgRule else outboundNsgRule.get('destinationAddressPrefixes', [destinationIp])[0],
            outboundNsgRule['destinationPortRanges'][0]
        )

        destination_asg = i.get("destinationAsg")
        if destination_asg not in rules_by_destination_asg:
            rules_by_destination_asg[destination_asg] = []
        rules_by_destination_asg[destination_asg].append(inboundNsgRule)

        if sourceAsg not in rules_by_source_asg:
            rules_by_source_asg[sourceAsg] = []
        rules_by_source_asg[sourceAsg].append(outboundNsgRule)

        c += 1  # Increment the counter

    # Create a directory to store the files
    os.makedirs(output_dir, exist_ok=True)

    # Write each set of inbound rules to a separate file
    for destination_asg, rules in rules_by_destination_asg.items():
        file_path = os.path.join(output_dir, f'{destination_asg}_inbound_subnet.json')
        with open(file_path, 'w') as f:
            json.dump(rules, f, indent=4)

    # Write each set of outbound rules to a separate file
    for source_asg, rules in rules_by_source_asg.items():
        file_path = os.path.join(output_dir, f'{source_asg}_outbound_subnet.json')
        with open(file_path, 'w') as f:
            json.dump(rules, f, indent=4)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process Excel file to generate NSG rules.')
    parser.add_argument('input_file', type=str, nargs='?', default='input_2.xls', help='Path to the input Excel file')
    parser.add_argument('output_dir', type=str, nargs='?', default='output', help='Directory to store the output JSON files')
    args = parser.parse_args()
    main(args.input_file, args.output_dir)
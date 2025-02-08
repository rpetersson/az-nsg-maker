from python_excel2json import parse_excel_to_json
import json
import os
import argparse  # Import argparse for command-line arguments
from schema import EXCEL_SHEET_SCHEMA  # Import the schema

class LoadDataFromExcel:
    def __init__(self, path: str) -> None:
        self.path = path
        self.data = None  # Initialize data as None
        
    def loadExcel(self) -> None:
        self.data = parse_excel_to_json(EXCEL_SHEET_SCHEMA, self.path)  # Use the imported schema
        
    def getData(self) -> list:
        return self.data

class NSGRule:
    def __init__(self, priority: int, direction: str, source_asg: str, destination_asg: str, destination_port: str) -> None:
        self.priority = priority
        self.direction = direction
        self.source_asg = source_asg
        self.destination_asg = destination_asg
        self.destination_port = destination_port

    def to_dict(self) -> dict:
        return {
            'name': 'Allow-{}-{}-to-{}-{}'.format(self.direction, self.source_asg, self.destination_asg, self.destination_port),
            'priority': self.priority,
            'direction': self.direction,
            'access': 'Allow',
            'protocol': 'Tcp',
            'sourcePortRanges': ['*'],
            'destinationPortRanges': [self.destination_port],
            'sourceApplicationSecurityGroups': [{'id': self.source_asg}],
            'destinationApplicationSecurityGroups': [{'id': self.destination_asg}]
        }

def main(input_file: str, output_dir: str) -> None:
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
        if previousSourceAsg != sourceAsg:
            c = 0
        c += 1
        previousSourceAsg = sourceAsg

        inboundNsgRule = NSGRule(
            priority=1000+c, 
            direction='Inbound', 
            source_asg=i.get("sourceAsg"), 
            destination_asg=i.get("destinationAsg"), 
            destination_port=i.get("Destination port")).to_dict()

        outboundNsgRule = NSGRule(
            priority=1000+c, 
            direction='Outbound', 
            source_asg=i.get("sourceAsg"), 
            destination_asg=i.get("destinationAsg"), 
            destination_port=i.get("Destination port")).to_dict()
        outboundNsgRule['name'] = 'Allow-Outbound-{}-to-{}-{}'.format(outboundNsgRule['sourceApplicationSecurityGroups'][0]['id'], outboundNsgRule['destinationApplicationSecurityGroups'][0]['id'], outboundNsgRule['destinationPortRanges'][0])

        destination_asg = i.get("destinationAsg")
        if destination_asg not in rules_by_destination_asg:
            rules_by_destination_asg[destination_asg] = []
        rules_by_destination_asg[destination_asg].append(inboundNsgRule)

        if sourceAsg not in rules_by_source_asg:
            rules_by_source_asg[sourceAsg] = []
        rules_by_source_asg[sourceAsg].append(outboundNsgRule)

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
    parser.add_argument('input_file', type=str, nargs='?', default='input.xls', help='Path to the input Excel file')
    parser.add_argument('output_dir', type=str, nargs='?', default='output', help='Directory to store the output JSON files')
    args = parser.parse_args()
    main(args.input_file, args.output_dir)
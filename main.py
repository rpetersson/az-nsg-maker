from python_excel2json import parse_excel_to_json
import json

class NSGRule:
    def __init__(self, name: str, priority: int, direction: str, source_asg: str, destination_asg: str, destination_port: str) -> None:
        self.name = name
        self.priority = priority
        self.direction = direction
        self.source_asg = source_asg
        self.destination_asg = destination_asg
        self.destination_port = destination_port

    def to_dict(self) -> dict:
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

class GenerateNSGJson:
    def __init__(self, data: list) -> None:
        self.data = data
        self.nsgs = []

    def create_nsg_rule(self, item: dict, direction: str, count: int) -> NSGRule:
        name = f"Allow-ASG-{direction}-{item.get('Destination port')}"
        return NSGRule(
            name=name,
            priority=100 + count,
            direction=direction,
            source_asg=item.get('sourceAsg'),
            destination_asg=item.get('destinationAsg'),
            destination_port=item.get('Destination port')
        )

    def generateNsg(self) -> list:
        for sheet in self.data:
            results = sheet.get('results', [])
            for count, item in enumerate(results, start=1):
                outbound_nsg = self.create_nsg_rule(item, 'Outbound', count)
                inbound_nsg = self.create_nsg_rule(item, 'Inbound', count)
                self.nsgs.append(outbound_nsg.to_dict())
                self.nsgs.append(inbound_nsg.to_dict())
        return self.nsgs

    def save_to_file(self, filename: str) -> None:
        with open(filename, 'w') as f:
            json.dump(self.nsgs, f, indent=2)

class LoadDataFromExcel:
    def __init__(self, path: str) -> None:
        self.path = path
        self.data = None  # Initialize data as None
        
    def loadExcel(self) -> None:
        excel_sheets_format = {
            'start_row_sheet_parsing': 1,
            'start_column_sheet_parsing': 0,
            'sheet_formats': [
                {
                    'sheet_index': 1,
                    'column_names': [
                        {
                            'name': 'Source server name',
                            'type': 'str'
                        },
                        {
                            'name': 'sourceAsg',
                            'type': 'str'
                        },
                        {
                            'name': 'Source IP',
                            'type': 'str'
                        },
                        {
                            'name': 'Destination server name',
                            'type': 'str'
                        },  
                        {
                            'name': 'Destination IP',
                            'type': 'str'
                        },
                        {
                            'name': 'Destination port',
                            'type': 'str'
                        },
                        {
                            'name': 'Comment',
                            'type': 'str'
                        },
                        {
                            'name': 'Environment',
                            'type': 'str'
                        },
                        {
                            'name': 'destinationAsg',
                            'type': 'str'
                        },
                        {
                            'name': 'Az snet',
                            'type': 'str'
                        }
                    ],
                    'is_ordered': True
                }
            ]
        }
        self.data = parse_excel_to_json(excel_sheets_format, self.path)
        
    def getData(self) -> list:
        return self.data
    
# Create an instance of LoadDataFromExcel
loader = LoadDataFromExcel('/Users/robban/Downloads/azmigratefiltered.xls')
loader.loadExcel()
data = loader.getData()  # Access the data variable

print(json.dumps(data, indent=3))

# Create an instance of GenerateNSGJson
nsg_generator = GenerateNSGJson(data)
nsgs = nsg_generator.generateNsg()

print(json.dumps(nsgs, indent=2))

# Save the NSGs to a file
nsg_generator.save_to_file('nsgs.json')

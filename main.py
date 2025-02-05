from python_excel2json import parse_excel_to_json
import json

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


# Create an instance of LoadDataFromExcel
loader = LoadDataFromExcel('/Users/robban/Downloads/azmigratefiltered.xls')
loader.loadExcel()
data = loader.getData()  # Access the data variable

sheet_data = data[0].get("results")
#sort sheet data by subnet name
sortedSheetData = sorted(sheet_data, key=lambda x: x['Az snet'])

c = 0
previousSubnet = ""

for i in sortedSheetData:
    subnet = i.get("Az snet")
    if previousSubnet != subnet:
        c = 0
    c += 1
    previousSubnet = subnet

    inboundNsgRule = NSGRule(
        priority=1000+c, 
        direction='Inbound', 
        source_asg=i.get("sourceAsg"), 
        destination_asg=i.get("destinationAsg"), 
        destination_port=i.get("Destination port")).to_dict()
    
    outobundNsgRule = NSGRule(
        priority=1000+c, 
        direction='Outbound', 
        source_asg=i.get("destinationAsg"), 
        destination_asg=i.get("sourceAsg"), 
        destination_port=i.get("Destination port")).to_dict()

    print(json.dumps(inboundNsgRule, indent=4))

    print(json.dumps(outobundNsgRule, indent=4))

    with open(f'{subnet}_inbound.json', 'a') as f:
        f.write(json.dumps(inboundNsgRule, indent=4))
        f.write('\n')
    
    with open(f'{subnet}_outbound.json', 'a') as f:
        f.write(json.dumps(outobundNsgRule, indent=4))
        f.write('\n')
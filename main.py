from python_excel2json import parse_excel_to_json
import json

class GenerateNSGJson:
    def __init__(self, data: list) -> None:
        self.data = data
        self.nsgs = []  # Initialize nsgs as an empty dictionary
    
    '''
    Generate NSG JSON from the data like the following template:
        name: 'Allow-ASG-Inbound'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '22'
          sourceApplicationSecurityGroups: [
            {
              id: asg.id
            }
          ]
          destinationApplicationSecurityGroups: [
            {
              id: asg.id
            }
          ]
        }
      }
    '''
    def generateNsg(self) -> list:
        for sheet in self.data:
            results = sheet.get('results', [])
            count = 0
            for item in results:
                count += 1
                outboundNsgs = {
                    'name': 'Allow-ASG-Outbound-'+item.get('Destination port'),
                    'priority': 100+count,
                    'direction': 'Outbound',
                    'access': 'Allow',
                    'protocol': 'Tcp',
                    'sourcePortRanges': ['*'],
                    'destinationPortRanges': [item.get('Destination port')],
                    'sourceApplicationSecurityGroups': [
                        {
                            'id': item.get('sourceAsg')
                        }
                    ],
                    'destinationApplicationSecurityGroups': [
                        {
                            'id': item.get('destinationAsg')
                        }
                    ]
                }
                inboundNsgs = {
                    'name': 'Allow-ASG-Inbound-'+item.get('Destination port'),
                    'priority': 100+count,
                    'direction': 'Inbound',
                    'access': 'Allow',
                    'protocol': 'Tcp',
                    'sourcePortRanges': ['*'],
                    'destinationPortRanges': [item.get('Destination port')],
                    'sourceApplicationSecurityGroups': [
                        {
                            'id': item.get('sourceAsg')
                        }
                    ],
                    'destinationApplicationSecurityGroups': [
                        {
                            'id': item.get('destinationAsg')
                        }
                    ]
                }
                self.nsgs.append(outboundNsgs)
                self.nsgs.append(inboundNsgs)
                
        return self.nsgs


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


print(json.dumps(data, indent=3))

 # Create an instance of GenerateNSGJson
nsgs = GenerateNSGJson(data).generateNsg()

print(json.dumps(nsgs, indent=2))

# save the nsgs to a file
with open('nsgs.json', 'w') as f:
    json.dump(nsgs, f, indent=2)
